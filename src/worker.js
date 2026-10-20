// Cloudflare Worker — Encrypted Group Chat (auth + routing + Durable Objects)
//
// ARCHITECTURE (no KV, no polling)
//   Browser ──WebSocket /api/ws──► ChatRoomDO   (one instance per room)
//      │                             ├─ SQLite: messages table (ordered writes)
//      │                             └─ fan-out: one broadcast → every socket
//   Browser ──POST /api/messages──► Worker ──► ChatRoomDO (write + broadcast)
//
//   One Durable Object = one chat room. Writes are serialised inside the
//   object, so there is no read-modify-write race, and clients receive new
//   messages by push instead of polling.
//
// SECURITY MODEL
// - The chat password (env.PASSWORD) and session signing key (env.SESSION_SECRET)
//   are Cloudflare Secrets. They live ONLY in the dashboard, never in this repo.
// - The password is NEVER returned by any endpoint. Login compares SHA-256
//   digests in constant time, then issues an HttpOnly, Secure, SameSite session
//   cookie. The password is never persisted or echoed.
// - Message bodies are AES-256-GCM ciphertext produced in the browser. The Worker
//   and Durable Objects only store and forward opaque blobs — neither can read
//   the chat content.
// - Same-origin only: no wildcard CORS. Static assets and /api share the origin.
// - Brute-force protection lives in a second Durable Object (LoginGuardDO) so
//   no KV namespace is needed at all.

const COOKIE_NAME = 'egc_session';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const LOGIN_MAX_ATTEMPTS = 8;
const LOGIN_WINDOW_SECONDS = 600; // 10 minutes
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;
const MAX_CIPHERTEXT = 16384; // base64 chars per message
const SESSION_VERSION = 'egc.session.v1';

const ROOM_DO_NAME = 'room';
const GUARD_DO_NAME = 'login-guard';
const MSG_LIMIT = 500; // rows kept in the messages table
const BACKLOG_LIMIT = 300; // rows replayed to a freshly connected socket

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------------------------------------------------------------------------
// crypto / auth / cookie helpers
// ---------------------------------------------------------------------------

function timingSafeEqual(a, b) {
	if (typeof a !== 'string' || typeof b !== 'string') return false;
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
	return diff === 0;
}

async function sha256Hex(value) {
	const digest = await crypto.subtle.digest('SHA-256', encoder.encode(value));
	return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hmacHex(secret, message) {
	const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
	const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
	return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function makeSessionToken(secret, now = Date.now()) {
	const exp = now + SESSION_TTL_MS;
	const sig = await hmacHex(secret, `${SESSION_VERSION}.${exp}`);
	return { token: `${exp}.${sig}`, expiresAt: exp };
}

async function verifySessionToken(secret, token) {
	if (!secret || typeof token !== 'string') return false;
	const dot = token.indexOf('.');
	if (dot < 1) return false;
	const expRaw = token.slice(0, dot);
	const sig = token.slice(dot + 1);
	const exp = Number(expRaw);
	if (!Number.isInteger(exp) || exp <= Date.now()) return false;
	const expected = await hmacHex(secret, `${SESSION_VERSION}.${exp}`);
	return timingSafeEqual(sig, expected);
}

function readCookie(request, name) {
	const header = request.headers.get('cookie');
	if (!header) return null;
	for (const part of header.split(';')) {
		const eq = part.indexOf('=');
		if (eq === -1) continue;
		if (part.slice(0, eq).trim() === name) return decodeURIComponent(part.slice(eq + 1).trim());
	}
	return null;
}

function sessionCookie(token, maxAgeSeconds) {
	const attrs = [`Path=/`, `HttpOnly`, `Secure`, `SameSite=Lax`, `Max-Age=${maxAgeSeconds}`];
	return `${COOKIE_NAME}=${encodeURIComponent(token)}; ${attrs.join('; ')}`;
}

function clientIp(request) {
	return request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 'unknown';
}

function missingConfig(env) {
	const missing = [];
	if (!env.PASSWORD) missing.push('PASSWORD');
	if (!env.SESSION_SECRET) missing.push('SESSION_SECRET');
	if (!env.CHAT_ROOM) missing.push('CHAT_ROOM (Durable Object binding)');
	if (!env.LOGIN_GUARD) missing.push('LOGIN_GUARD (Durable Object binding)');
	return missing;
}

function json(body, status = 200, headers = {}) {
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			'content-type': 'application/json; charset=utf-8',
			'cache-control': 'no-store',
			'x-content-type-options': 'nosniff',
			...headers,
		},
	});
}

// ---------------------------------------------------------------------------
// Durable Object stubs
// ---------------------------------------------------------------------------

function roomStub(env) {
	return env.CHAT_ROOM.get(env.CHAT_ROOM.idFromName(ROOM_DO_NAME));
}

function guardStub(env) {
	return env.LOGIN_GUARD.get(env.LOGIN_GUARD.idFromName(GUARD_DO_NAME));
}

// The guard is an internal Durable Object: only the Worker talks to it, over a
// stub — the public routing table never forwards browser traffic there.
async function guardCall(env, action, payload) {
	const res = await guardStub(env).fetch(
		new Request(`https://login-guard.internal/${action}`, {
			method: 'POST',
			headers: { 'content-type': 'application/json' },
			body: JSON.stringify(payload),
		})
	);
	return res.json();
}

// ---------------------------------------------------------------------------
// route handlers
// ---------------------------------------------------------------------------

async function handleLogin(request, env) {
	const missing = missingConfig(env);
	if (missing.length) return json({ ok: false, error: 'server_not_configured', missing }, 500);

	const ip = clientIp(request);
	const state = await guardCall(env, 'check', { ip });
	if (state.blocked) {
		return json({ ok: false, error: 'too_many_attempts', retry_after_seconds: LOGIN_WINDOW_SECONDS }, 429);
	}

	let body;
	try {
		body = await request.json();
	} catch {
		return json({ ok: false, error: 'bad_request' }, 400);
	}

	const password = typeof body?.password === 'string' ? body.password : '';
	const ok = password.length > 0 && password.length <= 512 &&
		timingSafeEqual(await sha256Hex(password), await sha256Hex(env.PASSWORD));

	if (!ok) {
		await guardCall(env, 'fail', { ip });
		return json({ ok: false, error: 'invalid_password' }, 401);
	}

	await guardCall(env, 'reset', { ip });
	const { token, expiresAt } = await makeSessionToken(env.SESSION_SECRET);
	return json(
		{ ok: true, expires_at: new Date(expiresAt).toISOString() },
		200,
		{ 'set-cookie': sessionCookie(token, Math.floor(SESSION_TTL_MS / 1000)) }
	);
}

async function handleLogout() {
	return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
}

async function handleSession(request, env) {
	if (missingConfig(env).length) return json({ ok: false, error: 'server_not_configured' }, 500);
	const token = readCookie(request, COOKIE_NAME);
	return json({ ok: await verifySessionToken(env.SESSION_SECRET, token) });
}

async function handleHealth(env) {
	const missing = missingConfig(env);
	return json({ ok: missing.length === 0, missing });
}

async function isAuthorised(request, env) {
	return verifySessionToken(env.SESSION_SECRET, readCookie(request, COOKIE_NAME));
}

// ---------------------------------------------------------------------------
// Worker entrypoint
// ---------------------------------------------------------------------------

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const path = url.pathname;

		if (request.method === 'OPTIONS') return new Response(null, { status: 204 });

		if (path === '/api/login') {
			if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
			return handleLogin(request, env);
		}
		if (path === '/api/logout') {
			if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
			return handleLogout();
		}
		if (path === '/api/session' && request.method === 'GET') return handleSession(request, env);
		if (path === '/api/health' && request.method === 'GET') return handleHealth(env);

		// Message history / new messages → the room Durable Object.
		if (path === '/api/messages') {
			if (request.method !== 'GET' && request.method !== 'POST') {
				return json({ ok: false, error: 'method_not_allowed' }, 405);
			}
			if (!(await isAuthorised(request, env))) return json({ ok: false, error: 'unauthorized' }, 401);
			return roomStub(env).fetch(request);
		}

		// WebSocket upgrade → the room Durable Object.
		if (path === '/api/ws') {
			if (request.method !== 'GET') return json({ ok: false, error: 'method_not_allowed' }, 405);
			if (request.headers.get('upgrade')?.toLowerCase() !== 'websocket') {
				return json({ ok: false, error: 'upgrade_required' }, 426);
			}
			if (!(await isAuthorised(request, env))) return json({ ok: false, error: 'unauthorized' }, 401);
			return roomStub(env).fetch(request);
		}

		if (path.startsWith('/api/')) return json({ ok: false, error: 'not_found' }, 404);

		// Static assets.
		if (env.ASSETS) return env.ASSETS.fetch(request);
		return new Response('Not Found', { status: 404 });
	},
};

// ---------------------------------------------------------------------------
// Durable Object: the chat room
// ---------------------------------------------------------------------------
//
// One instance per room (idFromName("room")), so every client shares the same
// connection set and the same SQLite database.
//
// Message rows carry three keys the browser can rely on:
//   seq — monotonic counter (AUTOINCREMENT) → exact "give me what is new"
//   id  — UUID → stable de-duplication key
//   t   — millisecond timestamp → display + coarse catch-up

export class ChatRoomDO {
	constructor(ctx, env) {
		this.ctx = ctx;
		this.env = env;
		this.sessions = new Set();
	}

	async fetch(request) {
		const url = new URL(request.url);
		const upgrade = request.headers.get('upgrade')?.toLowerCase() === 'websocket';

		if (upgrade) {
			const authorised = await verifySessionToken(this.env.SESSION_SECRET, readCookie(request, COOKIE_NAME));
			if (!authorised) return new Response('Unauthorized', { status: 401 });
			return this.acceptSocket(request, url);
		}

		const authorised = await verifySessionToken(this.env.SESSION_SECRET, readCookie(request, COOKIE_NAME));
		if (!authorised) return json({ ok: false, error: 'unauthorized' }, 401);

		if (request.method === 'GET') {
			const since = Number(url.searchParams.get('since') || 0) || 0;
			// No cursor → the retained history; a cursor → only what is newer.
			const rows = since > 0 ? await this.loadSince(since) : await this.loadRecent(MSG_LIMIT);
			return json({ ok: true, messages: rows });
		}

		if (request.method === 'POST') {
			let body;
			try {
				body = await request.json();
			} catch {
				return json({ ok: false, error: 'bad_request' }, 400);
			}
			const ciphertext = typeof body?.content === 'string' ? body.content : '';
			if (!ciphertext || ciphertext.length > MAX_CIPHERTEXT || !B64_RE.test(ciphertext)) {
				return json({ ok: false, error: 'invalid_payload' }, 400);
			}

			const row = await this.appendMessage(ciphertext);
			this.broadcast(JSON.stringify(row));
			return json({ ok: true, id: row.id, seq: row.seq, t: row.t }, 201);
		}

		return json({ ok: false, error: 'method_not_allowed' }, 405);
	}

	// -- WebSocket lifecycle -------------------------------------------------

	async acceptSocket(request, url) {
		const pair = new WebSocketPair();
		const [client, server] = Object.values(pair);
		server.accept();

		this.sessions.add(server);
		server.addEventListener('close', () => {
			this.sessions.delete(server);
			this.broadcastPresence();
		});
		server.addEventListener('message', (event) => this.onClientMessage(server, event.data));

		// Replay: either everything newer than the client's cursor, or the tail
		// of the history for a first-time connection.
		const since = Number(url.searchParams.get('since') || 0) || 0;
		try {
			const rows = since > 0 ? await this.loadSince(since) : await this.loadRecent();
			for (const row of rows) server.send(JSON.stringify(row));
		} catch {
			// A replay failure must not break the connection — the client can
			// still receive live messages.
		}

		this.broadcastPresence();
		return new Response(null, { status: 101, webSocket: client });
	}

	// How many browsers are currently attached to this room. Purely cosmetic —
	// it carries no user data.
	broadcastPresence() {
		this.broadcast(JSON.stringify({ type: 'presence', online: this.sessions.size }));
	}

	broadcast(data) {
		for (const ws of [...this.sessions]) {
			try {
				ws.send(data);
			} catch {
				this.sessions.delete(ws);
			}
		}
	}

	async onClientMessage(socket, raw) {
		// Clients only send lightweight control frames (ping). Message creation
		// always goes through POST /api/messages so auth and payload validation
		// stay in one place.
		if (typeof raw !== 'string') return;
		let msg;
		try {
			msg = JSON.parse(raw);
		} catch {
			return;
		}
		if (msg?.type === 'ping') socket.send(JSON.stringify({ type: 'pong', t: Date.now() }));
	}

	// -- storage -------------------------------------------------------------

	async ensureSchema() {
		if (this.schemaReady) return;
		this.ctx.storage.sql.exec(`
			CREATE TABLE IF NOT EXISTS messages (
				seq INTEGER PRIMARY KEY AUTOINCREMENT,
				id TEXT NOT NULL UNIQUE,
				ts INTEGER NOT NULL,
				payload TEXT NOT NULL
			);
			CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages (ts);
		`);
		this.schemaReady = true;
	}

	async appendMessage(ciphertext) {
		await this.ensureSchema();
		const sql = this.ctx.storage.sql;
		const id = crypto.randomUUID();
		const ts = Date.now();

		sql.exec('INSERT INTO messages (id, ts, payload) VALUES (?, ?, ?)', id, ts, ciphertext);
		const seqRow = sql.exec('SELECT last_insert_rowid() AS seq').toArray()[0];
		let seq = Number(seqRow?.seq || 0);
		if (!seq) {
			// Fallback in case last_insert_rowid() is unavailable.
			const maxRow = sql.exec('SELECT COALESCE(MAX(seq), 0) AS m FROM messages').toArray()[0];
			seq = Number(maxRow?.m || 0) + 1;
		}

		// Trim to the newest MSG_LIMIT rows, but only when needed — the check
		// keeps the common path (append) cheap. AUTOINCREMENT keeps `seq`
		// monotonic even when every row is deleted, so client cursors stay valid.
		const countRow = sql.exec('SELECT COUNT(*) AS n FROM messages').toArray()[0];
		if (Number(countRow?.n || 0) > MSG_LIMIT) {
			sql.exec(
				`DELETE FROM messages WHERE seq NOT IN (SELECT seq FROM messages ORDER BY seq DESC LIMIT ${MSG_LIMIT})`
			);
		}

		return { seq, id, t: ts, c: ciphertext };
	}

	async loadSince(since) {
		await this.ensureSchema();
		const rows = this.ctx.storage.sql.exec(
			`SELECT seq, id, ts AS t, payload AS c FROM messages WHERE seq > ? ORDER BY seq ASC LIMIT ${MSG_LIMIT}`,
			since
		);
		return rows.toArray();
	}

	async loadRecent(limit = BACKLOG_LIMIT) {
		await this.ensureSchema();
		const rows = this.ctx.storage.sql.exec(
			`SELECT seq, id, ts AS t, payload AS c FROM messages ORDER BY seq DESC LIMIT ${limit}`
		);
		return rows.toArray().reverse();
	}
}

// ---------------------------------------------------------------------------
// Durable Object: login brute-force guard
// ---------------------------------------------------------------------------
//
// Keeps the failed-login counter out of KV. The Worker talks to it only
// through a stub, so the counters are not reachable from the public internet.

export class LoginGuardDO {
	constructor(ctx, env) {
		this.ctx = ctx;
		this.env = env;
	}

	async fetch(request) {
		const url = new URL(request.url);
		let body = {};
		try {
			body = await request.json();
		} catch {
			return json({ ok: false, error: 'bad_request' }, 400);
		}
		const ip = typeof body.ip === 'string' ? body.ip.slice(0, 64) : '';
		if (!ip) return json({ ok: false, error: 'bad_request' }, 400);

		const sql = this.ctx.storage.sql;
		this.ensureSchema(sql);

		if (url.pathname.endsWith('/check')) {
			const row = sql.exec('SELECT n, ts FROM attempts WHERE ip = ?', ip).toArray()[0];
			if (!row) return json({ ok: true, count: 0, blocked: false });
			if (Date.now() - Number(row.ts) > LOGIN_WINDOW_SECONDS * 1000) {
				sql.exec('DELETE FROM attempts WHERE ip = ?', ip);
				return json({ ok: true, count: 0, blocked: false });
			}
			const count = Number(row.n) || 0;
			return json({ ok: true, count, blocked: count >= LOGIN_MAX_ATTEMPTS });
		}

		if (url.pathname.endsWith('/fail')) {
			const row = sql.exec('SELECT n FROM attempts WHERE ip = ?', ip).toArray()[0];
			const count = (Number(row?.n) || 0) + 1;
			if (row) {
				sql.exec('UPDATE attempts SET n = ?, ts = ? WHERE ip = ?', count, Date.now(), ip);
			} else {
				sql.exec('INSERT INTO attempts (ip, n, ts) VALUES (?, ?, ?)', ip, count, Date.now());
			}
			return json({ ok: true, count, blocked: count >= LOGIN_MAX_ATTEMPTS });
		}

		if (url.pathname.endsWith('/reset')) {
			sql.exec('DELETE FROM attempts WHERE ip = ?', ip);
			return json({ ok: true, count: 0, blocked: false });
		}

		return json({ ok: false, error: 'not_found' }, 404);
	}

	ensureSchema(sql) {
		if (this.schemaReady) return;
		sql.exec(`
			CREATE TABLE IF NOT EXISTS attempts (
				ip TEXT PRIMARY KEY,
				n INTEGER NOT NULL,
				ts INTEGER NOT NULL
			);
		`);
		this.schemaReady = true;
	}
}
