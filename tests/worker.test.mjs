// Local test harness for the Worker + Durable Object logic — runs in plain
// Node (no Cloudflare account needed). The Durable Objects are exercised
// through a small in-memory SQLite mock, so ordering, trimming, fan-out and
// de-duplication are all covered without a live runtime.
//
// Run with: npm test   (or: node tests/worker.test.mjs)

import assert from 'node:assert/strict';
import worker, { ChatRoomDO, LoginGuardDO } from '../src/worker.js';

// Node's Response constructor rejects status 101 (undici allows 200-599),
// but the Workers runtime requires 101 for a WebSocket upgrade. Patch it so
// the upgrade path is exercised for real instead of being skipped.
const NativeResponse = globalThis.Response;
globalThis.Response = class extends NativeResponse {
	constructor(body, init = {}) {
		if (init && init.status === 101) {
			super(null, { status: 200, headers: init.headers });
			this._status = 101;
			this._webSocket = init.webSocket;
		} else {
			super(body, init);
			this._status = undefined;
			this._webSocket = undefined;
		}
	}
	get status() { return this._status ?? super.status; }
	get webSocket() { return this._webSocket; }
};

const PASSWORD = 'room-pass-123';
const SESSION_SECRET = 'session-signing-secret-value';

// ---------------------------------------------------------------------------
// a tiny in-memory stand-in for ctx.storage.sql
// ---------------------------------------------------------------------------
// It understands exactly the statements the Durable Objects issue, which keeps
// the test honest: if the code starts using another query shape, the mock
// throws instead of silently passing.

class FakeSql {
	constructor() {
		this.tables = { messages: [], attempts: [] };
	}

	exec(query, ...bindings) {
		const sql = query.trim().replace(/\s+/g, ' ');

		if (/^CREATE TABLE IF NOT EXISTS messages/i.test(sql)) {
			this.tables.messages = [];
			return emptyCursor();
		}
		if (/^CREATE TABLE IF NOT EXISTS attempts/i.test(sql)) {
			this.tables.attempts = [];
			return emptyCursor();
		}
		if (/^CREATE INDEX/i.test(sql)) return emptyCursor();

		if (/^INSERT INTO messages/i.test(sql)) {
			const [id, ts, payload] = bindings;
			const seq = this.tables.messages.length
				? Math.max(...this.tables.messages.map((m) => m.seq)) + 1
				: 1;
			this.tables.messages.push({ seq, id, ts, payload });
			return emptyCursor();
		}
		if (/^SELECT last_insert_rowid\(\)/i.test(sql)) {
			const last = this.tables.messages[this.tables.messages.length - 1];
			return cursor([{ seq: last ? last.seq : 0 }]);
		}
		if (/^SELECT COALESCE\(MAX\(seq\), 0\) AS m FROM messages/i.test(sql)) {
			const max = this.tables.messages.reduce((acc, m) => Math.max(acc, m.seq), 0);
			return cursor([{ m: max }]);
		}
		if (/^SELECT COUNT\(\*\) AS n FROM messages/i.test(sql)) {
			return cursor([{ n: this.tables.messages.length }]);
		}
		if (/^DELETE FROM messages/i.test(sql)) {
			const limit = Number((sql.match(/LIMIT (\d+)\)/) || [])[1] || 500);
			const sorted = [...this.tables.messages].sort((a, b) => b.seq - a.seq);
			const keep = new Set(sorted.slice(0, limit).map((m) => m.seq));
			this.tables.messages = this.tables.messages.filter((m) => keep.has(m.seq));
			return emptyCursor();
		}
		if (/^SELECT seq, id, ts AS t, payload AS c FROM messages WHERE seq >/i.test(sql)) {
			const since = Number(bindings[0]);
			const limit = Number((sql.match(/LIMIT (\d+)/) || [])[1] || 500);
			const rows = this.tables.messages
				.filter((m) => m.seq > since)
				.sort((a, b) => a.seq - b.seq)
				.slice(0, limit)
				.map((m) => ({ seq: m.seq, id: m.id, t: m.ts, c: m.payload }));
			return cursor(rows);
		}
		if (/^SELECT seq, id, ts AS t, payload AS c FROM messages ORDER BY seq DESC/i.test(sql)) {
			const limit = Number((sql.match(/LIMIT (\d+)/) || [])[1] || 300);
			const rows = [...this.tables.messages]
				.sort((a, b) => b.seq - a.seq)
				.slice(0, limit)
				.map((m) => ({ seq: m.seq, id: m.id, t: m.ts, c: m.payload }));
			return cursor(rows);
		}

		if (/^SELECT n, ts FROM attempts WHERE ip/i.test(sql)) {
			const row = this.tables.attempts.find((a) => a.ip === bindings[0]);
			return cursor(row ? [{ n: row.n, ts: row.ts }] : []);
		}
		if (/^SELECT n FROM attempts WHERE ip/i.test(sql)) {
			const row = this.tables.attempts.find((a) => a.ip === bindings[0]);
			return cursor(row ? [{ n: row.n }] : []);
		}
		if (/^UPDATE attempts SET n/i.test(sql)) {
			const [n, ts, ip] = bindings;
			const row = this.tables.attempts.find((a) => a.ip === ip);
			if (row) { row.n = n; row.ts = ts; }
			return emptyCursor();
		}
		if (/^INSERT INTO attempts/i.test(sql)) {
			const [ip, n, ts] = bindings;
			this.tables.attempts.push({ ip, n, ts });
			return emptyCursor();
		}
		if (/^DELETE FROM attempts WHERE ip/i.test(sql)) {
			const ip = bindings[0];
			this.tables.attempts = this.tables.attempts.filter((a) => a.ip !== ip);
			return emptyCursor();
		}

		throw new Error(`FakeSql: unsupported query → ${sql}`);
	}
}

function cursor(rows) {
	return {
		toArray: () => rows.map((r) => ({ ...r })),
		[Symbol.iterator]: function* () { yield* rows.map((r) => ({ ...r })); },
	};
}

function emptyCursor() {
	return cursor([]);
}

// ---------------------------------------------------------------------------
// Durable Object harness
// ---------------------------------------------------------------------------

function makeCtx(name = 'room') {
	return { id: { name }, storage: { sql: new FakeSql() } };
}

// A fake WebSocket that records what the DO sends.
class FakeSocket {
	constructor() {
		this.sent = [];
		this.listeners = {};
		this.accepted = false;
	}
	accept() { this.accepted = true; }
	addEventListener(type, fn) { (this.listeners[type] ||= []).push(fn); }
	send(data) { this.sent.push(data); }
	close() {}
	emit(type, event) { for (const fn of this.listeners[type] || []) fn(event); }
}

async function withFakeWebSocketPair(fn) {
	const original = globalThis.WebSocketPair;
	const created = [];
	globalThis.WebSocketPair = class {
		constructor() {
			const client = new FakeSocket();
			const server = new FakeSocket();
			created.push(server);
			return { 0: client, 1: server, length: 2, [Symbol.iterator]: function* () { yield client; yield server; } };
		}
	};
	try {
		return await fn(created);
	} finally {
		globalThis.WebSocketPair = original;
	}
}

// Build a namespace binding that hands out stubs backed by real DO instances.
function makeNamespace(instances) {
	return {
		idFromName(name) { return name; },
		get(id) {
			const key = String(id);
			if (!instances[key]) {
				const Ctor = key === 'login-guard' ? LoginGuardDO : ChatRoomDO;
				instances[key] = new Ctor(makeCtx(key), makeEnv());
			}
			return instances[key];
		},
	};
}

function makeEnv(overrides = {}) {
	const instances = {};
	return {
		PASSWORD,
		SESSION_SECRET,
		instances,
		CHAT_ROOM: makeNamespace(instances),
		LOGIN_GUARD: makeNamespace(instances),
		...overrides,
	};
}

// ---------------------------------------------------------------------------
// request helpers
// ---------------------------------------------------------------------------

async function call(env, path, { method = 'GET', body, cookie, headers = {} } = {}) {
	const h = { ...headers };
	if (body !== undefined) h['content-type'] = 'application/json';
	if (cookie) h.cookie = cookie;
	const request = new Request(`https://chat.example.com${path}`, {
		method,
		headers: h,
		body: body === undefined ? undefined : JSON.stringify(body),
		cf: { connectingIp: '203.0.113.7' },
	});
	const response = await worker.fetch(request, env, {});
	let json = null;
	try {
		json = await response.clone().json();
	} catch {
		/* not JSON */
	}
	return { status: response.status, headers: response.headers, json, text: await response.text() };
}

function cookieFrom(res) {
	const raw = res.headers.get('set-cookie') || '';
	return raw.split(';')[0];
}

const b64 = (text) => Buffer.from(text).toString('base64');

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

// --- config / diagnostics -------------------------------------------------

test('health reports missing config without leaking values', async () => {
	const res = await call(makeEnv({ PASSWORD: undefined }), '/api/health');
	assert.equal(res.status, 200);
	assert.equal(res.json.ok, false);
	assert.ok(res.json.missing.includes('PASSWORD'));
	assert.ok(!res.text.includes(SESSION_SECRET), 'health must not leak secret values');
});

test('the old /api/config password endpoint is gone', async () => {
	const res = await call(makeEnv(), '/api/config');
	assert.equal(res.status, 404);
	assert.ok(!res.text.includes(PASSWORD), 'password must never be served');
});

test('login refuses to run when secrets are missing', async () => {
	const res = await call(makeEnv({ SESSION_SECRET: undefined }), '/api/login', { method: 'POST', body: { password: PASSWORD } });
	assert.equal(res.status, 500);
	assert.equal(res.json.error, 'server_not_configured');
	assert.ok(res.headers.get('set-cookie') === null || !cookieFrom(res).includes('='), 'no session issued when unconfigured');
});

// --- authentication -------------------------------------------------------

test('wrong password is rejected and issues no cookie', async () => {
	const res = await call(makeEnv(), '/api/login', { method: 'POST', body: { password: 'nope' } });
	assert.equal(res.status, 401);
	assert.equal(res.json.error, 'invalid_password');
	assert.equal(res.headers.get('set-cookie'), null);
	assert.ok(!res.text.includes(PASSWORD));
});

test('correct password issues an HttpOnly Secure SameSite session cookie', async () => {
	const res = await call(makeEnv(), '/api/login', { method: 'POST', body: { password: PASSWORD } });
	assert.equal(res.status, 200);
	assert.equal(res.json.ok, true);
	const raw = res.headers.get('set-cookie');
	assert.ok(raw, 'expected a set-cookie header');
	assert.match(raw, /HttpOnly/);
	assert.match(raw, /Secure/);
	assert.match(raw, /SameSite=Lax/);
	assert.match(raw, /Path=\//);
	assert.ok(!raw.includes(PASSWORD), 'cookie must not contain the password');
});

test('session endpoint confirms auth without exposing the password', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const res = await call(env, '/api/session', { cookie: cookieFrom(login) });
	assert.equal(res.json.ok, true);
	assert.ok(!res.text.includes(PASSWORD));
});

test('tampered session cookie is rejected', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const [exp, sig] = cookieFrom(login).split('=')[1].split('.');
	const res = await call(env, '/api/session', { cookie: `egc_session=${exp}.${'0'.repeat(sig.length)}` });
	assert.equal(res.json.ok, false);
});

test('messages require a valid session', async () => {
	const env = makeEnv();
	const get = await call(env, '/api/messages');
	assert.equal(get.status, 401);
	const post = await call(env, '/api/messages', { method: 'POST', body: { content: 'AAAA' } });
	assert.equal(post.status, 401);
});

test('logout clears the cookie', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const res = await call(env, '/api/logout', { method: 'POST', cookie: cookieFrom(login) });
	assert.equal(res.status, 200);
	assert.match(res.headers.get('set-cookie'), /Max-Age=0/);
});

// --- message storage (Durable Object) --------------------------------------

test('stores ciphertext verbatim and returns it to authorised clients', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);
	const ciphertext = b64('hello encrypted world');

	const post = await call(env, '/api/messages', { method: 'POST', cookie, body: { content: ciphertext } });
	assert.equal(post.status, 201);
	assert.equal(post.json.ok, true);
	assert.ok(post.json.id, 'the server assigns a message id');
	assert.ok(Number.isInteger(post.json.seq), 'the server assigns a monotonic seq');

	const list = await call(env, '/api/messages', { cookie });
	assert.equal(list.status, 200);
	assert.equal(list.json.messages.length, 1);
	assert.equal(list.json.messages[0].c, ciphertext, 'worker must not alter ciphertext');
	assert.equal(typeof list.json.messages[0].t, 'number');
	assert.equal(list.json.messages[0].id, post.json.id, 'ids must round-trip');
});

test('rejects malformed or oversized payloads', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);

	const notString = await call(env, '/api/messages', { method: 'POST', cookie, body: { content: 123 } });
	assert.equal(notString.status, 400);

	const notBase64 = await call(env, '/api/messages', { method: 'POST', cookie, body: { content: 'not base64!!' } });
	assert.equal(notBase64.status, 400);

	const huge = await call(env, '/api/messages', { method: 'POST', cookie, body: { content: 'A'.repeat(16385) } });
	assert.equal(huge.status, 400);

	const list = await call(env, '/api/messages', { cookie });
	assert.equal(list.json.messages.length, 0, 'nothing should have been stored');
});

test('writes are ordered and each message gets a unique id and seq', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);

	const ids = new Set();
	const seqs = [];
	for (let i = 0; i < 5; i++) {
		const res = await call(env, '/api/messages', { method: 'POST', cookie, body: { content: b64(`m${i}`) } });
		assert.equal(res.status, 201);
		ids.add(res.json.id);
		seqs.push(res.json.seq);
	}
	assert.equal(ids.size, 5, 'ids must be unique');
	assert.deepEqual(seqs, [...seqs].sort((a, b) => a - b), 'seq must increase monotonically');

	const list = await call(env, '/api/messages', { cookie });
	assert.deepEqual(list.json.messages.map((m) => m.c), [0, 1, 2, 3, 4].map((i) => b64(`m${i}`)));
});

test('history is capped, newest kept, and the cursor still works', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);

	for (let i = 0; i < 520; i++) {
		await call(env, '/api/messages', { method: 'POST', cookie, body: { content: b64(`m${i}`) } });
	}

	const list = await call(env, '/api/messages', { cookie });
	assert.equal(list.json.messages.length, 500, 'history is trimmed to 500 rows');
	assert.equal(list.json.messages[499].c, b64('m519'), 'the newest message survives');
	assert.equal(list.json.messages[0].c, b64('m20'), 'the oldest 20 were trimmed');

	// `since` returns only what is newer than the cursor — no array-length
	// guessing needed on the client.
	const cursor = list.json.messages[499].seq;
	const fresh = await call(env, `/api/messages?since=${cursor}`, { cookie });
	assert.equal(fresh.json.messages.length, 0, 'nothing newer than the cursor');
});

test('the since cursor returns exactly the new messages', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);

	const first = await call(env, '/api/messages', { method: 'POST', cookie, body: { content: b64('one') } });
	const second = await call(env, '/api/messages', { method: 'POST', cookie, body: { content: b64('two') } });

	const since = await call(env, `/api/messages?since=${first.json.seq}`, { cookie });
	assert.equal(since.json.messages.length, 1);
	assert.equal(since.json.messages[0].id, second.json.id);
});

// --- WebSocket path -------------------------------------------------------

test('an unauthenticated websocket upgrade is rejected', async () => {
	const env = makeEnv();
	const res = await call(env, '/api/ws', { headers: { upgrade: 'websocket' } });
	assert.equal(res.status, 401);
});

test('an authenticated websocket upgrade replays the history', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);
	await call(env, '/api/messages', { method: 'POST', cookie, body: { content: b64('old') } });

	let sockets = [];
	await withFakeWebSocketPair(async (created) => {
		sockets = created;
		const res = await call(env, '/api/ws', { cookie, headers: { upgrade: 'websocket' } });
		assert.equal(res.status, 101);
	});
	assert.equal(sockets.length, 1);
	assert.equal(sockets[0].accepted, true, 'the server socket must be accepted');
	// the socket also receives a presence frame — only count message rows here
	const frames = sockets[0].sent.map((s) => JSON.parse(s)).filter((f) => f.type === undefined);
	assert.equal(frames.length, 1);
	assert.equal(frames[0].c, b64('old'));
	assert.ok(frames[0].id && frames[0].seq, 'replayed rows carry id + seq');
});

test('a websocket upgrade with since only replays newer messages', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);
	const first = await call(env, '/api/messages', { method: 'POST', cookie, body: { content: b64('old') } });
	await call(env, '/api/messages', { method: 'POST', cookie, body: { content: b64('new') } });

	let sockets = [];
	await withFakeWebSocketPair(async (created) => {
		sockets = created;
		const res = await call(env, `/api/ws?since=${first.json.seq}`, { cookie, headers: { upgrade: 'websocket' } });
		assert.equal(res.status, 101);
	});
	const frames = sockets[0].sent.map((s) => JSON.parse(s)).filter((f) => f.type === undefined);
	assert.equal(frames.length, 1);
	assert.equal(frames[0].c, b64('new'));
});

test('new messages are broadcast to every connected socket', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);

	let sockets = [];
	await withFakeWebSocketPair(async (created) => {
		sockets = created;
		await call(env, '/api/ws', { cookie, headers: { upgrade: 'websocket' } });
		await call(env, '/api/ws', { cookie, headers: { upgrade: 'websocket' } });
		assert.equal(created.length, 2, 'both clients share the same room object');
	});

	const before = sockets.map((s) => s.sent.length);
	await call(env, '/api/messages', { method: 'POST', cookie, body: { content: b64('broadcast me') } });
	for (let i = 0; i < sockets.length; i++) {
		const frames = sockets[i].sent.slice(before[i]).map((s) => JSON.parse(s));
		assert.equal(frames.length, 1, 'each connected client receives the message once');
		assert.equal(frames[0].c, b64('broadcast me'));
	}
});

test('ping frames are answered with a pong', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);

	let sockets = [];
	await withFakeWebSocketPair(async (created) => {
		sockets = created;
		await call(env, '/api/ws', { cookie, headers: { upgrade: 'websocket' } });
		sockets[0].emit('message', { data: JSON.stringify({ type: 'ping' }) });
	});
	const frames = sockets[0].sent.map((s) => JSON.parse(s));
	const pongs = frames.filter((f) => f.type === 'pong');
	assert.equal(pongs.length, 1, 'exactly one pong');
});

test('presence is broadcast on connect and on disconnect', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);

	let sockets = [];
	await withFakeWebSocketPair(async (created) => {
		sockets = created;
		await call(env, '/api/ws', { cookie, headers: { upgrade: 'websocket' } });
	});
	const presenceOf = (list) => list.map((s) => JSON.parse(s)).filter((f) => f.type === 'presence');

	let first = presenceOf(sockets[0].sent);
	assert.equal(first.length, 1, 'the connecting client is told how many are online');
	assert.equal(first[0].online, 1);

	// a second client joins → the first one is told
	let sockets2 = [];
	await withFakeWebSocketPair(async (created) => {
		sockets2 = created;
		await call(env, '/api/ws', { cookie, headers: { upgrade: 'websocket' } });
	});
	const afterJoin = presenceOf(sockets[0].sent);
	assert.equal(afterJoin[afterJoin.length - 1].online, 2, 'the first client sees the count rise');
	assert.equal(presenceOf(sockets2[0].sent)[0].online, 2, 'the new client sees the current count');

	// ... and leaves again
	sockets2[0].emit('close');
	const afterLeave = presenceOf(sockets[0].sent);
	assert.equal(afterLeave[afterLeave.length - 1].online, 1, 'the count drops on disconnect');
});

// --- brute force protection ----------------------------------------------

test('rate limits repeated failed logins', async () => {
	const env = makeEnv();
	let last = null;
	for (let i = 0; i < 9; i++) {
		last = await call(env, '/api/login', { method: 'POST', body: { password: 'wrong' } });
	}
	assert.equal(last.status, 429);
	assert.equal(last.json.error, 'too_many_attempts');

	// even the correct password is refused while the limiter is hot
	const blocked = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	assert.equal(blocked.status, 429);
});

test('a successful login clears the failure counter', async () => {
	const env = makeEnv();
	for (let i = 0; i < 3; i++) await call(env, '/api/login', { method: 'POST', body: { password: 'wrong' } });
	const guardRows = env.instances['login-guard'];
	assert.ok(guardRows, 'the guard Durable Object should exist');

	const ok = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	assert.equal(ok.status, 200);
});

// --- routing --------------------------------------------------------------

test('unknown api routes 404, unknown methods 405', async () => {
	const env = makeEnv();
	assert.equal((await call(env, '/api/nope')).status, 404);
	assert.equal((await call(env, '/api/login', { method: 'GET' })).status, 405);
	assert.equal((await call(env, '/api/messages', { method: 'DELETE' })).status, 405);
});

test('non-api paths fall through to the ASSETS binding', async () => {
	let fetched = null;
	const env = makeEnv({
		ASSETS: {
			async fetch(request) {
				fetched = new URL(request.url).pathname;
				return new Response('<html>ok</html>', { headers: { 'content-type': 'text/html' } });
			},
		},
	});
	const res = await call(env, '/');
	assert.equal(res.status, 200);
	assert.equal(fetched, '/', 'asset request must be forwarded');
});

test('no CORS wildcard anywhere (same-origin only)', async () => {
	const env = makeEnv();
	for (const path of ['/api/health', '/api/session', '/api/messages']) {
		const res = await call(env, path);
		assert.equal(res.headers.get('access-control-allow-origin'), null, `${path} must not send CORS headers`);
	}
	const preflight = await call(env, '/api/messages', { method: 'OPTIONS' });
	assert.equal(preflight.status, 204);
	assert.equal(preflight.headers.get('access-control-allow-origin'), null);
});

// --- runner ---------------------------------------------------------------

let passed = 0;
const failures = [];
for (const [name, fn] of tests) {
	try {
		await fn();
		passed++;
		console.log(`  ok  ${name}`);
	} catch (err) {
		failures.push([name, err]);
		console.log(`FAIL  ${name}\n      ${err.message}`);
	}
}

console.log(`\n${passed}/${tests.length} passed`);
if (failures.length) process.exit(1);
