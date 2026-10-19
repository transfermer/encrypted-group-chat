// Cloudflare Worker — Encrypted Group Chat API
//
// SECURITY MODEL
// - The chat password (env.PASSWORD) and the session signing key (env.SESSION_SECRET)
//   are Cloudflare Secrets. They live ONLY in the dashboard, never in this repo.
// - The password is NEVER returned by any endpoint. Login compares SHA-256 digests
//   in constant time, then issues an HttpOnly, Secure, SameSite session cookie.
// - Message bodies are AES-256-GCM ciphertext produced in the browser. The Worker
//   only stores and forwards opaque blobs — it cannot read the chat.
// - Same-origin only: no wildcard CORS, and the session cookie is not readable by JS.

const MSG_KEY = 'messages:v1';
const COOKIE_NAME = 'egc_session';
const MAX_MESSAGES = 200; // kept in KV, oldest trimmed
const MAX_CIPHERTEXT = 16384; // base64 chars per message
const MAX_NAME = 32;
const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
const LOGIN_MAX_ATTEMPTS = 8;
const LOGIN_WINDOW_SECONDS = 600; // 10 minutes
const B64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

const encoder = new TextEncoder();

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

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
	const sig = await hmacHex(secret, `egc.session.v1.${exp}`);
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
	const expected = await hmacHex(secret, `egc.session.v1.${exp}`);
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
	if (!env.CHAT_KV) missing.push('CHAT_KV (KV binding)');
	return missing;
}

// Brute-force protection. Counters are only written on FAILED attempts, so a
// normal login costs no KV writes.
async function isRateLimited(kv, ip) {
	const raw = await kv.get(`rl:login:${ip}`);
	return raw !== null && Number(raw) >= LOGIN_MAX_ATTEMPTS;
}

async function recordFailedLogin(kv, ip) {
	const key = `rl:login:${ip}`;
	const current = Number(await kv.get(key)) || 0;
	await kv.put(key, String(current + 1), { expirationTtl: LOGIN_WINDOW_SECONDS });
}

async function isAuthorised(request, env) {
	return verifySessionToken(env.SESSION_SECRET, readCookie(request, COOKIE_NAME));
}

// ---------------------------------------------------------------------------
// route handlers
// ---------------------------------------------------------------------------

async function handleLogin(request, env) {
	const missing = missingConfig(env);
	if (missing.length) {
		return json({ ok: false, error: 'server_not_configured', missing }, 500);
	}

	const ip = clientIp(request);
	if (await isRateLimited(env.CHAT_KV, ip)) {
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
		await recordFailedLogin(env.CHAT_KV, ip);
		return json({ ok: false, error: 'invalid_password' }, 401);
	}

	await env.CHAT_KV.delete(`rl:login:${ip}`);
	const { token, expiresAt } = await makeSessionToken(env.SESSION_SECRET);
	return json(
		{ ok: true, expires_at: new Date(expiresAt).toISOString() },
		200,
		{ 'set-cookie': sessionCookie(token, Math.floor(SESSION_TTL_MS / 1000)) }
	);
}

async function handleLogout(env) {
	return json({ ok: true }, 200, { 'set-cookie': sessionCookie('', 0) });
}

async function handleSession(request, env) {
	if (missingConfig(env).length) return json({ ok: false, error: 'server_not_configured' }, 500);
	return json({ ok: await isAuthorised(request, env) });
}

async function handleHealth(env) {
	// Diagnostic only — reports whether config exists, never the values.
	const missing = missingConfig(env);
	return json({ ok: missing.length === 0, missing, messages_key: MSG_KEY });
}

async function handleGetMessages(request, env) {
	if (!(await isAuthorised(request, env))) return json({ ok: false, error: 'unauthorized' }, 401);
	const stored = await env.CHAT_KV.get(MSG_KEY, 'json');
	return json({ ok: true, messages: Array.isArray(stored) ? stored : [] });
}

async function handlePostMessage(request, env) {
	if (!(await isAuthorised(request, env))) return json({ ok: false, error: 'unauthorized' }, 401);

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

	const stored = await env.CHAT_KV.get(MSG_KEY, 'json');
	const messages = Array.isArray(stored) ? stored : [];
	messages.push({ c: ciphertext, t: Date.now() });
	if (messages.length > MAX_MESSAGES) messages.splice(0, messages.length - MAX_MESSAGES);
	await env.CHAT_KV.put(MSG_KEY, JSON.stringify(messages));

	return json({ ok: true, count: messages.length }, 201);
}

// ---------------------------------------------------------------------------
// entrypoint
// ---------------------------------------------------------------------------

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const path = url.pathname;

		// The frontend is served from the same Worker (static assets), so there is
		// no cross-origin caller and no CORS header is needed or wanted.
		if (request.method === 'OPTIONS') return new Response(null, { status: 204 });

		if (path === '/api/login') {
			if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
			return handleLogin(request, env);
		}
		if (path === '/api/logout') {
			if (request.method !== 'POST') return json({ ok: false, error: 'method_not_allowed' }, 405);
			return handleLogout(env);
		}
		if (path === '/api/session' && request.method === 'GET') return handleSession(request, env);
		if (path === '/api/health' && request.method === 'GET') return handleHealth(env);

		if (path === '/api/messages') {
			if (request.method === 'GET') return handleGetMessages(request, env);
			if (request.method === 'POST') return handlePostMessage(request, env);
			return json({ ok: false, error: 'method_not_allowed' }, 405);
		}

		if (path.startsWith('/api/')) return json({ ok: false, error: 'not_found' }, 404);

		// Anything else falls through to the static asset binding.
		if (env.ASSETS) return env.ASSETS.fetch(request);
		return new Response('Not Found', { status: 404 });
	},
};
