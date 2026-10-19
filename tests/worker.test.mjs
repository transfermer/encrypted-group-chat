// Local test harness for the Worker logic — runs in plain Node (no Cloudflare
// account needed). Mocks the KV binding and crypto is provided by Node's
// built-in Web Crypto, exactly like the Workers runtime.
//
// Run with: npm test   (or: node tests/worker.test.mjs)

import assert from 'node:assert/strict';
import worker from '../src/worker.js';

const PASSWORD = 'room-pass-123';
const SESSION_SECRET = 'session-signing-secret-value';

function makeKV() {
	const store = new Map();
	return {
		store,
		async get(key, type) {
			const value = store.get(key);
			if (value === undefined) return null;
			return type === 'json' ? JSON.parse(value) : value;
		},
		async put(key, value) {
			store.set(key, String(value));
		},
		async delete(key) {
			store.delete(key);
		},
	};
}

function makeEnv(overrides = {}) {
	return { PASSWORD, SESSION_SECRET, CHAT_KV: makeKV(), ...overrides };
}

async function call(env, path, { method = 'GET', body, cookie } = {}) {
	const headers = {};
	if (body !== undefined) headers['content-type'] = 'application/json';
	if (cookie) headers.cookie = cookie;
	const request = new Request(`https://chat.example.com${path}`, {
		method,
		headers,
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

const tests = [];
const test = (name, fn) => tests.push([name, fn]);

// --- config / diagnostics -------------------------------------------------

test('health reports missing config without leaking values', async () => {
	const res = await call(makeEnv({ PASSWORD: undefined }), '/api/health');
	assert.equal(res.status, 200);
	assert.equal(res.json.ok, false);
	assert.deepEqual(res.json.missing, ['PASSWORD']);
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

// --- message storage ------------------------------------------------------

test('stores ciphertext verbatim and returns it to authorised clients', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);
	const ciphertext = Buffer.from('hello encrypted world').toString('base64');

	const post = await call(env, '/api/messages', { method: 'POST', cookie, body: { content: ciphertext } });
	assert.equal(post.status, 201);
	assert.equal(post.json.ok, true);

	const list = await call(env, '/api/messages', { cookie });
	assert.equal(list.status, 200);
	assert.equal(list.json.messages.length, 1);
	assert.equal(list.json.messages[0].c, ciphertext, 'worker must not alter ciphertext');
	assert.equal(typeof list.json.messages[0].t, 'number');
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

test('history is capped at 200 messages, newest kept', async () => {
	const env = makeEnv();
	const login = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	const cookie = cookieFrom(login);

	const seeded = Array.from({ length: 250 }, (_, i) => ({ c: Buffer.from(`m${i}`).toString('base64'), t: i }));
	await env.CHAT_KV.put('messages:v1', JSON.stringify(seeded));
	await call(env, '/api/messages', { method: 'POST', cookie, body: { content: Buffer.from('newest').toString('base64') } });

	const list = await call(env, '/api/messages', { cookie });
	assert.equal(list.json.messages.length, 200);
	assert.equal(list.json.messages[199].c, Buffer.from('newest').toString('base64'));
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
	assert.ok([...env.CHAT_KV.store.keys()].some((k) => k.startsWith('rl:login:')), 'counter should exist');

	const ok = await call(env, '/api/login', { method: 'POST', body: { password: PASSWORD } });
	assert.equal(ok.status, 200);
	assert.equal([...env.CHAT_KV.store.keys()].filter((k) => k.startsWith('rl:login:')).length, 0);
});

// --- routing --------------------------------------------------------------

test('unknown api routes 404, unknown methods 405', async () => {
	const env = makeEnv();
	assert.equal((await call(env, '/api/nope')).status, 404);
	assert.equal((await call(env, '/api/login', { method: 'GET' })).status, 405);
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
