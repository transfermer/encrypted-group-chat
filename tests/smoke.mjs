// End-to-end smoke test against a REAL runtime (workerd).
//
//   npx wrangler dev --local --port 8787 \
//     --var PASSWORD:'room-pass-123' --var SESSION_SECRET:'session-signing-secret-value'
//   node tests/smoke.mjs
//
// Unlike tests/worker.test.mjs (plain Node + mocks) this exercises the real
// Durable Object, real SQLite and a real WebSocket handshake.

// End-to-end smoke test against a real `wrangler dev` (workerd) instance:
// real Durable Object, real SQLite, real WebSocket.
import { Socket } from 'node:net';
import crypto from 'node:crypto';

const BASE = 'http://127.0.0.1:8787';
const PASSWORD = 'room-pass-123';
const SESSION_SECRET = 'session-signing-secret-value';

const log = (...a) => console.log(...a);

async function health() {
	const res = await fetch(`${BASE}/api/health`);
	return { status: res.status, body: await res.json() };
}

async function login(password = PASSWORD) {
	const res = await fetch(`${BASE}/api/login`, {
		method: 'POST',
		headers: { 'content-type': 'application/json' },
		body: JSON.stringify({ password }),
	});
	const setCookie = res.headers.get('set-cookie') || '';
	return { status: res.status, body: await res.json(), cookie: setCookie.split(';')[0] };
}

async function postMessage(cookie, content) {
	const res = await fetch(`${BASE}/api/messages`, {
		method: 'POST',
		headers: { 'content-type': 'application/json', cookie },
		body: JSON.stringify({ content }),
	});
	return { status: res.status, body: await res.json() };
}

async function getMessages(cookie, since) {
	const url = since ? `${BASE}/api/messages?since=${since}` : `${BASE}/api/messages`;
	const res = await fetch(url, { headers: { cookie } });
	return { status: res.status, body: await res.json() };
}

// Minimal WebSocket client (RFC 6455 handshake + frame decode).
function wsConnect(cookie, path = '/api/ws') {
	return new Promise((resolve, reject) => {
		const key = crypto.randomBytes(16).toString('base64');
		const sock = new Socket();
		let buffer = Buffer.alloc(0);
		const frames = [];
		let handshakeDone = false;

		sock.connect(8787, '127.0.0.1', () => {
			sock.write(
				`GET ${path} HTTP/1.1\r\n` +
				`Host: 127.0.0.1:8787\r\n` +
				`Upgrade: websocket\r\n` +
				`Connection: Upgrade\r\n` +
				`Sec-WebSocket-Key: ${key}\r\n` +
				`Sec-WebSocket-Version: 13\r\n` +
				(cookie ? `Cookie: ${cookie}\r\n` : '') +
				`\r\n`
			);
		});

		const timer = setTimeout(() => reject(new Error('ws timeout')), 8000);

		sock.on('data', (chunk) => {
			buffer = Buffer.concat([buffer, chunk]);
			if (!handshakeDone) {
				const idx = buffer.indexOf('\r\n\r\n');
				if (idx === -1) return;
				const head = buffer.subarray(0, idx).toString();
				buffer = buffer.subarray(idx + 4);
				handshakeDone = true;
				clearTimeout(timer);
				if (!/101/.test(head)) {
					reject(new Error(`upgrade failed: ${head.split('\r\n')[0]}`));
					return;
				}
				resolve({
					frames,
					waitFor(count, timeoutMs = 5000) {
						return new Promise((res2) => {
							const started = Date.now();
							const tick = setInterval(() => {
								if (frames.length >= count) { clearInterval(tick); res2(frames); }
								else if (Date.now() - started > timeoutMs) { clearInterval(tick); res2(frames); }
							}, 25);
						});
					},
					send(text) {
						const payload = Buffer.from(text);
						const mask = crypto.randomBytes(4);
						const len = payload.length;
						let header;
						if (len < 126) header = Buffer.from([0x81, 0x80 | len]);
						else if (len < 65536) {
							header = Buffer.alloc(4);
							header[0] = 0x81; header[1] = 0x80 | 126; header.writeUInt16BE(len, 2);
						} else throw new Error('payload too long');
						const masked = Buffer.alloc(len);
						for (let i = 0; i < len; i++) masked[i] = payload[i] ^ mask[i % 4];
						sock.write(Buffer.concat([header, mask, masked]));
					},
					close() { sock.destroy(); },
				});
				// NOTE: do not return here — the server may have sent the replay
				// frames in the same TCP segment as the 101 response, and they
				// are still sitting in `buffer`.
			}
			// decode server→client frames (unmasked)
			while (buffer.length >= 2) {
				const opcode = buffer[0] & 0x0f;
				let len = buffer[1] & 0x7f;
				let offset = 2;
				if (len === 126) { if (buffer.length < 4) return; len = buffer.readUInt16BE(2); offset = 4; }
				else if (len === 127) { if (buffer.length < 10) return; len = Number(buffer.readBigUInt64BE(2)); offset = 10; }
				if (buffer.length < offset + len) return;
				const payload = buffer.subarray(offset, offset + len);
				buffer = buffer.subarray(offset + len);
				if (opcode === 1) frames.push(payload.toString());
				if (opcode === 8) { frames.push('__close__'); }
			}
		});

		sock.on('error', (e) => reject(e));
	});
}

(async () => {
	let failures = 0;
	const check = (name, cond, extra = '') => {
		if (cond) log(`  ok  ${name}`);
		else { failures++; log(`FAIL  ${name} ${extra}`); }
	};

	const h = await health();
	check('health reports configured', h.status === 200 && h.body.ok === true, JSON.stringify(h.body));
	if (!h.body.ok) { log('server not configured, aborting'); process.exit(1); }

	const bad = await login('wrong-password');
	check('wrong password rejected', bad.status === 401, JSON.stringify(bad));

	const lg = await login();
	check('login succeeds', lg.status === 200 && lg.body.ok === true, JSON.stringify(lg));
	const cookie = lg.cookie;
	check('session cookie issued', !!cookie && cookie.startsWith('egc_session='), cookie);

	const b64 = (t) => Buffer.from(t).toString('base64');

	// --- websocket: connect, receive replay + live broadcast ---
	const ws = await wsConnect(cookie);
	const post1 = await postMessage(cookie, b64('hello from smoke test'));
	check('post message accepted', post1.status === 201, JSON.stringify(post1));
	check('post returns id + seq', !!post1.body.id && Number.isInteger(post1.body.seq), JSON.stringify(post1.body));

	let frames = await ws.waitFor(1);
	check('websocket pushed the new message', frames.length >= 1 && JSON.parse(frames[0]).c === b64('hello from smoke test'), JSON.stringify(frames));

	// ping → pong
	ws.send(JSON.stringify({ type: 'ping' }));
	frames = await ws.waitFor(2);
	check('ping answered with pong', frames.length >= 2 && JSON.parse(frames[1]).type === 'pong', JSON.stringify(frames));

	// second client gets the history replay
	const ws2 = await wsConnect(cookie);
	frames = await ws2.waitFor(1);
	const replay = frames.map((f) => JSON.parse(f));
	check('new client replays history', replay.length >= 1 && replay[0].c === b64('hello from smoke test'), JSON.stringify(replay));

	// live broadcast reaches both
	await postMessage(cookie, b64('second message'));
	frames = await ws.waitFor(3);
	check('broadcast reached client 1', frames.length >= 3 && JSON.parse(frames[2]).c === b64('second message'), JSON.stringify(frames));
	frames = await ws2.waitFor(2);
	check('broadcast reached client 2', frames.length >= 2 && JSON.parse(frames[1]).c === b64('second message'), JSON.stringify(frames));

	// since cursor
	const list = await getMessages(cookie);
	check('rest endpoint lists history', list.status === 200 && list.body.messages.length >= 2, JSON.stringify(list.body).slice(0, 200));
	const lastSeq = list.body.messages[list.body.messages.length - 1].seq;
	const since = await getMessages(cookie, lastSeq);
	check('since cursor returns nothing new', since.body.messages.length === 0, JSON.stringify(since.body));

	await postMessage(cookie, b64('third message'));
	const since2 = await getMessages(cookie, lastSeq);
	check('since cursor returns exactly the new message', since2.body.messages.length === 1, JSON.stringify(since2.body));

	// unauthenticated websocket
	let rejected = false;
	try { await wsConnect(''); } catch (e) { rejected = /401/.test(e.message); }
	check('unauthenticated websocket rejected', rejected);

	// unauthenticated REST
	const unauth = await fetch(`${BASE}/api/messages`);
	check('unauthenticated REST rejected', unauth.status === 401, String(unauth.status));

	// rate limit
	for (let i = 0; i < 9; i++) await login('nope');
	const blocked = await login();
	check('rate limit blocks after 8 failures', blocked.status === 429, JSON.stringify(blocked.body));

	ws.close();
	ws2.close();
	log(failures === 0 ? '\nALL SMOKE CHECKS PASSED' : `\n${failures} SMOKE CHECKS FAILED`);
	process.exit(failures === 0 ? 0 : 1);
})().catch((e) => { console.error('SMOKE ERROR', e); process.exit(1); });
