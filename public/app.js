// Encrypted Group Chat — browser client
//
// The room password is turned into an AES-256-GCM key with PBKDF2 *in this
// browser*. Every message (author name + text) is encrypted before it leaves
// the device, so the Worker/Durable Object only ever stores ciphertext.
//
// The password is POSTed once to /api/login over HTTPS purely for
// authentication (the Worker compares SHA-256 digests). No endpoint ever
// returns the password back to the client.
//
// TRANSPORT
//   New messages arrive by WebSocket push (/api/ws) — no polling. The server
//   assigns every message a monotonic `seq` and a UUID `id`; this client uses
//   those keys to recognise new messages instead of comparing array lengths.

const APP_SALT = new TextEncoder().encode('encrypted-group-chat/v1');
const PBKDF2_ITERATIONS = 200000;
const IV_BYTES = 12;
const NAME_KEY = 'egc.displayName';
const HEARTBEAT_MS = 30000; // keeps the socket honest without flooding requests
const MAX_TRACKED_IDS = 2000; // bounded de-duplication window

let cryptoKey = null; // AES-GCM CryptoKey, memory only — never persisted
let displayName = '';
let sending = false;

let socket = null;
let reconnectTimer = null;
let heartbeatTimer = null;
let reconnectDelay = 1000;

// Cursor into the server's message sequence. `seq` is the exact catch-up key,
// `id` is the stable de-duplication key.
let lastSeq = 0;
let lastTs = 0;
const seenIds = new Set();
const seenOrder = [];

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// crypto
// ---------------------------------------------------------------------------

async function deriveKey(password) {
	const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
	return crypto.subtle.deriveKey(
		{ name: 'PBKDF2', salt: APP_SALT, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
		material,
		{ name: 'AES-GCM', length: 256 },
		false,
		['encrypt', 'decrypt']
	);
}

function bytesToBase64(bytes) {
	let binary = '';
	const chunk = 0x8000;
	for (let i = 0; i < bytes.length; i += chunk) {
		binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
	}
	return btoa(binary);
}

function base64ToBytes(b64) {
	const binary = atob(b64);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

async function encryptPayload(payload) {
	const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
	const plaintext = new TextEncoder().encode(JSON.stringify(payload));
	const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, plaintext);
	const packed = new Uint8Array(iv.length + ciphertext.byteLength);
	packed.set(iv, 0);
	packed.set(new Uint8Array(ciphertext), iv.length);
	return bytesToBase64(packed);
}

async function decryptPayload(b64) {
	const packed = base64ToBytes(b64);
	const iv = packed.subarray(0, IV_BYTES);
	const ciphertext = packed.subarray(IV_BYTES);
	const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, cryptoKey, ciphertext);
	return JSON.parse(new TextDecoder().decode(plaintext));
}

// ---------------------------------------------------------------------------
// api
// ---------------------------------------------------------------------------

async function api(path, options = {}) {
	const res = await fetch(path, { credentials: 'same-origin', ...options });
	let body = {};
	try {
		body = await res.json();
	} catch {
		/* non-JSON response */
	}
	return { status: res.status, ok: res.ok, body };
}

const postJson = (path, payload) =>
	api(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) });

// ---------------------------------------------------------------------------
// ui
// ---------------------------------------------------------------------------

function show(view) {
	$('login-view').classList.toggle('hidden', view !== 'login');
	$('chat-view').classList.toggle('hidden', view !== 'chat');
}

function setLoginStatus(message, kind = '') {
	const el = $('login-status');
	el.textContent = message || '';
	el.className = `status ${kind}`.trim();
}

function setConnState(label, kind = '') {
	const el = $('conn-state');
	el.textContent = label;
	el.className = `pill ${kind}`.trim();
}

function addMessageEl({ name, text, ts, mine, failed }) {
	const wrap = document.createElement('div');
	wrap.className = `msg${mine ? ' mine' : ''}${failed ? ' failed' : ''}`;

	const meta = document.createElement('div');
	meta.className = 'msg-meta';

	const nameEl = document.createElement('span');
	nameEl.className = 'msg-name';
	nameEl.textContent = name;

	const timeEl = document.createElement('span');
	timeEl.className = 'msg-time';
	timeEl.textContent = ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '';

	meta.append(nameEl, timeEl);

	const bodyEl = document.createElement('div');
	bodyEl.className = 'msg-body';
	bodyEl.textContent = text; // textContent, never innerHTML — user content can't inject markup

	wrap.append(meta, bodyEl);
	$('messages').appendChild(wrap);
}

function clearEmptyState() {
	const box = $('messages');
	if (box.querySelector('.empty')) box.textContent = '';
}

function renderEmpty() {
	const box = $('messages');
	box.textContent = '';
	const p = document.createElement('p');
	p.className = 'empty';
	p.textContent = 'No messages yet. Say something — it will be encrypted before it leaves your browser.';
	box.appendChild(p);
}

function scrollToBottom() {
	const box = $('messages');
	box.scrollTop = box.scrollHeight;
}

// ---------------------------------------------------------------------------
// message bookkeeping
// ---------------------------------------------------------------------------

// Returns true the first time an id is seen, false for duplicates.
function markSeen(id) {
	if (typeof id !== 'string' || !id) return false;
	if (seenIds.has(id)) return false;
	seenIds.add(id);
	seenOrder.push(id);
	if (seenOrder.length > MAX_TRACKED_IDS) {
		const oldest = seenOrder.shift();
		seenIds.delete(oldest);
	}
	return true;
}

function advanceCursor(row) {
	if (Number.isFinite(row.seq) && row.seq > lastSeq) lastSeq = row.seq;
	if (Number.isFinite(row.t) && row.t > lastTs) lastTs = row.t;
}

function renderPayload(payload, ts) {
	clearEmptyState();
	addMessageEl({
		name: typeof payload.n === 'string' && payload.n ? payload.n : 'anon',
		text: typeof payload.m === 'string' ? payload.m : '',
		ts,
		mine: payload.n === displayName,
		failed: false,
	});
	scrollToBottom();
}

// A row pushed over the WebSocket, or replayed from history on connect.
async function handleIncoming(row) {
	if (!row || typeof row !== 'object') return;
	if (row.type === 'pong') return;
	if (typeof row.id !== 'string') return;
	if (!markSeen(row.id)) return; // already rendered — the id is the source of truth
	advanceCursor(row);

	try {
		const payload = await decryptPayload(row.c);
		renderPayload(payload, row.t);
	} catch {
		clearEmptyState();
		addMessageEl({
			name: '?',
			text: '[could not decrypt — different room password?]',
			ts: row.t,
			mine: false,
			failed: true,
		});
		scrollToBottom();
	}
}

// ---------------------------------------------------------------------------
// websocket transport
// ---------------------------------------------------------------------------

function connect() {
	if (!cryptoKey) return;
	if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) return;

	const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
	// `since` lets the server replay only what we missed while disconnected.
	const query = lastSeq > 0 ? `?since=${lastSeq}` : '';

	try {
		socket = new WebSocket(`${proto}//${location.host}/api/ws${query}`);
	} catch {
		scheduleReconnect();
		return;
	}

	socket.onopen = () => {
		setConnState('live', 'live');
		reconnectDelay = 1000;
		startHeartbeat();
	};

	socket.onmessage = (event) => {
		let row;
		try {
			row = JSON.parse(event.data);
		} catch {
			return;
		}
		handleIncoming(row);
	};

	socket.onclose = () => {
		stopHeartbeat();
		socket = null;
		if (!cryptoKey) return;
		setConnState('reconnecting', 'error');
		scheduleReconnect();
	};

	socket.onerror = () => {
		// onclose always follows; nothing to do here.
	};
}

function scheduleReconnect() {
	clearTimeout(reconnectTimer);
	const delay = reconnectDelay;
	reconnectDelay = Math.min(reconnectDelay * 2, 15000);
	reconnectTimer = setTimeout(async () => {
		if (!cryptoKey) return;
		// A rejected session must not turn into an endless reconnect loop — but a
		// temporarily unreachable server must not log the user out either.
		let session = null;
		try {
			session = await api('/api/session');
		} catch {
			scheduleReconnect();
			return;
		}
		if (!session.body || session.body.ok !== true) {
			lock('Session expired — unlock again.');
			return;
		}
		connect();
	}, delay);
}

function startHeartbeat() {
	stopHeartbeat();
	heartbeatTimer = setInterval(() => {
		if (socket && socket.readyState === WebSocket.OPEN) {
			try {
				socket.send(JSON.stringify({ type: 'ping' }));
			} catch {
				/* the close handler takes over */
			}
		}
	}, HEARTBEAT_MS);
}

function stopHeartbeat() {
	if (heartbeatTimer) clearInterval(heartbeatTimer);
	heartbeatTimer = null;
}

function closeSocket() {
	clearTimeout(reconnectTimer);
	reconnectTimer = null;
	stopHeartbeat();
	if (socket) {
		try {
			socket.close();
		} catch {
			/* already closing */
		}
	}
	socket = null;
}

function lock(message) {
	cryptoKey = null;
	closeSocket();
	lastSeq = 0;
	lastTs = 0;
	seenIds.clear();
	seenOrder.length = 0;
	$('messages').textContent = '';
	show('login');
	$('login-btn').disabled = false;
	$('login-btn').textContent = 'Unlock';
	setLoginStatus(message || '', message ? 'error' : '');
}

// ---------------------------------------------------------------------------
// flows
// ---------------------------------------------------------------------------

async function handleLogin(event) {
	event.preventDefault();
	if (cryptoKey) return;

	const passwordInput = $('password-input');
	const password = passwordInput.value;
	const name = $('name-input').value.trim().slice(0, 32) || 'anon';
	const button = $('login-btn');

	if (!password) {
		setLoginStatus('Enter the room password.', 'error');
		return;
	}

	button.disabled = true;
	button.textContent = 'Deriving key...';
	setLoginStatus('', '');

	try {
		const { status, ok, body } = await postJson('/api/login', { password });

		if (!ok) {
			const reasons = {
				invalid_password: 'Wrong password.',
				too_many_attempts: `Too many attempts. Try again in ~${Math.ceil((body.retry_after_seconds || 600) / 60)} min.`,
				server_not_configured: `Server misconfigured. Missing: ${(body.missing || []).join(', ')}.`,
				bad_request: 'Bad request.',
			};
			throw new Error(reasons[body.error] || `Login failed (${status}).`);
		}

		// Key derivation happens only after the server accepts the password.
		cryptoKey = await deriveKey(password);
		displayName = name;
		sessionStorage.setItem(NAME_KEY, displayName);

		// Never keep the password in the DOM or in memory longer than needed.
		passwordInput.value = '';

		lastSeq = 0;
		lastTs = 0;
		seenIds.clear();
		seenOrder.length = 0;
		renderEmpty();

		show('chat');
		setConnState('connecting');
		connect();
		$('message-input').focus();
	} catch (err) {
		setLoginStatus(err.message || 'Login failed.', 'error');
		cryptoKey = null;
	} finally {
		button.disabled = false;
		button.textContent = 'Unlock';
	}
}

async function handleSend(event) {
	event.preventDefault();
	if (!cryptoKey || sending) return;

	const input = $('message-input');
	const text = input.value.trim();
	if (!text) return;

	sending = true;
	$('send-btn').disabled = true;

	try {
		const payload = { n: displayName, m: text };
		const content = await encryptPayload(payload);
		const { ok, status, body } = await postJson('/api/messages', { content });

		if (status === 401) {
			lock('Session expired — unlock again.');
			return;
		}
		if (!ok) {
			setConnState('send failed', 'error');
			return;
		}

		input.value = '';

		// The server echoes the stored row back over the WebSocket. If that
		// echo has not arrived yet, render locally — the message id makes the
		// two paths mutually exclusive.
		if (body && typeof body.id === 'string' && markSeen(body.id)) {
			advanceCursor(body);
			renderPayload(payload, body.t);
		}
	} catch (err) {
		setConnState('error', 'error');
		console.error('send failed', err);
	} finally {
		sending = false;
		$('send-btn').disabled = false;
	}
}

async function handleLogout() {
	await postJson('/api/logout', {});
	lock('');
}

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
	$('name-input').value = sessionStorage.getItem(NAME_KEY) || '';
	$('login-form').addEventListener('submit', handleLogin);
	$('send-form').addEventListener('submit', handleSend);
	$('logout-btn').addEventListener('click', handleLogout);
	$('message-input').addEventListener('keydown', (e) => {
		if (e.key === 'Enter' && !e.shiftKey) handleSend(e);
	});

	show('login');
	// Ask the Worker whether config is complete so setup problems are obvious.
	api('/api/health').then(({ body }) => {
		if (body && body.ok === false) {
			setLoginStatus(`Server needs setup — missing: ${(body.missing || []).join(', ')}`, 'error');
		}
	}).catch(() => {});
});
