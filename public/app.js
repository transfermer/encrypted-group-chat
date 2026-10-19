// Encrypted Group Chat — browser client
//
// The room password is turned into an AES-256-GCM key with PBKDF2 *in this
// browser*. Every message (author name + text) is encrypted before it leaves
// the device, so the Worker/KV only ever stores ciphertext.
//
// The password is POSTed once to /api/login over HTTPS purely for
// authentication (the Worker compares SHA-256 digests). No endpoint ever
// returns the password back to the client.

const APP_SALT = new TextEncoder().encode('encrypted-group-chat/v1');
const PBKDF2_ITERATIONS = 200000;
const IV_BYTES = 12;
const POLL_MS = 3000;
const NAME_KEY = 'egc.displayName';

let cryptoKey = null; // AES-GCM CryptoKey, memory only — never persisted
let displayName = '';
let renderedCount = 0;
let pollTimer = null;
let sending = false;

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

function renderEmpty() {
	const box = $('messages');
	box.textContent = '';
	const p = document.createElement('p');
	p.className = 'empty';
	p.textContent = 'No messages yet. Say something — it will be encrypted before it leaves your browser.';
	box.appendChild(p);
}

async function renderMessages(messages) {
	const box = $('messages');
	if (!messages.length) {
		if (!renderedCount) renderEmpty();
		return;
	}
	if (box.querySelector('.empty')) box.textContent = '';

	for (const msg of messages.slice(renderedCount)) {
		try {
			const payload = await decryptPayload(msg.c);
			addMessageEl({
				name: typeof payload.n === 'string' && payload.n ? payload.n : 'anon',
				text: typeof payload.m === 'string' ? payload.m : '',
				ts: msg.t,
				mine: payload.n === displayName,
				failed: false,
			});
		} catch {
			addMessageEl({ name: '?', text: '[could not decrypt — different room password?]', ts: msg.t, mine: false, failed: true });
		}
	}

	renderedCount = messages.length;
	box.scrollTop = box.scrollHeight;
}

async function refreshMessages() {
	if (!cryptoKey) return;
	const { status, ok, body } = await api('/api/messages');

	if (status === 401) {
		lock('Session expired — unlock again.');
		return;
	}
	if (!ok) {
		setConnState('error', 'error');
		return;
	}

	setConnState('live', 'live');
	await renderMessages(Array.isArray(body.messages) ? body.messages : []);
}

function lock(message) {
	cryptoKey = null;
	renderedCount = 0;
	$('messages').textContent = '';
	stopPolling();
	show('login');
	$('login-btn').disabled = false;
	$('login-btn').textContent = 'Unlock';
	setLoginStatus(message || '', message ? 'error' : '');
}

function startPolling() {
	stopPolling();
	pollTimer = setInterval(() => {
		refreshMessages().catch(() => setConnState('offline', 'error'));
	}, POLL_MS);
}

function stopPolling() {
	if (pollTimer) clearInterval(pollTimer);
	pollTimer = null;
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

		renderedCount = 0;
		$('messages').textContent = '';
		show('chat');
		setConnState('loading');
		await refreshMessages();
		startPolling();
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
		const content = await encryptPayload({ n: displayName, m: text });
		const { ok, status } = await postJson('/api/messages', { content });

		if (status === 401) {
			lock('Session expired — unlock again.');
			return;
		}
		if (!ok) {
			setConnState('send failed', 'error');
			return;
		}

		input.value = '';
		await refreshMessages();
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
