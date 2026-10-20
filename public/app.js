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
const THEME_KEY = 'egc.theme';
const HEARTBEAT_MS = 30000; // keeps the socket honest without flooding requests
const MAX_TRACKED_IDS = 2000; // bounded de-duplication window
const GROUP_WINDOW_MS = 5 * 60 * 1000; // same author within this window → grouped
const COUNTER_LIMIT = 3200; // show the character counter near the cap
const MAX_TEXTAREA_H = 160;

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

// Rendering state
let lastRender = null; // { day, author, ts } — drives grouping + day separators
let userScrolledUp = false; // true when the reader scrolled away from the tail
let unread = 0;
let scrollScheduled = false;
let connState = { label: 'connecting', kind: '' };

const $ = (id) => document.getElementById(id);

// ---------------------------------------------------------------------------
// theme — applied before the first paint so there is no flash
// ---------------------------------------------------------------------------
(function initTheme() {
	try {
		const stored = localStorage.getItem(THEME_KEY);
		if (stored === 'light' || stored === 'dark') document.documentElement.dataset.theme = stored;
	} catch {
		/* storage blocked — follow the OS preference */
	}
})();

function toggleTheme() {
	const root = document.documentElement;
	const current = root.dataset.theme;
	const systemDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
	// Without an explicit choice, the first click flips away from the OS theme.
	const next = current ? (current === 'light' ? 'dark' : 'light') : systemDark ? 'light' : 'dark';
	root.dataset.theme = next;
	try {
		localStorage.setItem(THEME_KEY, next);
	} catch {
		/* storage blocked — the theme still applies for this session */
	}
}

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
// small helpers
// ---------------------------------------------------------------------------

function setLoginStatus(message, kind = '') {
	const el = $('login-status');
	el.textContent = message || '';
	el.className = `status ${kind}`.trim();
}

function setConnState(label, kind = '') {
	connState = { label, kind };
	$('conn-text').textContent = label;
	$('conn-state').className = `pill ${kind}`.trim();
}

// Briefly show a transient state (e.g. "send failed") then fall back.
function flashConnState(label, kind, ms = 2600) {
	const prev = connState;
	setConnState(label, kind);
	setTimeout(() => {
		if (connState.label === label) setConnState(prev.label, prev.kind);
	}, ms);
}

function updateOnline(n) {
	const el = $('online-count');
	if (typeof n !== 'number' || n < 0) {
		el.textContent = '—';
		return;
	}
	// Counts live connections (one per open tab), not deduplicated people.
	el.textContent = n === 1 ? '1 online' : `${n} online`;
}

function initials(name) {
	const parts = String(name).trim().split(/\s+/).filter(Boolean);
	if (!parts.length) return '?';
	if (parts.length === 1) return Array.from(parts[0]).slice(0, 2).join('').toUpperCase();
	const first = Array.from(parts[0])[0] || '';
	const last = Array.from(parts[parts.length - 1])[0] || '';
	return (first + last).toUpperCase();
}

// Stable per-name colour so the same person always gets the same avatar hue.
function hueOf(name) {
	let h = 0;
	for (const ch of String(name)) h = (h * 31 + (ch.codePointAt(0) || 0)) % 9973;
	return h % 6;
}

function dayKey(ts) {
	const d = new Date(ts);
	return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

function dayLabel(ts) {
	const d = new Date(ts);
	const now = new Date();
	const yesterday = new Date(now.getTime() - 86400000);
	if (dayKey(ts) === dayKey(now.getTime())) return 'Today';
	if (dayKey(ts) === dayKey(yesterday.getTime())) return 'Yesterday';
	const opts = { month: 'short', day: 'numeric' };
	if (d.getFullYear() !== now.getFullYear()) opts.year = 'numeric';
	return d.toLocaleDateString([], opts);
}

function timeLabel(ts) {
	return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ---------------------------------------------------------------------------
// message rendering
// ---------------------------------------------------------------------------

function clearEmptyState() {
	const box = $('messages');
	const empty = box.querySelector('.empty');
	if (empty) empty.remove();
}

function renderEmpty() {
	const box = $('messages');
	box.textContent = '';
	box.appendChild($('tpl-empty').content.cloneNode(true));
}

function isAtBottom() {
	const box = $('messages');
	return box.scrollHeight - box.scrollTop - box.clientHeight < 48;
}

function scheduleScroll() {
	const box = $('messages');
	// Scroll immediately: requestAnimationFrame is throttled in background
	// tabs, which would otherwise leave the reader stranded mid-history.
	box.scrollTop = box.scrollHeight;
	if (scrollScheduled) return;
	scrollScheduled = true;
	requestAnimationFrame(() => {
		scrollScheduled = false;
		box.scrollTop = box.scrollHeight;
	});
}

function bumpUnread() {
	unread += 1;
	updateJump();
}

function updateJump() {
	const btn = $('jump-latest');
	if (unread > 0) {
		btn.classList.remove('hidden');
		$('unread-label').textContent = unread > 99 ? '99+ new' : `${unread} new`;
	} else {
		btn.classList.add('hidden');
	}
}

function daySeparator(label) {
	const sep = document.createElement('div');
	sep.className = 'day-sep';
	const span = document.createElement('span');
	span.textContent = label;
	sep.appendChild(span);
	return sep;
}

function messageRow({ author, text, ts, mine, grouped }) {
	const row = document.createElement('div');
	row.className = `row${mine ? ' mine' : ''}${grouped ? ' grouped' : ''}`;

	// Grouped messages drop the avatar, but the grid keeps the text aligned.
	if (!grouped) {
		const avatar = document.createElement('div');
		avatar.className = `avatar hue-${hueOf(author)}`;
		avatar.textContent = initials(author);
		avatar.setAttribute('aria-hidden', 'true');
		row.appendChild(avatar);
	}

	const wrap = document.createElement('div');
	wrap.className = 'msg-wrap';

	if (!grouped) {
		const head = document.createElement('div');
		head.className = 'msg-head';

		const name = document.createElement('span');
		name.className = 'msg-name';
		name.textContent = author;

		const time = document.createElement('time');
		time.className = 'msg-time';
		const d = new Date(ts);
		time.dateTime = d.toISOString();
		time.textContent = timeLabel(ts);
		time.title = d.toLocaleString();

		head.append(name, time);
		wrap.appendChild(head);
	}

	const bubbleWrap = document.createElement('div');
	bubbleWrap.className = 'bubble-wrap';

	const bubble = document.createElement('div');
	bubble.className = 'bubble';
	bubble.textContent = text; // textContent, never innerHTML — user content can't inject markup
	bubbleWrap.appendChild(bubble);

	const copy = $('tpl-copy').content.firstElementChild.cloneNode(true);
	copy.addEventListener('click', () => copyMessage(text, copy));
	bubbleWrap.appendChild(copy);

	wrap.appendChild(bubbleWrap);
	row.appendChild(wrap);
	return row;
}

async function copyMessage(text, btn) {
	try {
		await navigator.clipboard.writeText(text);
		const use = btn.querySelector('use');
		if (use) use.setAttribute('href', '#i-check');
		btn.classList.add('done');
		setTimeout(() => {
			if (use) use.setAttribute('href', '#i-copy');
			btn.classList.remove('done');
		}, 1400);
	} catch {
		flashConnState('copy failed', 'error');
	}
}

function renderPayload(payload, ts) {
	const author = typeof payload.n === 'string' && payload.n ? payload.n : 'anon';
	const text = typeof payload.m === 'string' ? payload.m : '';
	const mine = payload.n === displayName;
	const day = dayKey(ts);

	const box = $('messages');
	clearEmptyState();

	if (!lastRender || lastRender.day !== day) {
		box.appendChild(daySeparator(dayLabel(ts)));
		lastRender = { day, author: null, ts: 0 };
	}
	const grouped = lastRender.author === author && Math.abs(ts - lastRender.ts) < GROUP_WINDOW_MS;

	box.appendChild(messageRow({ author, text, ts, mine, grouped }));
	lastRender = { day, author, ts };

	if (userScrolledUp) bumpUnread();
	else scheduleScroll();
}

// A row pushed over the WebSocket, or replayed from history on connect.
async function handleIncoming(row) {
	if (!row || typeof row !== 'object') return;
	if (row.type === 'pong') return;
	if (row.type === 'presence') {
		updateOnline(row.online);
		return;
	}
	if (typeof row.id !== 'string') return;
	if (!markSeen(row.id)) return; // already rendered — the id is the source of truth
	advanceCursor(row);

	try {
		const payload = await decryptPayload(row.c);
		renderPayload(payload, row.t);
	} catch {
		clearEmptyState();
		const box = $('messages');
		box.appendChild(messageRow({
			author: '?',
			text: '[could not decrypt — different room password?]',
			ts: row.t,
			mine: false,
			grouped: false,
		}));
		if (userScrolledUp) bumpUnread();
		else scheduleScroll();
	}
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
		setConnState('reconnecting', 'busy');
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
	lastRender = null;
	unread = 0;
	userScrolledUp = false;
	$('messages').textContent = '';
	show('login');
	$('login-btn').disabled = false;
	$('login-btn-text').textContent = 'Unlock room';
	setConnState('connecting');
	setLoginStatus(message || '', message ? 'error' : '');
}

// ---------------------------------------------------------------------------
// composer
// ---------------------------------------------------------------------------

function autoGrow() {
	const el = $('message-input');
	el.style.height = 'auto';
	el.style.height = Math.min(el.scrollHeight, MAX_TEXTAREA_H) + 'px';
}

function updateCounter() {
	const len = $('message-input').value.length;
	const el = $('char-count');
	el.textContent = len > COUNTER_LIMIT ? `${len} / 4000` : '';
	el.classList.toggle('warn', len > 3800);
}

function updateSendState() {
	$('send-btn').disabled = $('message-input').value.trim() === '';
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
	$('login-btn-text').textContent = 'Deriving key…';
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
		lastRender = null;
		unread = 0;
		userScrolledUp = false;
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
		$('login-btn-text').textContent = 'Unlock room';
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
			flashConnState('send failed', 'error');
			return;
		}

		input.value = '';
		autoGrow();
		updateCounter();
		updateSendState();

		// The server echoes the stored row back over the WebSocket. If that
		// echo has not arrived yet, render locally — the message id makes the
		// two paths mutually exclusive.
		if (body && typeof body.id === 'string' && markSeen(body.id)) {
			advanceCursor(body);
			renderPayload(payload, body.t);
		}
	} catch (err) {
		flashConnState('send failed', 'error');
		console.error('send failed', err);
	} finally {
		sending = false;
		updateSendState();
	}
}

async function handleLogout() {
	await postJson('/api/logout', {});
	lock('');
}

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

function show(view) {
	$('login-view').classList.toggle('hidden', view !== 'login');
	$('chat-view').classList.toggle('hidden', view !== 'chat');
}

function boot() {
	$('name-input').value = sessionStorage.getItem(NAME_KEY) || '';
	$('login-form').addEventListener('submit', handleLogin);
	$('send-form').addEventListener('submit', handleSend);
	$('logout-btn').addEventListener('click', handleLogout);
	$('theme-btn').addEventListener('click', toggleTheme);
	$('jump-latest').addEventListener('click', () => {
		unread = 0;
		updateJump();
		userScrolledUp = false;
		scheduleScroll();
	});

	const input = $('message-input');
	input.addEventListener('input', () => {
		autoGrow();
		updateCounter();
		updateSendState();
	});
	input.addEventListener('keydown', (e) => {
		// Ignore Enter while an IME is composing — otherwise Chinese/Japanese
		// input would send the message mid-composition.
		if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) {
			e.preventDefault();
			handleSend(e);
		}
	});

	$('messages').addEventListener('scroll', () => {
		userScrolledUp = !isAtBottom();
		if (!userScrolledUp) {
			unread = 0;
			updateJump();
		}
	});

	show('login');
	updateSendState();

	// Ask the Worker whether config is complete so setup problems are obvious.
	api('/api/health').then(({ body }) => {
		if (body && body.ok === false) {
			setLoginStatus(`Server needs setup — missing: ${(body.missing || []).join(', ')}`, 'error');
		}
	}).catch(() => {});
}

if (document.readyState === 'loading') {
	document.addEventListener('DOMContentLoaded', boot);
} else {
	boot();
}
