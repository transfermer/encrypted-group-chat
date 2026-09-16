// Encrypted Chat App - Client-side AES-GCM encryption
const IV_LENGTH = 12;
let encryptionKey = null;
let passwordCorrect = false;

// Derive AES-GCM key from password using PBKDF2
async function deriveKey(password) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', encoder.encode(password), 'PBKDF2', false, ['deriveBits', 'deriveKey']
  );
  return await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: new Uint8Array(16), iterations: 100000, hash: 'SHA-256' },
    keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptMessage(message) {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encryptionKey, new TextEncoder().encode(message));
  const combined = new Uint8Array(iv.length + encrypted.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encrypted), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptMessage(encryptedBase64) {
  const combined = new Uint8Array(atob(encryptedBase64).split('').map(c => c.charCodeAt(0)));
  const iv = combined.slice(0, IV_LENGTH);
  const encrypted = combined.slice(IV_LENGTH);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, encryptionKey, encrypted);
  return new TextDecoder().decode(decrypted);
}

async function login() {
  const pwd = document.getElementById('password').value;
  const btn = document.getElementById('login-btn');
  const err = document.getElementById('login-error');
  btn.disabled = true;
  btn.textContent = 'Logging in...';
  err.textContent = '';
  
  try {
    const res = await fetch('/api/config');
    const config = await res.json();
    
    if (!config.ready) throw new Error(config.error || 'Server not ready');
    if (pwd !== config.password) throw new Error('Incorrect password');
    
    passwordCorrect = true;
    encryptionKey = await deriveKey(pwd);
    
    document.getElementById('login-page').style.display = 'none';
    document.getElementById('chat-page').style.display = 'block';
    document.getElementById('msg-input').disabled = false;
    document.getElementById('message-form').querySelector('button').disabled = false;
    
    await loadMessages();
    document.getElementById('msg-input').focus();
  } catch (e) {
    err.textContent = e.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Login';
  }
}

async function loadMessages() {
  if (!passwordCorrect) return;
  const container = document.getElementById('messages');
  container.innerHTML = '<p class="loading">Loading...</p>';
  
  try {
    const res = await fetch('/api/messages');
    const data = await res.json();
    container.innerHTML = '';
    
    for (const msg of data.messages) {
      try {
        const content = await decryptMessage(msg.content);
        const el = document.createElement('div');
        el.className = 'message';
        const time = new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        el.innerHTML = `<strong>${escHtml(msg.user)}:</strong> ${escHtml(content)} <span class="time">${time}</span>`;
        container.appendChild(el);
      } catch {
        // Skip corrupted messages
      }
    }
    container.scrollTop = container.scrollHeight;
  } catch (e) {
    container.innerHTML = '<p>No messages yet.</p>';
  }
}

async function sendMessage(e) {
  e.preventDefault();
  const input = document.getElementById('msg-input');
  const message = input.value.trim();
  if (!message) return;
  
  try {
    const encrypted = await encryptMessage(message);
    await fetch('/api/messages', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content: encrypted, user: 'You' })
    });
    input.value = '';
    await loadMessages();
  } catch (err) {
    console.error('Send failed:', err);
  }
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('login-btn').addEventListener('click', login);
  document.getElementById('password').addEventListener('keypress', e => { if (e.key === 'Enter') login(); });
  document.getElementById('message-form').addEventListener('submit', sendMessage);
  setInterval(loadMessages, 3000);
});