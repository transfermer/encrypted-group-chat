# 🔐 Encrypted Group Chat

Password-gated, end-to-end encrypted group chat on **Cloudflare Workers**.

## Security model

| Thing | Where | Never |
|-------|-------|-------|
| Chat password | **Dashboard → Secrets** (`PASSWORD`) | In the repo, in code, or in logs |
| Session signing key | **Dashboard → Secrets** (`SESSION_SECRET`) | In the repo |
| KV namespace ID | **Auto-provisioned** by Cloudflare (not written to the repo) | Hardcoded anywhere |
| Message bodies | AES-256-GCM ciphertext (created in browser) | The Worker never sees plaintext |

**Key guarantees**
- **No endpoint ever returns the password.** Login compares SHA-256 digests in constant time.
- **Messages are encrypted before leaving the browser** (PBKDF2 key from password + AES-GCM). The Worker only stores opaque blobs.
- **Session cookies are HttpOnly + Secure + SameSite=Lax** — JavaScript can't read them.
- **Brute-force protection**: 8 failed attempts per IP per 10 min → 429.
- **No wildcard CORS** — same-origin only. Static assets and API share the Worker's origin.
- **CSP + security headers** via `_headers` (no inline scripts/styles).

## Files

| File | Purpose |
|------|---------|
| `src/worker.js` | Cloudflare Worker API (auth, sessions, KV) |
| `public/index.html` | Login + chat UI (no inline JS, CSP) |
| `public/app.js` | PBKDF2 → AES-256-GCM encryption + API calls |
| `public/style.css` | Dark themed styling |
| `public/_headers` | Security headers (CSP, nosniff, etc.) |
| `wrangler.toml.example` | Minimal local dev template (no secrets) |
| `.gitignore` | Keeps `wrangler.toml` local-only, ignores node_modules |
| `tests/worker.test.mjs` | 17 tests (runs in plain Node, no account) |

## Deploy to Cloudflare (step by step)

### 1 Deploy the Worker

1. **Workers & Pages → Create Application → Worker → Deploy from Git**
   → connect `transfermer/encrypted-group-chat`, branch `main`.
2. Leave **Build command** empty, **Output directory** `.`.
   Cloudflare runs the default `npx wrangler deploy` using the committed
   `wrangler.jsonc`. No auto-configuration PR is created.
3. **Settings → Variables & Secrets → Add secret:**
   - `PASSWORD` → *your chat password*
   - `SESSION_SECRET` → *any long random string*
4. **Settings → Bindings → KV:** add binding `CHAT_KV` → your KV namespace.
   If you don't have one yet, **KV → Create Namespace** first.

### 2 Serve the frontend

The Worker serves the static files too, so you're done after step 1.
Your chat is live at `https://encrypted-chat.<your-sub>.workers.dev`.

> (Alternatively: deploy the `public/` folder to **Cloudflare Pages** and point
> the Pages Function/`_middleware` to the Worker API. The single-Worker setup
> above is simpler.)

### 3 Verify

Visit the URL — the login screen should appear. Hit `/api/health` to confirm
config is correct: `{"ok":true}`.

## Change the password

Dashboard → your Worker → Settings → Variables & Secrets → **PASSWORD** →
**Edit** → enter the new password → **Save** → **Deploy**.

## Run tests

```bash
npm test
```

17 tests cover auth, sessions, message storage, validation, rate limiting,
CORS, and that the password is never exposed by any endpoint.

## Architecture

```
Browser: PBKDF2(password) ──► AES-256-GCM
   │
HTTPS (password to /api/login only; session = HttpOnly cookie)
   │
Worker: routes /api/*, verifies cookie, reads/writes KV
   │
KV: stores only encrypted base64 blobs (messages:v1)
```

## Limitations

- **KV read-modify-write** on `messages:v1`: concurrent sends from two clients
  in the same instant *may* lose one message. Fine for a small group chat.
  For higher concurrency, switch to **Durable Objects** or **D1**.
- The password *is* transmitted once at login (over HTTPS). For a design where
  the server never sees the password, swap in SRP/OPAQUE or a static verifier
  secret. (The shared-password model above is by design.)
