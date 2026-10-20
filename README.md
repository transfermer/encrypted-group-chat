# 🔐 Encrypted Group Chat

Password-gated, end-to-end encrypted group chat on **Cloudflare Workers**, built on
**Durable Objects + WebSockets**.

## Why Durable Objects

The first version polled `GET /api/messages` every 3 seconds from every client, and
stored messages in Workers KV under a single key. That burned a huge number of
requests and had a read-modify-write race (two people typing at the same moment
could lose a message).

This version replaces both:

| | before | now |
|---|---|---|
| storage | Workers KV, one `messages:v1` key | **Durable Object** with its own SQLite table |
| writes | KV read → modify → write (racy) | serialised inside one object (ordered, conflict-free) |
| delivery | HTTP polling every 3 s per client | **WebSocket push** from the room object |
| request volume | ~20 req/min **per client**, forever | 1 handshake + 1 request per message sent |

One chat room = one Durable Object instance (`idFromName("room")`), so every client
in the room shares the same connection set and the same database. A second
Durable Object (`LoginGuardDO`) holds the brute-force counters, which is why **no
KV namespace is needed at all** any more.

## Security model

| Thing | Where | Never |
|-------|-------|-------|
| Chat password | **Dashboard → Secrets** (`PASSWORD`) | In the repo, in code, or in logs |
| Session signing key | **Dashboard → Secrets** (`SESSION_SECRET`) | In the repo |
| Durable Object namespaces | **Auto-provisioned** by Cloudflare (not written to the repo) | Hardcoded anywhere |
| Message bodies | AES-256-GCM ciphertext (created in browser) | The Worker never sees plaintext |

**Key guarantees**
- **No endpoint ever returns the password.** Login compares SHA-256 digests in constant time.
- **Messages are encrypted before leaving the browser** (PBKDF2 key from password + AES-256-GCM). The Worker and the Durable Object only store opaque blobs.
- **Session cookies are HttpOnly + Secure + SameSite=Lax** — JavaScript can't read them.
- **Brute-force protection**: 8 failed attempts per IP per 10 min → 429. Counters live in `LoginGuardDO`, which is only reachable through a Worker stub — never from the public internet.
- **WebSocket upgrades are authenticated** by the same session cookie; unauthenticated upgrades get 401.
- **No wildcard CORS** — same-origin only. Static assets and API share the Worker's origin.
- **CSP + security headers** via `_headers` (no inline scripts/styles).

## Message identity (no more array-length guessing)

Every stored message carries three keys:

| key | meaning | used for |
|-----|---------|----------|
| `seq` | monotonic counter (`AUTOINCREMENT`) | exact "give me what is new" cursor — survives reconnects, never reused |
| `id` | UUID | stable de-duplication key in the browser |
| `t` | millisecond timestamp | display + coarse catch-up |

The client de-duplicates on `id` and keeps a `seq` cursor. It never compares
array lengths, and it reconnects with `?since=<seq>` so it only receives what it
missed. The same `since` parameter works on `GET /api/messages`.

## Interface

The chat UI is a small design system rather than a pile of inline styles:

- **Chat bubbles** — your own messages sit right, everyone else's left, so a
  conversation is scannable at a glance. Avatars are generated from the display
  name (initials + a stable colour per name).
- **Message grouping** — consecutive messages from the same person within five
  minutes collapse into one block, so the author name and timestamp are printed
  once instead of on every line.
- **Day separators** — "Today" / "Yesterday" / a date, inserted between days.
- **Copy on hover** — every bubble has a copy button that puts the *decrypted*
  text on the clipboard.
- **Unread badge** — scroll up while you read and new messages are counted; a
  floating "↓ N new" button jumps back to the tail.
- **Composer** — a growing textarea: Enter sends, Shift+Enter inserts a newline,
  and the IME composition state is respected so Chinese/Japanese input is never
  sent half-finished. A character counter appears near the 4000-character limit.
- **Presence** — the header shows how many browsers are attached to the room
  (a cheap `presence` frame the Durable Object broadcasts on connect/disconnect).
- **Light and dark themes** — every colour is a token; `light-dark()` follows
  the OS preference and the header button overrides it (the choice is stored in
  `localStorage`). No flash on load, no extra request.
- **App-shell layout** — the header and composer are fixed while the message
  list scrolls on its own, so the input is always reachable on a phone.
- **Accessibility** — labelled controls, `aria-live` log, visible focus rings,
  and `prefers-reduced-motion` support.

## Files

| File | Purpose |
|------|---------|
| `src/worker.js` | Worker API (auth, sessions) + `ChatRoomDO` + `LoginGuardDO` |
| `public/index.html` | Login + chat UI (no inline JS, CSP, SVG icon sprite) |
| `public/app.js` | PBKDF2 → AES-256-GCM encryption + WebSocket client + rendering |
| `public/style.css` | Design tokens, light/dark themes, chat layout |
| `public/_headers` | Security headers (CSP, nosniff, etc.) |
| `wrangler.jsonc` | Bindings + DO class exports (no secrets, no resource IDs) |
| `.gitignore` | Keeps `wrangler.toml` local-only, ignores node_modules |
| `tests/worker.test.mjs` | 25 tests (runs in plain Node, no account) |
| `tests/smoke.mjs` | End-to-end checks against a real `wrangler dev` runtime |

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
4. **That's it.** The Durable Object namespaces are provisioned automatically on
   the first deploy — unlike KV, a DO binding needs no namespace ID in
   `wrangler.jsonc`, so there is no manual "add binding" step and no
   dashboard-created resources.

The Worker serves the static files too, so your chat is live at
`https://encrypted-chat.<your-sub>.workers.dev`.

### 2 Verify

Visit the URL — the login screen should appear. Hit `/api/health` to confirm
config is correct: `{"ok":true,"missing":[]}`.

## Change the password

Dashboard → your Worker → Settings → Variables & Secrets → **PASSWORD** →
**Edit** → enter the new password → **Save** → **Deploy**.

## Run tests

```bash
npm test
```

25 tests cover auth, sessions, message ordering, the `since` cursor, history
trimming, WebSocket upgrades, presence, broadcast fan-out, validation, rate
limiting, CORS, and that the password is never exposed by any endpoint.

There is also an end-to-end check against a real local runtime:

```bash
npx wrangler dev --local --port 8787 \
  --var PASSWORD:'room-pass-123' --var SESSION_SECRET:'session-signing-secret-value'
# then, from another shell:
node tests/smoke.mjs        # real Durable Object, real SQLite, real WebSocket
```

> The smoke test deliberately triggers the brute-force limiter, so run it
> against a **fresh** `wrangler dev` (or restart the server between runs).

## Architecture

```
Browser: PBKDF2(password) ──► AES-256-GCM
   │
   ├── WebSocket /api/ws ──────────► ChatRoomDO ──► broadcast to every socket
   │                                  └─ SQLite: messages (seq, id, ts, payload)
   └── POST /api/messages ─► Worker ─► ChatRoomDO (insert + broadcast)

Worker: routes /api/*, verifies the session cookie
LoginGuardDO: failed-login counters (Worker-stub only)
```

## Limitations

- The password *is* transmitted once at login (over HTTPS). For a design where
  the server never sees the password, swap in SRP/OPAQUE or a static verifier
  secret. (The shared-password model above is by design.)
- History is capped at 500 messages (older rows are trimmed). The WebSocket
  replay sends the newest 300; the REST endpoint returns the full retained
  window.
- The room is a single Durable Object, so it is the natural limit for one
  busy room. Several rooms = one DO instance per room, selected by name.
- The socket uses the standard (non-hibernating) WebSocket API, so the object
  stays in memory while a client is connected. For very long-lived idle rooms,
  the Hibernation API (`ctx.acceptWebSocket`) would let it be evicted.
