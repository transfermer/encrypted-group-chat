# 🔐 Encrypted Chat Room

End-to-end encrypted chat room with password login. Messages are encrypted client-side using AES-256-GCM before being stored in Cloudflare KV.

## How it works

1. **Password authentication** — enter the shared password to unlock chat history
2. **Client-side encryption** — PBKDF2 derives an AES-256-GCM key from your password
3. **Messages stored encrypted** — all chat messages are encrypted before hitting the server
4. **Only decrypted in-browser** — even the server never sees plaintext messages

## Files

| File | Purpose |
|------|---------|
| `index.html` | Login + chat UI |
| `style.css` | Dark-themed styling |
| `app.js` | Encryption logic + API calls |
| `worker.js` | Cloudflare Worker backend |
| `wrangler.toml.example` | Template config (commit this) |
| `wrangler.toml` | Local config only (git-ignored, don't commit) |

---

## Why Password Goes as a **Secret**, Not a Variable

In Cloudflare Workers there are two types of env config:

| Type | Where it lives | Visibility | Use for |
|------|---------------|------------|---------|
| **Variable** | Dashboard → Settings → Variables | Plain text, visible in logs | Public config (e.g. feature flags) |
| **Secret** | Dashboard → Settings → Secrets | Encrypted, hidden, never in logs | Passwords, API keys, tokens |

**Always use Secrets for passwords.** If you put `PASSWORD` as a Variable, it will be logged in plain text in Cloudflare's request logs. Secrets are encrypted at rest and never appear in logs.

## Deploy to Cloudflare (Step by Step)

### Prerequisites
- Wrangler installed: `npm install -g wrangler`
- Logged in: `wrangler login`

### Step 1 — Create KV Namespace
```bash
wrangler kv namespace create CHAT_KV
```
Copy the returned `id` (looks like `xxxxxxxxxxxxxxxxxxxxxxxx`)

### Step 2 — Set Password as Secret
```bash
wrangler secret put PASSWORD
# You'll be prompted to type the password (hidden input)
```

### Step 3 — Update wrangler.toml (local only, git-ignored)
```bash
cp wrangler.toml.example wrangler.toml
# Edit wrangler.toml and paste your KV namespace ID into id = "..."
```

### Step 4 — Deploy Worker
```bash
wrangler deploy
```

### Step 5 — Commit everything except wrangler.toml
```bash
git add index.html style.css app.js worker.js wrangler.toml.example .gitignore README.md
git commit -m "feat: encrypted chat room"
git push
```

`wrangler.toml` stays local — **never committed**.

---

## Architecture

```
Browser (AES-GCM encrypt/decrypt)
    ↓ HTTPS
Cloudflare Worker (routes API)
    ↓
Cloudflare KV (stores encrypted JSON blobs)
```

## Security Notes

- **Server cannot read messages** — encryption happens entirely in the browser
- **Password is sent over HTTPS** — always use HTTPS in production
- **KV stores encrypted blobs** — even if KV is compromised, messages are safe
- **No user auth** — anyone with the password sees everything (by design)