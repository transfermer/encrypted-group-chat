# 🔐 Encrypted Chat Room

End-to-end encrypted chat room. Messages are AES-256-GCM encrypted **in the browser** before ever reaching the server.

## Security Design

| What | Where it lives | Why |
|------|---------------|-----|
| Password | Cloudflare **Secrets** (dashboard) | Encrypted at rest, never in logs |
| KV namespace ID | Cloudflare **Bindings** (dashboard) | Never exposed in code |
| Encryption key | Derived in-browser from password | Server never sees plaintext |
| Messages | Stored encrypted in KV | Even KV compromise = no read access |

**Zero secrets in code. Zero IDs in config files.** Everything is bound from the Cloudflare dashboard.

---

## How to Deploy

### Step 1 — Push code to GitHub
```bash
git push origin main
```
Already done. The repo is at: https://github.com/transfermer/encrypted-group-chat

### Step 2 — Create KV Namespace in Cloudflare Dashboard
1. Go to: https://dash.cloudflare.com → **KV** → **Create Namespace**
2. Name: `CHAT_KV` (must match the binding name in worker.js)
3. Note the **Namespace ID** (you won't need to paste it anywhere — see Step 4)

### Step 3 — Deploy Worker via Dashboard
1. Go to: https://dash.cloudflare.com → **Workers & Pages** → **Create Application** → **Worker**
2. **Deploy from Git** → connect your GitHub account → select `transfermer/encrypted-group-chat`
3. **Framework**: None
4. **Build command**: (leave empty)
5. Click **Deploy**

### Step 4 — Configure Bindings & Secrets in Dashboard
After deployment, go to your Worker's **Settings**:

**Variables and Secrets:**
| Name | Type | Value |
|------|------|-------|
| `PASSWORD` | **Secret** | Your chat password (e.g. `my-secret-pass`) |

**KV Namespace Bindings:**
| Binding Name | Namespace |
|-------------|-----------|
| `CHAT_KV` | `CHAT_KV` (the one you created in Step 2) |

Click **Save**.

### Step 5 — Done
Your chat is live at `https://encrypted-chat.<your-worker-name>.workers.dev`

---

## Architecture

```
Browser (AES-256-GCM encrypt/decrypt in JS)
    ↓ HTTPS
Cloudflare Worker  ←  env.PASSWORD (secret), env.CHAT_KV (binding)
    ↓
Cloudflare KV  ←  stores only encrypted base64 blobs
```

## Files in This Repo

| File | Purpose |
|------|---------|
| `index.html` | Login + chat UI |
| `style.css` | Dark themed styling |
| `app.js` | Client-side encryption (AES-GCM) |
| `worker.js` | Server API — reads secrets/boundings from env only |
| `wrangler.toml.example` | Template for local dev (not committed with IDs) |
| `.gitignore` | Keeps `wrangler.toml` local-only |

## Local Development (Optional)

```bash
# 1. Copy example config (local only, git-ignored)
cp wrangler.toml.example wrangler.toml

# 2. Create KV namespace locally
wrangler kv namespace create CHAT_KV

# 3. Set password secret
wrangler secret put PASSWORD
# (you'll be prompted)

# 4. Edit wrangler.toml — paste the KV namespace ID into the id field
#    (this file is git-ignored, never committed)

# 5. Run locally
wrangler dev
```
