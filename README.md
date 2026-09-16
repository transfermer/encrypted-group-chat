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

## Deploy to Cloudflare

### Option A: Cloudflare Pages (easiest)

1. Create a Cloudflare KV namespace called `CHAT_KV`
2. Push this repo to GitHub
3. In Cloudflare Dashboard → Pages → Connect to Git
4. Build settings:
   - Build command: `echo "done"` (no build needed)
   - Output dir: `.`
5. Add KV binding: namespace `CHAT_KV` → variable name `CHAT_KV`
6. Deploy!

### Option B: Cloudflare Worker + Pages

1. Create KV namespace `CHAT_KV`
2. Update `worker.js` line 5 with your password
3. Deploy worker:
   ```bash
   wrangler deploy worker.js
   ```
4. Deploy static files to Pages separately

### Option C: Quick local test

```bash
npx wrangler dev --local
```

## Change the password

Edit `worker.js` line 5:
```js
const PASSWORD = 'your-secure-password';
```

## Security notes

- **Server cannot read messages** — encryption happens entirely in the browser
- **Password is sent in plain over HTTPS** — always use HTTPS
- **KV stores encrypted blobs** — even if KV is compromised, messages are safe
- **No user authentication** — anyone with the password can see everything

## Architecture

```
Browser (AES-GCM encrypt/decrypt)
    ↓ HTTPS
Cloudflare Worker (routes API)
    ↓
Cloudflare KV (stores encrypted JSON)
```