# Roblox → Discord Webhook Proxy (Corporate-grade, Free Tier)
A battle-tested proxy for Roblox developers to send Discord webhooks via `HttpService`, built for Cloudflare’s free tier.

## Highlights
- **Two modes**: Admin-only (default) or **Self-serve** issuance
- **KV** for key storage, **Durable Object** for token-bucket rate limiting (per key & IP)
- **Strict validation** of Discord webhook URLs
- **CORS controls**; supports JSON, urlencoded, multipart
- **Health & metrics**: `/healthz`, `/version`, `/metrics`
- **Brandable UI**: darker corporate look, top-left logo slot

## Deploy
```bash
# 1) Create KV
wrangler kv:namespace create PROXY_KV

# 2) Deploy Durable Object
# (no extra step; DO is bound in wrangler.toml)

# 3) Set secrets
wrangler secret put ADMIN_TOKEN
# Optional if self-serve + Turnstile
# wrangler secret put TURNSTILE_SECRET

# 4) Configure vars (edit wrangler.toml)
# MODE = "closed" or "selfserve"
# ALLOWED_ORIGINS = "https://your-domain"

# 5) Deploy
wrangler deploy
```

## Admin API
`POST /api/new` with `Authorization: Bearer <ADMIN_TOKEN>`
```json
{ "webhook_url": "https://discord.com/api/webhooks/123/abc", "note": "My App", "limit_rpm": 120 }
```
Response:
```json
{ "key": "abc...xyz", "send_url": "/api/send/abc...xyz" }
```

## Self-serve (optional)
Enable with `MODE="selfserve"`. Optionally set `TURNSTILE_SECRET` for bot protection. Users can paste a Discord webhook on `/` and get a key.

## Sending from Roblox
See `examples/roblox/SendFromRoblox.lua`. Replace `KEY` with your issued key.

## Metrics
Prometheus-style counters at `/metrics` (approximate via KV).

## Security
- Keys map to webhooks server-side; never expose raw webhooks
- Strict domain/path check for Discord webhooks
- Per-key & IP rate limiting via Durable Objects
- Lock CORS to your domains for browser calls
