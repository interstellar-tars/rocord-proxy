// worker.js — Roblox → Discord Webhook Proxy (Corporate-grade, Cloudflare Free Tier)
/*
Features
- Admin-controlled or self-serve modes (env.MODE = "closed" | "selfserve")
- KV-backed key → webhook mapping (PROXY_KV)
- Durable Object token-bucket rate limiting per key and per IP (Limiter DO)
- Optional Cloudflare Turnstile validation for self-serve forms
- Strict Discord webhook validation (hostname + path)
- CORS control (ALLOWED_ORIGINS), JSON/multipart/urlencoded support
- Health, version, and Prometheus-like metrics endpoint
- Copy-ready Roblox example generator on the frontend
*/

export default {
  async fetch(request, env, ctx) {
    const { pathname, searchParams } = new URL(request.url);
    const method = request.method.toUpperCase();
    const origin = request.headers.get("Origin") || "";
    const cors = makeCORSHeaders(origin, env.ALLOWED_ORIGINS);

    if (method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

    // Health and version
    if (pathname === "/healthz") return new Response("ok", { headers: cors });
    if (pathname === "/version") return json({ version: "1.0.0" }, 200, cors);

    // Simple metrics (approximate + safe for free tier)
    if (pathname === "/metrics") {
      const v = await env.PROXY_KV.get("metrics:counts", "json") || {};
      const lines = Object.entries(v).map(([k, n]) => `proxy_requests_total{key="${escapeLabel(k)}"} ${n}`);
      return new Response(lines.join("\n") + "\n", { headers: { ...Object.fromEntries(cors), "content-type": "text/plain" } });
    }

    // Static UI
    if (pathname === "/" && method === "GET") {
      return new Response(HOME_HTML(env), { headers: { ...Object.fromEntries(cors), "content-type": "text/html; charset=utf-8" } });
    }
    if (pathname === "/admin" && method === "GET") {
      return new Response(ADMIN_HTML(), { headers: { ...Object.fromEntries(cors), "content-type": "text/html; charset=utf-8" } });
    }

    // Admin: create key
    if (pathname === "/api/new" && method === "POST") {
      if (!(await isAuthed(request, env.ADMIN_TOKEN))) {
        return json({ error: "Unauthorized" }, 401, cors);
      }
      const body = await safeJSON(request);
      const { webhook_url, note = "", key, limit_rpm = 60 } = body || {};
      if (!isValidDiscordWebhook(webhook_url)) return json({ error: "Invalid Discord webhook URL" }, 400, cors);

      const k = key || genKey();
      await env.PROXY_KV.put(`hook:${k}`, webhook_url);
      if (note) await env.PROXY_KV.put(`note:${k}`, note);
      await env.PROXY_KV.put(`lim:${k}`, String(limit_rpm));

      return json({ key: k, send_url: `/api/send/${k}` }, 201, cors);
    }

    // Self-serve (optional): user pastes webhook → key issued
    if (pathname === "/api/selfserve" && method === "POST") {
      if ((env.MODE || "closed") !== "selfserve") return json({ error: "Self-serve disabled" }, 403, cors);

      // Turnstile check (optional but recommended)
      if (env.TURNSTILE_SECRET) {
        const form = await request.clone().formData().catch(() => null);
        const token = form?.get("cf-turnstile-response") || (await request.clone().json().catch(()=>({})) )["cf-turnstile-response"];
        const ok = await verifyTurnstile(token, request.headers.get("CF-Connecting-IP"), env.TURNSTILE_SECRET);
        if (!ok) return json({ error: "Captcha failed" }, 400, cors);
      }

      // Basic IP based rate-limit for key creation
      const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      const limiterId = env.LIMITER.idFromName(`signup:${ip}`);
      const limiter = env.LIMITER.get(limiterId);
      const allowed = await limiter.fetch("https://limit/signup?rpm=6").then(r=>r.ok);
      if (!allowed) return json({ error: "Too many requests" }, 429, cors);

      const body = (await safeJSON(request)) || {};
      const { webhook_url } = body;
      if (!isValidDiscordWebhook(webhook_url)) return json({ error: "Invalid Discord webhook URL" }, 400, cors);

      const k = genKey();
      await env.PROXY_KV.put(`hook:${k}`, webhook_url);
      await env.PROXY_KV.put(`lim:${k}`, String(60)); // default 60 rpm per key
      return json({ key: k, send_url: `/api/send/${k}` }, 201, cors);
    }

    // Send via key
    const send = pathname.match(/^\/api\/send\/([A-Za-z0-9_-]{12,64})$/);
    if (send && method === "POST") {
      const key = send[1];
      const hook = await env.PROXY_KV.get(`hook:${key}`);
      if (!hook) return json({ error: "Unknown key" }, 404, cors);

      // Per-key + per-IP rate limiting via Durable Object
      const ip = request.headers.get("CF-Connecting-IP") || "0.0.0.0";
      const rpm = parseInt((await env.PROXY_KV.get(`lim:${key}`)) || "60", 10);
      const limiterId = env.LIMITER.idFromName(`key:${key}:ip:${ip}`);
      const limiter = env.LIMITER.get(limiterId);
      const allowed = await limiter.fetch(`https://limit/send?rpm=${rpm}`).then(r => r.ok);
      if (!allowed) return json({ error: "Rate limit" }, 429, cors);

      // Build upstream request
      const ct = request.headers.get("content-type") || "";
      let body; let headers = new Headers();
      if (ct.startsWith("application/json")) {
        const raw = await request.text();
        headers.set("content-type", "application/json");
        body = raw;
      } else if (ct.startsWith("multipart/form-data")) {
        const form = await request.formData();
        const fd = new FormData();
        for (const [k,v] of form.entries()) {
          if (v instanceof File) fd.append(k, v, v.name);
          else fd.append(k, v);
        }
        body = fd;
      } else if (ct.startsWith("application/x-www-form-urlencoded")) {
        const raw = await request.text();
        headers.set("content-type", "application/x-www-form-urlencoded");
        body = raw;
      } else {
        const buf = await request.arrayBuffer();
        body = buf;
        if (ct) headers.set("content-type", ct);
      }

      // Optional overrides via query string for convenience
      const qp = searchParams;
      const name = qp.get("username");
      const avatar = qp.get("avatar_url");
      if ((name || avatar) && headers.get("content-type")==="application/json") {
        try {
          const parsed = JSON.parse(body);
          if (name) parsed.username = name;
          if (avatar) parsed.avatar_url = avatar;
          body = JSON.stringify(parsed);
        } catch { /* ignore */ }
      }

      const upstream = await fetch(hook, { method: "POST", headers, body });
      const text = await upstream.text();

      // Bump lightweight metrics
      ctx.waitUntil(incrCounter(env.PROXY_KV, key));

      const outHeaders = new Headers(cors);
      for (const h of ["x-ratelimit-limit","x-ratelimit-remaining","x-ratelimit-reset","retry-after"]) {
        const v = upstream.headers.get(h); if (v) outHeaders.set(h, v);
      }
      return new Response(text, { status: upstream.status, headers: outHeaders });
    }

    return json({ error: "Not found" }, 404, cors);
  }
};

// Durable Object: token bucket limiter
export class LIMITER {
  constructor(state, env) {
    this.state = state;
  }
  async fetch(req) {
    const url = new URL(req.url);
    const key = url.pathname + url.search; // instance is already partitioned by name
    const rpm = parseInt(url.searchParams.get("rpm") || "60", 10);
    const now = Date.now();
    const stored = (await this.state.storage.get("bucket")) || { tokens: rpm, ts: now };
    // Refill
    const elapsed = Math.max(0, now - stored.ts);
    const refill = (elapsed / 60000) * rpm;
    let tokens = Math.min(rpm, stored.tokens + refill);
    const allowed = tokens >= 1;
    tokens = Math.max(0, tokens - 1);
    await this.state.storage.put("bucket", { tokens, ts: now });
    return new Response(allowed ? "ok" : "nope", { status: allowed ? 200 : 429 });
  }
}

// Helpers
function genKey(len=28) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-";
  let out = ""; crypto.getRandomValues(new Uint8Array(len)).forEach(n => out += chars[n % chars.length]);
  return out;
}
function isValidDiscordWebhook(u) {
  try {
    const x = new URL(u);
    const hostOk = (x.hostname === "discord.com" || x.hostname === "discordapp.com");
    return hostOk && /\/api\/webhooks\/\d+\/[A-Za-z0-9_\-]+/.test(x.pathname);
  } catch { return false; }
}
function makeCORSHeaders(origin, allow) {
  const h = new Headers({
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  });
  const allowNorm = normalizeAllowedOrigins(allow);
  if (origin && (allowNorm === "*" || allowNorm.split(",").includes(origin))) {
    h.set("Access-Control-Allow-Origin", origin); h.set("Vary", "Origin");
  } else if (allowNorm === "*") { h.set("Access-Control-Allow-Origin", "*"); }
  return h;
}
function normalizeAllowedOrigins(v) { return v ? v.split(",").map(s=>s.trim()).filter(Boolean).join(",") : "*"; }
function json(data, status=200, headers={}) { const h=new Headers(headers); h.set("content-type","application/json; charset=utf-8"); return new Response(JSON.stringify(data), { status, headers: h }); }
function escapeLabel(s){return String(s).replace(/["\\\n]/g,"_");}
async function safeJSON(req){ try { return await req.json(); } catch { return null; } }
async function incrCounter(kv, key) {
  const m = (await kv.get("metrics:counts","json")) || {};
  m[key] = (m[key] || 0) + 1;
  await kv.put("metrics:counts", JSON.stringify(m));
}
async function verifyTurnstile(token, ip, secret) {
  if (!token) return false;
  try {
    const res = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: new URLSearchParams({ secret, response: token, remoteip: ip })
    });
    const data = await res.json();
    return !!data.success;
  } catch { return false; }
}

// UI templates
function HOME_HTML(env) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Roblox ↔ Discord Webhook Proxy</title>
<style>
:root{--bg:#23262b;--panel:#2b2f36;--ink:#e7e9ed;--muted:#b8bec9;--accent:#3ea6ff;--accent-2:#2c89d6;}
*{box-sizing:border-box} body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{display:flex;align-items:center;gap:.75rem;padding:14px 18px;background:#1c2025;box-shadow:0 2px 10px rgba(0,0,0,.25);position:sticky;top:0;z-index:2}
header img{height:36px;width:auto;border-radius:8px;background:#111}
header .title{font-weight:700;font-size:18px}
main{max-width:960px;margin:0 auto;padding:24px;display:grid;gap:18px}
.card{background:var(--panel);border-radius:16px;padding:18px 18px 20px;box-shadow:0 6px 24px rgba(0,0,0,.22);}
h1{margin:0 0 6px 0;font-size:22px} .muted{color:var(--muted);margin-top:0}
label{display:block;font-weight:600;margin-top:10px}
input,textarea,button{font:inherit} input,textarea{width:100%;padding:10px 12px;border-radius:10px;border:1px solid #3a3f47;background:#20242a;color:var(--ink)}
button{padding:10px 14px;border:0;border-radius:10px;background:var(--accent);color:#0b1220;font-weight:700;cursor:pointer}
button:hover{background:var(--accent-2)}
.row{display:grid;gap:12px;grid-template-columns:1fr auto}
.code{background:#1d2127;border:1px dashed #39414b;border-radius:12px;padding:12px;white-space:pre-wrap;word-break:break-word}
.small{font-size:12px;color:var(--muted)}
.copy{margin-left:8px}
</style>
</head>
<body>
<header>
  <img src="/public/logo.png" alt="Logo" onerror="this.style.opacity=0"/>
  <div class="title">Roblox → Discord Webhook Proxy</div>
</header>
<main>
  <section class="card">
    <h1>Create a proxy key</h1>
    <p class="muted">Paste a Discord Webhook URL. We’ll generate a proxy endpoint that works with Roblox <code>HttpService</code>. ${env.MODE==="selfserve"?"":"<strong>(Admin-only mode)</strong>"}</p>
    <div>
      <label>Discord Webhook URL</label>
      <input id="wh" placeholder="https://discord.com/api/webhooks/..." autocomplete="off"/>
    </div>
    ${env.MODE==="selfserve" ? `<div class="small muted">Protected by Turnstile if configured.</div>` : `<div class="small muted">Self-serve is disabled. An admin must register keys.</div>`}
    <div class="row" style="margin-top:12px">
      ${env.MODE==="selfserve" ? `<button id="gen">Generate key</button>` : `<button id="gen" disabled title="Self-serve disabled">Generate key</button>`}
      <button id="roblox" title="Create example snippet">Roblox snippet</button>
    </div>
    <div id="out" class="code" style="margin-top:12px;display:none"></div>
  </section>

  <section class="card">
    <h1>Already have a key?</h1>
    <p class="muted">Your send URL looks like: <code>https://YOUR-WORKER/api/send/&lt;key&gt;</code>. Send JSON payloads with <code>content</code>, <code>embeds</code>, etc.</p>
    <div class="code small">curl -X POST -H "Content-Type: application/json" \\
-d '{"content":"Hello from Roblox!"}' \\
https://your-worker.workers.dev/api/send/KEY</div>
  </section>
</main>
<script>
const $ = sel => document.querySelector(sel);
const show = (el, txt) => { el.textContent = txt; el.style.display = 'block'; };
$("#gen")?.addEventListener("click", async () => {
  const wh = $("#wh").value.trim();
  if (!/^https:\/\/(discord(app)?\.com)\/api\/webhooks\//.test(wh)) { return show($("#out"), "❌ Invalid Discord webhook URL"); }
  const res = await fetch("/api/selfserve", { method:"POST", headers:{ "content-type":"application/json" }, body: JSON.stringify({ webhook_url: wh }) });
  const text = await res.text(); try {
    const data = JSON.parse(text);
    if (!res.ok) return show($("#out"), "Error: " + (data.error || res.status));
    const send = new URL(data.send_url, location.origin).toString();
    show($("#out"), "✅ Key created\\nSend URL: " + send);
  } catch { show($("#out"), text); }
});
$("#roblox").addEventListener("click", () => {
  const origin = location.origin;
  const example = `local HttpService = game:GetService("HttpService")\nlocal SEND_URL = "${origin}/api/send/KEY"\n\nlocal payload = { content = "Hello from Roblox!" }\nlocal ok, res = pcall(function()\n  return HttpService:PostAsync(\n    SEND_URL,\n    HttpService:JSONEncode(payload),\n    Enum.HttpContentType.ApplicationJson\n  )\nend)\n\nif ok then print("Sent:", res) else warn("Failed:", res) end`;
  show($("#out"), example);
});
</script>
</body></html>`;
}
function ADMIN_HTML() {
  return `<!doctype html><meta charset="utf-8"/><title>Admin</title>
<style>body{font-family:system-ui;margin:2rem;background:#f6f7f9}label{display:block;margin:.5rem 0}input,button{font:inherit;padding:.5rem}</style>
<h1>Admin: Create key</h1>
<p>POST /api/new with Authorization: Bearer &lt;ADMIN_TOKEN&gt;</p>`;
}
