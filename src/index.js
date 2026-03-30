import { buildPushHTTPRequest } from "@pushforge/builder";

/**
 * KV keys we use:
 *  - vapid:publicjwk
 *  - vapid:privatejwk
 *  - sub:<deviceId>
 *  - rem:<deviceId>:<reminderId>
 */

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type",
      "access-control-allow-methods": "GET,POST,OPTIONS",
      ...extraHeaders,
    },
  });
}

function ok(text = "ok") {
  return new Response(text, {
    headers: {
      "access-control-allow-origin": "*",
      "access-control-allow-headers": "content-type",
      "access-control-allow-methods": "GET,POST,OPTIONS",
    },
  });
}

function b64urlToBytes(b64url) {
  const pad = "=".repeat((4 - (b64url.length % 4)) % 4);
  const b64 = (b64url + pad).replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(b64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

function bytesToB64url(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = btoa(bin);
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

// Convert public JWK (x,y) into the browser "applicationServerKey" format (base64url of 65 bytes: 0x04 + X + Y)
function publicJwkToVapidPublicKey(publicJwk) {
  const x = b64urlToBytes(publicJwk.x);
  const y = b64urlToBytes(publicJwk.y);
  const raw = new Uint8Array(1 + x.length + y.length);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 1 + x.length);
  return bytesToB64url(raw);
}

async function ensureVapidKeys(env) {
  // generate once and store in KV
  const existingPub = await env.KV.get("vapid:publicjwk");
  const existingPriv = await env.KV.get("vapid:privatejwk");
  if (existingPub && existingPriv) {
    return {
      publicJwk: JSON.parse(existingPub),
      privateJwk: JSON.parse(existingPriv),
    };
  }

  // Cloudflare Workers supports Web Crypto API [6](https://developers.cloudflare.com/workers/runtime-apis/web-crypto/)
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );

  const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

  // Add expected fields (safe, helps libs)
  publicJwk.kty = "EC";
  publicJwk.crv = "P-256";
  publicJwk.alg = "ES256";

  privateJwk.kty = "EC";
  privateJwk.crv = "P-256";
  privateJwk.alg = "ES256";

  await env.KV.put("vapid:publicjwk", JSON.stringify(publicJwk));
  await env.KV.put("vapid:privatejwk", JSON.stringify(privateJwk));

  return { publicJwk, privateJwk };
}

async function sendPushToDevice(env, deviceId, payload) {
  const subStr = await env.KV.get(`sub:${deviceId}`);
  if (!subStr) return { ok: false, reason: "no-subscription" };

  const subscription = JSON.parse(subStr);

  const { privateJwk } = await ensureVapidKeys(env);

  const { endpoint, headers, body } = await buildPushHTTPRequest({
    privateJWK: privateJwk,
    subscription,
    message: {
      payload,
      adminContact: "mailto:reminders@example.com"
    }
  });

  const res = await fetch(endpoint, { method: "POST", headers, body });

  // If the subscription is gone, remove it
  if (res.status === 404 || res.status === 410) {
    await env.KV.delete(`sub:${deviceId}`);
  }

  return { ok: res.ok, status: res.status };
}

async function handleFetch(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;

  if (request.method === "OPTIONS") return ok();

  // GET /public-key  -> returns { publicKey }
  if (request.method === "GET" && path === "/public-key") {
    const { publicJwk } = await ensureVapidKeys(env);
    const publicKey = publicJwkToVapidPublicKey(publicJwk);
    return json({ publicKey });
  }

  // POST /subscribe -> { deviceId, subscription }
  if (request.method === "POST" && path === "/subscribe") {
    const body = await request.json();
    const deviceId = (body.deviceId || "").trim();
    const subscription = body.subscription;

    if (!deviceId || !subscription?.endpoint || !subscription?.keys) {
      return json({ error: "bad request" }, 400);
    }

    await env.KV.put(`sub:${deviceId}`, JSON.stringify(subscription));
    return json({ ok: true });
  }

  // POST /reminder -> { deviceId, id, text, timeMs }
  if (request.method === "POST" && path === "/reminder") {
    const body = await request.json();
    const deviceId = (body.deviceId || "").trim();
    const id = body.id || Date.now();
    const text = (body.text || "Reminder").toString().slice(0, 140);
    const timeMs = Number(body.timeMs);

    if (!deviceId || !Number.isFinite(timeMs)) {
      return json({ error: "bad request" }, 400);
    }

    const key = `rem:${deviceId}:${id}`;
    await env.KV.put(key, JSON.stringify({ deviceId, id, text, timeMs }));

    return json({ ok: true });
  }

  // POST /test -> { deviceId } sends a test push now
  if (request.method === "POST" && path === "/test") {
    const body = await request.json();
    const deviceId = (body.deviceId || "").trim();
    if (!deviceId) return json({ error: "bad request" }, 400);

    const r = await sendPushToDevice(env, deviceId, {
      title: "Test ✅",
      body: "If you see this, push notifications work!"
    });

    return json(r);
  }

  return json({ error: "not found" }, 404);
}

async function handleScheduled(env) {
  const now = Date.now();

  // list all reminders
  const list = await env.KV.list({ prefix: "rem:" });

  for (const k of list.keys) {
    const val = await env.KV.get(k.name);
    if (!val) continue;

    let rem;
    try { rem = JSON.parse(val); } catch { continue; }

    if (rem.timeMs <= now) {
      // send push
      await sendPushToDevice(env, rem.deviceId, {
        title: "Reminder",
        body: rem.text
      });

      // delete reminder (one-time)
      await env.KV.delete(k.name);
    }
  }
}

export default {
  async fetch(request, env, ctx) {
    return handleFetch(request, env);
  },
  async scheduled(controller, env, ctx) {
    // Cron Triggers call this on schedule [1](https://developers.cloudflare.com/workers/configuration/cron-triggers/)
    ctx.waitUntil(handleScheduled(env));
  }
};
