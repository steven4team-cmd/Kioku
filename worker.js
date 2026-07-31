/* ============================================================================
   Kioku Cloudflare Worker — AI proxy + Stripe + Whisper  (HARDENED v3)
   ----------------------------------------------------------------------------
   v3 change: the per-account rolling-24h AI limit is now stored in SUPABASE
   (table: ai_usage) instead of Cloudflare KV. Enforcement is fully server-side
   and keyed to the verified account, so it survives logout/login, refresh, new
   browsers, and cleared storage — there is no client-side way to reset it.

   No KV binding is required. Reuses the secrets you already have:
     ANTHROPIC_KEY, STRIPE_SECRET_KEY, STRIPE_PRICE_ID, STRIPE_WEBHOOK_SECRET,
     SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, APP_URL
   Still uses the Workers AI binding named  AI  (for /transcribe).

   ONE-TIME SETUP (Supabase → SQL Editor → Run):
     create table if not exists public.ai_usage (
       user_id uuid primary key,
       window_start bigint not null,
       used integer not null default 0
     );
     alter table public.ai_usage enable row level security;

   NOTE ON THE GLOBAL BUDGET: the hard ceiling on total spend is your Anthropic
   Console monthly spend limit ($20). That is what caps your worst case no matter
   how many accounts sign up. This Worker enforces the per-account fair-use cap.
   ============================================================================ */

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Expose-Headers": "X-Usage-Today, X-Usage-Limit, X-Limit-Reached",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { ...CORS, "Content-Type": "application/json" } });

// ---- limits ----
const FREE_DAILY = 4500;    // tokens per rolling 24h for free accounts
const PRO_DAILY  = 45000;   // tokens per rolling 24h for Pro accounts (10x free)
const MAX_PROMPT_CHARS = 24000;
const WINDOW_MS = 24 * 60 * 60 * 1000; // rolling 24h window

// Verify a Supabase access token → real user id, or null.
async function verifyUser(env, token) {
  if (!token || !env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) return null;
  try {
    const u = await fetch(env.SUPABASE_URL + "/auth/v1/user", {
      headers: { Authorization: "Bearer " + token, apikey: env.SUPABASE_SERVICE_ROLE_KEY },
    });
    if (!u.ok) return null;
    const j = await u.json();
    return j && j.id ? j.id : null;
  } catch (e) { return null; }
}

// Read a user's plan ("pro" | "free") from Supabase.
async function getPlan(env, uid) {
  try {
    const rows = await sb(env, "GET", `user_data?user_id=eq.${uid}&select=data`);
    return (rows[0] && rows[0].data && rows[0].data.plan === "pro") ? "pro" : "free";
  } catch (e) { return "free"; }
}

// Read the account's current usage window from Supabase (or null if none).
async function getUsage(env, uid) {
  try {
    const rows = await sb(env, "GET", `ai_usage?user_id=eq.${uid}&select=window_start,used`);
    if (rows[0]) return { start: Number(rows[0].window_start) || 0, used: rows[0].used || 0 };
  } catch (e) {}
  return null;
}
// Upsert the account's usage window.
async function setUsage(env, uid, start, used) {
  try { await sb(env, "POST", "ai_usage?on_conflict=user_id", { user_id: uid, window_start: start, used }); } catch (e) {}
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    // ---------- WHISPER: lecture transcription (login-gated) ----------
    if (url.pathname === "/transcribe" && request.method === "POST") {
      try {
        const { audio, language, token } = await request.json();
        const uid = await verifyUser(env, token);
        if (!uid) return json({ error: "Sign in required." }, 401);
        if (!audio) return json({ error: "No audio provided" }, 400);
        const out = await env.AI.run("@cf/openai/whisper-large-v3-turbo", {
          audio,
          language: language || "en",
        });
        return json({ text: out && out.text ? String(out.text).trim() : "" });
      } catch (e) {
        return json({ error: e.message || String(e) }, 500);
      }
    }

    // ---------- STRIPE: create checkout session ----------
    if (url.pathname === "/checkout" && request.method === "POST") {
      try {
        const { userId, email, returnUrl } = await request.json();
        if (!userId) return json({ error: "missing userId" }, 400);
        const base = returnUrl || env.APP_URL;

        let customerId = await getStripeCustomer(env, userId);
        if (!customerId) {
          const customer = await stripeApi(env, "customers", {
            email: email || "",
            "metadata[supabase_user_id]": userId,
          });
          customerId = customer.id;
          await setStripeCustomer(env, userId, customerId);
        }

        const session = await stripeApi(env, "checkout/sessions", {
          mode: "subscription",
          customer: customerId,
          "line_items[0][price]": env.STRIPE_PRICE_ID,
          "line_items[0][quantity]": "1",
          success_url: base + "?upgraded=1",
          cancel_url: base,
          "subscription_data[metadata][supabase_user_id]": userId,
          "metadata[supabase_user_id]": userId,
          allow_promotion_codes: "true",
        });
        if (!session.url) return json({ error: session.error ? session.error.message : "no url" }, 500);
        return json({ url: session.url });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ---------- STRIPE: customer portal ----------
    if (url.pathname === "/portal" && request.method === "POST") {
      try {
        const { userId, returnUrl } = await request.json();
        const customerId = await getStripeCustomer(env, userId);
        if (!customerId) return json({ error: "no customer" }, 400);
        const session = await stripeApi(env, "billing_portal/sessions", {
          customer: customerId,
          return_url: returnUrl || env.APP_URL,
        });
        if (!session.url) return json({ error: "portal unavailable" }, 500);
        return json({ url: session.url });
      } catch (e) {
        return json({ error: e.message }, 500);
      }
    }

    // ---------- STRIPE: webhook ----------
    if (url.pathname === "/webhook" && request.method === "POST") {
      const sig = request.headers.get("stripe-signature");
      const body = await request.text();
      const ok = await verifyStripeSignature(body, sig, env.STRIPE_WEBHOOK_SECRET);
      if (!ok) return new Response("bad signature", { status: 400 });

      let event;
      try { event = JSON.parse(body); } catch (e) { return new Response("bad json", { status: 400 }); }

      try {
        if (event.type === "checkout.session.completed") {
          const userId = event.data.object.metadata && event.data.object.metadata.supabase_user_id;
          if (userId) await setPlan(env, userId, "pro");
        } else if (
          event.type === "customer.subscription.deleted" ||
          (event.type === "customer.subscription.updated" &&
            ["canceled", "unpaid", "incomplete_expired"].includes(event.data.object.status))
        ) {
          const sub = event.data.object;
          const userId = sub.metadata && sub.metadata.supabase_user_id;
          if (userId) await setPlan(env, userId, "free");
        }
      } catch (e) {
        return new Response("handler error: " + e.message, { status: 500 });
      }
      return new Response("ok", { status: 200 });
    }

    // ---------- AI PROXY (login required + Supabase-backed rolling-24h cap) ----------
    if (request.method !== "POST") return new Response("POST only", { status: 405, headers: CORS });

    let payload;
    try { payload = await request.json(); } catch { return json({ error: { message: "Bad JSON" } }, 400); }
    const { prompt, maxTokens, token } = payload;
    if (typeof prompt !== "string" || !prompt || prompt.length > MAX_PROMPT_CHARS) {
      return json({ error: { message: "Invalid or oversized prompt" } }, 400);
    }

    const uid = await verifyUser(env, token);
    if (!uid) return json({ error: { message: "Sign in required." } }, 401);

    const now   = Date.now();
    const plan  = await getPlan(env, uid);
    const limit = plan === "pro" ? PRO_DAILY : FREE_DAILY;

    // Rolling 24h window, stored in Supabase and keyed to the verified account.
    // The window "starts" on the account's first request and only resets once a
    // full 24h has elapsed since that start — enforced on server time, with no
    // client-controlled value involved.
    let win = await getUsage(env, uid);
    if (!win || (now - win.start) >= WINDOW_MS) win = { start: now, used: 0 };

    if (win.used >= limit) {
      const retrySec = Math.max(1, Math.ceil((WINDOW_MS - (now - win.start)) / 1000));
      return new Response(
        JSON.stringify({ error: { type: "daily_limit", message: "Daily limit reached. Resets in about " + Math.ceil(retrySec / 3600) + "h." } }),
        { status: 429, headers: { ...CORS, "Content-Type": "application/json", "X-Limit-Reached": "daily", "Retry-After": String(retrySec), "X-Usage-Today": String(win.used), "X-Usage-Limit": String(limit) } }
      );
    }

    const r = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": env.ANTHROPIC_KEY,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({
        model: "claude-haiku-4-5-20251001",
        max_tokens: maxTokens || 8192,
        messages: [{ role: "user", content: prompt }],
      }),
    });
    const body = await r.text();

    // Meter this call's real usage into the account's window (persisted in Supabase).
    let total = win.used;
    try {
      const data = JSON.parse(body);
      const u = data.usage || {};
      const spent = (u.input_tokens || 0) + (u.output_tokens || 0);
      total = win.used + spent;
      await setUsage(env, uid, win.start, total);
    } catch (e) {}

    return new Response(body, {
      status: r.status,
      headers: { ...CORS, "Content-Type": "application/json", "X-Usage-Today": String(total), "X-Usage-Limit": String(limit) },
    });
  },
};

/* ---------- Stripe REST helper ---------- */
async function stripeApi(env, path, params) {
  const form = new URLSearchParams();
  for (const k in params) form.append(k, params[k]);
  const res = await fetch("https://api.stripe.com/v1/" + path, {
    method: "POST",
    headers: {
      Authorization: "Bearer " + env.STRIPE_SECRET_KEY,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });
  return res.json();
}

/* ---------- Stripe webhook signature verification ---------- */
async function verifyStripeSignature(payload, header, secret) {
  try {
    if (!header || !secret) return false;
    const parts = {};
    header.split(",").forEach((kv) => {
      const [k, v] = kv.split("=");
      if (k === "t") parts.t = v;
      if (k === "v1") parts.v1 = v;
    });
    if (!parts.t || !parts.v1) return false;
    const signedPayload = parts.t + "." + payload;
    const key = await crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPayload));
    const expected = [...new Uint8Array(sigBuf)].map((b) => b.toString(16).padStart(2, "0")).join("");
    if (expected.length !== parts.v1.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ parts.v1.charCodeAt(i);
    return diff === 0;
  } catch (e) { return false; }
}

/* ---------- Supabase REST helpers (service-role key, server-side only) ---------- */
async function sb(env, method, path, body) {
  const res = await fetch(env.SUPABASE_URL + "/rest/v1/" + path, {
    method,
    headers: {
      apikey: env.SUPABASE_SERVICE_ROLE_KEY,
      Authorization: "Bearer " + env.SUPABASE_SERVICE_ROLE_KEY,
      "Content-Type": "application/json",
      Prefer: "return=representation,resolution=merge-duplicates",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error("supabase " + res.status + ": " + (await res.text()));
  const txt = await res.text();
  return txt ? JSON.parse(txt) : [];
}

async function setPlan(env, userId, plan) {
  const rows = await sb(env, "GET", `user_data?user_id=eq.${userId}&select=data`);
  const data = (rows[0] && rows[0].data) || {};
  data.plan = plan;
  await sb(env, "POST", "user_data?on_conflict=user_id", { user_id: userId, data });
}

async function getStripeCustomer(env, userId) {
  const rows = await sb(env, "GET", `stripe_customers?user_id=eq.${userId}&select=customer_id`);
  return rows[0] ? rows[0].customer_id : null;
}
async function setStripeCustomer(env, userId, customerId) {
  await sb(env, "POST", "stripe_customers?on_conflict=user_id", { user_id: userId, customer_id: customerId });
}
