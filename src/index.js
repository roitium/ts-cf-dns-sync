const API = "https://api.tailscale.com/api/v2";

function hostnameOf(name) {
  return name.split(".")[0];
}

export function buildExpectedRecords(devices, { domain, prefix = "", postfix = "" }) {
  const records = [];
  for (const d of devices) {
    const name = `${prefix}${hostnameOf(d.name)}${postfix}.${domain}`;
    for (const addr of d.addresses || []) {
      if (addr.includes(":")) {
        if (addr.startsWith("fd7a:115c:a1e0:")) records.push({ name, type: "AAAA", content: addr });
      } else if (addr.startsWith("100.")) {
        records.push({ name, type: "A", content: addr });
      }
    }
  }
  return records;
}

const CG_NET = /^(100\.|fd7a:115c:a1e0:)/;

export function diffRecords(expected, existing, { prefix = "", postfix = "", domain }) {
  const key = (r) => `${r.name}|${r.type}|${r.content}`;
  const expectedKeys = new Set(expected.map(key));
  const managedName = (n) => n.startsWith(prefix) && n.endsWith(`${postfix}.${domain}`);

  const create = [];
  const update = [];
  const remove = [];

  for (const e of expected) {
    if (existing.some((r) => r.name === e.name && r.type === e.type && r.content === e.content)) continue;
    const prev = existing.find((r) => r.name === e.name && r.type === e.type && CG_NET.test(r.content));
    if (prev) update.push({ id: prev.id, ...e });
    else create.push(e);
  }

  for (const ex of existing) {
    if (!managedName(ex.name) || !CG_NET.test(ex.content)) continue;
    if (update.some((u) => u.id === ex.id)) continue;
    if (!expectedKeys.has(key(ex))) remove.push(ex);
  }

  return { create, update, remove };
}

export async function verifySignature(header, body, secret) {
  if (!header) return false;
  const parts = Object.fromEntries(header.split(",").map((p) => p.trim().split("=", 2)));
  const ts = Number(parts.t);
  if (!ts || Math.abs(Date.now() / 1000 - ts) > 300) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(`${ts}.${body}`));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex === parts.v1;
}

async function tailscaleDevices(env) {
  const res = await fetch(`${API}/tailnet/${env.TAILNET}/devices`, {
    headers: { Authorization: `Bearer ${env.TAILSCALE_API_KEY}` },
  });
  if (!res.ok) throw new Error(`tailscale api ${res.status}: ${await res.text()}`);
  return (await res.json()).devices;
}

async function cfRecords(env) {
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records?per_page=5000`,
    { headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` } },
  );
  if (!res.ok) throw new Error(`cloudflare api ${res.status}: ${await res.text()}`);
  return (await res.json()).result;
}

async function cfUpsert(env, rec, existingId) {
  const url = existingId
    ? `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records/${existingId}`
    : `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records`;
  const method = existingId ? "PUT" : "POST";
  const res = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${env.CF_API_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ type: rec.type, name: rec.name, content: rec.content, ttl: 1 }),
  });
  if (!res.ok) throw new Error(`cf upsert ${res.status}: ${await res.text()}`);
}

export function formatMessage({ create, update, remove }) {
  const lines = [];
  if (create.length) lines.push(`➕ 新增 ${create.length}`, ...create.map((r) => `  ${r.name} ${r.type} ${r.content}`));
  if (update.length) lines.push(`🔄 更新 ${update.length}`, ...update.map((r) => `  ${r.name} ${r.type} ${r.content}`));
  if (remove.length) lines.push(`➖ 删除 ${remove.length}`, ...remove.map((r) => `  ${r.name} ${r.type} ${r.content}`));
  return lines.length ? `🔄 [ts-cf-dns-sync] Tailscale → Cloudflare DNS 记录更新\n${lines.join("\n")}` : null;
}

async function sendTelegram(env, text) {
  const res = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: env.TG_CHAT_ID, text, disable_web_page_preview: true }),
  });
  if (!res.ok) throw new Error(`telegram ${res.status}: ${await res.text()}`);
}

async function sync(env) {
  const devices = await tailscaleDevices(env);
  const expected = buildExpectedRecords(devices, {
    domain: env.DOMAIN, prefix: env.PREFIX || "", postfix: env.POSTFIX || "",
  });
  const existing = await cfRecords(env);
  const { create, update, remove } = diffRecords(expected, existing, {
    domain: env.DOMAIN, prefix: env.PREFIX || "", postfix: env.POSTFIX || "",
  });
  for (const r of create) await cfUpsert(env, r);
  for (const r of update) await cfUpsert(env, r, r.id);
  for (const r of remove) {
    const res = await fetch(
      `https://api.cloudflare.com/client/v4/zones/${env.CF_ZONE_ID}/dns_records/${r.id}`,
      { method: "DELETE", headers: { Authorization: `Bearer ${env.CF_API_TOKEN}` } },
    );
    if (!res.ok) throw new Error(`cf delete ${res.status}: ${await res.text()}`);
  }
  if ((create.length || update.length || remove.length) && env.TG_BOT_TOKEN && env.TG_CHAT_ID) {
    await sendTelegram(env, formatMessage({ create, update, remove }));
  }
  return { devices: devices.length, create, update, remove };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/webhook" && request.method === "POST") {
      if (env.VERIFY_SIGNATURE !== "false") {
        const body = await request.text();
        const ok = await verifySignature(
          request.headers.get("Tailscale-Webhook-Signature"), body, env.TS_WEBHOOK_SECRET,
        );
        if (!ok) return new Response("bad signature", { status: 401 });
        const events = JSON.parse(body).map((e) => e.type).filter(
          (t) => t.startsWith("node") || t === "policyUpdate",
        );
        if (events.length === 0) return Response.json({ ok: true, skipped: true });
        const result = await sync(env);
        return Response.json({ ok: true, events, ...result });
      }
      const result = await sync(env);
      return Response.json({ ok: true, ...result });
    }

    if (url.pathname === "/" && request.method === "GET") {
      return Response.json({ ok: true, note: "tailscale webhook -> cloudflare dns sync" });
    }

    return new Response("not found", { status: 404 });
  },
};
