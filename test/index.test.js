import test from "node:test";
import assert from "node:assert/strict";
import { buildExpectedRecords, diffRecords, verifySignature, formatMessage } from "../src/index.js";

const opts = { domain: "example.com", prefix: "ts-", postfix: "" };

test("buildExpectedRecords: v4/v6 CGNAT only, prefix applied", () => {
  const devices = [
    { name: "nas.tailnet.ts.net", addresses: ["100.10.0.1", "fd7a:115c:a1e0:ab12::1"] },
    { name: "server.tailnet.ts.net", addresses: ["100.10.0.2"] },
    { name: "public.tailnet.ts.net", addresses: ["8.8.8.8"] },
  ];
  const got = buildExpectedRecords(devices, opts);
  assert.deepEqual(got, [
    { name: "ts-nas.example.com", type: "A", content: "100.10.0.1" },
    { name: "ts-nas.example.com", type: "AAAA", content: "fd7a:115c:a1e0:ab12::1" },
    { name: "ts-server.example.com", type: "A", content: "100.10.0.2" },
  ]);
});

test("diffRecords: create/update/remove, keeps foreign records", () => {
  const existing = [
    { id: "1", name: "ts-nas.example.com", type: "A", content: "100.10.0.9" },
    { id: "2", name: "ts-old.example.com", type: "A", content: "100.10.0.99" },
    { id: "3", name: "manual.example.com", type: "A", content: "100.10.0.77" },
    { id: "4", name: "ts-nas.example.com", type: "A", content: "1.2.3.4" },
  ];
  const expected = [
    { name: "ts-nas.example.com", type: "A", content: "100.10.0.1" },
    { name: "ts-nas.example.com", type: "AAAA", content: "fd7a:115c:a1e0::1" },
  ];
  const { create, update, remove } = diffRecords(expected, existing, opts);
  assert.deepEqual(create, [{ name: "ts-nas.example.com", type: "AAAA", content: "fd7a:115c:a1e0::1" }]);
  assert.deepEqual(update, [{ id: "1", name: "ts-nas.example.com", type: "A", content: "100.10.0.1" }]);
  assert.deepEqual(remove, [{ id: "2", name: "ts-old.example.com", type: "A", content: "100.10.0.99" }]);
});

test("verifySignature: accepts valid, rejects tampered", async () => {
  const secret = "s3cret";
  const body = JSON.stringify([{ type: "nodeCreated" }]);
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const ts = Math.floor(Date.now() / 1000);
  const sig = [...new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(`${ts}.${body}`)))]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
  const header = `t=${ts},v1=${sig}`;

  assert.equal(await verifySignature(header, body, secret), true);
  assert.equal(await verifySignature(header, body + "x", secret), false);
  assert.equal(await verifySignature(null, body, secret), false);
});

test("formatMessage: null when no changes, lists records when changed", () => {
  assert.equal(formatMessage({ create: [], update: [], remove: [] }), null);
  const msg = formatMessage({
    create: [{ name: "ts-nas.example.com", type: "A", content: "100.10.0.1" }],
    update: [],
    remove: [{ name: "ts-old.example.com", type: "A", content: "100.10.0.99" }],
  });
  assert.match(msg, /ts-cf-dns-sync/);
  assert.match(msg, /DNS 记录更新/);
  assert.match(msg, /新增 1/);
  assert.match(msg, /ts-nas.example.com A 100.10.0.1/);
  assert.match(msg, /删除 1/);
  assert.match(msg, /ts-old.example.com A 100.10.0.99/);
});
