import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import test from "node:test";
import worker, { verifyTicket } from "./worker.js";

const key = "0123456789abcdef0123456789abcdef";
const nextKey = "next-0123456789abcdef0123456789abcdef";
const host = "aaaaaaaaaaaaaaaaaaaaaaaaaa.edge.example";
const path = "/v1/tunnel/ws";
const url = `https://${host}${path}`;
const jti = "desktop-42_Abc";
const seconds = 1800000000;
const vector = "1800000000-JRoH8hF8kjS5hI8QPR-9jfnvdgVvIs9n75FJp2WY_S0";
const current = { EDGE_KEY: key };

function ticket(secret, timestamp = seconds) {
  const signature = createHmac("sha256", secret).update(`${host}|${path}|${jti}|${timestamp}`).digest("base64url");
  return `${timestamp}-${signature}`;
}

function request(options = {}) {
  return {
    url: options.url ?? url,
    method: options.method ?? "GET",
    headers: new Headers({
      Upgrade: "WebSocket",
      "Vanora-Ticket-ID": jti,
      "Vanora-Edge-Ticket": vector,
      ...options.headers,
    }),
  };
}

test("accepts the exact Go interoperability vector and inclusive skew bounds", async () => {
  assert.equal(ticket(key), vector);
  for (const age of [-3, 0, 20]) {
    assert.equal(await verifyTicket(request(), current, seconds + age), true);
  }
  for (const age of [-4, 21]) {
    assert.equal(await verifyTicket(request(), current, seconds + age), false);
  }
});

test("supports both keys during rotation and retires the previous key", async () => {
  const rotating = { EDGE_KEY: nextKey, EDGE_PREV_KEY: key };
  const newRequest = request({ headers: { "Vanora-Edge-Ticket": ticket(nextKey) } });
  assert.equal(await verifyTicket(request(), rotating, seconds), true);
  assert.equal(await verifyTicket(newRequest, rotating, seconds), true);
  assert.equal(await verifyTicket(newRequest, current, seconds), false);
  assert.equal(await verifyTicket(request(), { EDGE_KEY: nextKey }, seconds), false);
  assert.equal(await verifyTicket(request(), { EDGE_PREV_KEY: key }, seconds), false);
});

test("rejects aliased paths and hosts and ignores spoofed routing headers", async () => {
  for (const alias of [
    `${url}?`, `${url}#`, `${url}?a=1`, `${url}#fragment`, `${url}/`, `${url}\n`,
    `https://${host}/v1/tunnel/%77s`, `https://${host}/v1/tunnel%2fws`,
    `https://${host}/v1//tunnel/ws`, `https://${host}/v1/./tunnel/ws`,
    `https://${host}/nope/../v1/tunnel/ws`, `https://${host}:443${path}`,
    `https://someone@${host}${path}`, `http://${host}${path}`,
    `https://${host.toUpperCase()}${path}`, `https://${host}.${path}`,
    `https://other.edge.example${path}`,
  ]) {
    const headers = { Host: host, "X-Forwarded-Host": host, "Forwarded": `host=${host}` };
    assert.equal(await verifyTicket(request({ url: alias, headers }), current, seconds), false, alias);
  }
  assert.equal(await verifyTicket(request({ headers: { Host: "untrusted.example" } }), current, seconds), true);
});

test("rejects invalid handshakes, ticket encodings, duplicated headers and substitutions", async () => {
  const cases = [
    { method: "POST" },
    { headers: { Upgrade: "" } },
    { headers: { Upgrade: "h2c, websocket" } },
    { headers: { "Vanora-Ticket-ID": "" } },
    { headers: { "Vanora-Ticket-ID": "x".repeat(129) } },
    { headers: { "Vanora-Ticket-ID": "another-valid-id" } },
    { headers: { "Vanora-Ticket-ID": `${jti}, ${jti}` } },
    ...["", `${vector}=`, `${vector}, ${vector}`, `x${vector.slice(1)}`, `${vector.slice(0, -1)}1`,
      `${vector.slice(0, 11)}A${vector.slice(12)}`, `1800000001${vector.slice(10)}`].map(value => (
      { headers: { "Vanora-Edge-Ticket": value } }
    )),
  ];
  for (const options of cases) {
    assert.equal(await verifyTicket(request(options), current, seconds), false, JSON.stringify(options));
  }
});

test("forwards the original accepted upgrade and returns a minimal no-store 403 on rejection", async t => {
  const origin = new Response("origin");
  const fetch = t.mock.method(globalThis, "fetch", async () => origin);
  const now = Math.floor(Date.now() / 1000);
  const valid = request({ headers: { "Vanora-Edge-Ticket": ticket(key, now) } });
  assert.equal(await worker.fetch(valid, current), origin);
  assert.deepEqual(fetch.mock.calls[0].arguments, [valid]);
  const denied = await worker.fetch(request({ method: "DELETE" }), current);
  assert.equal(denied.status, 403);
  assert.equal(denied.headers.get("Cache-Control"), "no-store");
  assert.equal(await denied.text(), "Forbidden");
  assert.equal(fetch.mock.callCount(), 1);
});
