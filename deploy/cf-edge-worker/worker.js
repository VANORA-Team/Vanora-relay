const path = "/v1/tunnel/ws";
const urlPattern = /^https:\/\/([a-z0-9.-]+)\/v1\/tunnel\/ws$/;
const labelPattern = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const jtiPattern = /^[A-Za-z0-9_-]{1,128}(?![\s\S])/;
const ticketPattern = /^[0-9]{10}-[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const utf8 = new TextEncoder();
const verificationKeys = new Map();
const maxVerificationKeys = 4;

async function verificationKey(secret) {
  const cached = verificationKeys.get(secret);
  if (cached) {
    return cached;
  }
  const bytes = utf8.encode(secret);
  if (bytes.length < 32) {
    return null;
  }
  const key = await crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
  if (!verificationKeys.has(secret) && verificationKeys.size >= maxVerificationKeys) {
    verificationKeys.delete(verificationKeys.keys().next().value);
  }
  verificationKeys.set(secret, key);
  return key;
}

export async function verifyTicket(request, env, now = Math.floor(Date.now() / 1000)) {
  if (request.method !== "GET" || request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
    return false;
  }
  const url = urlPattern.exec(request.url);
  if (!url || url[0] !== request.url) {
    return false;
  }
  const hostname = url[1];
  const labels = hostname.split(".");
  if (hostname.length > 253 || labels.length < 2 || labels.some(label => !labelPattern.test(label)) ||
      labels.length === 4 && labels.every(label => /^(?:0|[1-9][0-9]{0,2})$/.test(label) && Number(label) <= 255)) {
    return false;
  }
  const jti = request.headers.get("Vanora-Ticket-ID");
  const ticket = request.headers.get("Vanora-Edge-Ticket");
  if (!jti || !jtiPattern.test(jti) || !ticket ||
      ticket.length !== 54 || !ticketPattern.test(ticket) || !env.EDGE_KEY) {
    return false;
  }
  const timestamp = ticket.slice(0, 10);
  const age = now - Number(timestamp);
  if (age > 20 || age < -3) {
    return false;
  }
  const signature = Uint8Array.from(atob(ticket.slice(11).replaceAll("-", "+").replaceAll("_", "/") + "="),
    char => char.charCodeAt(0));
  const input = utf8.encode(`${hostname}|${path}|${jti}|${timestamp}`);
  const secrets = env.EDGE_PREV_KEY ? [env.EDGE_KEY, env.EDGE_PREV_KEY] : [env.EDGE_KEY];
  const matches = await Promise.all(secrets.map(async secret => {
    const key = await verificationKey(secret);
    return key !== null && crypto.subtle.verify("HMAC", key, signature, input);
  }));
  return matches.includes(true);
}

export default {
  async fetch(request, env) {
    let authorized = false;
    try {
      authorized = await verifyTicket(request, env);
    } catch {
      return forbidden();
    }
    if (!authorized) {
      return forbidden();
    }
    return fetch(request);
  },
};

function forbidden() {
  return new Response("Forbidden", { status: 403, headers: { "Cache-Control": "no-store" } });
}
