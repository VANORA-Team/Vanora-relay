# Vanora Tunnel edge gate

The Worker verifies the 20-second edge ticket before forwarding the WebSocket upgrade to the tunnel. The desktop still verifies the single-use permit, client proof and inner mTLS.

1. In `wrangler.toml`, set the route to the dedicated proxied tunnel suffix and its owning zone. Route all paths on that suffix to the Worker. Keep the relay control hostname outside that route.
2. Use a random printable-ASCII secret of at least 32 bytes. Set the same literal value as `RELAY_CF_EDGE_KEY` and as `EDGE_KEY`. Neither component decodes the secret from hex or base64.
3. Deploy the Worker and set the secret with Wrangler.

   ```sh
   wrangler deploy
   wrangler secret put EDGE_KEY
   node --test worker.test.mjs
   ```

4. For rotation, first put the old key in `EDGE_PREV_KEY` using `wrangler secret put EDGE_PREV_KEY`. Then set the new `EDGE_KEY`. Switch the relay to the new key after the Worker deploys, wait for outstanding tickets and deployments to expire, then run `wrangler secret delete EDGE_PREV_KEY`.
5. Configure `RELAY_TUNNEL_EDGE_GATE=worker_hmac` and set `RELAY_TUNNEL_EDGE_CANARY_HOST` to a proxied name covered by the route and the same TLS certificate depth as tenant tunnels. On a full-zone setup, Universal SSL covers the apex and first-level subdomains. With a base such as `tunnel.example.com`, obtain coverage for `*.tunnel.example.com` or use a dedicated zone apex.

Check the canary without tickets or redirect following. TLS must validate and the response must be `401` or `403`.

```sh
curl --http1.1 --path-as-is -i \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  'https://canary.edge.example/v1/tunnel/ws'
```

Use a real test tunnel and ticket to confirm `101` on the canonical URL. Repeat with fresh tickets and query strings, encoded path aliases and duplicate ticket headers and expect `403`. The Worker matches the URL string it receives. Configure the zone to preserve path distinctions used by these checks, and use an edge rule to reject aliases if the zone normalizes them before Workers run.
