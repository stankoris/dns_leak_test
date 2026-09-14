# DNS Leak Test

A small self-hosted DNS leak test built with Node.js, Express, and an authoritative DNS server.

## Security behavior

- The DNS server answers only for the configured delegated test zone.
- Any query outside the configured zone returns `REFUSED` with no answer records.
- Recursion is never advertised (`RA=0`).
- DNS is served over both UDP and TCP.
- Only active, random test sessions receive probe A responses.
- HTTP binds to loopback and is intended to sit behind Nginx.
- Test sessions are in-memory, short-lived, and use separate DNS and result identifiers.
- Missing TCP peer metadata is never stored as a fake resolver entry.
- Optional ISP/location enrichment uses local MaxMind-compatible databases only.

## Install

```bash
cd /opt/dns-leak-test
npm install --omit=dev
cp .env.example .env
nano .env
```

Keep HTTP on `127.0.0.1`. Set `DNS_BIND_ADDRESS` to the server's public IPv4 address.

## Run

```bash
npm start
```

Health check:

```bash
curl http://127.0.0.1:3001/api/healthz
```

## Open-resolver regression test

These must return `REFUSED`, `ANSWER: 0`, and no `ra` flag:

```bash
dig @SERVER_IP cert-bund.de A
dig +tcp @SERVER_IP cert-bund.de A
dig @SERVER_IP google.com A
```

## Valid probe test

Create a session:

```bash
curl -sS -X POST http://127.0.0.1:3001/api/tests \
  -H 'Content-Type: application/json' \
  -d '{"privacyAcknowledged":true,"termsAccepted":true}'
```

A valid DNS probe has this shape:

```text
<hex-probe-id>.<32-char-test-id>.<DNS_TEST_DOMAIN>
```

## DNS records

Create an A record for the authoritative nameserver and delegate the test zone to it. Example:

```text
ns1.dnstest.firewallmindset.site     A     SERVER_PUBLIC_IP
dnstest.firewallmindset.site         NS    ns1.dnstest.firewallmindset.site
```

If Cloudflare is used for the nameserver A record, keep it **DNS only**.

## Legal templates

`privacy.html` and `terms.html` are technical placeholders, not legal advice. Replace the operator/controller details and have the final public text reviewed for the intended jurisdiction.
