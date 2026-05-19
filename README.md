# Domain Technical Intelligence MCP

**One-call domain intelligence for AI agents.** Tech stack, DNS, SSL, WHOIS, subdomains, social profiles — normalized into a single typed object.

Listed on the [Context marketplace](https://ctxprotocol.com).

## What it replaces

| Tool | Cost | What it provided |
|---|---|---|
| BuiltWith Pro | $295/mo | Tech stack fingerprinting |
| Wappalyzer Teams | $250/mo | Tech stack detection |
| DomainTools Iris | $1,500+/yr | DNS + WHOIS + subdomain research |

This MCP tool returns all of the above in one call, for $0.001/execute or $0.10/query response.

## Data sources

| Signal | Source | Auth |
|---|---|---|
| Tech stack | HTTP headers + HTML parsing (Wappalyzer patterns, MIT) | None |
| DNS records | Node.js `dns/promises` (direct resolver) | None |
| Email stack | SPF/MX record classification | None |
| SSL/TLS cert | Node.js `tls` module (direct handshake) | None |
| Subdomain enumeration | crt.sh Certificate Transparency logs | None |
| WHOIS / RDAP | rdap.org (ICANN standard) | None |
| Social profiles | HTML link parsing | None |
| Mobile apps | App Store / Play Store link detection | None |
| HTTP security posture | Response header parsing | None |
| Well-known paths | Direct HTTP HEAD checks | None |

**Zero paid APIs. Zero scraping of gated content. Zero auth required.**

## Tools

| Tool | Description | Latency |
|---|---|---|
| `get_domain_intelligence` | Full intelligence object — all signals in one call | sub-200ms cached / 8–15s cold |
| `get_tech_stack` | Tech stack only (CMS, framework, CDN, analytics, email provider) | sub-200ms (shares cache) |
| `get_dns_records` | Full DNS + email stack classification | sub-200ms (shares cache) |
| `get_subdomains` | CT log subdomain enumeration | sub-200ms (shares cache) |

All 4 tools share the same 24h domain cache — the first call for a domain pays the cold penalty; subsequent calls for the same domain are instant regardless of which tool is called.

## Run locally

```bash
npm install
npm run build
npm start
```

Test with curl:

```bash
# List tools
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/list","id":1}'

# Full intelligence for stripe.com
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"get_domain_intelligence","arguments":{"domain":"stripe.com"}}}'
```

> **Note:** `tools/call` returns `{"error":"Unauthorized"}` locally unless you have a valid CTX JWT.
> Comment out `createContextMiddleware()` in `server.ts` for local development testing.

## Transport

Same hybrid pattern as AppSignal MCP:

- `GET /mcp` — SSE session (for MCP Inspector and SDK clients)
- `POST /mcp` — Stateless single-shot handler for CTX discovery and paid calls
  - `tools/list` and `initialize` return plain JSON, no session required
  - `tools/call` executes directly and returns plain JSON

## Deploy

### Railway / Render (easiest)

Push to GitHub, connect repo, set `PORT` env var. No volume mount or database needed — cache is in-memory.

### Hetzner CX22 (~€4/mo)

```bash
docker build -t domain-intel-mcp .
docker run -d -p 3000:3000 --restart unless-stopped domain-intel-mcp
```

Expose via Caddy or nginx for HTTPS.

## List on CTX marketplace

1. Deploy and get a public HTTPS endpoint
2. Go to [ctxprotocol.com/contribute](https://ctxprotocol.com/contribute)
3. Paste your endpoint URL
4. CTX auto-discovers all 4 tools via `tools/list`
5. Set listing price ($0.10/response)
6. Stake $10 USDC → listing goes live

## Architecture

```
GET /mcp or POST tools/call
        ↓
fetcher.ts:getDomainIntelligence(domain)
        ↓ parallel Promise.all (all 5 sources fire simultaneously)
  ┌─────┬─────────┬──────────┬────────────┬─────────────┐
  ↓     ↓         ↓          ↓            ↓             ↓
dns.ts ssl.ts   ssl.ts    rdap.ts     scraper.ts
(DNS)  (TLS)  (crt.sh)   (RDAP)   (HTTP + fingerprints)
  └─────┴─────────┴──────────┴────────────┴─────────────┘
        ↓
  DomainIntelligence object → Cache 24h → Return
```

No database. No background jobs. No state. Cold fetches are 8–15s; warm cache hits are sub-200ms.
