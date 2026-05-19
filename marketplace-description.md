# Domain Technical Intelligence

One-call domain intelligence for sales, BD, and security research agents. Pass any domain — get back tech stack, DNS records with email provider, SSL certificate, WHOIS ownership, CT log subdomains, social profiles, and HTTP security posture, all normalized into a single typed object.

---

## What free LLMs get wrong

Ask ChatGPT or Gemini a domain intelligence question and you get confident, plausible, specific answers that look live and aren't.

**"What email provider does stripe.com use?"**
Free LLM: *"Stripe likely uses Google Workspace."* (reputation-based guess, no verification)
This tool: MX records → `aspmx.l.google.com` → **Google Workspace confirmed**. SPF policy: soft. DMARC: quarantine. Five MX entries with priorities.

**"What vendors does vercel.com use?"**
Free LLM: *"Probably Stripe for billing and some analytics tools."*
This tool: Live DNS TXT records → **Stripe** (3 verification tokens), **Salesforce**, **DocuSign**, **Mixpanel**, **Zoom**, **Loom**, **HubSpot**, **DoorDash**, **Notion**, **Whimsical**. The full back-office stack, in DNS, without touching a browser.

**"What subdomains has notion.so exposed?"**
Free LLM: *"Probably api.notion.so and www.notion.so."*
This tool: Certificate Transparency logs → actual enumeration of every subdomain that has ever had a TLS certificate issued, with first-seen dates.

The pattern is always the same. Free LLMs answer domain questions from training data and reputation. This tool answers them from live DNS resolution, TLS handshakes, RDAP queries, and CT log lookups — or says it can't.

---

## What it returns

Five data sources, one typed JSON object, one call.

**Tech stack fingerprint** — CMS, framework, CDN, ecommerce platform, server, language, analytics tools, and marketing tools, detected from HTTP response headers and HTML. Evidence field on every detection shows exactly what triggered it: `header:x-vercel-id=...`, `html:wp-content/`.

**DNS records with email stack classification** — A, MX, NS, TXT, CAA records, plus parsed `_dmarc` and `_bimi` subdomains. MX records are classified by provider (Google Workspace, Microsoft 365, Proton Mail, Zoho, Fastmail, SendGrid, Mailgun, Amazon SES, and more). SPF policy (strict/soft/neutral) and DMARC policy (reject/quarantine/none) are parsed and typed.

**TXT record vendor intelligence** — the highest-signal field. Companies verify ownership with every SaaS tool they use. Stripe, Salesforce, DocuSign, HubSpot, Zoom, Mixpanel, Loom, Notion, Whimsical — all visible in DNS, invisible to any HTML/JS-based tech stack detector.

**SSL certificate** — issuer org, subject, exact days until expiry, Subject Alternative Names (reveals sibling domains on the same cert), wildcard status, and key size. From a live TLS handshake, not cached data.

**WHOIS/RDAP ownership** — registrar, registration date, expiry date, privacy protection status, registrant org (when not privacy-masked), and authoritative nameservers. Via the ICANN RDAP standard; routes to the correct TLD registry automatically.

**Certificate Transparency subdomains** — every subdomain that has ever had a TLS cert issued, sourced from crt.sh CT logs. Includes first-seen dates and issuer. Reveals staging environments, internal tools, acquired products, and deprecated services.

**Social profiles and mobile apps** — self-declared links to Twitter/X, LinkedIn, GitHub, YouTube, Instagram, TikTok, Discord. iOS App Store and Google Play app IDs when linked from the homepage.

**HTTP security posture** — HSTS (with max-age and includeSubDomains flag), CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.

**Well-known path signals** — `security.txt`, `robots.txt`, `sitemap.xml`, `ads.txt`. Direct HEAD checks, not guesses.

---

## Replaces

| Tool | Cost | What it provided |
|---|---|---|
| BuiltWith Pro | $295/mo | Tech stack only, no DNS/WHOIS/subdomains, no API |
| Wappalyzer Teams | $250/mo | Tech stack only, documented 30–40% miss rate post-2023 |
| DomainTools Iris Investigate | $1,500+/yr | WHOIS + DNS, no tech stack, no CT subdomains |

All three are dashboard-only. None are agent-callable. None combine all five signals. This tool is all five in one JSON object at $0.001/execute.

---

## Try asking

- What tech stack does stripe.com run and which email provider do they use?
- What third-party vendors does vercel.com use, based on their DNS TXT records?
- What subdomains has notion.so exposed in their TLS certificates?
- Does shopify.com have a strict DMARC policy and what does their SPF record include?
- Is linear.app's SSL certificate expiring soon and does it cover any other domains?
- What's the full security posture of figma.com — HSTS, CSP, DMARC, X-Frame-Options?
- Who registered supabase.com and when, and are they using a domain privacy service?
- Compare the email security posture of hubspot.com versus salesforce.com — which has the stricter DMARC policy?

---

## Agent tips

**Cache sharing.** All four tools (`get_domain_intelligence`, `get_tech_stack`, `get_dns_records`, `get_subdomains`) share a 24-hour domain cache. The first call for any domain pays the cold fetch penalty (8–15s). Every subsequent call for the same domain — regardless of which tool — is a sub-200ms cache read. Call `get_domain_intelligence` first to warm the cache, then call the focused tools for free.

**Comparison queries.** For "compare X vs Y" prompts, call both domains in parallel. They are independent fetches with no shared state.

**TXT records are the highest-signal field.** For vendor intelligence ("what SaaS tools does this company use?"), `dns.txt_records` is the richest source. Parse for `*-verification=` and `*-verify=` patterns to reconstruct the full vendor stack. `dns.email_stack` gives the typed summary; `dns.txt_records` gives the raw evidence.

**crt.sh availability.** The CT log subdomain lookup uses crt.sh, which occasionally returns 502 or times out for extremely large domains (tens of thousands of certificates). The `subdomains.error` field will indicate timeout vs. HTTP error. This does not affect the other four data sources — they complete independently.

**Cold vs. warm latency.** `get_domain_intelligence` is classified `slow` (8–15s cold). The three focused tools are classified `fast` but this assumes a warm cache. For first-fetch scenarios where you only need one signal, call `get_domain_intelligence` once and use the relevant sub-object rather than calling a focused tool cold.

**Domain input.** All four tools accept any format: `stripe.com`, `www.stripe.com`, `https://stripe.com/pricing`. The normalizer strips protocol, path, query, fragment, and `www.` prefix automatically.
