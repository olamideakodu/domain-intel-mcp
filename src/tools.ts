// ── Shared sub-schemas ─────────────────────────────────────────────────────

const TECH_STACK_SCHEMA = {
  type: "object",
  description: "Detected technology stack for the domain",
  properties: {
    detected: {
      type: "array",
      description: "All detected technologies with confidence scores and evidence",
      items: {
        type: "object",
        properties: {
          name:       { type: "string", description: "Technology name (e.g. 'Next.js')" },
          category:   { type: "string", description: "Category: CMS, Framework, CDN, Analytics, Ecommerce, Server, Language, Hosting, Marketing, Other" },
          confidence: { type: "number", description: "Confidence score 0–100" },
          evidence:   { type: "string", description: "What triggered detection (e.g. 'header:server=cloudflare', 'html:wp-content/')" },
        },
        required: ["name", "category", "confidence", "evidence"],
      },
    },
    cms:            { type: ["string", "null"], description: "Primary CMS if detected (e.g. 'WordPress', 'Ghost')" },
    framework:      { type: ["string", "null"], description: "Primary JS framework (e.g. 'Next.js', 'Nuxt.js')" },
    ecommerce:      { type: ["string", "null"], description: "Ecommerce platform if detected (e.g. 'Shopify', 'WooCommerce')" },
    server:         { type: ["string", "null"], description: "Web server (e.g. 'Nginx', 'Apache')" },
    language:       { type: ["string", "null"], description: "Server-side language (e.g. 'PHP', 'Node.js')" },
    cdn:            { type: ["string", "null"], description: "CDN provider (e.g. 'Cloudflare', 'AWS CloudFront')" },
    hosting:        { type: ["string", "null"], description: "Hosting platform (e.g. 'Vercel', 'Netlify')" },
    analytics:      { type: "array", items: { type: "string" }, description: "All detected analytics tools" },
    marketing:      { type: "array", items: { type: "string" }, description: "All detected marketing/CRM tools" },
    email_provider: { type: ["string", "null"], description: "Email provider derived from MX records (e.g. 'Google Workspace', 'Microsoft 365')" },
    confidence:     { type: "string", enum: ["high", "medium", "low"], description: "Overall detection confidence" },
  },
  required: ["detected", "cms", "framework", "ecommerce", "server", "language", "cdn", "hosting", "analytics", "marketing", "email_provider", "confidence"],
};

const DNS_SCHEMA = {
  type: "object",
  description: "Full DNS record set with email stack classification",
  properties: {
    a_records:   { type: "array", items: { type: "string" }, description: "IPv4 addresses" },
    mx_records: {
      type: "array",
      description: "MX records with provider classification",
      items: {
        type: "object",
        properties: {
          exchange: { type: "string", description: "Mail exchanger hostname" },
          priority: { type: "number", description: "MX priority (lower = higher priority)" },
          provider: { type: ["string", "null"], description: "Classified provider (e.g. 'Google Workspace')" },
        },
        required: ["exchange", "priority", "provider"],
      },
    },
    ns_records:  { type: "array", items: { type: "string" }, description: "Nameserver records" },
    txt_records: { type: "array", items: { type: "string" }, description: "TXT records including SPF, DMARC, verification tokens" },
    caa_records: { type: "array", items: { type: "string" }, description: "CAA records specifying allowed certificate authorities" },
    spf:         { type: ["string", "null"], description: "Raw SPF record value if present" },
    dmarc:       { type: ["string", "null"], description: "Raw DMARC record value if present" },
    bimi:        { type: ["string", "null"], description: "Raw BIMI record value if present" },
    email_stack: {
      type: "object",
      description: "Classified email infrastructure",
      properties: {
        provider:       { type: ["string", "null"], description: "Email provider name" },
        has_spf:        { type: "boolean" },
        has_dmarc:      { type: "boolean" },
        spf_policy:     { type: ["string", "null"], enum: ["strict", "soft", "neutral", "none", null] },
        dmarc_policy:   { type: ["string", "null"], enum: ["reject", "quarantine", "none", null] },
      },
      required: ["provider", "has_spf", "has_dmarc", "spf_policy", "dmarc_policy"],
    },
    has_dnssec: { type: "boolean" },
    error:      { type: ["string", "null"] },
  },
  required: ["a_records", "mx_records", "ns_records", "txt_records", "caa_records", "spf", "dmarc", "bimi", "email_stack", "has_dnssec", "error"],
};

const SSL_SCHEMA = {
  type: "object",
  description: "TLS/SSL certificate details",
  properties: {
    valid:              { type: "boolean", description: "Whether the certificate is currently valid" },
    issuer:             { type: ["string", "null"], description: "Certificate issuer CN (e.g. 'R11' for Let's Encrypt)" },
    issuer_org:         { type: ["string", "null"], description: "Issuer organisation (e.g. 'Let\\'s Encrypt')" },
    subject:            { type: ["string", "null"], description: "Certificate subject CN" },
    valid_from:         { type: ["string", "null"], description: "Certificate validity start (ISO 8601)" },
    valid_to:           { type: ["string", "null"], description: "Certificate expiry date (ISO 8601)" },
    days_until_expiry:  { type: ["number", "null"], description: "Days until certificate expires (negative = already expired)" },
    san_domains:        { type: "array", items: { type: "string" }, description: "Subject Alternative Names — reveals sibling domains and subdomains on the same cert" },
    wildcard:           { type: "boolean", description: "Whether the cert covers a wildcard (*.domain.com)" },
    key_bits:           { type: ["number", "null"], description: "RSA key size in bits" },
    protocols_supported:{ type: "array", items: { type: "string" } },
    error:              { type: ["string", "null"] },
  },
  required: ["valid", "issuer", "issuer_org", "subject", "valid_from", "valid_to", "days_until_expiry", "san_domains", "wildcard", "key_bits", "protocols_supported", "error"],
};

const OWNERSHIP_SCHEMA = {
  type: "object",
  description: "WHOIS/RDAP domain ownership data",
  properties: {
    registrar:        { type: ["string", "null"], description: "Domain registrar name" },
    registered_at:    { type: ["string", "null"], description: "Registration date (ISO 8601)" },
    expires_at:       { type: ["string", "null"], description: "Expiry date (ISO 8601)" },
    updated_at:       { type: ["string", "null"], description: "Last updated date (ISO 8601)" },
    status:           { type: "array", items: { type: "string" }, description: "RDAP status codes (e.g. 'clientTransferProhibited')" },
    privacy_protected:{ type: "boolean", description: "Whether registrant info is hidden by a privacy service" },
    registrant_org:   { type: ["string", "null"], description: "Registrant organisation name (null if privacy-protected)" },
    name_servers:     { type: "array", items: { type: "string" }, description: "Authoritative nameservers" },
    error:            { type: ["string", "null"] },
  },
  required: ["registrar", "registered_at", "expires_at", "updated_at", "status", "privacy_protected", "registrant_org", "name_servers", "error"],
};

const SUBDOMAIN_SCHEMA = {
  type: "object",
  description: "Subdomains discovered via Certificate Transparency logs (crt.sh)",
  properties: {
    subdomains: {
      type: "array",
      description: "Discovered subdomains with first-seen dates from CT logs",
      items: {
        type: "object",
        properties: {
          subdomain:  { type: "string", description: "Full subdomain (e.g. 'api.stripe.com')" },
          first_seen: { type: ["string", "null"], description: "First seen in CT logs (ISO 8601)" },
          issuer:     { type: ["string", "null"], description: "Certificate issuer org" },
        },
        required: ["subdomain", "first_seen", "issuer"],
      },
    },
    total_found:          { type: "number", description: "Total unique subdomains discovered" },
    first_seen_earliest:  { type: ["string", "null"], description: "Earliest subdomain first-seen date across all results" },
    error:                { type: ["string", "null"] },
  },
  required: ["subdomains", "total_found", "first_seen_earliest", "error"],
};

const WEB_SCHEMA = {
  type: "object",
  description: "HTTP/web signals: meta, social profiles, mobile apps, security headers, well-known paths",
  properties: {
    live:         { type: "boolean" },
    status_code:  { type: ["number", "null"] },
    title:        { type: ["string", "null"] },
    description:  { type: ["string", "null"] },
    redirects_to: { type: ["string", "null"], description: "Final URL if the domain redirects away to a different domain" },
    social_profiles: {
      type: "array",
      items: {
        type: "object",
        properties: {
          platform: { type: "string" },
          url:      { type: "string" },
          handle:   { type: ["string", "null"] },
        },
        required: ["platform", "url", "handle"],
      },
    },
    mobile_apps: {
      type: "array",
      items: {
        type: "object",
        properties: {
          platform: { type: "string", enum: ["ios", "android"] },
          app_id:   { type: "string" },
          url:      { type: "string" },
        },
        required: ["platform", "app_id", "url"],
      },
    },
    security: {
      type: "object",
      properties: {
        https:                    { type: "boolean" },
        hsts:                     { type: "boolean" },
        hsts_max_age:             { type: ["number", "null"] },
        hsts_includes_subdomains: { type: "boolean" },
        csp:                      { type: "boolean" },
        x_frame_options:          { type: ["string", "null"] },
        x_content_type_options:   { type: "boolean" },
        referrer_policy:          { type: ["string", "null"] },
        permissions_policy:       { type: "boolean" },
      },
      required: ["https", "hsts", "hsts_max_age", "hsts_includes_subdomains", "csp", "x_frame_options", "x_content_type_options", "referrer_policy", "permissions_policy"],
    },
    well_known: {
      type: "object",
      properties: {
        has_security_txt: { type: "boolean" },
        has_robots_txt:   { type: "boolean" },
        has_sitemap:      { type: "boolean" },
        has_ads_txt:      { type: "boolean" },
      },
      required: ["has_security_txt", "has_robots_txt", "has_sitemap", "has_ads_txt"],
    },
    error: { type: ["string", "null"] },
  },
  required: ["live", "status_code", "title", "description", "redirects_to", "social_profiles", "mobile_apps", "security", "well_known", "error"],
};

// ── Full intelligence schema ───────────────────────────────────────────────

const DOMAIN_INTEL_SCHEMA = {
  type: "object",
  description: "Full domain intelligence object — tech stack, DNS, SSL, WHOIS, subdomains, social, security",
  properties: {
    domain:          { type: "string", description: "Normalised root domain (e.g. 'stripe.com')" },
    tech_stack:      TECH_STACK_SCHEMA,
    dns:             DNS_SCHEMA,
    ssl:             SSL_SCHEMA,
    ownership:       OWNERSHIP_SCHEMA,
    subdomains:      SUBDOMAIN_SCHEMA,
    web:             WEB_SCHEMA,
    data_freshness:  { type: "string", format: "date-time" },
    latency_ms:      { type: "number", description: "Total fetch latency in milliseconds" },
  },
  required: ["domain", "tech_stack", "dns", "ssl", "ownership", "subdomains", "web", "data_freshness", "latency_ms"],
};

// ── Tool definitions ───────────────────────────────────────────────────────

export const TOOLS = [
  {
    name: "get_domain_intelligence",
    description: [
      "Full domain intelligence object for any domain in one call.",
      "Returns: tech stack fingerprint (CMS, framework, CDN, analytics, ecommerce, marketing tools),",
      "full DNS records with email provider classification (Google Workspace, Microsoft 365, etc.),",
      "SSL certificate chain with SAN exposure revealing sibling domains,",
      "WHOIS/RDAP ownership data (registrar, registration date, privacy protection status),",
      "subdomain enumeration from certificate transparency logs (crt.sh),",
      "self-declared social profiles and mobile app links,",
      "HTTP security posture (HSTS, CSP, X-Frame-Options, etc.),",
      "and well-known path signals (security.txt, ads.txt, robots.txt, sitemap).",
      "Replaces BuiltWith Pro ($295/mo), Wappalyzer Teams ($250/mo), and DomainTools Iris ($1,500+/yr).",
      "Sub-200ms for cached domains. Cold: 8–15s (parallel async fetch).",
    ].join(" "),
    examples: [
      { input: { domain: "stripe.com" } },
      { input: { domain: "shopify.com" } },
    ],
    _meta: {
      surface: "both",
      queryEligible: true,
      latencyClass: "fast",
      pricing: { executeUsd: "0.0015" },
      rateLimit: {
        maxRequestsPerMinute: 30,
        cooldownMs: 2000,
        maxConcurrency: 5,
        notes: "Cold fetches hit 5 upstream sources in parallel. Respect rate limits on crt.sh and RDAP.",
      },
    },
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain to analyse. Accepts any format: 'stripe.com', 'www.stripe.com', 'https://stripe.com/products'",
          default: "stripe.com",
          examples: ["stripe.com", "vercel.com", "notion.so", "linear.app", "supabase.com"],
        },
      },
      required: ["domain"],
    },
    outputSchema: DOMAIN_INTEL_SCHEMA,
  },

  {
    name: "get_tech_stack",
    description: [
      "Tech stack fingerprint for a domain — fast single-signal lookup for sales and BD research.",
      "Returns: CMS, framework, ecommerce platform, CDN, hosting, server, language, analytics tools,",
      "marketing tools, and email provider (from DNS MX records).",
      "Uses the same cached data as get_domain_intelligence — no extra network cost if the domain was recently fetched.",
      "Ideal for prospect research: 'What stack does this company run?' in one call.",
    ].join(" "),
    examples: [
      { input: { domain: "notion.so" } },
      { input: { domain: "linear.app" } },
    ],
    _meta: {
      surface: "both",
      queryEligible: true,
      latencyClass: "fast",
      pricing: { executeUsd: "0.0010" },
      rateLimit: {
        maxRequestsPerMinute: 60,
        cooldownMs: 1000,
        maxConcurrency: 10,
        notes: "Served from cache if domain was recently fetched.",
      },
    },
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain to fingerprint",
          default: "notion.so",
          examples: ["notion.so", "linear.app", "loom.com", "figma.com", "retool.com"],
        },
      },
      required: ["domain"],
    },
    outputSchema: {
      type: "object",
      properties: {
        domain:     { type: "string" },
        tech_stack: TECH_STACK_SCHEMA,
        data_freshness: { type: "string", format: "date-time" },
      },
      required: ["domain", "tech_stack", "data_freshness"],
    },
  },

  {
    name: "get_dns_records",
    description: [
      "Full DNS record set for a domain with email stack classification.",
      "Returns: A records, MX records with provider classification (Google Workspace, Microsoft 365, Proton, etc.),",
      "NS records, TXT records, CAA records, parsed SPF and DMARC with policy classification,",
      "and a normalised email_stack object.",
      "Useful for: sales qualification (do they use GSuite or Office365?),",
      "security research (SPF/DMARC posture), and email deliverability audits.",
    ].join(" "),
    examples: [
      { input: { domain: "github.com" } },
      { input: { domain: "cloudflare.com" } },
    ],
    _meta: {
      surface: "both",
      queryEligible: true,
      latencyClass: "fast",
      pricing: { executeUsd: "0.0010" },
      rateLimit: {
        maxRequestsPerMinute: 60,
        cooldownMs: 500,
        maxConcurrency: 10,
        notes: "Pure DNS lookups via Node built-in. Very low latency.",
      },
    },
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain to look up DNS records for",
          default: "github.com",
          examples: ["github.com", "cloudflare.com", "vercel.com", "anthropic.com"],
        },
      },
      required: ["domain"],
    },
    outputSchema: {
      type: "object",
      properties: {
        domain:         { type: "string" },
        dns:            DNS_SCHEMA,
        data_freshness: { type: "string", format: "date-time" },
      },
      required: ["domain", "dns", "data_freshness"],
    },
  },

  {
    name: "get_subdomains",
    description: [
      "Subdomain enumeration for a domain via Certificate Transparency logs (crt.sh).",
      "Returns all subdomains discovered from issued TLS certificates — api., app., staging., admin., etc.",
      "Reveals product architecture, internal tooling exposure, and acquisition targets.",
      "Useful for: competitive intelligence, security research, due diligence, and attack surface mapping.",
      "Data is sourced from public CT logs — no scraping, no auth required.",
      "Note: large domains (e.g. google.com) may have thousands of subdomains; results are deduplicated.",
    ].join(" "),
    examples: [
      { input: { domain: "stripe.com" } },
      { input: { domain: "vercel.com" } },
    ],
    _meta: {
      surface: "both",
      queryEligible: true,
      latencyClass: "fast",
      pricing: { executeUsd: "0.0010" },
      rateLimit: {
        maxRequestsPerMinute: 20,
        cooldownMs: 3000,
        maxConcurrency: 3,
        notes: "crt.sh can be slow for large domains. Cached for 24h after first fetch.",
      },
    },
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Root domain to enumerate subdomains for",
          default: "stripe.com",
          examples: ["stripe.com", "vercel.com", "linear.app", "supabase.com"],
        },
      },
      required: ["domain"],
    },
    outputSchema: {
      type: "object",
      properties: {
        domain:         { type: "string" },
        subdomains:     SUBDOMAIN_SCHEMA,
        data_freshness: { type: "string", format: "date-time" },
      },
      required: ["domain", "subdomains", "data_freshness"],
    },
  },
];
