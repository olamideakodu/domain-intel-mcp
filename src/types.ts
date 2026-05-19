// ── Top-level output ──────────────────────────────────────────────────────

export interface DomainIntelligence {
  domain: string;
  tech_stack: TechStackResult;
  dns: DnsResult;
  ssl: SslResult;
  ownership: OwnershipResult;
  subdomains: SubdomainResult;
  web: WebResult;
  data_freshness: string; // ISO 8601
  latency_ms: number;
}

// ── Tech stack ────────────────────────────────────────────────────────────

export interface TechStackResult {
  detected: DetectedTechnology[];
  cms: string | null;
  framework: string | null;
  ecommerce: string | null;
  server: string | null;
  language: string | null;
  cdn: string | null;
  hosting: string | null;
  analytics: string[];
  marketing: string[];
  email_provider: string | null; // derived from DNS MX
  confidence: "high" | "medium" | "low";
}

export interface DetectedTechnology {
  name: string;
  category: string;
  confidence: number; // 0–100
  evidence: string;   // what triggered detection (e.g. "header:server", "html:wp-content")
}

// ── DNS ───────────────────────────────────────────────────────────────────

export interface DnsResult {
  a_records: string[];
  mx_records: MxRecord[];
  ns_records: string[];
  txt_records: string[];
  caa_records: string[];
  spf: string | null;
  dmarc: string | null;
  bimi: string | null;
  email_stack: EmailStack;
  has_dnssec: boolean;
  error: string | null;
}

export interface MxRecord {
  exchange: string;
  priority: number;
  provider: string | null; // "Google Workspace", "Microsoft 365", etc.
}

export interface EmailStack {
  provider: string | null;
  has_spf: boolean;
  has_dmarc: boolean;
  spf_policy: "strict" | "soft" | "neutral" | "none" | null;
  dmarc_policy: "reject" | "quarantine" | "none" | null;
}

// ── SSL ───────────────────────────────────────────────────────────────────

export interface SslResult {
  valid: boolean;
  issuer: string | null;
  issuer_org: string | null;
  subject: string | null;
  valid_from: string | null;
  valid_to: string | null;
  days_until_expiry: number | null;
  san_domains: string[];  // Subject Alternative Names — reveals sibling domains
  wildcard: boolean;
  key_bits: number | null;
  protocols_supported: string[];
  error: string | null;
}

// ── WHOIS / RDAP ──────────────────────────────────────────────────────────

export interface OwnershipResult {
  registrar: string | null;
  registered_at: string | null;
  expires_at: string | null;
  updated_at: string | null;
  status: string[];
  privacy_protected: boolean;
  registrant_org: string | null;
  name_servers: string[];
  error: string | null;
}

// ── Subdomains (CT logs) ──────────────────────────────────────────────────

export interface SubdomainResult {
  subdomains: SubdomainEntry[];
  total_found: number;
  first_seen_earliest: string | null;
  error: string | null;
}

export interface SubdomainEntry {
  subdomain: string;
  first_seen: string | null;
  issuer: string | null;
}

// ── Web / HTTP signals ────────────────────────────────────────────────────

export interface WebResult {
  live: boolean;
  status_code: number | null;
  title: string | null;
  description: string | null;
  redirects_to: string | null;
  social_profiles: SocialProfile[];
  mobile_apps: MobileApp[];
  security: HttpSecurity;
  well_known: WellKnownSignals;
  error: string | null;
}

export interface SocialProfile {
  platform: string;
  url: string;
  handle: string | null;
}

export interface MobileApp {
  platform: "ios" | "android";
  app_id: string;
  url: string;
}

export interface HttpSecurity {
  https: boolean;
  hsts: boolean;
  hsts_max_age: number | null;
  hsts_includes_subdomains: boolean;
  csp: boolean;
  x_frame_options: string | null;
  x_content_type_options: boolean;
  referrer_policy: string | null;
  permissions_policy: boolean;
}

export interface WellKnownSignals {
  has_security_txt: boolean;
  has_robots_txt: boolean;
  has_sitemap: boolean;
  has_ads_txt: boolean;
}

// ── Internal scrape result ────────────────────────────────────────────────

export interface ScrapeResult {
  web: WebResult;
  tech_stack: TechStackResult;
}

// ── Fingerprint definitions ───────────────────────────────────────────────

export interface TechSignature {
  name: string;
  category: string;
  weight: number; // base confidence 0–100
  detect: {
    headers?: Record<string, RegExp>;  // header name (lowercase) → pattern
    body?: RegExp[];                   // patterns against full HTML
    scripts?: RegExp[];                // patterns against script[src] attributes
    cookies?: RegExp[];                // cookie name patterns
    meta_generator?: RegExp;           // pattern for <meta name="generator">
  };
}
