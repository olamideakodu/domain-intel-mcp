import type { DomainIntelligence } from "./types.js";
import { Cache } from "./cache.js";
import { resolveDns } from "./dns.js";
import { fetchSsl, fetchSubdomains } from "./ssl.js";
import { fetchOwnership } from "./rdap.js";
import { scrapeWeb } from "./scraper.js";

const TTL_MS = 24 * 60 * 60 * 1000; // 24 hours — domain data changes slowly

const cache = new Cache<DomainIntelligence>();

// ── Domain normalisation ───────────────────────────────────────────────────

export function normalizeDomain(input: string): string {
  let raw = input.trim().toLowerCase();
  // Strip protocol prefix if present
  raw = raw.replace(/^https?:\/\//i, "");
  // Strip path, query, fragment
  raw = raw.split("/")[0].split("?")[0].split("#")[0];
  // Strip www.
  raw = raw.replace(/^www\./, "");
  // Strip port
  raw = raw.split(":")[0];
  return raw;
}

// ── Main fetch ─────────────────────────────────────────────────────────────

export async function getDomainIntelligence(rawInput: string): Promise<DomainIntelligence> {
  const domain = normalizeDomain(rawInput);
  if (!domain || domain.length < 3) throw new Error(`Invalid domain: "${rawInput}"`);

  const cached = cache.get(domain);
  if (cached) return cached;

  const t0 = Date.now();

  // Fire all 5 fetch operations in parallel
  const [dnsResult, sslResult, subdomainResult, ownershipResult, scrapeResult] =
    await Promise.all([
      resolveDns(domain).catch(() => ({
        a_records: [], mx_records: [], ns_records: [], txt_records: [],
        caa_records: [], spf: null, dmarc: null, bimi: null,
        email_stack: { provider: null, has_spf: false, has_dmarc: false, spf_policy: null, dmarc_policy: null },
        has_dnssec: false, error: "DNS resolution failed",
      })),
      fetchSsl(domain).catch(() => ({
        valid: false, issuer: null, issuer_org: null, subject: null,
        valid_from: null, valid_to: null, days_until_expiry: null,
        san_domains: [], wildcard: false, key_bits: null,
        protocols_supported: [], error: "SSL fetch failed",
      })),
      fetchSubdomains(domain).catch(() => ({
        subdomains: [], total_found: 0, first_seen_earliest: null, error: "crt.sh lookup failed",
      })),
      fetchOwnership(domain).catch(() => ({
        registrar: null, registered_at: null, expires_at: null, updated_at: null,
        status: [], privacy_protected: false, registrant_org: null, name_servers: [],
        error: "RDAP lookup failed",
      })),
      // Pass email provider from DNS to scraper to merge into tech_stack
      // DNS runs first then scraper picks it up — but since they're parallel we pass null
      // and the fetcher merges afterwards
      scrapeWeb(domain, null).catch(() => ({
        web: {
          live: false, status_code: null, title: null, description: null,
          redirects_to: null, social_profiles: [], mobile_apps: [],
          security: {
            https: false, hsts: false, hsts_max_age: null, hsts_includes_subdomains: false,
            csp: false, x_frame_options: null, x_content_type_options: false,
            referrer_policy: null, permissions_policy: false,
          },
          well_known: {
            has_security_txt: false, has_robots_txt: false,
            has_sitemap: false, has_ads_txt: false,
          },
          error: "Web scrape failed",
        },
        tech_stack: {
          detected: [], cms: null, framework: null, ecommerce: null,
          server: null, language: null, cdn: null, hosting: null,
          analytics: [], marketing: [], email_provider: null, confidence: "low" as const,
        },
      })),
    ]);

  // Merge DNS email provider into tech_stack (DNS and scraper ran in parallel)
  const emailProvider = dnsResult.email_stack.provider;
  if (emailProvider) {
    scrapeResult.tech_stack.email_provider = emailProvider;
  }

  const intel: DomainIntelligence = {
    domain,
    tech_stack:  scrapeResult.tech_stack,
    dns:         dnsResult,
    ssl:         sslResult,
    ownership:   ownershipResult,
    subdomains:  subdomainResult,
    web:         scrapeResult.web,
    data_freshness: new Date().toISOString(),
    latency_ms:  Date.now() - t0,
  };

  cache.set(domain, intel, TTL_MS);
  return intel;
}

// ── Cache stats for health endpoint ───────────────────────────────────────

export function getCacheSize(): number {
  return cache.size();
}
