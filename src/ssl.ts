import * as tls from "node:tls";
import type { SslResult, SubdomainResult, SubdomainEntry } from "./types.js";

// ── TLS certificate fetch ──────────────────────────────────────────────────

interface RawCert {
  subject?: { CN?: string };
  issuer?: { O?: string; CN?: string };
  valid_from?: string;
  valid_to?: string;
  subjectaltname?: string;
  bits?: number;
}

async function fetchTlsCert(hostname: string): Promise<RawCert | null> {
  return new Promise((resolve) => {
    let settled = false;

    const settle = (val: RawCert | null) => {
      if (settled) return;
      settled = true;
      try { socket.destroy(); } catch { /* ignore */ }
      resolve(val);
    };

    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false, // capture cert even if expired/self-signed
        timeout: 8000,
      },
      () => {
        const cert = socket.getPeerCertificate(false) as RawCert;
        settle(cert && Object.keys(cert).length > 0 ? cert : null);
      }
    );

    socket.on("error",   () => settle(null));
    socket.on("timeout", () => settle(null));
    // Guard: resolve after 10s regardless
    setTimeout(() => settle(null), 12_000);
  });
}

function parseSans(subjectaltname: string | undefined): string[] {
  if (!subjectaltname) return [];
  return subjectaltname
    .split(",")
    .map(s => s.trim())
    .filter(s => s.startsWith("DNS:"))
    .map(s => s.slice(4).trim())
    .filter(Boolean);
}

function parseCertDate(raw: string | undefined): string | null {
  if (!raw) return null;
  try {
    return new Date(raw).toISOString();
  } catch {
    return raw;
  }
}

function daysUntilExpiry(validTo: string | null): number | null {
  if (!validTo) return null;
  const diff = new Date(validTo).getTime() - Date.now();
  return Math.round(diff / (1000 * 60 * 60 * 24));
}

// ── Public: fetchSsl ───────────────────────────────────────────────────────

export async function fetchSsl(domain: string): Promise<SslResult> {
  try {
    const cert = await fetchTlsCert(domain);

    if (!cert) {
      return {
        valid: false,
        issuer: null, issuer_org: null, subject: null,
        valid_from: null, valid_to: null, days_until_expiry: null,
        san_domains: [], wildcard: false, key_bits: null,
        protocols_supported: [],
        error: "TLS connection failed or no certificate returned",
      };
    }

    const sans     = parseSans(cert.subjectaltname);
    const validTo  = parseCertDate(cert.valid_to);
    const days     = daysUntilExpiry(validTo);
    const isValid  = days !== null && days > 0;

    return {
      valid:           isValid,
      issuer:          cert.issuer?.CN ?? cert.issuer?.O ?? null,
      issuer_org:      cert.issuer?.O ?? null,
      subject:         cert.subject?.CN ?? null,
      valid_from:      parseCertDate(cert.valid_from),
      valid_to:        validTo,
      days_until_expiry: days,
      san_domains:     sans,
      wildcard:        sans.some(s => s.startsWith("*.")),
      key_bits:        cert.bits ?? null,
      protocols_supported: [], // TLS version negotiation handled by OS; skip version enumeration
      error: null,
    };
  } catch (err) {
    return {
      valid: false,
      issuer: null, issuer_org: null, subject: null,
      valid_from: null, valid_to: null, days_until_expiry: null,
      san_domains: [], wildcard: false, key_bits: null,
      protocols_supported: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// ── Certificate Transparency — dual source race ───────────────────────────
// Runs crt.sh and CertSpotter in parallel. Promise.any resolves with the
// first successful result — if crt.sh 502s or times out, CertSpotter saves
// the response (and vice versa). Both sources failing produces an AggregateError
// with both messages surfaced in the output error field.

interface CrtShEntry {
  logged_at:   string;
  not_before:  string;
  not_after:   string;
  name_value:  string;  // newline-separated SANs
  issuer_name: string;
}

interface CertSpotterIssuance {
  id:         string;
  dns_names:  string[];  // clean array — no newline parsing needed
  not_before: string;
  not_after:  string;
  revoked:    boolean;
  issuer:     { name: string };
}

export interface FetchSubdomainsOptions {
  timeoutMs?: number; // default 8000 for getDomainIntelligence, 20000 for get_subdomains
}

// ── Shared helpers ─────────────────────────────────────────────────────────

function extractIssuerOrg(issuerStr: string): string | null {
  const m = issuerStr.match(/O=([^,]+)/);
  if (!m) return null;
  // Strip surrounding quotes — some CAs (DigiCert) quote their O= value in the DN
  return m[1].trim().replace(/^"(.*)"$/, "$1").trim();
}

function buildResult(entries: SubdomainEntry[], domain: string): SubdomainResult {
  const deduped = new Map<string, SubdomainEntry>();
  for (const e of entries) {
    if (!deduped.has(e.subdomain)) deduped.set(e.subdomain, e);
  }

  const subdomains = [...deduped.values()]
    .filter(e => e.subdomain !== domain)
    .sort((a, b) => a.subdomain.localeCompare(b.subdomain));

  let earliest: string | null = null;
  for (const e of subdomains) {
    if (!e.first_seen) continue;
    if (!earliest || e.first_seen < earliest) earliest = e.first_seen;
  }

  return { subdomains, total_found: subdomains.length, first_seen_earliest: earliest, error: null };
}

// ── Source 1: crt.sh ──────────────────────────────────────────────────────

async function fetchFromCrtSh(domain: string, timeoutMs: number): Promise<SubdomainEntry[]> {
  let lastError = "";

  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(`https://crt.sh/?q=%.${domain}&output=json`, {
        signal: AbortSignal.timeout(timeoutMs),
        headers: { Accept: "application/json" },
      });

      if (res.status >= 500) {
        lastError = `crt.sh HTTP ${res.status}`;
        if (attempt < 3) { await new Promise(r => setTimeout(r, attempt * 800)); continue; }
        throw new Error(lastError);
      }
      if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);

      const data = await res.json() as CrtShEntry[];
      const seen = new Map<string, SubdomainEntry>();

      for (const entry of data) {
        const names = entry.name_value.split("\n")
          .map(n => n.trim().toLowerCase())
          .filter(n => n.endsWith(`.${domain}`) || n === domain);

        for (const name of names) {
          if (!seen.has(name)) {
            seen.set(name, {
              subdomain:  name,
              first_seen: entry.logged_at ?? entry.not_before ?? null,
              issuer:     extractIssuerOrg(entry.issuer_name),
            });
          } else {
            const existing = seen.get(name)!;
            const existingTs = existing.first_seen ? new Date(existing.first_seen).getTime() : Infinity;
            const newTs = entry.logged_at ? new Date(entry.logged_at).getTime() : Infinity;
            if (newTs < existingTs) existing.first_seen = entry.logged_at;
          }
        }
      }

      return [...seen.values()];

    } catch (err) {
      const isTimeout = err instanceof Error &&
        (err.name === "AbortError" || err.name === "TimeoutError");
      if (isTimeout) throw new Error(`crt.sh: timeout after ${timeoutMs}ms`);
      lastError = err instanceof Error ? err.message : String(err);
      if (attempt < 3) { await new Promise(r => setTimeout(r, attempt * 800)); continue; }
      throw new Error(lastError);
    }
  }

  throw new Error(lastError || "crt.sh: unknown error");
}

// ── Source 2: CertSpotter (SSLMate) ───────────────────────────────────────
// Free tier works without an API key (subject to rate limits).
// Set CERTSPOTTER_API_KEY env var for higher limits (free account at sslmate.com).

async function fetchFromCertSpotter(domain: string, timeoutMs: number): Promise<SubdomainEntry[]> {
  const apiKey = process.env.CERTSPOTTER_API_KEY;
  const headers: Record<string, string> = { Accept: "application/json" };
  if (apiKey) headers["Authorization"] = `Bearer ${apiKey}`;

  // expand=dns_names returns actual names (not SHA256 hashes)
  // expand=issuer returns issuer details (not included by default)
  const url = `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names&expand=issuer`;

  const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), headers });

  if (res.status === 429) throw new Error("CertSpotter: rate limited — set CERTSPOTTER_API_KEY for higher limits");
  if (!res.ok) throw new Error(`CertSpotter: HTTP ${res.status}`);

  const data = await res.json() as CertSpotterIssuance[];
  const seen = new Map<string, SubdomainEntry>();

  for (const cert of data) {
    if (!Array.isArray(cert.dns_names)) continue; // guard against unexpected shape
    for (const name of cert.dns_names) {
      const normalized = name.toLowerCase().trim();
      if (!normalized.endsWith(`.${domain}`) && normalized !== domain) continue;
      if (!seen.has(normalized)) {
        seen.set(normalized, {
          subdomain:  normalized,
          first_seen: cert.not_before ?? null,
          issuer:     cert.issuer?.name ? extractIssuerOrg(cert.issuer.name) : null,
        });
      }
    }
  }

  return [...seen.values()];
}

// ── Public: fetchSubdomains ────────────────────────────────────────────────

export async function fetchSubdomains(domain: string, opts: FetchSubdomainsOptions = {}): Promise<SubdomainResult> {
  const timeoutMs = opts.timeoutMs ?? 8_000;

  try {
    // Race both CT log sources. Promise.any resolves with the first success.
    // One source being down or timing out does not fail the whole request.
    const entries = await Promise.any([
      fetchFromCrtSh(domain, timeoutMs),
      fetchFromCertSpotter(domain, timeoutMs),
    ]);

    return buildResult(entries, domain);

  } catch (err) {
    // AggregateError: both sources failed
    let errorMsg: string;
    if (err instanceof AggregateError) {
      const msgs = (err.errors as Error[]).map(e => e.message ?? String(e));
      errorMsg = `All CT sources failed — [${msgs.join("] [")}]`;
    } else {
      errorMsg = err instanceof Error ? err.message : String(err);
    }
    return { subdomains: [], total_found: 0, first_seen_earliest: null, error: errorMsg };
  }
}

