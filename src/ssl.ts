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

// ── Certificate Transparency logs via crt.sh ──────────────────────────────

interface CrtShEntry {
  logged_at:   string;
  not_before:  string;
  not_after:   string;
  name_value:  string;
  issuer_name: string;
}

export async function fetchSubdomains(domain: string): Promise<SubdomainResult> {
  try {
    const url = `https://crt.sh/?q=%.${domain}&output=json`;
    const res = await fetch(url, {
      signal: AbortSignal.timeout(5_000),
      headers: { "Accept": "application/json" },
    });

    if (!res.ok) {
      return { subdomains: [], total_found: 0, first_seen_earliest: null, error: `crt.sh HTTP ${res.status}` };
    }

    const data = await res.json() as CrtShEntry[];

    // Deduplicate by subdomain name — keep the earliest logged_at for each
    const seen = new Map<string, SubdomainEntry>();

    for (const entry of data) {
      // name_value can contain multiple SANs separated by newline
      const names = entry.name_value
        .split("\n")
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
          // Update first_seen to earliest
          const existing = seen.get(name)!;
          const existingDate = existing.first_seen ? new Date(existing.first_seen).getTime() : Infinity;
          const newDate      = entry.logged_at ? new Date(entry.logged_at).getTime() : Infinity;
          if (newDate < existingDate) {
            existing.first_seen = entry.logged_at;
          }
        }
      }
    }

    const subdomains = [...seen.values()]
      .filter(e => e.subdomain !== domain) // exclude the root domain itself
      .sort((a, b) => a.subdomain.localeCompare(b.subdomain));

    // Find overall earliest first_seen
    let earliest: string | null = null;
    for (const e of subdomains) {
      if (!e.first_seen) continue;
      if (!earliest || e.first_seen < earliest) earliest = e.first_seen;
    }

    return {
      subdomains,
      total_found: subdomains.length,
      first_seen_earliest: earliest,
      error: null,
    };
  } catch (err) {
    return {
      subdomains: [],
      total_found: 0,
      first_seen_earliest: null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

// Extract "O=Let's Encrypt" from issuer string
function extractIssuerOrg(issuerName: string): string | null {
  const m = issuerName.match(/O=([^,]+)/);
  return m ? m[1].trim() : null;
}
