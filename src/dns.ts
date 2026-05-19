import { promises as dns } from "dns";
import type { DnsResult, MxRecord, EmailStack } from "./types.js";
import { MX_PROVIDERS } from "./fingerprints.js";

// ── Node dns record shapes ────────────────────────────────────────────────

interface NodeMxRecord  { exchange: string; priority: number }
interface NodeCaaRecord { critical: number; issue?: string; issuewild?: string; iodef?: string }

// ── MX provider classification ─────────────────────────────────────────────

function classifyMxProvider(exchange: string): string | null {
  for (const { pattern, provider } of MX_PROVIDERS) {
    if (pattern.test(exchange)) return provider;
  }
  return null;
}

function parseMxRecords(raw: NodeMxRecord[]): MxRecord[] {
  return raw
    .sort((a, b) => a.priority - b.priority)
    .map(r => ({
      exchange: r.exchange,
      priority: r.priority,
      provider: classifyMxProvider(r.exchange),
    }));
}

// ── SPF / DMARC / BIMI extraction from TXT records ────────────────────────

function extractSpf(txts: string[][]): string | null {
  for (const parts of txts) {
    const joined = parts.join(" ");
    if (/^v=spf1/i.test(joined)) return joined;
  }
  return null;
}

function extractDmarc(txts: string[][]): string | null {
  for (const parts of txts) {
    const joined = parts.join(" ");
    if (/^v=DMARC1/i.test(joined)) return joined;
  }
  return null;
}

function extractBimi(txts: string[][]): string | null {
  for (const parts of txts) {
    const joined = parts.join(" ");
    if (/^v=BIMI1/i.test(joined)) return joined;
  }
  return null;
}

function flattenTxt(txts: string[][]): string[] {
  return txts.map(parts => parts.join(" "));
}

// ── SPF / DMARC policy parsing ─────────────────────────────────────────────

function parseSpfPolicy(spf: string | null): EmailStack["spf_policy"] {
  if (!spf) return null;
  if (/\-all/.test(spf)) return "strict";
  if (/~all/.test(spf))  return "soft";
  if (/\?all/.test(spf)) return "neutral";
  if (/\+all/.test(spf)) return "none";
  return null;
}

function parseDmarcPolicy(dmarc: string | null): EmailStack["dmarc_policy"] {
  if (!dmarc) return null;
  const m = dmarc.match(/p=(\w+)/i);
  if (!m) return null;
  const p = m[1].toLowerCase();
  if (p === "reject")     return "reject";
  if (p === "quarantine") return "quarantine";
  if (p === "none")       return "none";
  return null;
}

// ── Email stack inference ──────────────────────────────────────────────────

function buildEmailStack(
  mxRecords: MxRecord[],
  spf: string | null,
  dmarc: string | null
): EmailStack {
  // Provider: prefer MX-derived (more reliable), fall back to SPF include
  let provider = mxRecords[0]?.provider ?? null;

  if (!provider && spf) {
    if (/include:_spf\.google\.com/i.test(spf))              provider = "Google Workspace";
    else if (/include:spf\.protection\.outlook\.com/i.test(spf)) provider = "Microsoft 365";
    else if (/include:spf\.zoho\.com/i.test(spf))            provider = "Zoho Mail";
    else if (/include:sendgrid\.net/i.test(spf))             provider = "SendGrid";
    else if (/include:mailgun\.org/i.test(spf))              provider = "Mailgun";
    else if (/include:amazonses\.com/i.test(spf))            provider = "Amazon SES";
  }

  return {
    provider,
    has_spf:      spf !== null,
    has_dmarc:    dmarc !== null,
    spf_policy:   parseSpfPolicy(spf),
    dmarc_policy: parseDmarcPolicy(dmarc),
  };
}

// ── Safe DNS resolve helpers ───────────────────────────────────────────────

async function safeResolve<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

// ── Public API ─────────────────────────────────────────────────────────────

export async function resolveDns(domain: string): Promise<DnsResult> {
  try {
    const [
      a_raw,
      mx_raw,
      ns_raw,
      txt_raw,
      caa_raw,
    ] = await Promise.all([
      safeResolve(() => dns.resolve4(domain), [] as string[]),
      safeResolve(() => dns.resolveMx(domain), [] as NodeMxRecord[]),
      safeResolve(() => dns.resolveNs(domain), [] as string[]),
      safeResolve(() => dns.resolveTxt(domain), [] as string[][]),
      safeResolve(() => dns.resolveCaa(domain), [] as NodeCaaRecord[]),
    ]);

    // TXT lookups for _dmarc and _bimi subdomains
    const [dmarc_raw, bimi_raw] = await Promise.all([
      safeResolve(() => dns.resolveTxt(`_dmarc.${domain}`), [] as string[][]),
      safeResolve(() => dns.resolveTxt(`_bimi.${domain}`),  [] as string[][]),
    ]);

    const mxRecords = parseMxRecords(mx_raw);
    const allTxt    = [...txt_raw, ...dmarc_raw, ...bimi_raw];
    const spf       = extractSpf(txt_raw);
    const dmarc     = extractDmarc(dmarc_raw) ?? extractDmarc(txt_raw);
    const bimi      = extractBimi(bimi_raw) ?? extractBimi(txt_raw);

    return {
      a_records:  a_raw,
      mx_records: mxRecords,
      ns_records: ns_raw,
      txt_records: flattenTxt(allTxt).slice(0, 20), // cap at 20 to keep payload clean
      caa_records: caa_raw.map(c => {
        const type = c.issue !== undefined ? `issue "${c.issue}"` :
                     c.issuewild !== undefined ? `issuewild "${c.issuewild}"` :
                     c.iodef !== undefined ? `iodef "${c.iodef}"` : "";
        return `${c.critical} ${type}`;
      }),
      spf,
      dmarc,
      bimi,
      email_stack: buildEmailStack(mxRecords, spf, dmarc),
      has_dnssec: false, // DNSSEC detection requires resolvers that expose the AD flag; skip for now
      error: null,
    };
  } catch (err) {
    return {
      a_records: [], mx_records: [], ns_records: [], txt_records: [],
      caa_records: [], spf: null, dmarc: null, bimi: null,
      email_stack: { provider: null, has_spf: false, has_dmarc: false, spf_policy: null, dmarc_policy: null },
      has_dnssec: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
