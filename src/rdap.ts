import type { OwnershipResult } from "./types.js";

// ── RDAP response types ────────────────────────────────────────────────────

interface RdapEvent {
  eventAction: string;
  eventDate: string;
}

interface RdapEntity {
  roles: string[];
  vcardArray?: unknown[];
  handle?: string;
  publicIds?: Array<{ type: string; identifier: string }>;
}

interface RdapNameserver {
  ldhName: string;
}

interface RdapResponse {
  ldhName?: string;
  status?: string[];
  events?: RdapEvent[];
  entities?: RdapEntity[];
  nameservers?: RdapNameserver[];
  handle?: string;
  secureDNS?: { delegationSigned: boolean };
}

// ── RDAP fetch ────────────────────────────────────────────────────────────

async function fetchRdap(domain: string): Promise<RdapResponse | null> {
  // rdap.org is the universal RDAP lookup service — routes to the correct
  // TLD registry automatically, free, no auth.
  const url = `https://rdap.org/domain/${domain}`;
  try {
    const res = await fetch(url, {
      signal: AbortSignal.timeout(10_000),
      headers: { Accept: "application/rdap+json" },
    });
    if (!res.ok) return null;
    return await res.json() as RdapResponse;
  } catch {
    return null;
  }
}

// ── Parsers ───────────────────────────────────────────────────────────────

function getEvent(events: RdapEvent[], action: string): string | null {
  const ev = events.find(e => e.eventAction.toLowerCase() === action);
  return ev ? ev.eventDate : null;
}

function getRegistrar(entities: RdapEntity[]): string | null {
  const registrar = entities.find(e => e.roles.includes("registrar"));
  if (!registrar) return null;

  // Try vcardArray for registrar name
  if (Array.isArray(registrar.vcardArray) && registrar.vcardArray.length > 1) {
    const vcard = registrar.vcardArray[1] as unknown[][];
    for (const entry of vcard) {
      if (Array.isArray(entry) && entry[0] === "fn") {
        return String(entry[3] ?? "");
      }
    }
  }
  return registrar.handle ?? null;
}

function getRegistrantOrg(entities: RdapEntity[]): string | null {
  const registrant = entities.find(e => e.roles.includes("registrant"));
  if (!registrant) return null;

  if (Array.isArray(registrant.vcardArray) && registrant.vcardArray.length > 1) {
    const vcard = registrant.vcardArray[1] as unknown[][];
    for (const entry of vcard) {
      if (Array.isArray(entry) && (entry[0] === "org" || entry[0] === "fn")) {
        const val = String(entry[3] ?? "");
        if (val) return val;
      }
    }
  }
  return null;
}

const PRIVACY_PATTERNS = [
  /domains by proxy/i,
  /whoisguard/i,
  /privacy protect/i,
  /contactprivacy/i,
  /withheld for privacy/i,
  /redacted for privacy/i,
  /identity protection/i,
  /data protected/i,
  /private registration/i,
  /gdpr masked/i,
];

function isPrivacyProtected(registrantOrg: string | null, entities: RdapEntity[]): boolean {
  if (registrantOrg && PRIVACY_PATTERNS.some(p => p.test(registrantOrg))) return true;

  // Check status flags
  for (const entity of entities) {
    if (Array.isArray(entity.vcardArray)) {
      const raw = JSON.stringify(entity.vcardArray);
      if (PRIVACY_PATTERNS.some(p => p.test(raw))) return true;
    }
  }
  return false;
}

// ── Public API ─────────────────────────────────────────────────────────────

export async function fetchOwnership(domain: string): Promise<OwnershipResult> {
  try {
    const data = await fetchRdap(domain);

    if (!data) {
      return {
        registrar: null, registered_at: null, expires_at: null, updated_at: null,
        status: [], privacy_protected: false, registrant_org: null, name_servers: [],
        error: "RDAP lookup returned no data",
      };
    }

    const events      = data.events ?? [];
    const entities    = data.entities ?? [];
    const nameservers = (data.nameservers ?? []).map(n => n.ldhName.toLowerCase());
    const registrantOrg = getRegistrantOrg(entities);

    return {
      registrar:       getRegistrar(entities),
      registered_at:   getEvent(events, "registration"),
      expires_at:      getEvent(events, "expiration"),
      updated_at:      getEvent(events, "last changed"),
      status:          data.status ?? [],
      privacy_protected: isPrivacyProtected(registrantOrg, entities),
      registrant_org:  registrantOrg,
      name_servers:    nameservers,
      error: null,
    };
  } catch (err) {
    return {
      registrar: null, registered_at: null, expires_at: null, updated_at: null,
      status: [], privacy_protected: false, registrant_org: null, name_servers: [],
      error: err instanceof Error ? err.message : String(err),
    };
  }
}
