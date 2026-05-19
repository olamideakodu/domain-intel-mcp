import { parse as parseHtml } from "node-html-parser";
import type {
  ScrapeResult, WebResult, TechStackResult, HttpSecurity,
  WellKnownSignals, SocialProfile, MobileApp, DetectedTechnology,
} from "./types.js";
import { SIGNATURES, getCategoryField } from "./fingerprints.js";

// ── Fetch helpers ─────────────────────────────────────────────────────────

async function fetchWithFollowRedirect(
  url: string,
  maxRedirects = 4
): Promise<{ status: number; headers: Headers; body: string; finalUrl: string } | null> {
  let currentUrl = url;
  for (let i = 0; i <= maxRedirects; i++) {
    try {
      const res = await fetch(currentUrl, {
        signal: AbortSignal.timeout(12_000),
        redirect: "manual",
        headers: {
          "User-Agent":
            "Mozilla/5.0 (compatible; DomainIntel/1.0; +https://ctxprotocol.com)",
          Accept: "text/html,application/xhtml+xml,*/*",
          "Accept-Language": "en-US,en;q=0.9",
        },
      });

      if (res.status >= 300 && res.status < 400) {
        const loc = res.headers.get("location");
        if (!loc) break;
        // Handle relative redirects
        currentUrl = loc.startsWith("http") ? loc : new URL(loc, currentUrl).href;
        continue;
      }

      const body = await res.text();
      return { status: res.status, headers: res.headers, body, finalUrl: currentUrl };
    } catch {
      return null;
    }
  }
  return null;
}

async function headExists(url: string): Promise<boolean> {
  try {
    const res = await fetch(url, {
      method: "HEAD",
      signal: AbortSignal.timeout(5_000),
      headers: { "User-Agent": "Mozilla/5.0 (compatible; DomainIntel/1.0)" },
    });
    return res.status < 400;
  } catch {
    return false;
  }
}

// ── Tech stack detection ──────────────────────────────────────────────────

function detectTechStack(
  headers: Headers,
  html: string,
  cookies: string[],
): DetectedTechnology[] {
  const detected: DetectedTechnology[] = [];
  const seen = new Set<string>();

  // Extract script src values once for the scripts check
  const scriptSrcs: string[] = [];
  const scriptTagRe = /<script[^>]+src=["']([^"']+)["']/gi;
  let scriptMatch: RegExpExecArray | null;
  while ((scriptMatch = scriptTagRe.exec(html)) !== null) {
    scriptSrcs.push(scriptMatch[1]);
  }

  const addTech = (name: string, category: string, weight: number, evidence: string) => {
    if (seen.has(name)) return;
    seen.add(name);
    detected.push({ name, category, confidence: weight, evidence });
  };

  for (const sig of SIGNATURES) {
    // ── Header matching ─────────────────────────────────────────────────────
    if (sig.detect.headers) {
      for (const [headerName, pattern] of Object.entries(sig.detect.headers)) {
        const val = headers.get(headerName);
        if (val && pattern.test(val)) {
          addTech(sig.name, sig.category, sig.weight, `header:${headerName}=${val.slice(0, 80)}`);
          break;
        }
      }
    }

    // ── Script src matching (more precise than body for async-loaded scripts) ─
    if (sig.detect.scripts) {
      for (const pattern of sig.detect.scripts) {
        const hit = scriptSrcs.find(src => pattern.test(src));
        if (hit) {
          addTech(sig.name, sig.category, sig.weight, `script:${hit.slice(0, 80)}`);
          break;
        }
      }
    }

    // ── HTML body matching ──────────────────────────────────────────────────
    if (sig.detect.body) {
      for (const pattern of sig.detect.body) {
        const match = html.match(pattern);
        if (match) {
          // Show the actual matched text (up to 60 chars), not the regex
          const snippet = match[0].trim().slice(0, 60);
          addTech(sig.name, sig.category, sig.weight, `html:${snippet}`);
          break;
        }
      }
    }

    // ── Cookie matching ─────────────────────────────────────────────────────
    if (sig.detect.cookies) {
      for (const cookiePat of sig.detect.cookies) {
        if (cookies.some(c => cookiePat.test(c))) {
          addTech(sig.name, sig.category, sig.weight, "cookie");
          break;
        }
      }
    }

    // ── Meta generator ──────────────────────────────────────────────────────
    if (sig.detect.meta_generator) {
      const genMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i)
        ?? html.match(/<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator["']/i);
      if (genMatch && sig.detect.meta_generator.test(genMatch[1])) {
        addTech(sig.name, sig.category, sig.weight + 5, `meta:generator=${genMatch[1].slice(0, 60)}`);
      }
    }
  }

  return detected.sort((a, b) => b.confidence - a.confidence);
}

function buildTechSummary(
  detected: DetectedTechnology[],
  emailProvider: string | null,
): TechStackResult {
  const summary: Record<string, string> = {};
  const analytics: string[] = [];
  const marketing: string[] = [];

  for (const tech of detected) {
    const field = getCategoryField(tech.category);
    if (field && !summary[field]) {
      summary[field] = tech.name;
    } else if (tech.category === "Analytics") {
      analytics.push(tech.name);
    } else if (tech.category === "Marketing") {
      marketing.push(tech.name);
    }
  }

  const highConfidenceCount = detected.filter(t => t.confidence >= 85).length;
  const confidence =
    highConfidenceCount >= 3 ? "high" :
    highConfidenceCount >= 1 ? "medium" :
    "low";

  return {
    detected,
    cms:       summary["cms"]       ?? null,
    framework: summary["framework"] ?? null,
    ecommerce: summary["ecommerce"] ?? null,
    server:    summary["server"]    ?? null,
    language:  summary["language"]  ?? null,
    cdn:       summary["cdn"]       ?? null,
    hosting:   summary["hosting"]   ?? null,
    analytics,
    marketing,
    email_provider: emailProvider,
    confidence,
  };
}

// ── Social profile extraction ─────────────────────────────────────────────

const SOCIAL_PATTERNS: Array<{
  platform: string;
  urlPattern: RegExp;
  handleExtract: RegExp | null;
}> = [
  { platform: "Twitter / X",  urlPattern: /https?:\/\/(twitter\.com|x\.com)\/([A-Za-z0-9_]{1,50})/i, handleExtract: /(?:twitter\.com|x\.com)\/([A-Za-z0-9_]{1,50})/i },
  { platform: "LinkedIn",     urlPattern: /https?:\/\/(?:www\.)?linkedin\.com\/(company|in)\/([^/"?\s]+)/i, handleExtract: /linkedin\.com\/(?:company|in)\/([^/"?\s]+)/i },
  { platform: "GitHub",       urlPattern: /https?:\/\/github\.com\/([A-Za-z0-9_-]{1,100})/i, handleExtract: /github\.com\/([A-Za-z0-9_-]{1,100})/i },
  { platform: "Facebook",     urlPattern: /https?:\/\/(?:www\.)?facebook\.com\/([^/"?\s]+)/i, handleExtract: /facebook\.com\/([^/"?\s]+)/i },
  { platform: "Instagram",    urlPattern: /https?:\/\/(?:www\.)?instagram\.com\/([A-Za-z0-9_.]{1,50})/i, handleExtract: /instagram\.com\/([A-Za-z0-9_.]{1,50})/i },
  { platform: "YouTube",      urlPattern: /https?:\/\/(?:www\.)?youtube\.com\/(channel|@|c)\/([^/"?\s]+)/i, handleExtract: /youtube\.com\/(?:channel\/|@|c\/)([^/"?\s]+)/i },
  { platform: "TikTok",       urlPattern: /https?:\/\/(?:www\.)?tiktok\.com\/@([^/"?\s]+)/i, handleExtract: /tiktok\.com\/@([^/"?\s]+)/i },
  { platform: "Discord",      urlPattern: /https?:\/\/discord\.(?:gg|com\/invite)\/([^/"?\s]+)/i, handleExtract: /discord\.(?:gg|com\/invite)\/([^/"?\s]+)/i },
];

const SKIP_HANDLES = new Set([
  "home", "about", "login", "signup", "share", "sharer", "intent",
  "status", "search", "explore", "terms", "privacy", "legal",
]);

function extractSocialProfiles(html: string): SocialProfile[] {
  const profiles: SocialProfile[] = [];
  const seen = new Set<string>();

  for (const { platform, urlPattern, handleExtract } of SOCIAL_PATTERNS) {
    const matches = html.matchAll(new RegExp(urlPattern.source, "gi"));
    for (const match of matches) {
      const url = match[0].replace(/['">\s].*$/, "").split(/['">\s]/)[0];
      if (seen.has(url)) continue;

      const handleMatch = handleExtract ? url.match(handleExtract) : null;
      const handle = handleMatch ? handleMatch[1] : null;

      if (handle && SKIP_HANDLES.has(handle.toLowerCase())) continue;

      seen.add(url);
      profiles.push({ platform, url, handle });
      break; // one profile per platform
    }
  }
  return profiles;
}

// ── Mobile app link extraction ────────────────────────────────────────────

function extractMobileApps(html: string): MobileApp[] {
  const apps: MobileApp[] = [];

  // iOS App Store
  const iosMatch = html.match(/https?:\/\/apps\.apple\.com\/[a-z]{2}\/app\/[^/"?\s]+\/id(\d+)/i);
  if (iosMatch) {
    apps.push({ platform: "ios", app_id: iosMatch[1], url: iosMatch[0].split(/['">\s]/)[0] });
  }

  // Android Google Play
  const androidMatch = html.match(/https?:\/\/play\.google\.com\/store\/apps\/details\?id=([A-Za-z0-9_.]+)/i);
  if (androidMatch) {
    apps.push({ platform: "android", app_id: androidMatch[1], url: androidMatch[0].split(/['">\s]/)[0] });
  }

  return apps;
}

// ── Security headers ──────────────────────────────────────────────────────

function extractHttpSecurity(headers: Headers, isHttps: boolean): HttpSecurity {
  const hsts        = headers.get("strict-transport-security");
  const hstsMaxAge  = hsts ? (hsts.match(/max-age=(\d+)/)?.[1] ?? null) : null;

  return {
    https:                    isHttps,
    hsts:                     hsts !== null,
    hsts_max_age:             hstsMaxAge ? parseInt(hstsMaxAge, 10) : null,
    hsts_includes_subdomains: hsts ? /includeSubDomains/i.test(hsts) : false,
    csp:                      headers.has("content-security-policy"),
    x_frame_options:          headers.get("x-frame-options"),
    x_content_type_options:   headers.get("x-content-type-options")?.toLowerCase() === "nosniff",
    referrer_policy:          headers.get("referrer-policy"),
    permissions_policy:       headers.has("permissions-policy") || headers.has("feature-policy"),
  };
}

// ── Well-known paths ──────────────────────────────────────────────────────

async function checkWellKnown(baseUrl: string): Promise<WellKnownSignals> {
  const checks = await Promise.allSettled([
    headExists(`${baseUrl}/.well-known/security.txt`),
    headExists(`${baseUrl}/robots.txt`),
    headExists(`${baseUrl}/sitemap.xml`),
    headExists(`${baseUrl}/ads.txt`),
  ]);

  const val = (r: PromiseSettledResult<boolean>) =>
    r.status === "fulfilled" ? r.value : false;

  return {
    has_security_txt: val(checks[0]),
    has_robots_txt:   val(checks[1]),
    has_sitemap:      val(checks[2]),
    has_ads_txt:      val(checks[3]),
  };
}

// ── HTML meta extraction ──────────────────────────────────────────────────

function extractMeta(html: string): { title: string | null; description: string | null } {
  const titleMatch = html.match(/<title[^>]*>([^<]{1,300})<\/title>/i);
  const title = titleMatch ? titleMatch[1].trim() : null;

  const descMatch =
    html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']{1,300})["']/i) ??
    html.match(/<meta[^>]+content=["']([^"']{1,300})["'][^>]+name=["']description["']/i);
  const description = descMatch ? descMatch[1].trim() : null;

  return { title, description };
}

// ── Public API ─────────────────────────────────────────────────────────────

export async function scrapeWeb(
  domain: string,
  emailProvider: string | null, // from DNS
): Promise<ScrapeResult> {
  const baseUrl = `https://${domain}`;

  const fetchResult = await fetchWithFollowRedirect(baseUrl);

  if (!fetchResult) {
    // Try HTTP fallback
    const httpResult = await fetchWithFollowRedirect(`http://${domain}`);
    if (!httpResult) {
      const emptyTech = buildTechSummary([], emailProvider);
      return {
        web: {
          live: false, status_code: null, title: null, description: null,
          redirects_to: null, social_profiles: [], mobile_apps: [],
          security: {
            https: false, hsts: false, hsts_max_age: null,
            hsts_includes_subdomains: false, csp: false,
            x_frame_options: null, x_content_type_options: false,
            referrer_policy: null, permissions_policy: false,
          },
          well_known: {
            has_security_txt: false, has_robots_txt: false,
            has_sitemap: false, has_ads_txt: false,
          },
          error: "Domain unreachable over both HTTPS and HTTP",
        },
        tech_stack: emptyTech,
      };
    }
    // Use HTTP result, note downgrade
    return buildScrapeResult(httpResult, domain, emailProvider, false);
  }

  const isHttps = fetchResult.finalUrl.startsWith("https://");
  const redirectedAway = !fetchResult.finalUrl.includes(domain);

  return buildScrapeResult(fetchResult, domain, emailProvider, isHttps, redirectedAway);
}

async function buildScrapeResult(
  { status, headers, body, finalUrl }: { status: number; headers: Headers; body: string; finalUrl: string },
  domain: string,
  emailProvider: string | null,
  isHttps: boolean,
  redirectedAway = false,
): Promise<ScrapeResult> {
  const html = body;
  const { title, description } = extractMeta(html);

  // Cookie names from Set-Cookie headers
  const setCookie = headers.get("set-cookie") ?? "";
  const cookies   = setCookie.split(",").map(c => c.split("=")[0].trim());

  const detected  = detectTechStack(headers, html, cookies);
  const tech      = buildTechSummary(detected, emailProvider);
  const security  = extractHttpSecurity(headers, isHttps);
  const social    = extractSocialProfiles(html);
  const apps      = extractMobileApps(html);
  const wellKnown = await checkWellKnown(`https://${domain}`);

  return {
    web: {
      live:        status >= 200 && status < 400,
      status_code: status,
      title,
      description,
      redirects_to: redirectedAway ? finalUrl : null,
      social_profiles: social,
      mobile_apps:     apps,
      security,
      well_known: wellKnown,
      error: null,
    },
    tech_stack: tech,
  };
}
