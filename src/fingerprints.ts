import type { TechSignature } from "./types.js";

// ── MX → email provider classification ───────────────────────────────────

export const MX_PROVIDERS: Array<{ pattern: RegExp; provider: string }> = [
  { pattern: /google\.com|googlemail\.com/i,          provider: "Google Workspace" },
  { pattern: /outlook\.com|protection\.outlook\.com|microsoft\.com/i, provider: "Microsoft 365" },
  { pattern: /protonmail\.ch|proton\.me/i,            provider: "Proton Mail" },
  { pattern: /zoho\.com/i,                            provider: "Zoho Mail" },
  { pattern: /fastmail\.com|messagingengine\.com/i,   provider: "Fastmail" },
  { pattern: /mailgun\.org/i,                         provider: "Mailgun" },
  { pattern: /sendgrid\.net/i,                        provider: "SendGrid" },
  { pattern: /amazonses\.com/i,                       provider: "Amazon SES" },
  { pattern: /mimecast\.com/i,                        provider: "Mimecast" },
  { pattern: /pphosted\.com|proofpoint\.com/i,        provider: "Proofpoint" },
  { pattern: /barracudanetworks\.com/i,               provider: "Barracuda" },
  { pattern: /icloud\.com/i,                          provider: "Apple iCloud" },
  { pattern: /yandex\.net|yandex\.ru/i,               provider: "Yandex Mail" },
];

// ── Technology fingerprints ───────────────────────────────────────────────

export const SIGNATURES: TechSignature[] = [
  // ── Servers ──────────────────────────────────────────────────────────────
  {
    name: "Nginx",
    category: "Server",
    weight: 90,
    detect: { headers: { server: /nginx/i } },
  },
  {
    name: "Apache",
    category: "Server",
    weight: 90,
    detect: { headers: { server: /apache/i } },
  },
  {
    name: "Caddy",
    category: "Server",
    weight: 90,
    detect: { headers: { server: /caddy/i } },
  },
  {
    name: "LiteSpeed",
    category: "Server",
    weight: 90,
    detect: { headers: { server: /litespeed/i } },
  },
  {
    name: "IIS",
    category: "Server",
    weight: 90,
    detect: { headers: { server: /microsoft-iis/i } },
  },
  {
    name: "OpenResty",
    category: "Server",
    weight: 90,
    detect: { headers: { server: /openresty/i } },
  },
  {
    name: "Gunicorn",
    category: "Server",
    weight: 80,
    detect: { headers: { server: /gunicorn/i } },
  },

  // ── Languages ─────────────────────────────────────────────────────────────
  {
    name: "PHP",
    category: "Language",
    weight: 90,
    detect: { headers: { "x-powered-by": /^php/i } },
  },
  {
    name: "ASP.NET",
    category: "Language",
    weight: 90,
    detect: { headers: { "x-powered-by": /asp\.net/i, "x-aspnet-version": /.+/ } },
  },
  {
    name: "Node.js",
    category: "Language",
    weight: 80,
    detect: { headers: { "x-powered-by": /express/i } },
  },
  {
    name: "Ruby on Rails",
    category: "Language",
    weight: 80,
    detect: {
      headers: { "x-powered-by": /phusion passenger/i },
      body: [/data-remote="true"/i, /rails\.js/i],
    },
  },

  // ── CDNs ──────────────────────────────────────────────────────────────────
  {
    name: "Cloudflare",
    category: "CDN",
    weight: 95,
    detect: { headers: { "cf-ray": /.+/, server: /cloudflare/i } },
  },
  {
    name: "AWS CloudFront",
    category: "CDN",
    weight: 95,
    detect: { headers: { "x-amz-cf-id": /.+/ } },
  },
  {
    name: "Fastly",
    category: "CDN",
    weight: 95,
    detect: { headers: { "x-fastly-request-id": /.+/ } },
  },
  {
    name: "Akamai",
    category: "CDN",
    weight: 90,
    detect: { headers: { "x-akamai-request-id": /.+/, "akamai-grn": /.+/ } },
  },
  {
    name: "Varnish",
    category: "CDN",
    weight: 85,
    detect: { headers: { "x-varnish": /.+/, via: /varnish/i } },
  },
  {
    name: "BunnyCDN",
    category: "CDN",
    weight: 85,
    detect: { headers: { "cdn-pullzone": /.+/, "cdn-uid": /.+/ } },
  },

  // ── Hosting platforms ─────────────────────────────────────────────────────
  {
    name: "Vercel",
    category: "Hosting",
    weight: 95,
    detect: { headers: { "x-vercel-id": /.+/ } },
  },
  {
    name: "Netlify",
    category: "Hosting",
    weight: 95,
    detect: { headers: { "x-netlify": /.+/, server: /netlify/i } },
  },
  {
    name: "GitHub Pages",
    category: "Hosting",
    weight: 90,
    detect: { headers: { server: /github\.com/i } },
  },
  {
    name: "Heroku",
    category: "Hosting",
    weight: 85,
    detect: { headers: { "x-request-id": /.+/, via: /1\.1 vegur/i } },
  },
  {
    name: "Fly.io",
    category: "Hosting",
    weight: 85,
    detect: { headers: { "fly-request-id": /.+/ } },
  },
  {
    name: "Render",
    category: "Hosting",
    weight: 85,
    detect: { headers: { "render-request-id": /.+/ } },
  },
  {
    name: "Railway",
    category: "Hosting",
    weight: 80,
    detect: { headers: { "x-railway-request-id": /.+/ } },
  },

  // ── CMS ───────────────────────────────────────────────────────────────────
  {
    name: "WordPress",
    category: "CMS",
    weight: 95,
    detect: {
      headers: { link: /wp-json/i, "x-pingback": /.+/ },
      body: [/wp-content\//i, /wp-includes\//i, /wp-emoji/i],
      meta_generator: /wordpress/i,
    },
  },
  {
    name: "Drupal",
    category: "CMS",
    weight: 95,
    detect: {
      headers: { "x-drupal-cache": /.+/, "x-generator": /drupal/i },
      body: [/drupal\.js/i, /"drupalSettings"/i, /sites\/default\/files/i],
      meta_generator: /drupal/i,
    },
  },
  {
    name: "Joomla",
    category: "CMS",
    weight: 95,
    detect: {
      body: [/\/media\/jui\//i, /joomla!/i],
      meta_generator: /joomla/i,
    },
  },
  {
    name: "Ghost",
    category: "CMS",
    weight: 95,
    detect: {
      headers: { "x-ghost-cache-status": /.+/ },
      body: [/ghost\.io/i, /ghost\.min\.js/i, /ghost-theme/i],
      meta_generator: /ghost/i,
    },
  },
  {
    name: "Contentful",
    category: "CMS",
    weight: 85,
    detect: { body: [/ctfassets\.net/i, /cdn\.contentful\.com/i] },
  },
  {
    name: "Sanity",
    category: "CMS",
    weight: 85,
    detect: { body: [/cdn\.sanity\.io/i] },
  },
  {
    name: "Strapi",
    category: "CMS",
    weight: 75,
    detect: { body: [/strapi/i] },
  },

  // ── E-commerce ────────────────────────────────────────────────────────────
  {
    name: "Shopify",
    category: "Ecommerce",
    weight: 95,
    detect: {
      headers: { "x-shopid": /.+/, "x-shopify-stage": /.+/ },
      body: [/cdn\.shopify\.com/i, /shopify\.com\/s\/files/i, /Shopify\.theme/i],
    },
  },
  {
    name: "WooCommerce",
    category: "Ecommerce",
    weight: 90,
    detect: { body: [/woocommerce/i, /wc-ajax/i, /wc_cart_hash/i] },
  },
  {
    name: "Magento",
    category: "Ecommerce",
    weight: 90,
    detect: {
      body: [/mage\/cookies\.js/i, /Magento_/i, /mage-init/i],
      cookies: [/MAGE_CACHE_SESSID/],
    },
  },
  {
    name: "BigCommerce",
    category: "Ecommerce",
    weight: 90,
    detect: { body: [/cdn\.bigcommerce\.com/i, /bigcommerce\.com/i, /BCData/i] },
  },
  {
    name: "PrestaShop",
    category: "Ecommerce",
    weight: 90,
    detect: {
      body: [/prestashop/i],
      meta_generator: /prestashop/i,
    },
  },

  // ── Site builders ─────────────────────────────────────────────────────────
  {
    name: "Wix",
    category: "CMS",
    weight: 95,
    detect: {
      headers: { "x-wix-request-id": /.+/ },
      body: [/static\.parastorage\.com/i, /wixstatic\.com/i],
    },
  },
  {
    name: "Squarespace",
    category: "CMS",
    weight: 95,
    detect: {
      body: [/squarespace\.com/i, /static1\.squarespace\.com/i, /squarespace-cdn\.com/i],
      meta_generator: /squarespace/i,
    },
  },
  {
    name: "Webflow",
    category: "CMS",
    weight: 95,
    detect: {
      headers: { "x-wf-request-id": /.+/ },
      body: [/webflow\.com/i, /assets-global\.website-files\.com/i],
      meta_generator: /webflow/i,
    },
  },
  {
    name: "Framer",
    category: "CMS",
    weight: 90,
    detect: { body: [/framer\.com/i, /framerusercontent\.com/i] },
  },

  // ── JS Frameworks ─────────────────────────────────────────────────────────
  {
    name: "Next.js",
    category: "Framework",
    weight: 90,
    detect: {
      headers: { "x-nextjs-cache": /.+/, "x-powered-by": /next\.js/i },
      body: [/__NEXT_DATA__/i, /_next\/static\//i],
    },
  },
  {
    name: "Nuxt.js",
    category: "Framework",
    weight: 85,
    detect: { body: [/__nuxt/i, /_nuxt\//i, /nuxt-loading/i] },
  },
  {
    name: "Gatsby",
    category: "Framework",
    weight: 85,
    detect: {
      body: [/\/page-data\//i, /gatsby-chunk/i],
      meta_generator: /gatsby/i,
    },
  },
  {
    name: "SvelteKit",
    category: "Framework",
    weight: 80,
    detect: { body: [/__sveltekit/i, /\/_app\/immutable\//i, /sveltekit-hydrated/i] },
  },
  {
    name: "Astro",
    category: "Framework",
    weight: 80,
    detect: {
      headers: { "x-astro-version": /.+/ },
      body: [/astro-island/i],
      meta_generator: /astro/i,
    },
  },
  {
    name: "Remix",
    category: "Framework",
    weight: 80,
    detect: { body: [/__remixContext/i, /remix\.run/i] },
  },
  {
    name: "Angular",
    category: "Framework",
    weight: 80,
    detect: { body: [/ng-version=/i, /angular\.min\.js/i, /ng-app=/i] },
  },
  {
    name: "Vue.js",
    category: "Framework",
    weight: 75,
    detect: { body: [/__vue_app__/i, /vue\.min\.js/i, /v-app/i] },
  },
  {
    name: "React",
    category: "Framework",
    weight: 65,
    detect: { body: [/__reactFiber/i, /react\.development\.js/i] },
  },
  {
    name: "Laravel",
    category: "Framework",
    weight: 75,
    detect: { cookies: [/laravel_session/] },
  },
  {
    name: "Django",
    category: "Framework",
    weight: 75,
    detect: { cookies: [/csrftoken/] },
  },

  // ── Analytics ─────────────────────────────────────────────────────────────
  {
    name: "Google Analytics",
    category: "Analytics",
    weight: 90,
    detect: {
      body: [/google-analytics\.com\/analytics\.js/, /gtag\(/, /G-[A-Z0-9]{8,}/, /UA-\d{5,}-\d+/],
      scripts: [/googletagmanager\.com\/gtag/i, /google-analytics\.com/i],
    },
  },
  {
    name: "Google Tag Manager",
    category: "Analytics",
    weight: 90,
    detect: {
      body: [/googletagmanager\.com\/gtm\.js/i],
      scripts: [/googletagmanager\.com\/gtm/i],
    },
  },
  {
    name: "Plausible",
    category: "Analytics",
    weight: 90,
    detect: {
      body: [/plausible\.io\/js/i],
      scripts: [/plausible\.io/i],
    },
  },
  {
    name: "Mixpanel",
    category: "Analytics",
    weight: 85,
    detect: { body: [/cdn\.mxpnl\.com/i, /mixpanel\.init/i] },
  },
  {
    name: "Segment",
    category: "Analytics",
    weight: 85,
    detect: { body: [/cdn\.segment\.com/i, /analytics\.load/i] },
  },
  {
    name: "Amplitude",
    category: "Analytics",
    weight: 85,
    detect: { body: [/cdn\.amplitude\.com/i, /amplitude\.getInstance/i] },
  },
  {
    name: "Hotjar",
    category: "Analytics",
    weight: 85,
    detect: { body: [/hotjar\.com\/c\/hotjar/i, /static\.hotjar\.com/i] },
  },
  {
    name: "FullStory",
    category: "Analytics",
    weight: 85,
    detect: { body: [/fullstory\.com\/s\/fs\.js/i] },
  },
  {
    name: "PostHog",
    category: "Analytics",
    weight: 85,
    detect: { body: [/posthog\.com\/static/i, /posthog\.init/i] },
  },

  // ── Marketing / CRM ───────────────────────────────────────────────────────
  {
    name: "HubSpot",
    category: "Marketing",
    weight: 90,
    detect: {
      body: [/js\.hs-scripts\.com/i, /hs-analytics\.net/i, /hs-banner\.com/i],
      cookies: [/hubspotutk/, /__hstc/],
    },
  },
  {
    name: "Intercom",
    category: "Marketing",
    weight: 90,
    detect: {
      body: [/widget\.intercom\.io/i, /intercomcdn\.com/i],
      cookies: [/intercom-/],
    },
  },
  {
    name: "Drift",
    category: "Marketing",
    weight: 90,
    detect: { body: [/js\.driftt\.com/i, /drift\.com\/core/i] },
  },
  {
    name: "Zendesk",
    category: "Marketing",
    weight: 85,
    detect: { body: [/static\.zdassets\.com/i, /ekr\.zdassets\.com/i] },
  },
  {
    name: "Crisp",
    category: "Marketing",
    weight: 85,
    detect: { body: [/client\.crisp\.chat/i] },
  },
  {
    name: "Mailchimp",
    category: "Marketing",
    weight: 80,
    detect: { body: [/chimpstatic\.com/i] },
  },
  {
    name: "Klaviyo",
    category: "Marketing",
    weight: 85,
    detect: { body: [/static\.klaviyo\.com/i] },
  },
  {
    name: "Customer.io",
    category: "Marketing",
    weight: 80,
    detect: { body: [/track\.customer\.io/i] },
  },

  // ── Payments ──────────────────────────────────────────────────────────────
  {
    name: "Stripe",
    category: "Other",
    weight: 90,
    detect: {
      scripts: [/js\.stripe\.com/i],
      body: [/js\.stripe\.com\/v3/i],
    },
  },
  {
    name: "PayPal",
    category: "Other",
    weight: 90,
    detect: { body: [/paypal\.com\/sdk/i, /paypalobjects\.com/i] },
  },
  {
    name: "Paddle",
    category: "Other",
    weight: 85,
    detect: { body: [/cdn\.paddle\.com/i, /paddle\.com\/vendor/i] },
  },

  // ── Search & Infrastructure ───────────────────────────────────────────────
  {
    name: "Algolia",
    category: "Other",
    weight: 85,
    detect: { body: [/algolia\.net/i, /algoliacdn\.net/i] },
  },
  {
    name: "Elasticsearch",
    category: "Other",
    weight: 60,
    detect: { headers: { "x-elastic-product": /.+/ } },
  },
];

// ── Helper: classify a list of detected tech into summary fields ──────────

export type SummaryField = "cms" | "framework" | "ecommerce" | "server" | "language" | "cdn" | "hosting";

const CATEGORY_TO_FIELD: Record<string, SummaryField | null> = {
  CMS:        "cms",
  Framework:  "framework",
  Ecommerce:  "ecommerce",
  Server:     "server",
  Language:   "language",
  CDN:        "cdn",
  Hosting:    "hosting",
  Analytics:  null, // multi-value → array
  Marketing:  null, // multi-value → array
  Other:      null,
};

export function getCategoryField(category: string): SummaryField | null {
  return CATEGORY_TO_FIELD[category] ?? null;
}
