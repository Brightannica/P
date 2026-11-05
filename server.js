'use strict';

/**
 * Production-grade sticky-session reverse proxy.
 *
 * Runtime: Node.js 18+ / Express 4 / http-proxy-middleware 3 (modular API).
 * Deployment target: Render.
 *
 * Routing model:
 *   1. `GET /?_px=<base64url>` resolves the upstream target, refreshes the
 *      sticky session cookies and proxies the request.
 *   2. Any later request without `_px` is reconstructed from the sticky
 *      session cookies (`_px_target` + `_px_base`).
 *   3. `GET /` with no active session renders the built-in launcher UI.
 *
 * Authorization model:
 *   Upstream targets are validated against ALLOWED_ORIGINS. Only origins the
 *   operator is authorized to front may be proxied, and response-header
 *   sanitisation (CSP / X-Frame-Options / COOP / COEP removal, permissive
 *   CORS) is applied only to those allowlisted origins.
 *
 * Operational endpoints:
 *   GET /healthz     liveness probe
 *   GET /readyz      readiness probe (configuration validity)
 *   GET /metrics     Prometheus text exposition
 *   GET /_px/session current sticky session summary
 *   GET /_px/new     clear the sticky session and return to the launcher
 */

const crypto = require('crypto');
const dns = require('dns').promises;
const http = require('http');
const https = require('https');
const net = require('net');
const express = require('express');
const { createProxyMiddleware, fixRequestBody } = require('http-proxy-middleware');

/* ------------------------------------------------------------------ *
 * Configuration
 * ------------------------------------------------------------------ */

const PORT = Number(process.env.PORT) || 3000;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';

/**
 * How many proxy hops to trust when resolving the client address.
 *
 * Trusting every hop (`true`) makes `req.ip` the left-most `X-Forwarded-For`
 * entry, which the client controls, and therefore lets anyone bypass the
 * rate limiter by rotating that header. A fixed hop count makes `req.ip` the
 * address appended by the trusted edge, which the client cannot forge.
 */
const TRUST_PROXY = (() => {
  const raw = String(process.env.TRUST_PROXY ?? '1').trim().toLowerCase();
  if (raw === 'false' || raw === '0' || raw === 'off' || raw === 'no') return false;
  if (raw === 'true' || raw === 'yes' || raw === 'on') return 1;
  const hops = Number(raw);
  return Number.isFinite(hops) && hops >= 0 ? hops : 1;
})();

const STICKY_COOKIE = '_px_target'; // upstream origin
const BASE_COOKIE = '_px_base'; // upstream origin + base path (entry point)
const STICKY_MAX_AGE = 14400; // 4 hours, in seconds
const ENTRY_PARAM = '_px';

function num(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : fallback;
}

function parseList(value) {
  return String(value || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/** Hides upstream credentials before an allowlist entry reaches a log line. */
function redactEntry(entry) {
  return String(entry).replace(/^([^:@/]*):([^@]*)@/, '$1:***@');
}

function redactList(entries) {
  return entries.map(redactEntry);
}

const CONFIG = {
  /** Origins this instance is authorized to proxy. */
  allowedOrigins: parseList(process.env.ALLOWED_ORIGINS),
  /** Origins for which restrictive response headers may be removed. */
  stripHeadersOrigins: parseList(process.env.STRIP_SECURITY_HEADERS_ORIGINS),
  enableCors: process.env.ENABLE_CORS !== 'false',
  /** Public origin of this deployment, used to rewrite redirects. */
  publicOrigin: (process.env.PUBLIC_ORIGIN || '').replace(/\/+$/, ''),
  /** Example target pre-filled in the launcher UI. */
  exampleTarget: process.env.EXAMPLE_TARGET || '',
  /** Optional bearer token required in front of the whole proxy. */
  accessToken: process.env.PROXY_ACCESS_TOKEN || '',
  /**
   * Optional HTTP Basic credentials. Browsers send Basic credentials on
   * navigations automatically, so this is the browser-friendly way to put
   * the proxy behind an authentication prompt.
   */
  accessUser: process.env.PROXY_ACCESS_USER || '',
  accessPassword: process.env.PROXY_ACCESS_PASSWORD || '',
  /** Maximum accepted request body size, in bytes. */
  bodyLimitBytes: num(process.env.MAX_BODY_BYTES, 10 * 1024 * 1024),
  /** Session creations allowed per client per window. */
  rateLimitMax: num(process.env.RATE_LIMIT_MAX, 30),
  rateLimitWindowMs: num(process.env.RATE_LIMIT_WINDOW_MS, 60 * 1000),
  /** Retry budget for idempotent requests against a failing upstream. */
  retryAttempts: num(process.env.RETRY_ATTEMPTS, 2),
  retryBaseDelayMs: num(process.env.RETRY_BASE_DELAY_MS, 100),
  /** Upstream connection pool sizing. */
  upstreamMaxSockets: num(process.env.UPSTREAM_MAX_SOCKETS, 32),
  upstreamKeepAliveMs: num(process.env.UPSTREAM_KEEPALIVE_MS, 30 * 1000),
  upstreamMaxFreeSockets: num(process.env.UPSTREAM_MAX_FREE_SOCKETS, 8),
  /** SSRF containment. */
  ssrfGuard: process.env.SSRF_GUARD !== 'false',
  allowPrivateTargets: process.env.ALLOW_PRIVATE_TARGETS === 'true',
  dnsCacheTtlMs: num(process.env.DNS_CACHE_TTL_MS, 60 * 1000),
  /** Maximum accepted `_px` payload length. */
  maxTargetLength: num(process.env.MAX_TARGET_LENGTH, 4096),
  /** Logging. */
  logLevel: process.env.LOG_LEVEL || 'info',
  logFormat: process.env.LOG_FORMAT || 'json',
  /** Graceful shutdown budget. */
  shutdownGraceMs: num(process.env.SHUTDOWN_GRACE_MS, 20 * 1000),
  /**
   * Signal fidelity.
   *
   * A reverse proxy is easiest to spot when it contradicts the client it is
   * forwarding for. By default the client's own fingerprint, origin headers
   * and compression negotiation are relayed verbatim, because a real browser
   * is self-consistent and a proxied copy of it is not.
   */
  /** Emit `X-Forwarded-*` headers upstream (a clear proxy tell). */
  forwardedHeaders: process.env.FORWARDED_HEADERS === 'true',
  /** Relay the correlation id upstream. */
  forwardRequestId: process.env.FORWARD_REQUEST_ID === 'true',
  /** Replace the client's fingerprint with the built-in browser profile. */
  overrideFingerprint: process.env.OVERRIDE_FINGERPRINT === 'true',
  /** Drop `accept-encoding` instead of relaying the client's negotiation. */
  stripAcceptEncoding: process.env.STRIP_ACCEPT_ENCODING === 'true',
  /**
   * How `Origin` and `Referer` are handled:
   *   relay  - forward when the client sent one, rewritten onto the upstream
   *   always - always synthesise them (matches a classic reverse proxy)
   *   never  - strip them entirely
   */
  originHeaders: process.env.ORIGIN_HEADERS_MODE || 'relay',
};

if (CONFIG.stripHeadersOrigins.length === 0) {
  CONFIG.stripHeadersOrigins = CONFIG.allowedOrigins.slice();
}

if (CONFIG.allowedOrigins.length === 0 && IS_PRODUCTION) {
  console.warn(
    '[config] ALLOWED_ORIGINS is empty: every upstream target will be rejected with HTTP 403. ' +
      'Set ALLOWED_ORIGINS to a comma-separated list of origins you are authorized to proxy.'
  );
}

/**
 * A single, internally consistent browser fingerprint. Headers are stable
 * across requests so the upstream sees one coherent client rather than a
 * randomising agent.
 */
const FINGERPRINT = {
  userAgent:
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) ' +
    'Chrome/131.0.0.0 Safari/537.36',
  secChUa: '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
  secChUaMobile: '?0',
  secChUaPlatform: '"Windows"',
  acceptLanguage: 'en-US,en;q=0.9',
  accept:
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,*/*;q=0.8',
};

/** Hop-by-hop headers that must never be forwarded upstream. */
const HOP_BY_HOP_HEADERS = [
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
];

/**
 * Forwarding headers are either a self-inflicted proxy tell or a client
 * supplied spoofing attempt, so whatever arrives is dropped before the
 * request reaches the upstream.
 */
const FORWARDING_HEADERS = [
  'forwarded',
  'x-forwarded-for',
  'x-forwarded-host',
  'x-forwarded-port',
  'x-forwarded-proto',
  'x-real-ip',
];

/** Response headers removed for allowlisted origins. */
const STRIPPED_RESPONSE_HEADERS = [
  'content-security-policy',
  'content-security-policy-report-only',
  'x-frame-options',
  'cross-origin-opener-policy',
  'cross-origin-embedder-policy',
  'cross-origin-resource-policy',
  'x-powered-by',
  'server',
  'via',
  'x-proxied-by',
];

/** Upstream failures that are worth retrying for idempotent requests. */
const RETRYABLE_CODES = new Set([
  'ECONNRESET',
  'ECONNREFUSED',
  'ETIMEDOUT',
  'EPIPE',
  'EAI_AGAIN',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENETDOWN',
]);

const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Client classification.
 *
 * A browser's own fingerprint is self-consistent, so relaying it is always
 * faithful. A non-browser client (a script, a crawler, a CLI) announces
 * itself as one, which is just as conspicuous on an origin that serves web
 * applications. Those clients are normalised onto the built-in profile.
 */
const BROWSER_UA_PATTERN = /(Chrome|Chromium|Safari|Firefox|Edg|OPR|Android|iPhone|iPad)/i;
const NON_BROWSER_UA_PATTERN =
  /(bot\b|crawler|spider|crawling|headless|curl|wget|python-requests|python-urllib|httpclient|node-fetch|undici|axios|go-http-client|java|okhttp|libwww|postman|insomnia)/i;

/** True when the incoming request already carries a browser-like identity. */
function isBrowserLike(proxyReq) {
  // Real browsers that support client hints always send them.
  if (proxyReq.getHeader('sec-ch-ua')) return true;

  const userAgent = proxyReq.getHeader('user-agent');
  if (!userAgent) return false;
  if (NON_BROWSER_UA_PATTERN.test(userAgent)) return false;

  return BROWSER_UA_PATTERN.test(userAgent);
}

/* ------------------------------------------------------------------ *
 * Logging
 * ------------------------------------------------------------------ */

const LOG_LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };

/**
 * Whether a level would be emitted. Hot paths use this to avoid building a
 * payload object that would only be discarded.
 */
function logEnabled(level) {
  return (LOG_LEVELS[level] ?? 2) <= (LOG_LEVELS[CONFIG.logLevel] ?? 2);
}

function log(level, message, fields) {
  if ((LOG_LEVELS[level] ?? 2) > (LOG_LEVELS[CONFIG.logLevel] ?? 2)) return;

  const payload = { ts: new Date().toISOString(), level, msg: message, ...(fields || {}) };

  if (CONFIG.logFormat === 'pretty') {
    const { ts, level: lvl, msg, ...rest } = payload;
    const suffix = Object.keys(rest).length ? ` ${JSON.stringify(rest)}` : '';
    const line = `${ts} ${String(lvl).toUpperCase().padEnd(5)} ${msg}${suffix}`;
    (level === 'error' ? console.error : console.log)(line);
    return;
  }

  const line = JSON.stringify(payload);
  (level === 'error' ? console.error : console.log)(line);
}

/* ------------------------------------------------------------------ *
 * Metrics
 * ------------------------------------------------------------------ */

const METRICS = {
  requests: 0,
  proxied: 0,
  errors: 0,
  bytesOut: 0,
  sessions: 0,
  retries: 0,
  upstreamErrors: 0,
  upstreamRequests: 0,
  upstreamDurationSumMs: 0,
  rateLimited: 0,
  rejected: 0,
  active: 0,
  durationSumMs: 0,
};

const DURATION_BUCKETS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
const durationHistogram = new Map(DURATION_BUCKETS.map((bucket) => [bucket, 0]));

function observeDuration(durationMs) {
  METRICS.durationSumMs += durationMs;
  for (const bucket of DURATION_BUCKETS) {
    if (durationMs <= bucket) {
      durationHistogram.set(bucket, durationHistogram.get(bucket) + 1);
      return;
    }
  }
}

function renderMetrics() {
  const memory = process.memoryUsage();
  const lines = [
    '# HELP px_requests_total Total HTTP requests handled.',
    '# TYPE px_requests_total counter',
    `px_requests_total ${METRICS.requests}`,
    '# HELP px_proxied_total Requests forwarded to an upstream origin.',
    '# TYPE px_proxied_total counter',
    `px_proxied_total ${METRICS.proxied}`,
    '# HELP px_errors_total Responses served as an error.',
    '# TYPE px_errors_total counter',
    `px_errors_total ${METRICS.errors}`,
    '# HELP px_rejected_total Requests rejected before proxying.',
    '# TYPE px_rejected_total counter',
    `px_rejected_total ${METRICS.rejected}`,
    '# HELP px_rate_limited_total Requests rejected by the rate limiter.',
    '# TYPE px_rate_limited_total counter',
    `px_rate_limited_total ${METRICS.rateLimited}`,
    '# HELP px_upstream_errors_total Upstream connection or protocol failures.',
    '# TYPE px_upstream_errors_total counter',
    `px_upstream_errors_total ${METRICS.upstreamErrors}`,
    '# HELP px_upstream_requests_total Responses received from an upstream.',
    '# TYPE px_upstream_requests_total counter',
    `px_upstream_requests_total ${METRICS.upstreamRequests}`,
    '# HELP px_upstream_duration_ms Total time spent waiting on upstream responses.',
    '# TYPE px_upstream_duration_ms counter',
    `px_upstream_duration_ms_sum ${METRICS.upstreamDurationSumMs.toFixed(3)}`,
    `px_upstream_duration_ms_count ${METRICS.upstreamRequests}`,
    '# HELP px_retries_total Idempotent requests retried after an upstream failure.',
    '# TYPE px_retries_total counter',
    `px_retries_total ${METRICS.retries}`,
    '# HELP px_sessions_total Sticky sessions opened.',
    '# TYPE px_sessions_total counter',
    `px_sessions_total ${METRICS.sessions}`,
    '# HELP px_bytes_out_total Bytes streamed to clients.',
    '# TYPE px_bytes_out_total counter',
    `px_bytes_out_total ${METRICS.bytesOut}`,
    '# HELP px_active_requests Requests currently in flight.',
    '# TYPE px_active_requests gauge',
    `px_active_requests ${METRICS.active}`,
    '# HELP px_process_resident_memory_bytes Resident set size of the process.',
    '# TYPE px_process_resident_memory_bytes gauge',
    `px_process_resident_memory_bytes ${memory.rss}`,
    '# HELP px_process_heap_used_bytes V8 heap currently in use.',
    '# TYPE px_process_heap_used_bytes gauge',
    `px_process_heap_used_bytes ${memory.heapUsed}`,
    '# HELP px_request_duration_ms Request duration in milliseconds.',
    '# TYPE px_request_duration_ms histogram',
  ];

  let cumulative = 0;
  for (const bucket of DURATION_BUCKETS) {
    cumulative += durationHistogram.get(bucket);
    lines.push(`px_request_duration_ms_bucket{le="${bucket}"} ${cumulative}`);
  }
  lines.push(`px_request_duration_ms_bucket{le="+Inf"} ${METRICS.requests}`);
  lines.push(`px_request_duration_ms_sum ${METRICS.durationSumMs.toFixed(3)}`);
  lines.push(`px_request_duration_ms_count ${METRICS.requests}`);

  return `${lines.join('\n')}\n`;
}

/* ------------------------------------------------------------------ *
 * Upstream connection pool
 * ------------------------------------------------------------------ */

/**
 * Protocol-aware upstream connection pool.
 *
 * `node-http-proxy` sets `outgoing.agent = options.agent || false` and, when
 * no agent is supplied, explicitly forces `Connection: close` on every
 * upstream request. Supplying an agent therefore both removes that header
 * and enables keep-alive pooling, so a page with dozens of background asset
 * requests reuses a single upstream connection instead of handshaking once
 * per asset.
 */
function createUpstreamAgent() {
  const options = {
    keepAlive: true,
    keepAliveMsecs: CONFIG.upstreamKeepAliveMs,
    maxSockets: CONFIG.upstreamMaxSockets,
    maxFreeSockets: CONFIG.upstreamMaxFreeSockets,
    scheduling: 'lifo',
  };

  const httpAgent = new http.Agent(options);
  const httpsAgent = new https.Agent(options);

  return {
    // Node reads these to decide whether a connection may be reused.
    keepAlive: true,
    maxSockets: CONFIG.upstreamMaxSockets,
    maxFreeSockets: CONFIG.upstreamMaxFreeSockets,
    keepAliveMsecs: CONFIG.upstreamKeepAliveMs,

    addRequest(req, requestOptions) {
      const selected = requestOptions.protocol === 'https:' ? httpsAgent : httpAgent;
      return selected.addRequest(req, requestOptions);
    },

    getName(requestOptions) {
      const selected = requestOptions.protocol === 'https:' ? httpsAgent : httpAgent;
      return selected.getName(requestOptions);
    },

    destroy() {
      httpAgent.destroy();
      httpsAgent.destroy();
    },
  };
}

/* ------------------------------------------------------------------ *
 * Small utilities
 * ------------------------------------------------------------------ */

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

/** Minimal cookie-header parser (also used for WebSocket upgrade requests). */
function parseCookieHeader(header) {
  const jar = Object.create(null);
  if (!header) return jar;
  for (const part of String(header).split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const key = part.slice(0, index).trim();
    if (!key) continue;
    jar[key] = safeDecodeURIComponent(part.slice(index + 1).trim());
  }
  return jar;
}

function readCookie(req, name) {
  const jar = parseCookieHeader(req.headers && req.headers.cookie);
  return jar[name] || null;
}

/**
 * Splits a raw query string without decoding, so that the raw `_px` segment
 * stays intact. Returns `[{ key, rawValue, value }]`.
 */
function parseRawQuery(search) {
  const query = (search || '').replace(/^\?/, '');
  if (!query) return [];
  return query
    .split('&')
    .filter((segment) => segment.length > 0)
    .map((segment) => {
      const index = segment.indexOf('=');
      const rawKey = index === -1 ? segment : segment.slice(0, index);
      const rawValue = index === -1 ? '' : segment.slice(index + 1);
      return {
        key: safeDecodeURIComponent(rawKey),
        rawValue,
        value: safeDecodeURIComponent(rawValue),
      };
    });
}

/** Rebuilds a query string from parsed segments, preserving order. */
function buildQuery(segments) {
  const parts = segments
    .filter((segment) => segment.key !== ENTRY_PARAM)
    .map((segment) => `${encodeURIComponent(segment.key)}=${encodeURIComponent(segment.value)}`);
  return parts.length ? `?${parts.join('&')}` : '';
}

/**
 * Repairs and decodes a base64 (or base64url) payload.
 *
 * - splits at the first `&` so trailing query collisions are discarded
 * - replaces spaces with `+`
 * - maps the base64url alphabet onto standard base64
 * - restores missing `=` padding
 */
function decodeBase64Target(rawValue) {
  if (typeof rawValue !== 'string' || rawValue.trim() === '') {
    throw new Error('Missing target payload');
  }

  let payload = rawValue.split('&')[0].trim();

  // Percent-decode first (handles %3D padding, %2B plus signs).
  payload = safeDecodeURIComponent(payload);

  // Form-encoding turns `+` into a space; restore it.
  payload = payload.replace(/\s+/g, '+');

  // base64url -> base64.
  payload = payload.replace(/-/g, '+').replace(/_/g, '/');

  // Drop anything that is not part of the base64 alphabet.
  payload = payload.replace(/[^A-Za-z0-9+/]/g, '');

  if (!payload) {
    throw new Error('Target payload contained no decodable data');
  }

  // Rebuild padding from scratch.
  const remainder = payload.length % 4;
  if (remainder === 1) {
    throw new Error('Target payload is truncated');
  }
  if (remainder > 0) {
    payload += '='.repeat(4 - remainder);
  }

  const decoded = Buffer.from(payload, 'base64').toString('utf8').trim();

  if (!decoded) {
    throw new Error('Target payload decoded to an empty string');
  }

  return decoded;
}

/** Parses and validates a decoded target string. */
function parseTargetUrl(decoded) {
  let url;
  try {
    url = new URL(decoded);
  } catch {
    throw new Error(`Invalid target URL: ${decoded}`);
  }

  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Unsupported target protocol: only http and https are allowed');
  }

  if (!url.hostname) {
    throw new Error('Target URL is missing a hostname');
  }

  return url;
}

/** Splits a raw request URL into pathname and search without a base URL. */
function splitRequestUrl(rawUrl) {
  const raw = rawUrl || '/';
  const index = raw.indexOf('?');
  if (index === -1) return { pathname: raw, search: '' };
  return { pathname: raw.slice(0, index), search: raw.slice(index) };
}

/** Public origin of this deployment, used to rewrite absolute redirects. */
function publicOriginOf(req) {
  if (CONFIG.publicOrigin) return CONFIG.publicOrigin;
  const forwardedHost = String(req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  const host = forwardedHost || req.headers.host || `localhost:${PORT}`;
  const forwardedProto = String(req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const proto =
    forwardedProto || (req.socket && req.socket.encrypted ? 'https' : 'http') || 'http';
  return `${proto}://${host}`;
}

/* ------------------------------------------------------------------ *
 * Allowlist
 * ------------------------------------------------------------------ */

/**
 * Compiles the allowlist once at boot so request-time matching is a set
 * lookup rather than a URL parse per entry per request.
 *
 * Supported entry forms:
 *   `https://example.com`        exact origin
 *   `example.com`                any scheme, exact host
 *   `*.example.com`              any subdomain of example.com
 *   `user:pass@example.com`      host with upstream Basic credentials
 *   `*`                          allow every origin (development convenience)
 */
function compileAllowlist(entries) {
  const compiled = {
    allowAll: false,
    origins: new Set(),
    hosts: new Set(),
    suffixes: [],
    credentials: new Map(),
  };

  for (const entry of entries) {
    if (entry === '*') {
      compiled.allowAll = true;
      continue;
    }

    let value = entry;
    let credentials = null;

    const atIndex = value.lastIndexOf('@');
    if (atIndex !== -1) {
      const raw = value.slice(0, atIndex);
      value = value.slice(atIndex + 1);
      const colon = raw.indexOf(':');
      credentials =
        colon === -1
          ? { username: raw, password: '' }
          : { username: raw.slice(0, colon), password: raw.slice(colon + 1) };
    }

    if (value.startsWith('*.')) {
      compiled.suffixes.push(value.slice(1).toLowerCase());
      continue;
    }

    if (value.includes('://')) {
      try {
        const url = new URL(value);
        compiled.origins.add(url.origin);
        if (credentials) compiled.credentials.set(url.host, credentials);
      } catch {
        log('warn', 'ignoring malformed allowlist entry', { entry: redactEntry(entry) });
      }
      continue;
    }

    compiled.hosts.add(value.toLowerCase());
    if (credentials) compiled.credentials.set(value.toLowerCase(), credentials);
  }

  return compiled;
}

const ALLOWLIST = compileAllowlist(CONFIG.allowedOrigins);
const STRIP_ALLOWLIST = compileAllowlist(CONFIG.stripHeadersOrigins);

function matchesAllowlist(allowlist, target) {
  if (allowlist.allowAll) return true;
  if (allowlist.origins.has(target.origin)) return true;

  const host = target.hostname.toLowerCase();
  if (allowlist.hosts.has(host)) return true;

  for (const suffix of allowlist.suffixes) {
    if (host.endsWith(suffix) && host.length > suffix.length) return true;
  }

  return false;
}

function isOriginAllowed(target) {
  return matchesAllowlist(ALLOWLIST, target);
}

function isHeaderStripAllowed(target) {
  return matchesAllowlist(STRIP_ALLOWLIST, target);
}

function credentialsFor(target) {
  return (
    ALLOWLIST.credentials.get(target.host) ||
    ALLOWLIST.credentials.get(target.hostname.toLowerCase()) ||
    null
  );
}

/* ------------------------------------------------------------------ *
 * SSRF containment
 * ------------------------------------------------------------------ */

const dnsCache = new Map();
const DNS_CACHE_MAX = 256;

/** True for addresses that must never be reached through the proxy. */
function isPrivateAddress(address) {
  const type = net.isIP(address);
  if (type === 4) {
    const parts = address.split('.').map(Number);
    const [a, b, c] = parts;
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 192 && b === 0 && c === 0) return true;
    if (a === 198 && (c === 18 || c === 19)) return true;
    if (a >= 224) return true;
    return false;
  }

  if (type === 6) {
    const addr = address.toLowerCase();
    if (addr === '::' || addr === '::1') return true;
    if (addr.startsWith('fc') || addr.startsWith('fd')) return true; // unique local
    if (addr.startsWith('fe80')) return true; // link local
    if (addr.startsWith('::ffff:')) return isPrivateAddress(addr.slice(7));
    return false;
  }

  return true;
}

async function resolveHostAddresses(hostname) {
  const cached = dnsCache.get(hostname);
  if (cached && cached.expires > Date.now()) {
    // Refresh recency for the least-recently-used eviction below.
    dnsCache.delete(hostname);
    dnsCache.set(hostname, cached);
    return cached.addresses;
  }

  let addresses;
  try {
    const results = await dns.lookup(hostname, { all: true, verbatim: true });
    addresses = results.map((result) => result.address);
  } catch (error) {
    throw new Error(`DNS lookup failed for ${hostname}: ${error.code || error.message}`);
  }

  // Bounded cache: evict the least recently used entry rather than clearing
  // the whole map, which keeps memory flat without losing warm entries.
  if (dnsCache.size >= DNS_CACHE_MAX) {
    const oldest = dnsCache.keys().next().value;
    if (oldest !== undefined) dnsCache.delete(oldest);
  }
  dnsCache.set(hostname, { addresses, expires: Date.now() + CONFIG.dnsCacheTtlMs });
  return addresses;
}

/**
 * Blocks targets that resolve to private, loopback, link-local or otherwise
 * internal addresses. Only meaningful for wildcard allowlists, where an
 * attacker could otherwise point the proxy at internal infrastructure.
 */
async function assertSafeTarget(url) {
  if (!CONFIG.ssrfGuard || CONFIG.allowPrivateTargets) return;

  const literal = net.isIP(url.hostname);
  if (literal) {
    if (isPrivateAddress(url.hostname)) {
      throw new Error('Target resolves to a private network address');
    }
    return;
  }

  const addresses = await resolveHostAddresses(url.hostname);
  if (addresses.some((address) => isPrivateAddress(address))) {
    throw new Error('Target resolves to a private network address');
  }
}

/* ------------------------------------------------------------------ *
 * Rate limiting
 * ------------------------------------------------------------------ */

const rateBuckets = new Map();
const RATE_BUCKETS_MAX = 5000;

/** Sliding-window limiter keyed by client address. */
function checkRateLimit(key, limit, windowMs) {
  if (limit <= 0) return true;

  const now = Date.now();
  const hits = (rateBuckets.get(key) || []).filter((stamp) => now - stamp < windowMs);

  if (hits.length >= limit) {
    rateBuckets.set(key, hits);
    return false;
  }

  hits.push(now);
  rateBuckets.set(key, hits);

  // Bound the table so a spray of distinct addresses cannot grow it without
  // limit; the sweep below reclaims the rest.
  if (rateBuckets.size > RATE_BUCKETS_MAX) {
    const oldest = rateBuckets.keys().next().value;
    if (oldest !== undefined) rateBuckets.delete(oldest);
  }

  return true;
}

const rateSweep = setInterval(() => {
  const now = Date.now();
  for (const [key, hits] of rateBuckets) {
    const live = hits.filter((stamp) => now - stamp < CONFIG.rateLimitWindowMs);
    if (live.length === 0) rateBuckets.delete(key);
    else rateBuckets.set(key, live);
  }
}, 60 * 1000);
rateSweep.unref();

/* ------------------------------------------------------------------ *
 * Target resolution
 * ------------------------------------------------------------------ */

/**
 * Resolves the upstream target for a request and rewrites `req.url` to the
 * exact upstream path + query. Safe to call from the Express pipeline and
 * from the WebSocket upgrade path (which bypasses Express).
 *
 * @returns {Promise<{ok: true, ...} | {ok: false, status: number, reason: string}>}
 */
async function resolveTarget(req) {
  if (req.pxPromise) return req.pxPromise;
  req.pxPromise = resolveTargetUncached(req);
  return req.pxPromise;
}

async function resolveTargetUncached(req) {
  const rawUrl = req.originalUrl || req.url || '/';
  const { pathname, search } = splitRequestUrl(rawUrl);
  const segments = parseRawQuery(search);
  const entry = segments.find((segment) => segment.key === ENTRY_PARAM);
  const stickyCookie = readCookie(req, STICKY_COOKIE);

  const reject = (status, reason) => ({
    ok: false,
    status,
    reason,
    hasEntry: Boolean(entry),
    hasSession: Boolean(stickyCookie),
  });

  let origin = null;
  let basePath = null;
  let baseSearch = '';
  let explicit = false;
  let parsedTarget = null;

  if (entry) {
    explicit = true;

    if (entry.rawValue.length > CONFIG.maxTargetLength) {
      return reject(400, 'Target payload is too large');
    }

    let decoded;
    try {
      decoded = decodeBase64Target(entry.rawValue);
    } catch (error) {
      return reject(400, error.message);
    }

    let url;
    try {
      url = parseTargetUrl(decoded);
    } catch (error) {
      return reject(400, error.message);
    }

    if (!isOriginAllowed(url)) {
      return reject(403, `Origin ${url.origin} is not in ALLOWED_ORIGINS`);
    }

    try {
      await assertSafeTarget(url);
    } catch (error) {
      return reject(403, error.message);
    }

    origin = url.origin;
    parsedTarget = url;
    basePath = url.pathname && url.pathname !== '/' ? url.pathname.replace(/\/+$/, '') : '/';
    baseSearch = url.search || '';
  } else {
    if (!stickyCookie) {
      return reject(400, 'No active proxy session');
    }

    let stickyUrl;
    try {
      stickyUrl = parseTargetUrl(stickyCookie);
    } catch {
      return reject(400, 'Sticky session target is invalid');
    }

    if (!isOriginAllowed(stickyUrl)) {
      return reject(403, `Origin ${stickyUrl.origin} is not in ALLOWED_ORIGINS`);
    }

    origin = stickyUrl.origin;
    parsedTarget = stickyUrl;

    const stickyBase = readCookie(req, BASE_COOKIE);
    if (stickyBase) {
      try {
        const baseUrl = parseTargetUrl(stickyBase);
        basePath =
          baseUrl.pathname && baseUrl.pathname !== '/' ? baseUrl.pathname.replace(/\/+$/, '') : '/';
        baseSearch = baseUrl.search || '';
      } catch {
        basePath = '/';
      }
    } else {
      basePath = '/';
    }
  }

  // Path composition.
  //
  // Proxy paths map 1:1 onto upstream paths so relative asset URLs, redirects
  // and media playlists resolve identically on both sides.
  //
  //  - explicit entry at "/" with a base path -> canonical 302 onto the base
  //    path (the redirect keeps the `_px` payload, so it stays self-resolving)
  //  - explicit entry at any other path   -> forwarded verbatim
  //  - sticky request at "/"              -> returns to the session entry point
  const extraQuery = buildQuery(segments); // excludes the `_px` parameter
  let needsRedirect = false;
  let redirectPath = null;
  let upstreamPath;
  let upstreamSearch;

  if (explicit) {
    if (pathname === '/' && basePath !== '/') {
      needsRedirect = true;
      const canonical = `${origin}${basePath}${baseSearch}`;
      const payload = Buffer.from(canonical, 'utf8').toString('base64url');
      redirectPath =
        `${basePath}?${ENTRY_PARAM}=${encodeURIComponent(payload)}` +
        (extraQuery ? `&${extraQuery.replace(/^\?/, '')}` : '');
      upstreamPath = basePath;
      upstreamSearch = mergeSearch(baseSearch, '');
    } else {
      upstreamPath = pathname;
      upstreamSearch =
        pathname === basePath ? mergeSearch(baseSearch, extraQuery) : mergeSearch('', extraQuery);
    }
  } else if (pathname === '/' && basePath !== '/') {
    upstreamPath = basePath;
    upstreamSearch = mergeSearch(baseSearch, '');
  } else {
    upstreamPath = pathname;
    upstreamSearch = mergeSearch('', extraQuery);
  }

  if (!upstreamPath.startsWith('/')) upstreamPath = `/${upstreamPath}`;

  const upstreamUrl = `${origin}${upstreamPath}${upstreamSearch}`;

  // The proxy engine forwards `req.url` verbatim (prependPath: false), so
  // this is the exact upstream path and query.
  req.url = `${upstreamPath}${upstreamSearch}`;

  // A lightweight description of the upstream. Parsing the assembled URL
  // again would cost a URL parse on every request, so the pieces are taken
  // from the target that was already parsed.
  const target = {
    origin,
    hostname: parsedTarget.hostname,
    host: parsedTarget.host,
    protocol: parsedTarget.protocol,
    href: upstreamUrl,
  };

  const resolution = {
    ok: true,
    origin,
    upstreamUrl,
    explicit,
    baseUrl: `${origin}${basePath}${baseSearch}`,
    target,
    needsRedirect,
    redirectPath,
    credentials: credentialsFor(target),
    attempts: 0,
  };

  req.px = resolution;
  return resolution;
}

/** Combines an upstream query string with additional proxy-side parameters. */
function mergeSearch(baseSearch, extraSearch) {
  const base = baseSearch || '';
  const extra = extraSearch || '';
  if (!base) return extra;
  if (!extra) return base;
  return `${base}&${extra.replace(/^\?/, '')}`;
}

/* ------------------------------------------------------------------ *
 * CORS
 * ------------------------------------------------------------------ */

/** Merges a value into a `Vary` header without discarding the existing one. */
function mergeVary(existing, value) {
  const values = String(existing || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

  if (!values.some((entry) => entry.toLowerCase() === value.toLowerCase())) {
    values.push(value);
  }

  return values.join(', ');
}

/**
 * Builds the CORS headers for a request. The caller's origin is echoed so
 * credentialed requests keep working; a literal wildcard would break them.
 */
function corsHeadersFor(req) {
  if (!CONFIG.enableCors) return null;

  const requestOrigin = req.headers ? req.headers.origin : null;
  const headers = {
    'access-control-allow-methods': 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD',
    'access-control-allow-headers':
      (req.headers && req.headers['access-control-request-headers']) || '*',
    'access-control-max-age': '86400',
    'access-control-expose-headers': '*',
  };

  if (requestOrigin) {
    headers['access-control-allow-origin'] = requestOrigin;
    headers['access-control-allow-credentials'] = 'true';
    headers.vary = 'Origin';
  } else {
    headers['access-control-allow-origin'] = '*';
  }

  return headers;
}

/** Applies CORS headers to a response generated by the proxy itself. */
function applyCorsHeaders(req, res) {
  const headers = corsHeadersFor(req);
  if (!headers) return;

  for (const [name, value] of Object.entries(headers)) {
    if (name === 'vary') {
      res.vary(value);
      continue;
    }
    res.set(name, value);
  }
}

/* ------------------------------------------------------------------ *
 * Session cookies
 * ------------------------------------------------------------------ */

function issueSessionCookies(req, resolution) {
  const secure = Boolean(req.secure || req.headers['x-forwarded-proto'] === 'https');
  const attributes = ['Path=/', `Max-Age=${STICKY_MAX_AGE}`, 'HttpOnly'];
  // `SameSite=None` requires `Secure`; without TLS fall back to `Lax` so the
  // browser still stores the cookie during local development.
  if (secure) {
    attributes.push('SameSite=None', 'Secure');
  } else {
    attributes.push('SameSite=Lax');
  }

  const build = (name, value) =>
    `${name}=${encodeURIComponent(value)}; ${attributes.join('; ')}`;

  return [build(STICKY_COOKIE, resolution.origin), build(BASE_COOKIE, resolution.baseUrl)];
}

function clearSessionCookies(res) {
  const attributes = [
    'Path=/',
    'Max-Age=0',
    'HttpOnly',
    'Expires=Thu, 01 Jan 1970 00:00:00 GMT',
  ];
  for (const name of [STICKY_COOKIE, BASE_COOKIE]) {
    res.append('Set-Cookie', `${name}=; ${attributes.join('; ')}`);
  }
}

function escapeHtml(value) {
  const amp = String.fromCharCode(38);
  const map = {
    '&': `${amp}amp;`,
    '<': `${amp}lt;`,
    '>': `${amp}gt;`,
    '"': `${amp}quot;`,
    "'": `${amp}#39;`,
  };
  return String(value || '').replace(/[&<>"']/g, (character) => map[character]);
}

/**
 * Renders the launcher. The inline stylesheet and script carry a per-request
 * nonce so the page can ship a strict Content-Security-Policy.
 */
function renderLauncher(nonce) {
  const example = escapeHtml(CONFIG.exampleTarget);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<meta name="robots" content="noindex, nofollow" />
<meta name="referrer" content="no-referrer" />
<title>Proxy Launcher</title>
<style nonce="${nonce}">
  :root {
    --bg: #090d16;
    --card: #111827;
    --card-2: #0d1424;
    --accent: #38bdf8;
    --accent-dim: rgba(56, 189, 248, 0.14);
    --text: #e5e7eb;
    --muted: #8b98ad;
    --border: #1f2a3c;
    --danger: #f87171;
  }
  * { box-sizing: border-box; }
  html, body { height: 100%; }
  body {
    margin: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 24px;
    background: radial-gradient(1200px 600px at 50% -10%, #14243c 0%, var(--bg) 60%);
    color: var(--text);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    -webkit-font-smoothing: antialiased;
  }
  .card {
    width: 100%;
    max-width: 620px;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 16px;
    padding: 32px;
    box-shadow: 0 24px 60px rgba(0, 0, 0, 0.45);
  }
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    font-size: 12px;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: var(--accent);
    background: var(--accent-dim);
    border: 1px solid rgba(56, 189, 248, 0.28);
    border-radius: 999px;
    padding: 6px 12px;
  }
  .dot { width: 7px; height: 7px; border-radius: 50%; background: var(--accent); }
  h1 { font-size: 24px; margin: 18px 0 8px; font-weight: 650; letter-spacing: -0.01em; }
  p.sub { margin: 0 0 24px; color: var(--muted); font-size: 14px; line-height: 1.6; }
  form { display: flex; flex-direction: column; gap: 12px; }
  label {
    font-size: 12px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.08em;
  }
  input {
    width: 100%;
    background: var(--card-2);
    border: 1px solid var(--border);
    border-radius: 10px;
    color: var(--text);
    font-size: 15px;
    padding: 14px 16px;
    outline: none;
    transition: border-color 0.15s ease, box-shadow 0.15s ease;
  }
  input:focus { border-color: var(--accent); box-shadow: 0 0 0 3px var(--accent-dim); }
  input::placeholder { color: #5b6779; }
  .row { display: flex; gap: 10px; }
  .row input { flex: 1; }
  button {
    background: var(--accent);
    color: #04121d;
    border: 0;
    border-radius: 10px;
    padding: 14px 18px;
    font-size: 15px;
    font-weight: 650;
    cursor: pointer;
    transition: filter 0.15s ease, transform 0.05s ease;
    white-space: nowrap;
  }
  button:hover { filter: brightness(1.08); }
  button:active { transform: translateY(1px); }
  button:disabled { opacity: 0.6; cursor: progress; }
  button.ghost {
    background: transparent;
    color: var(--muted);
    border: 1px solid var(--border);
    font-weight: 550;
  }
  button.ghost:hover { color: var(--text); border-color: var(--accent); filter: none; }
  .error {
    display: none;
    margin-top: 14px;
    padding: 12px 14px;
    border-radius: 10px;
    background: rgba(239, 68, 68, 0.12);
    border: 1px solid rgba(239, 68, 68, 0.35);
    color: #fca5a5;
    font-size: 13px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    word-break: break-word;
  }
  .error.visible { display: block; }
  .section { margin-top: 24px; }
  .section h2 {
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.1em;
    margin: 0 0 10px;
    font-weight: 600;
  }
  .chips { display: flex; flex-wrap: wrap; gap: 8px; }
  .chip {
    background: var(--card-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--muted);
    font-size: 12.5px;
    padding: 7px 11px;
    cursor: pointer;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    transition: border-color 0.15s ease, color 0.15s ease;
  }
  .chip:hover { border-color: var(--accent); color: var(--text); }
  .meta {
    margin-top: 24px;
    padding-top: 18px;
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--muted);
    line-height: 1.8;
  }
  .meta code {
    background: var(--card-2);
    border: 1px solid var(--border);
    border-radius: 5px;
    padding: 1px 6px;
    font-size: 11px;
  }
  .meta a { color: var(--accent); text-decoration: none; }
  .meta a:hover { text-decoration: underline; }
  kbd {
    background: var(--card-2);
    border: 1px solid var(--border);
    border-bottom-width: 2px;
    border-radius: 5px;
    padding: 1px 6px;
    font-size: 11px;
  }
  [hidden] { display: none !important; }
  @media (max-width: 520px) {
    .card { padding: 24px 20px; border-radius: 14px; }
    h1 { font-size: 20px; }
    .row { flex-direction: column; }
  }
</style>
</head>
<body>
  <main class="card">
    <span class="badge"><span class="dot"></span>Reverse Proxy</span>
    <h1>Launch a proxied session</h1>
    <p class="sub">
      Enter the target origin. A sticky session is opened and background asset, API and
      media requests are routed back to the same upstream automatically.
    </p>

    <form id="launcher" autocomplete="off">
      <label for="target">Target URL</label>
      <input id="target" name="target" type="text" inputmode="url" spellcheck="false"
             placeholder="https://example.com/path" value="${example}" />
      <div class="row">
        <button id="submit" type="submit">Open session</button>
        <button id="copy" class="ghost" type="button">Copy link</button>
      </div>
    </form>

    <div id="error" class="error" role="alert" aria-live="assertive"></div>

    <div class="section" id="recent-section" hidden>
      <h2>Recent targets</h2>
      <div class="chips" id="recent"></div>
    </div>

    <div class="meta">
      Direct link format: <code>/?_px=<base64></code><br />
      Press <kbd>Enter</kbd> to launch. Sessions expire after 4 hours.<br />
      <a href="/_px/new">Reset session</a>
    </div>
  </main>

<script nonce="${nonce}">
(function () {
  var form = document.getElementById('launcher');
  var input = document.getElementById('target');
  var submit = document.getElementById('submit');
  var copyButton = document.getElementById('copy');
  var errorBox = document.getElementById('error');
  var recentSection = document.getElementById('recent-section');
  var recentList = document.getElementById('recent');
  var STORAGE_KEY = 'px.recent.targets';
  var MAX_RECENT = 5;

  function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.add('visible');
    input.focus();
  }

  function clearError() {
    errorBox.textContent = '';
    errorBox.classList.remove('visible');
  }

  // UTF-8 safe base64 encoding (btoa alone throws on non-Latin-1 characters).
  function encodeBase64(value) {
    var bytes = new TextEncoder().encode(value);
    var binary = '';
    for (var i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  function normalizeTarget(raw) {
    var value = String(raw || '').trim();
    if (!value) {
      throw new Error('Enter a target URL.');
    }
    if (!/^https?:\\/\\//i.test(value)) {
      value = 'https://' + value;
    }
    var parsed;
    try {
      parsed = new URL(value);
    } catch (error) {
      throw new Error('That does not look like a valid URL.');
    }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('Only http and https targets are supported.');
    }
    return parsed.toString();
  }

  function sessionUrl(target) {
    return '/?_px=' + encodeURIComponent(encodeBase64(target));
  }

  function readRecent() {
    try {
      var raw = window.localStorage.getItem(STORAGE_KEY);
      var parsed = raw ? JSON.parse(raw) : [];
      return Array.isArray(parsed) ? parsed.filter(function (item) {
        return typeof item === 'string';
      }) : [];
    } catch (error) {
      return [];
    }
  }

  function writeRecent(targets) {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(targets.slice(0, MAX_RECENT)));
    } catch (error) {
      /* storage unavailable (private mode): recent targets are optional */
    }
  }

  function remember(target) {
    var targets = readRecent().filter(function (item) { return item !== target; });
    targets.unshift(target);
    writeRecent(targets);
  }

  function renderRecent() {
    var targets = readRecent();
    if (!targets.length) {
      recentSection.hidden = true;
      return;
    }
    recentList.textContent = '';
    targets.slice(0, MAX_RECENT).forEach(function (target) {
      var chip = document.createElement('button');
      chip.type = 'button';
      chip.className = 'chip';
      chip.textContent = target;
      chip.title = target;
      chip.addEventListener('click', function () {
        input.value = target;
        clearError();
        input.focus();
      });
      recentList.appendChild(chip);
    });
    recentSection.hidden = false;
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    clearError();
    var target;
    try {
      target = normalizeTarget(input.value);
    } catch (error) {
      showError(error.message);
      return;
    }
    remember(target);
    submit.disabled = true;
    window.location.assign(sessionUrl(target));
  });

  copyButton.addEventListener('click', function () {
    clearError();
    var target;
    try {
      target = normalizeTarget(input.value);
    } catch (error) {
      showError(error.message);
      return;
    }
    var url = window.location.origin + sessionUrl(target);
    var done = function () {
      copyButton.textContent = 'Copied';
      window.setTimeout(function () { copyButton.textContent = 'Copy link'; }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(done, function () {
        showError('Clipboard unavailable. The link is: ' + url);
      });
      return;
    }
    showError('Clipboard unavailable. The link is: ' + url);
  });

  input.addEventListener('input', clearError);
  renderRecent();
})();
</script>
</body>
</html>`;
}

/* ------------------------------------------------------------------ *
 * Application
 * ------------------------------------------------------------------ */

const app = express();

app.set('trust proxy', TRUST_PROXY);
app.disable('x-powered-by');
app.disable('etag');

/** Constant-time comparison for the optional access token. */
function safeEqual(a, b) {
  const left = Buffer.from(String(a || ''));
  const right = Buffer.from(String(b || ''));
  if (left.length !== right.length) return false;
  return crypto.timingSafeEqual(left, right);
}

function clientKey(req) {
  const raw = req.ip || (req.socket && req.socket.remoteAddress) || 'unknown';
  // Normalise the IPv4-mapped IPv6 form (`::ffff:127.0.0.1`) so the same
  // client always lands in the same bucket regardless of how its address was
  // expressed by the socket or by a forwarding header.
  return String(raw).replace(/^::ffff:/i, '');
}

/** Request context: correlation id, timing, metrics and access logging. */
app.use((req, res, next) => {
  const supplied = String(req.headers['x-request-id'] || '')
    .slice(0, 64)
    .replace(/[^A-Za-z0-9._-]/g, '');
  req.requestId = supplied || crypto.randomUUID();
  res.setHeader('x-request-id', req.requestId);

  const startedAt = process.hrtime.bigint();
  METRICS.active++;
  let settled = false;

  const settle = () => {
    if (settled) return;
    settled = true;
    METRICS.active--;
    const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
    METRICS.requests++;
    observeDuration(durationMs);
    // The payload is only built when the level would actually be emitted.
    if (logEnabled('info')) {
      log('info', 'request', {
        requestId: req.requestId,
        method: req.method,
        // The path only: query strings routinely carry tokens.
        path: String(req.originalUrl || req.url || '/').split('?')[0],
        status: res.statusCode,
        durationMs: Number(durationMs.toFixed(2)),
        clientIp: clientKey(req),
        target: req.px && req.px.ok ? req.px.origin : undefined,
      });
    }
  };

  res.on('finish', settle);
  res.on('close', settle);
  next();
});

app.get('/healthz', (req, res) => {
  res.status(200).json({
    status: 'ok',
    uptime: Math.round(process.uptime()),
    active: METRICS.active,
  });
});

app.get('/readyz', (req, res) => {
  const ready = CONFIG.allowedOrigins.length > 0 || !IS_PRODUCTION;
  res.status(ready ? 200 : 503).json({
    status: ready ? 'ready' : 'not_ready',
    allowlistSize: CONFIG.allowedOrigins.length,
  });
});

// CORS preflight is answered locally so the upstream never sees it. It runs
// before the access check because preflights cannot carry credentials.
app.options('*', (req, res) => {
  if (!CONFIG.enableCors) {
    res.status(204).end();
    return;
  }
  const requestOrigin = req.headers.origin;
  res
    .status(204)
    .set('Access-Control-Allow-Origin', requestOrigin || '*')
    .set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD')
    .set('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || '*')
    .set('Access-Control-Max-Age', '86400')
    .end();
});

// Optional authentication in front of the proxy. Health probes stay open so
// the platform can still reach them.
app.use((req, res, next) => {
  if (!CONFIG.accessToken && !CONFIG.accessUser) {
    next();
    return;
  }

  const header = String(req.headers.authorization || '');
  let authorised = false;

  if (CONFIG.accessToken && header.startsWith('Bearer ')) {
    authorised = safeEqual(header.slice(7).trim(), CONFIG.accessToken);
  } else if (CONFIG.accessUser && header.startsWith('Basic ')) {
    const decoded = Buffer.from(header.slice(6).trim(), 'base64').toString('utf8');
    const separator = decoded.indexOf(':');
    const user = separator === -1 ? decoded : decoded.slice(0, separator);
    const password = separator === -1 ? '' : decoded.slice(separator + 1);
    authorised = safeEqual(user, CONFIG.accessUser) && safeEqual(password, CONFIG.accessPassword);
  } else if (!CONFIG.accessToken && CONFIG.accessUser) {
    const provided = String(req.headers['x-proxy-token'] || '').trim();
    authorised = safeEqual(provided, CONFIG.accessPassword);
  }

  if (!authorised) {
    METRICS.rejected++;
    applyCorsHeaders(req, res);
    res
      .status(401)
      .set('WWW-Authenticate', 'Basic realm="proxy", charset="UTF-8"')
      .json({ error: 'unauthorized', message: 'Valid proxy credentials are required.' });
    return;
  }

  next();
});

app.get('/metrics', (req, res) => {
  res.status(200).set('Content-Type', 'text/plain; version=0.0.4; charset=utf-8').send(renderMetrics());
});

app.get('/_px/session', (req, res) => {
  const target = readCookie(req, STICKY_COOKIE);
  const base = readCookie(req, BASE_COOKIE);
  res.status(200).json({
    active: Boolean(target),
    target: target || null,
    base: base || null,
    maxAgeSeconds: STICKY_MAX_AGE,
  });
});

app.get('/_px/new', (req, res) => {
  clearSessionCookies(res);
  res.status(302).set('Cache-Control', 'no-store').redirect('/');
});

// A tiny inline favicon keeps the access log free of 404 noise.
app.get('/favicon.ico', (req, res) => {
  const icon =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">' +
    '<rect width="32" height="32" rx="7" fill="#111827"/>' +
    '<circle cx="16" cy="16" r="6" fill="none" stroke="#38bdf8" stroke-width="2.5"/>' +
    '<path d="M16 4v4M16 24v4M4 16h4M24 16h4" stroke="#38bdf8" stroke-width="2.5" stroke-linecap="round"/>' +
    '</svg>';
  res.status(200).set('Content-Type', 'image/svg+xml').set('Cache-Control', 'public, max-age=86400').send(icon);
});

// Resolve the session and normalise the outgoing URL before proxying.
app.use(async (req, res, next) => {
  try {
    const rawUrl = req.originalUrl || req.url || '/';

    // Session creation is rate limited; media and asset traffic is not.
    if (rawUrl.includes(`${ENTRY_PARAM}=`)) {
      if (!checkRateLimit(clientKey(req), CONFIG.rateLimitMax, CONFIG.rateLimitWindowMs)) {
        METRICS.rateLimited++;
        applyCorsHeaders(req, res);
        res
          .status(429)
          .set('Retry-After', String(Math.ceil(CONFIG.rateLimitWindowMs / 1000)))
          .json({ error: 'rate_limited', message: 'Too many sessions opened. Try again shortly.' });
        return;
      }
    }

    const resolution = await resolveTarget(req);

    if (!resolution.ok) {
      const isRoot = (req.path || '/') === '/';

      // No session and no explicit target: render the launcher on the root path.
      if (resolution.status === 400 && !resolution.hasEntry && !resolution.hasSession && isRoot) {
        const nonce = crypto.randomBytes(16).toString('base64');
        res
          .status(200)
          .set('Cache-Control', 'no-store')
          .set(
            'Content-Security-Policy',
            [
              "default-src 'none'",
              `style-src 'nonce-${nonce}'`,
              `script-src 'nonce-${nonce}'`,
              'img-src data:',
              "connect-src 'self'",
              "base-uri 'none'",
              "form-action 'none'",
              "frame-ancestors 'none'",
            ].join('; ')
          )
          .set('X-Content-Type-Options', 'nosniff')
          .set('Referrer-Policy', 'no-referrer')
          .type('html')
          .send(renderLauncher(nonce));
        return;
      }

      METRICS.rejected++;
      applyCorsHeaders(req, res);
      res.status(resolution.status).json({
        error: resolution.status === 403 ? 'forbidden' : 'bad_request',
        message: resolution.reason,
      });
      return;
    }

    if (resolution.explicit) METRICS.sessions++;

    // Refresh the sticky session on every proxied response (sliding expiry).
    resolution.sessionCookies = issueSessionCookies(req, resolution);

    if (resolution.needsRedirect) {
      // Canonicalise the entry point so relative asset URLs resolve correctly.
      for (const cookie of resolution.sessionCookies) {
        res.append('Set-Cookie', cookie);
      }
      res.status(302).set('Cache-Control', 'no-store').redirect(resolution.redirectPath);
      return;
    }

    next();
  } catch (error) {
    next(error);
  }
});

// Bound the size of proxied request bodies.
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD') {
    next();
    return;
  }

  const declared = Number(req.headers['content-length'] || 0);
  if (declared > CONFIG.bodyLimitBytes) {
    METRICS.rejected++;
    applyCorsHeaders(req, res);
    res
      .status(413)
      .json({ error: 'payload_too_large', message: 'Request body exceeds the configured limit.' });
    return;
  }

  // Chunked bodies carry no content-length and are counted while they are
  // forwarded, from the proxy hook (see below), where the upstream pipe is
  // already attached. Attaching a reader here would switch the request
  // stream to flowing mode before the proxy pipes it, dropping the body.
  next();
});

/**
 * The proxy engine. `router` resolves the upstream origin per request, which
 * also covers WebSocket upgrades, which bypass the Express pipeline.
 */
let proxyMiddleware;

const upstreamAgent = createUpstreamAgent();

proxyMiddleware = createProxyMiddleware({
  target: 'http://127.0.0.1',
  agent: upstreamAgent,
  router: async (req) => {
    const resolution = await resolveTarget(req);
    if (!resolution.ok) {
      throw new Error(resolution.reason);
    }
    return resolution.origin;
  },
  changeOrigin: true,
  secure: false, // accept self-signed certificates on the upstream origin
  xfwd: CONFIG.forwardedHeaders,
  ws: true,
  prependPath: false,
  proxyTimeout: 0,
  timeout: 0,

  on: {
    proxyReq: (proxyReq, req, res) => {
      const resolution = req.px;
      const targetOrigin = resolution && resolution.ok ? resolution.origin : null;

      // Timestamp the upstream attempt so response latency can be separated
      // from total request time.
      if (resolution) resolution.upstreamStartedAt = process.hrtime.bigint();

      // Never advertise the proxy chain. `proxyReq` is a ClientRequest, so
      // headers are manipulated through its header API.
      for (const header of HOP_BY_HOP_HEADERS) {
        proxyReq.removeHeader(header);
      }

      // Drop client supplied forwarding headers: they would either expose the
      // proxy or let a client spoof its own address upstream.
      for (const header of FORWARDING_HEADERS) {
        proxyReq.removeHeader(header);
      }

      // Keep the sticky-session cookies on the proxy side. The common case is
      // a request that carries no proxy cookies at all, so the header is left
      // untouched rather than parsed and rebuilt.
      const incomingCookie = proxyReq.getHeader('cookie');
      if (
        incomingCookie &&
        (incomingCookie.includes(STICKY_COOKIE) || incomingCookie.includes(BASE_COOKIE))
      ) {
        const filtered = parseCookieHeader(incomingCookie);
        delete filtered[STICKY_COOKIE];
        delete filtered[BASE_COOKIE];
        const rebuilt = Object.keys(filtered)
          .map((key) => `${key}=${filtered[key]}`)
          .join('; ');
        if (rebuilt) {
          proxyReq.setHeader('cookie', rebuilt);
        } else {
          proxyReq.removeHeader('cookie');
        }
      }

      if (targetOrigin) {
        // Fingerprint fidelity: a real browser's own user agent and client
        // hints are internally consistent. Replacing them with a fixed
        // profile risks contradicting the hints the client still sends, which
        // is a stronger tell than either version alone. Browser clients are
        // therefore relayed verbatim; non-browser clients are normalised onto
        // the built-in profile so they do not announce themselves as scripts.
        //
        // The profile is applied as a whole: a browser identity paired with a
        // script's `accept-language: *` is just as inconsistent as the
        // reverse, so either everything is relayed or everything is replaced.
        const useBuiltInProfile = CONFIG.overrideFingerprint || !isBrowserLike(proxyReq);

        if (useBuiltInProfile) {
          proxyReq.setHeader('user-agent', FINGERPRINT.userAgent);
          proxyReq.setHeader('sec-ch-ua', FINGERPRINT.secChUa);
          proxyReq.setHeader('sec-ch-ua-mobile', FINGERPRINT.secChUaMobile);
          proxyReq.setHeader('sec-ch-ua-platform', FINGERPRINT.secChUaPlatform);
          proxyReq.setHeader('accept-language', FINGERPRINT.acceptLanguage);
          proxyReq.setHeader('accept', FINGERPRINT.accept);
        }

        // Origin: relayed only when the client sent one, rewritten onto the
        // upstream origin so the proxy domain never appears upstream.
        const clientOrigin = proxyReq.getHeader('origin');
        if (CONFIG.originHeaders === 'always') {
          proxyReq.setHeader('origin', targetOrigin);
        } else if (CONFIG.originHeaders === 'never') {
          proxyReq.removeHeader('origin');
        } else if (clientOrigin) {
          proxyReq.setHeader('origin', targetOrigin);
        } else {
          proxyReq.removeHeader('origin');
        }

        // Referer: the client's referer is rewritten onto the upstream origin
        // (keeping its path) so that the proxy domain is never disclosed.
        const clientReferer = proxyReq.getHeader('referer');
        if (CONFIG.originHeaders === 'always') {
          proxyReq.setHeader('referer', `${targetOrigin}/`);
        } else if (CONFIG.originHeaders === 'never') {
          proxyReq.removeHeader('referer');
        } else if (clientReferer) {
          try {
            const referer = new URL(clientReferer);
            proxyReq.setHeader(
              'referer',
              `${targetOrigin}${referer.pathname}${referer.search}`
            );
          } catch {
            proxyReq.setHeader('referer', `${targetOrigin}/`);
          }
        } else {
          proxyReq.removeHeader('referer');
        }

        // Compression negotiation is relayed so the upstream responds exactly
        // as it would for the original client. Bodies are streamed untouched,
        // so the encoding always matches what the client asked for.
        if (CONFIG.stripAcceptEncoding) {
          proxyReq.removeHeader('accept-encoding');
        }

        // The correlation id belongs to our own logs, not to the upstream.
        if (CONFIG.forwardRequestId) {
          proxyReq.setHeader('x-request-id', req.requestId || '');
        } else {
          proxyReq.removeHeader('x-request-id');
        }

        // Upstream Basic credentials from the allowlist entry, if configured.
        if (resolution.credentials) {
          const { username, password } = resolution.credentials;
          const encoded = Buffer.from(`${username}:${password}`, 'utf8').toString('base64');
          proxyReq.setHeader('authorization', `Basic ${encoded}`);
        }
      }

      // Stream request bodies through (POST/PUT/PATCH).
      if (req.method !== 'GET' && req.method !== 'HEAD') {
        // Chunked uploads carry no content-length: count them as they are
        // forwarded. This runs once the upstream pipe is attached, so the
        // body is never lost.
        if (!req.headers['content-length']) {
          let received = 0;
          req.on('data', (chunk) => {
            received += chunk.length;
            if (received > CONFIG.bodyLimitBytes) {
              if (res && !res.headersSent) {
                METRICS.rejected++;
                res.status(413).json({
                  error: 'payload_too_large',
                  message: 'Request body exceeds the configured limit.',
                });
              }
              proxyReq.destroy();
              req.destroy();
            }
          });
        }

        fixRequestBody(proxyReq, req);
      }
    },

    proxyRes: (proxyRes, req) => {
      const resolution = req.px;
      const targetOrigin = resolution && resolution.ok ? resolution.origin : null;
      const stripAllowed =
        resolution && resolution.ok ? isHeaderStripAllowed(resolution.target) : false;

      METRICS.upstreamRequests++;
      if (resolution && resolution.upstreamStartedAt) {
        METRICS.upstreamDurationSumMs +=
          Number(process.hrtime.bigint() - resolution.upstreamStartedAt) / 1e6;
      }

      // Count streamed bytes without consuming the stream.
      proxyRes.on('data', (chunk) => {
        METRICS.bytesOut += chunk.length;
      });

      if (stripAllowed) {
        for (const header of STRIPPED_RESPONSE_HEADERS) {
          delete proxyRes.headers[header];
        }
      }

      if (CONFIG.enableCors) {
        // Echo the caller's origin so credentialed requests keep working;
        // fall back to a wildcard for non-browser clients.
        const corsHeaders = corsHeadersFor(req);
        for (const [name, value] of Object.entries(corsHeaders)) {
          if (name === 'vary') {
            // Preserve whatever the upstream varied on.
            proxyRes.headers.vary = mergeVary(proxyRes.headers.vary, value);
            continue;
          }
          proxyRes.headers[name] = value;
        }
      }

      // Keep upstream cookies working on the proxy domain, and append the
      // sticky-session cookies (upstream Set-Cookie headers would otherwise
      // replace them entirely when the response headers are written).
      const upstreamCookies = Array.isArray(proxyRes.headers['set-cookie'])
        ? proxyRes.headers['set-cookie']
        : proxyRes.headers['set-cookie']
          ? [proxyRes.headers['set-cookie']]
          : [];

      // A browser drops `Secure` cookies received over plain HTTP, which
      // would silently break the upstream session outside TLS deployments.
      const clientIsSecure = Boolean(req.secure || req.headers['x-forwarded-proto'] === 'https');

      const cleanedCookies = upstreamCookies.map((cookie) => {
        let cleaned = cookie.replace(/;\s*domain=[^;]*/gi, '');
        if (!clientIsSecure) cleaned = cleaned.replace(/;\s*Secure/gi, '');
        return cleaned;
      });

      if (resolution && resolution.ok && Array.isArray(resolution.sessionCookies)) {
        cleanedCookies.push(...resolution.sessionCookies);
      }

      if (cleanedCookies.length > 0) {
        proxyRes.headers['set-cookie'] = cleanedCookies;
      }

      // Rewrite same-origin redirects back onto the proxy domain.
      const location = proxyRes.headers.location;
      if (location && targetOrigin) {
        try {
          const resolved = new URL(location, targetOrigin);
          if (resolved.origin === targetOrigin) {
            proxyRes.headers.location =
              publicOriginOf(req) + resolved.pathname + resolved.search + resolved.hash;
          }
        } catch {
          /* leave malformed Location headers untouched */
        }
      }

      // Streaming responses should not be buffered by intermediaries.
      proxyRes.headers['x-accel-buffering'] = 'no';
    },

    proxyReqWs: (proxyReq, req) => {
      const resolution = req.px;
      if (!resolution || !resolution.ok) return;

      const incomingCookie = proxyReq.getHeader('cookie');
      if (
        incomingCookie &&
        (incomingCookie.includes(STICKY_COOKIE) || incomingCookie.includes(BASE_COOKIE))
      ) {
        const filtered = parseCookieHeader(incomingCookie);
        delete filtered[STICKY_COOKIE];
        delete filtered[BASE_COOKIE];
        const rebuilt = Object.keys(filtered)
          .map((key) => `${key}=${filtered[key]}`)
          .join('; ');
        if (rebuilt) {
          proxyReq.setHeader('cookie', rebuilt);
        } else {
          proxyReq.removeHeader('cookie');
        }
      }

      // The same fidelity rules apply to upgrade requests.
      if (CONFIG.overrideFingerprint || !isBrowserLike(proxyReq)) {
        proxyReq.setHeader('user-agent', FINGERPRINT.userAgent);
        proxyReq.setHeader('sec-ch-ua', FINGERPRINT.secChUa);
        proxyReq.setHeader('sec-ch-ua-mobile', FINGERPRINT.secChUaMobile);
        proxyReq.setHeader('sec-ch-ua-platform', FINGERPRINT.secChUaPlatform);
        proxyReq.setHeader('accept-language', FINGERPRINT.acceptLanguage);
        proxyReq.setHeader('accept', FINGERPRINT.accept);
      }

      if (CONFIG.originHeaders !== 'never') {
        proxyReq.setHeader('origin', resolution.origin);
        proxyReq.setHeader('referer', `${resolution.origin}/`);
      }

      if (CONFIG.stripAcceptEncoding) {
        proxyReq.removeHeader('accept-encoding');
      }

      proxyReq.removeHeader('x-request-id');
    },

    error: (error, req, res) => {
      METRICS.upstreamErrors++;

      const resolution = req.px;
      const code = error && error.code;
      const retryable =
        resolution &&
        resolution.ok &&
        IDEMPOTENT_METHODS.has(req.method) &&
        RETRYABLE_CODES.has(code) &&
        !res.headersSent &&
        (resolution.attempts || 0) < CONFIG.retryAttempts;

      if (retryable) {
        resolution.attempts += 1;
        METRICS.retries++;
        const delay =
          CONFIG.retryBaseDelayMs * 2 ** (resolution.attempts - 1) + Math.floor(Math.random() * 50);
        log('warn', 'upstream failure, retrying', {
          requestId: req.requestId,
          code,
          attempt: resolution.attempts,
          delayMs: delay,
        });
        setTimeout(() => {
          proxyMiddleware(req, res, (nextError) => {
            if (nextError) sendProxyError(nextError, req, res);
          });
        }, delay);
        return;
      }

      sendProxyError(error, req, res);
    },
  },
});

function sendProxyError(error, req, res) {
  if (!res) return;

  // A raw socket (WebSocket upgrade path) has no HTTP response API.
  if (typeof res.writeHead !== 'function' && typeof res.destroy === 'function') {
    res.destroy();
    return;
  }

  if (res.headersSent) {
    if (typeof res.end === 'function') res.end();
    return;
  }

  METRICS.errors++;
  log('error', 'upstream failure', {
    requestId: req && req.requestId,
    code: error && error.code,
    message: error && error.message,
  });

  applyCorsHeaders(req, res);

  res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(
    JSON.stringify({
      error: 'bad_gateway',
      message: 'The upstream origin could not be reached.',
    })
  );
}

app.use(proxyMiddleware);

// Final error handler: never let a request take the process down.
app.use((error, req, res, next) => {
  METRICS.errors++;
  log('error', 'unhandled request error', {
    requestId: req && req.requestId,
    message: error && error.message,
  });
  if (res.headersSent) {
    res.end();
    return;
  }
  applyCorsHeaders(req, res);
  res.status(500).json({ error: 'internal_error', message: 'Unexpected server error.' });
});

/* ------------------------------------------------------------------ *
 * Server lifecycle
 * ------------------------------------------------------------------ */

const server = http.createServer(app);

// Render closes idle connections; these values keep long-lived streams alive.
server.keepAliveTimeout = 65000;
server.headersTimeout = 70000;
server.requestTimeout = 0;
server.maxHeadersCount = 100;

// Malformed requests must not surface as uncaught exceptions.
server.on('clientError', (error, socket) => {
  if (!socket || socket.destroyed) return;
  log('warn', 'client error', { code: error && error.code });
  socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n');
});

// WebSocket upgrades bypass the Express pipeline, so they are routed through
// the same resolver via the proxy engine's `router` option.
//
// The proxy engine subscribes to `upgrade` itself once `ws: true` is set and
// the first request arrives. This listener only handles the window before
// that happens, avoiding a double-handled upgrade.
server.on('upgrade', (req, socket, head) => {
  if (server.listenerCount('upgrade') > 1) return; // the engine handles it
  if (typeof proxyMiddleware.upgrade === 'function') {
    proxyMiddleware.upgrade(req, socket, head);
  } else {
    socket.destroy();
  }
});

server.listen(PORT, () => {
  log('info', 'server listening', {
    port: PORT,
    allowlistSize: CONFIG.allowedOrigins.length,
    allowlist: redactList(CONFIG.allowedOrigins),
    authentication: CONFIG.accessToken
      ? 'bearer'
      : CONFIG.accessUser
        ? 'basic'
        : 'none',
  });
});

process.on('uncaughtException', (error) => {
  log('error', 'uncaught exception (server kept alive)', { message: error && error.message });
});

process.on('unhandledRejection', (reason) => {
  log('error', 'unhandled rejection (server kept alive)', { reason: String(reason) });
});

let shuttingDown = false;

function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  log('info', 'shutdown requested', { signal, graceMs: CONFIG.shutdownGraceMs });

  let finished = false;
  const finish = () => {
    if (finished) return;
    finished = true;
    log('info', 'shutdown complete');
    process.exit(0);
  };

  server.close(finish);
  if (typeof server.closeIdleConnections === 'function') server.closeIdleConnections();

  const timer = setTimeout(() => {
    if (typeof server.closeAllConnections === 'function') server.closeAllConnections();
    finish();
  }, CONFIG.shutdownGraceMs);
  timer.unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

module.exports = {
  app,
  server,
  internals: {
    CONFIG,
    METRICS,
    decodeBase64Target,
    parseRawQuery,
    buildQuery,
    compileAllowlist,
    isPrivateAddress,
    resolveTarget,
    renderMetrics,
  },
};
