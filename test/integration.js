'use strict';

/**
 * End-to-end integration suite.
 *
 * Covers routing, sticky sessions, base64 repair, header fingerprinting,
 * response sanitisation, CORS, redirect rewriting, streaming, WebSockets,
 * allowlist enforcement, SSRF containment, rate limiting, access control,
 * retries, connection pooling and the operational endpoints.
 *
 * Usage: node test/integration.js
 */

const http = require('http');
const net = require('net');
const crypto = require('crypto');
const assert = require('assert');
const path = require('path');
const { spawn } = require('child_process');

const SERVER_PATH = path.join(__dirname, '..', 'server.js');

const UPSTREAM_PORT = 45901;
const PROXY_PORT = 45902;
const UPSTREAM_ORIGIN = `http://127.0.0.1:${UPSTREAM_PORT}`;
const PROXY_ORIGIN = `http://127.0.0.1:${PROXY_PORT}`;

const CHUNK_SIZE = 512 * 1024;
const CHUNK_BYTES = Buffer.alloc(CHUNK_SIZE, 7);

let passed = 0;
const failures = [];
const upstreamSockets = [];
const spawnedChildren = [];

/** Kills every child started by the harness, whatever the outcome. */
function cleanupChildren() {
  for (const child of spawnedChildren) {
    if (child && child.exitCode === null) {
      try {
        child.kill('SIGKILL');
      } catch {
        /* already gone */
      }
    }
  }
}

process.on('exit', cleanupChildren);

/* ----------------------------- harness ----------------------------- */

async function scenario(name, fn) {
  try {
    await fn();
    passed += 1;
    console.log(`  ok   ${name}`);
  } catch (error) {
    failures.push({ name, error });
    console.log(`  FAIL ${name}\n       ${error.message}`);
  }
}

function section(title) {
  console.log(`\n${title}`);
}

function setCookies(response) {
  if (typeof response.headers.getSetCookie === 'function') return response.headers.getSetCookie();
  const raw = response.headers.get('set-cookie');
  return raw ? [raw] : [];
}

function stickyCookieHeader(response) {
  const cookies = setCookies(response)
    .map((cookie) => cookie.split(';')[0])
    .filter((cookie) => cookie.startsWith('_px_target=') || cookie.startsWith('_px_base='));
  return cookies.join('; ');
}

function encodeTarget(value) {
  return Buffer.from(value, 'utf8').toString('base64');
}

/* ----------------------------- upstream ----------------------------- */

let socketCounter = 0;
let flakyHits = 0;

function startUpstream() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, UPSTREAM_ORIGIN);

    if (url.pathname === '/') {
      res.writeHead(200, {
        'Content-Type': 'text/html; charset=utf-8',
        'Content-Security-Policy': "default-src 'none'",
        'X-Frame-Options': 'DENY',
        'Cross-Origin-Opener-Policy': 'same-origin',
        'Cross-Origin-Embedder-Policy': 'require-corp',
        'Cross-Origin-Resource-Policy': 'same-origin',
        'X-Powered-By': 'UpstreamApp',
        Server: 'UpstreamServer/1.0',
        'Set-Cookie': 'sid=abc123; Path=/; HttpOnly; SameSite=Lax',
      });
      res.end('<html><body>upstream root</body></html>');
      return;
    }

    if (url.pathname === '/echo') {
      res.writeHead(200, {
        'Content-Type': 'application/json',
        // The proxy must not discard the upstream's own Vary header.
        Vary: 'Accept-Encoding',
        'Set-Cookie': 'secure_sid=1; Path=/; Secure; HttpOnly',
      });
      res.end(
        JSON.stringify({
          url: req.url,
          method: req.method,
          headers: req.headers,
        })
      );
      return;
    }

    if (url.pathname === '/echo-body') {
      const chunks = [];
      req.on('data', (chunk) => chunks.push(chunk));
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(
          JSON.stringify({
            method: req.method,
            length: Buffer.concat(chunks).length,
            body: Buffer.concat(chunks).toString('utf8'),
            contentType: req.headers['content-type'] || null,
          })
        );
      });
      return;
    }

    if (url.pathname === '/socket-id') {
      // Identifies the upstream TCP connection that served the request.
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ socketId: req.socket.__pxId, header: req.headers['x-request-id'] }));
      return;
    }

    if (url.pathname === '/range') {
      const payload = Buffer.from('0123456789');
      const range = req.headers.range;
      if (range) {
        const match = /bytes=(\d+)-(\d*)/.exec(range);
        const start = match ? Number(match[1]) : 0;
        const end = match && match[2] ? Number(match[2]) : payload.length - 1;
        const slice = payload.slice(start, end + 1);
        res.writeHead(206, {
          'Content-Type': 'application/octet-stream',
          'Content-Range': `bytes ${start}-${end}/${payload.length}`,
          'Content-Length': String(slice.length),
          'Accept-Ranges': 'bytes',
        });
        res.end(slice);
        return;
      }
      res.writeHead(200, {
        'Content-Type': 'application/octet-stream',
        'Content-Length': String(payload.length),
        'Accept-Ranges': 'bytes',
      });
      res.end(payload);
      return;
    }

    if (url.pathname === '/flaky') {
      // Destroy the socket on the first attempt so the proxy must retry.
      flakyHits += 1;
      if (flakyHits === 1) {
        req.socket.destroy();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end('recovered');
      return;
    }

    if (url.pathname === '/redirect') {
      res.writeHead(302, { Location: `${UPSTREAM_ORIGIN}/target?x=1` });
      res.end();
      return;
    }

    if (url.pathname === '/chunk.ts') {
      res.writeHead(200, {
        'Content-Type': 'video/mp2t',
        'Content-Length': String(CHUNK_BYTES.length),
      });
      res.end(CHUNK_BYTES);
      return;
    }

    if (url.pathname === '/movie.m3u8') {
      res.writeHead(200, { 'Content-Type': 'application/vnd.apple.mpegurl' });
      res.end('#EXTM3U\n#EXT-X-VERSION:3\n#EXTINF:6.0,\nchunk.ts\n');
      return;
    }

    if (url.pathname === '/unicode') {
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('unicode ok');
      return;
    }

    if (url.pathname === '/assets/app.js') {
      res.writeHead(200, { 'Content-Type': 'application/javascript' });
      res.end('console.log("asset");');
      return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
  });

  server.on('connection', (socket) => {
    socket.__pxId = ++socketCounter;
  });

  server.on('upgrade', (req, socket) => {
    upstreamSockets.push(socket);
    const key = req.headers['sec-websocket-key'];
    const accept = crypto
      .createHash('sha1')
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');
    socket.write(
      'HTTP/1.1 101 Switching Protocols\r\n' +
        'Upgrade: websocket\r\n' +
        'Connection: Upgrade\r\n' +
        `Sec-WebSocket-Accept: ${accept}\r\n` +
        `X-Seen-Path: ${req.url}\r\n` +
        `X-Seen-Cookie: ${req.headers.cookie || ''}\r\n` +
        '\r\n'
    );
  });

  return new Promise((resolve) => server.listen(UPSTREAM_PORT, '127.0.0.1', () => resolve(server)));
}

/* ------------------------------ proxy ------------------------------- */

function startProxy() {
  process.env.PORT = String(PROXY_PORT);
  process.env.NODE_ENV = 'test';
  process.env.ALLOWED_ORIGINS = `${UPSTREAM_ORIGIN},http://127.0.0.1:45999`;
  process.env.ENABLE_CORS = 'true';
  process.env.MAX_BODY_BYTES = '1024';
  process.env.RATE_LIMIT_MAX = '100';
  // The test upstream lives on loopback, which the SSRF guard blocks by default.
  process.env.ALLOW_PRIVATE_TARGETS = 'true';

  // server.js reads configuration at module load.
  const { server } = require(SERVER_PATH);
  if (server.listening) return Promise.resolve(server);
  return new Promise((resolve) => server.once('listening', () => resolve(server)));
}

/** Starts a proxy in a child process with a specific environment. */
function startProxyChild(env, port) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [SERVER_PATH], {
      env: { ...process.env, PORT: String(port), NODE_ENV: 'test', ...env },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    spawnedChildren.push(child);

    let settled = false;
    let output = '';

    const onData = (chunk) => {
      output += chunk.toString('utf8');
      if (!settled && output.includes('server listening')) {
        settled = true;
        resolve({ child, getOutput: () => output });
      }
    };

    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('error', reject);
    child.on('exit', (code) => {
      if (!settled) reject(new Error(`proxy child exited early with code ${code}\n${output}`));
    });
    setTimeout(() => {
      if (!settled) reject(new Error('proxy child did not start in time'));
    }, 10000).unref();
  });
}

async function stopProxyChild(child) {
  if (!child || child.exitCode !== null) return;
  child.kill('SIGTERM');
  await new Promise((resolve) => child.once('exit', resolve));
}

/* --------------------------- main suite ---------------------------- */

async function main() {
  const upstream = await startUpstream();
  const proxy = await startProxy();

  let sticky = '';

  section('Core proxy behaviour');

  await scenario('launcher UI renders at / with no session', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/`);
    const body = await res.text();
    assert.strictEqual(res.status, 200);
    assert.ok(body.includes('Launch a proxied session'), 'launcher markup missing');
    assert.ok(body.includes('#090d16'), 'dark theme missing');
    assert.ok(body.includes('#38bdf8'), 'accent colour missing');
    assert.ok(body.includes('Copy link'), 'copy-link control missing');
  });

  await scenario('launcher ships a nonce-based Content-Security-Policy', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/`);
    const csp = res.headers.get('content-security-policy');
    const body = await res.text();
    assert.ok(csp, 'no CSP header');
    assert.ok(csp.includes("default-src 'none'"), 'CSP is not locked down');
    const nonce = /style-src 'nonce-([^']+)'/.exec(csp);
    assert.ok(nonce, 'no nonce in CSP');
    assert.ok(body.includes(`nonce="${nonce[1]}"`), 'nonce not applied to the document');
  });

  await scenario('explicit _px target proxies and issues sticky cookies', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/?_px=${encodeURIComponent(encodeTarget(UPSTREAM_ORIGIN))}`);
    const body = await res.text();
    assert.strictEqual(res.status, 200);
    assert.ok(body.includes('upstream root'), 'upstream body not proxied');

    const target = setCookies(res).find((cookie) => cookie.startsWith('_px_target='));
    assert.ok(target, '_px_target cookie missing');
    assert.ok(/HttpOnly/i.test(target), 'cookie must be HttpOnly');
    assert.ok(/Path=\//i.test(target), 'cookie must use Path=/');
    assert.ok(/Max-Age=14400/i.test(target), 'cookie must live for 4 hours');

    sticky = stickyCookieHeader(res);
    assert.ok(sticky.includes('_px_target='), 'sticky header not built');
  });

  await scenario('sticky cookie resolves asset requests without _px', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/assets/app.js`, { headers: { Cookie: sticky } });
    assert.strictEqual(res.status, 200);
    assert.ok((await res.text()).includes('console.log("asset")'), 'asset not served');
  });

  await scenario('upstream sees a coherent fingerprint and no proxy cookies', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: { Cookie: sticky, Origin: 'https://client.example' },
    });
    const echoed = await res.json();

    assert.ok(/Chrome\/131\.0\.0\.0/.test(echoed.headers['user-agent']), 'user-agent mismatch');
    assert.ok(echoed.headers['sec-ch-ua'], 'sec-ch-ua missing');
    assert.strictEqual(echoed.headers['sec-ch-ua-mobile'], '?0');
    assert.strictEqual(echoed.headers['sec-ch-ua-platform'], '"Windows"');
    assert.strictEqual(echoed.headers['accept-language'], 'en-US,en;q=0.9');
    assert.strictEqual(echoed.headers.origin, UPSTREAM_ORIGIN);
    assert.strictEqual(echoed.headers.referer, undefined, 'a referer was invented');
    assert.ok(!String(echoed.headers.cookie || '').includes('_px_target'), 'sticky cookie leaked');
  });

  await scenario('restrictive response headers are stripped and CORS injected', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/?_px=${encodeURIComponent(encodeTarget(UPSTREAM_ORIGIN))}`);
    await res.text();

    assert.strictEqual(res.headers.get('content-security-policy'), null);
    assert.strictEqual(res.headers.get('x-frame-options'), null);
    assert.strictEqual(res.headers.get('cross-origin-opener-policy'), null);
    assert.strictEqual(res.headers.get('cross-origin-embedder-policy'), null);
    assert.strictEqual(res.headers.get('x-powered-by'), null);
    assert.strictEqual(res.headers.get('server'), null);
    assert.strictEqual(res.headers.get('access-control-allow-origin'), '*');
    assert.ok(/GET, POST, PUT, DELETE, OPTIONS/.test(res.headers.get('access-control-allow-methods') || ''));
    assert.strictEqual(res.headers.get('access-control-allow-headers'), '*');

    const cookie = setCookies(res).find((entry) => entry.startsWith('sid='));
    assert.ok(cookie, 'upstream session cookie missing');
    assert.ok(!/domain=/i.test(cookie), 'upstream cookie domain must be stripped');
  });

  await scenario('same-origin redirects are rewritten to the proxy domain', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/redirect`, {
      headers: { Cookie: sticky },
      redirect: 'manual',
    });
    assert.strictEqual(res.status, 302);
    assert.strictEqual(res.headers.get('location'), `${PROXY_ORIGIN}/target?x=1`);
  });

  await scenario('malformed base64 is repaired and trailing params forwarded', async () => {
    const raw = encodeTarget(`${UPSTREAM_ORIGIN}/echo`).replace(/=+$/, '');
    const res = await fetch(`${PROXY_ORIGIN}/?_px=${encodeURIComponent(raw.replace(/\+/g, ' '))}&token=xyz`);
    const echoed = await res.json();
    assert.strictEqual(res.status, 200);
    assert.strictEqual(echoed.url, '/echo?token=xyz');
  });

  await scenario('invalid base64 returns a clean 400 without crashing', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/?_px=%%%not-base64%%%`);
    const body = await res.json();
    assert.strictEqual(res.status, 400);
    assert.strictEqual(body.error, 'bad_request');
    assert.ok(typeof body.message === 'string' && body.message.length > 0);
    assert.strictEqual((await fetch(`${PROXY_ORIGIN}/healthz`)).status, 200, 'server died');
  });

  await scenario('targets outside ALLOWED_ORIGINS are refused with 403', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/?_px=${encodeURIComponent(encodeTarget('https://example.com'))}`);
    const body = await res.json();
    assert.strictEqual(res.status, 403);
    assert.strictEqual(body.error, 'forbidden');
  });

  await scenario('binary media chunks stream through unmodified', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/chunk.ts`, { headers: { Cookie: sticky } });
    const body = Buffer.from(await res.arrayBuffer());
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'video/mp2t');
    assert.strictEqual(res.headers.get('content-length'), String(CHUNK_BYTES.length));
    assert.ok(body.equals(CHUNK_BYTES), 'chunk payload was altered');
  });

  await scenario('HLS playlists are proxied with the right content type', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/movie.m3u8`, { headers: { Cookie: sticky } });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.headers.get('content-type'), 'application/vnd.apple.mpegurl');
    assert.ok((await res.text()).startsWith('#EXTM3U'), 'playlist body missing');
  });

  await scenario('OPTIONS preflight is answered by the proxy', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/anything`, {
      method: 'OPTIONS',
      headers: { Origin: 'https://client.example', 'Access-Control-Request-Method': 'POST' },
    });
    assert.strictEqual(res.status, 204);
    assert.strictEqual(res.headers.get('access-control-allow-origin'), 'https://client.example');
  });

  await scenario('WebSocket upgrades are proxied with the sticky session', async () => {
    const encoded = encodeTarget(UPSTREAM_ORIGIN);
    const key = 'dGhlIHNhbXBsZSBub25jZQ==';
    const expectedAccept = crypto
      .createHash('sha1')
      .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
      .digest('base64');

    const response = await new Promise((resolve, reject) => {
      const socket = net.connect(PROXY_PORT, '127.0.0.1', () => {
        socket.write(
          `GET /ws?_px=${encodeURIComponent(encoded)} HTTP/1.1\r\n` +
            `Host: 127.0.0.1:${PROXY_PORT}\r\n` +
            'Upgrade: websocket\r\n' +
            'Connection: Upgrade\r\n' +
            `Sec-WebSocket-Key: ${key}\r\n` +
            'Sec-WebSocket-Version: 13\r\n' +
            `Cookie: ${sticky}\r\n` +
            '\r\n'
        );
      });

      let buffer = '';
      socket.on('data', (chunk) => {
        buffer += chunk.toString('utf8');
        if (buffer.includes('\r\n\r\n')) {
          socket.destroy();
          resolve(buffer);
        }
      });
      socket.on('error', reject);
      socket.setTimeout(5000, () => {
        socket.destroy();
        reject(new Error('websocket upgrade timed out'));
      });
    });

    const lower = response.toLowerCase();
    assert.ok(lower.startsWith('http/1.1 101'), `unexpected upgrade response: ${response.slice(0, 80)}`);
    assert.ok(lower.includes(`sec-websocket-accept: ${expectedAccept.toLowerCase()}`), 'accept mismatch');
    assert.ok(lower.includes('x-seen-path: /ws'), `unexpected upstream path: ${response}`);
    assert.ok(!lower.includes('_px_target'), 'sticky cookie leaked over the upgrade');
  });

  section('Advanced proxy behaviour');

  await scenario('POST bodies are forwarded to the upstream', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo-body`, {
      method: 'POST',
      headers: { Cookie: sticky, 'Content-Type': 'text/plain' },
      body: 'hello proxy',
    });
    const echoed = await res.json();
    assert.strictEqual(res.status, 200);
    assert.strictEqual(echoed.method, 'POST');
    assert.strictEqual(echoed.body, 'hello proxy');
    assert.strictEqual(echoed.length, 11);
  });

  await scenario('oversized request bodies are rejected with 413', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo-body`, {
      method: 'POST',
      headers: { Cookie: sticky, 'Content-Type': 'text/plain' },
      body: 'x'.repeat(4096),
    });
    const body = await res.json();
    assert.strictEqual(res.status, 413);
    assert.strictEqual(body.error, 'payload_too_large');
  });

  await scenario('HEAD requests are proxied without a body', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, { method: 'HEAD', headers: { Cookie: sticky } });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(await res.text(), '');
  });

  await scenario('range requests return 206 with Content-Range', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/range`, {
      headers: { Cookie: sticky, Range: 'bytes=2-5' },
    });
    const body = await res.text();
    assert.strictEqual(res.status, 206);
    assert.strictEqual(res.headers.get('content-range'), 'bytes 2-5/10');
    assert.strictEqual(body, '2345');
  });

  await scenario('upstream connections are pooled across requests', async () => {
    const ids = [];
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const res = await fetch(`${PROXY_ORIGIN}/socket-id`, { headers: { Cookie: sticky } });
      const payload = await res.json();
      ids.push(payload.socketId);
    }
    assert.strictEqual(ids.length, 3);
    assert.strictEqual(new Set(ids).size, 1, `upstream sockets were not reused: ${ids.join(',')}`);
  });

  await scenario('idempotent requests are retried after an upstream reset', async () => {
    const before = flakyHits;
    const res = await fetch(`${PROXY_ORIGIN}/flaky`, { headers: { Cookie: sticky } });
    const body = await res.text();
    assert.strictEqual(res.status, 200, 'retry did not recover the request');
    assert.strictEqual(body, 'recovered');
    assert.ok(flakyHits >= before + 2, `expected a retry, upstream hits: ${flakyHits - before}`);
  });

  await scenario('request ids are echoed to the client but kept off the wire', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/socket-id`, {
      headers: { Cookie: sticky, 'x-request-id': 'test-correlation-1' },
    });
    const payload = await res.json();
    assert.strictEqual(res.headers.get('x-request-id'), 'test-correlation-1');
    assert.strictEqual(payload.header, undefined, 'correlation id leaked upstream');
  });

  await scenario('UTF-8 targets round-trip through the encoder', async () => {
    const target = `${UPSTREAM_ORIGIN}/echo?q=caf%C3%A9`;
    const res = await fetch(`${PROXY_ORIGIN}/?_px=${encodeURIComponent(encodeTarget(target))}`);
    const echoed = await res.json();
    assert.strictEqual(res.status, 200);
    assert.strictEqual(echoed.url, '/echo?q=caf%C3%A9');
  });

  await scenario('base-path targets are canonicalised with a self-resolving 302', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/?_px=${encodeURIComponent(encodeTarget(`${UPSTREAM_ORIGIN}/app`))}`, {
      redirect: 'manual',
    });
    assert.strictEqual(res.status, 302);
    const location = res.headers.get('location');
    assert.ok(location.startsWith('/app?_px='), `unexpected canonical location: ${location}`);
  });

  section('Signal fidelity');

  await scenario('the client fingerprint is relayed rather than overwritten', async () => {
    const clientAgent =
      'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) ' +
      'Chrome/140.0.0.0 Safari/537.36';
    const res = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: {
        Cookie: sticky,
        'user-agent': clientAgent,
        'sec-ch-ua': '"Chromium";v="140", "Not_A Brand";v="24"',
        'sec-ch-ua-platform': '"macOS"',
      },
    });
    const echoed = await res.json();

    assert.strictEqual(echoed.headers['user-agent'], clientAgent, 'client user agent was replaced');
    assert.strictEqual(echoed.headers['sec-ch-ua-platform'], '"macOS"', 'client hints were replaced');
    assert.ok(
      !String(echoed.headers['sec-ch-ua'] || '').includes('131'),
      'the fixed profile leaked into a client request'
    );
  });

  await scenario('clients without a fingerprint receive a consistent profile', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: { Cookie: sticky, 'user-agent': '' },
    });
    const echoed = await res.json();

    assert.ok(/Chrome\/131\.0\.0\.0/.test(echoed.headers['user-agent']), 'profile not synthesised');
    assert.ok(echoed.headers['sec-ch-ua'].includes('131'), 'client hints inconsistent with user agent');
    assert.strictEqual(echoed.headers['sec-ch-ua-mobile'], '?0');
    assert.strictEqual(echoed.headers['sec-ch-ua-platform'], '"Windows"');
  });

  await scenario('no proxy forwarding headers reach the upstream', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: {
        Cookie: sticky,
        'x-forwarded-for': '203.0.113.9',
        'x-real-ip': '203.0.113.9',
        forwarded: 'for=203.0.113.9',
      },
    });
    const echoed = await res.json();

    assert.strictEqual(echoed.headers['x-forwarded-for'], undefined, 'X-Forwarded-For leaked');
    assert.strictEqual(echoed.headers['x-real-ip'], undefined, 'X-Real-IP leaked');
    assert.strictEqual(echoed.headers.forwarded, undefined, 'Forwarded leaked');
  });

  await scenario('the correlation id stays on the proxy side', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: { Cookie: sticky, 'x-request-id': 'local-only-1' },
    });
    const echoed = await res.json();
    assert.strictEqual(echoed.headers['x-request-id'], undefined, 'x-request-id leaked upstream');
    assert.strictEqual(res.headers.get('x-request-id'), 'local-only-1', 'client lost the id');
  });

  await scenario('origin and referer are relayed only when the client sent them', async () => {
    const withoutOrigin = await fetch(`${PROXY_ORIGIN}/echo`, { headers: { Cookie: sticky } });
    const bare = await withoutOrigin.json();
    assert.strictEqual(bare.headers.origin, undefined, 'Origin was invented on a plain GET');
    assert.strictEqual(bare.headers.referer, undefined, 'Referer was invented on a plain GET');

    const withOrigin = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: {
        Cookie: sticky,
        Origin: `${PROXY_ORIGIN}/page`,
        Referer: `${PROXY_ORIGIN}/page?a=1`,
      },
    });
    const sent = await withOrigin.json();
    assert.strictEqual(sent.headers.origin, UPSTREAM_ORIGIN, 'Origin was not rewritten');
    assert.strictEqual(
      sent.headers.referer,
      `${UPSTREAM_ORIGIN}/page?a=1`,
      'Referer leaked the proxy domain or lost its path'
    );
  });

  await scenario('compression negotiation is relayed to the upstream', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: { Cookie: sticky, 'accept-encoding': 'gzip, deflate, br' },
    });
    const echoed = await res.json();
    assert.strictEqual(echoed.headers['accept-encoding'], 'gzip, deflate, br');
  });

  await scenario('the host header identifies the upstream origin', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, { headers: { Cookie: sticky } });
    const echoed = await res.json();
    assert.strictEqual(echoed.headers.host, `127.0.0.1:${UPSTREAM_PORT}`);
  });

  await scenario('non-browser clients are normalised onto the browser profile', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: { Cookie: sticky, 'user-agent': 'curl/8.4.0' },
    });
    const echoed = await res.json();
    assert.ok(
      /Chrome\/131\.0\.0\.0/.test(echoed.headers['user-agent']),
      `script client was not normalised: ${echoed.headers['user-agent']}`
    );
  });

  await scenario('crawler clients are normalised as well', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: { Cookie: sticky, 'user-agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)' },
    });
    const echoed = await res.json();
    assert.ok(
      !/Googlebot/.test(echoed.headers['user-agent']),
      'crawler identity was relayed to the upstream'
    );
  });

  section('Protocol correctness');

  await scenario('the upstream Vary header is preserved and extended', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, {
      headers: { Cookie: sticky, Origin: 'https://client.example' },
    });
    const vary = res.headers.get('vary') || '';
    assert.ok(/accept-encoding/i.test(vary), `upstream Vary was discarded: "${vary}"`);
    assert.ok(/origin/i.test(vary), `Origin was not added to Vary: "${vary}"`);
  });

  await scenario('upstream cookies survive without their Secure flag over plain HTTP', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, { headers: { Cookie: sticky } });
    const cookie = setCookies(res).find((entry) => entry.startsWith('secure_sid='));
    assert.ok(cookie, 'upstream cookie missing');
    assert.ok(!/;\s*Secure/i.test(cookie), `Secure flag was not adjusted: ${cookie}`);
  });

  await scenario('error responses carry CORS headers', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/?_px=${encodeURIComponent(encodeTarget('https://example.com'))}`, {
      headers: { Origin: 'https://client.example' },
    });
    assert.strictEqual(res.status, 403);
    assert.strictEqual(
      res.headers.get('access-control-allow-origin'),
      'https://client.example',
      'a rejected request lost its CORS headers'
    );
  });

  await scenario('an unreachable upstream yields a clean 502 with CORS headers', async () => {
    const res = await fetch(
      `${PROXY_ORIGIN}/?_px=${encodeURIComponent(encodeTarget('http://127.0.0.1:45999'))}`,
      { headers: { Origin: 'https://client.example' } }
    );
    const body = await res.json();
    assert.strictEqual(res.status, 502);
    assert.strictEqual(body.error, 'bad_gateway');
    assert.strictEqual(res.headers.get('access-control-allow-origin'), 'https://client.example');
  });

  await scenario('concurrent requests all succeed', async () => {
    const responses = await Promise.all(
      Array.from({ length: 25 }, () =>
        fetch(`${PROXY_ORIGIN}/assets/app.js`, { headers: { Cookie: sticky } })
      )
    );
    const bodies = await Promise.all(responses.map((response) => response.text()));
    assert.ok(
      responses.every((response) => response.status === 200),
      'a concurrent request failed'
    );
    assert.ok(bodies.every((body) => body.includes('console.log("asset")')), 'a body was corrupted');
  });

  await scenario('metrics expose process memory for capacity planning', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/metrics`);
    const body = await res.text();
    assert.ok(
      /px_process_resident_memory_bytes \d+/.test(body),
      'resident memory gauge missing'
    );
    assert.ok(/px_process_heap_used_bytes \d+/.test(body), 'heap gauge missing');
  });

  await scenario('upstream cookies keep working when the proxy sets them', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/echo`, { headers: { Cookie: sticky } });
    const cookies = setCookies(res);
    assert.ok(
      cookies.some((cookie) => cookie.startsWith('secure_sid=')),
      'upstream cookie was dropped'
    );
    assert.ok(
      cookies.some((cookie) => cookie.startsWith('_px_target=')),
      'sticky cookie was dropped'
    );
  });

  section('Operational endpoints');

  await scenario('health, readiness and metrics are exposed', async () => {
    const health = await fetch(`${PROXY_ORIGIN}/healthz`);
    assert.strictEqual(health.status, 200);
    assert.strictEqual((await health.json()).status, 'ok');

    const ready = await fetch(`${PROXY_ORIGIN}/readyz`);
    assert.strictEqual(ready.status, 200);
    assert.strictEqual((await ready.json()).status, 'ready');

    const metrics = await fetch(`${PROXY_ORIGIN}/metrics`);
    const body = await metrics.text();
    assert.strictEqual(metrics.status, 200);
    assert.ok(body.includes('px_requests_total'), 'request counter missing');
    assert.ok(body.includes('px_bytes_out_total'), 'byte counter missing');
    assert.ok(body.includes('px_request_duration_ms_bucket'), 'duration histogram missing');
  });

  await scenario('session introspection reports the active target', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/_px/session`, { headers: { Cookie: sticky } });
    const body = await res.json();
    assert.strictEqual(body.active, true);
    assert.strictEqual(body.target, UPSTREAM_ORIGIN);
    assert.strictEqual(body.maxAgeSeconds, 14400);
  });

  await scenario('the session can be reset from the operator endpoint', async () => {
    const res = await fetch(`${PROXY_ORIGIN}/_px/new`, { redirect: 'manual' });
    assert.strictEqual(res.status, 302);
    const cleared = setCookies(res).filter((cookie) => cookie.startsWith('_px_target='));
    assert.ok(cleared.length > 0, 'no clearing cookie issued');
    assert.ok(/Max-Age=0/i.test(cleared[0]), 'session cookie was not expired');
  });

  // ---------------------------------------------------------------- //
  // Child-process suites: configuration that cannot be set in-process.
  // ---------------------------------------------------------------- //

  section('Deployment configuration');

  const ssrfChild = await startProxyChild(
    {
      ALLOWED_ORIGINS: `http://localhost:${UPSTREAM_PORT}`,
      ALLOW_PRIVATE_TARGETS: '',
      SSRF_GUARD: 'true',
    },
    45911
  );

  await scenario('the SSRF guard refuses targets that resolve to private addresses', async () => {
    const res = await fetch(
      `http://127.0.0.1:45911/?_px=${encodeURIComponent(encodeTarget(`http://localhost:${UPSTREAM_PORT}`))}`
    );
    const body = await res.json();
    assert.strictEqual(res.status, 403);
    assert.ok(/private network/i.test(body.message), `unexpected message: ${body.message}`);
  });

  await stopProxyChild(ssrfChild.child);

  const tokenChild = await startProxyChild(
    {
      ALLOWED_ORIGINS: UPSTREAM_ORIGIN,
      ALLOW_PRIVATE_TARGETS: 'true',
      PROXY_ACCESS_TOKEN: 'test-token',
    },
    45912
  );

  await scenario('an access token is required when configured', async () => {
    const denied = await fetch('http://127.0.0.1:45912/');
    assert.strictEqual(denied.status, 401);
    assert.strictEqual((await denied.json()).error, 'unauthorized');

    const allowed = await fetch('http://127.0.0.1:45912/', {
      headers: { Authorization: 'Bearer test-token' },
    });
    assert.strictEqual(allowed.status, 200);
  });

  await scenario('the metrics endpoint is protected by the access token', async () => {
    const denied = await fetch('http://127.0.0.1:45912/metrics');
    assert.strictEqual(denied.status, 401);

    const allowed = await fetch('http://127.0.0.1:45912/metrics', {
      headers: { Authorization: 'Bearer test-token' },
    });
    assert.strictEqual(allowed.status, 200);
  });

  await scenario('the health probe stays reachable behind the access token', async () => {
    const res = await fetch('http://127.0.0.1:45912/healthz');
    assert.strictEqual(res.status, 200);
  });

  await stopProxyChild(tokenChild.child);

  const basicChild = await startProxyChild(
    {
      ALLOWED_ORIGINS: UPSTREAM_ORIGIN,
      ALLOW_PRIVATE_TARGETS: 'true',
      PROXY_ACCESS_USER: 'operator',
      PROXY_ACCESS_PASSWORD: 's3cret',
    },
    45914
  );

  await scenario('HTTP Basic credentials are accepted', async () => {
    const credentials = Buffer.from('operator:s3cret').toString('base64');
    const res = await fetch('http://127.0.0.1:45914/', {
      headers: { Authorization: `Basic ${credentials}` },
    });
    assert.strictEqual(res.status, 200);
  });

  await scenario('wrong Basic credentials are rejected', async () => {
    const credentials = Buffer.from('operator:wrong').toString('base64');
    const res = await fetch('http://127.0.0.1:45914/', {
      headers: { Authorization: `Basic ${credentials}` },
    });
    assert.strictEqual(res.status, 401);
  });

  await scenario('upstream credentials never reach the logs', async () => {
    const credentialsChild = await startProxyChild(
      {
        ALLOWED_ORIGINS: `upstream-user:upstream-secret@127.0.0.1:${UPSTREAM_PORT}`,
        ALLOW_PRIVATE_TARGETS: 'true',
      },
      45915
    );
    const output = credentialsChild.getOutput();
    assert.ok(!output.includes('upstream-secret'), `credentials leaked into the logs: ${output}`);
    await stopProxyChild(credentialsChild.child);
  });

  await stopProxyChild(basicChild.child);

  const rateChild = await startProxyChild(
    {
      ALLOWED_ORIGINS: UPSTREAM_ORIGIN,
      ALLOW_PRIVATE_TARGETS: 'true',
      RATE_LIMIT_MAX: '2',
      RATE_LIMIT_WINDOW_MS: '60000',
    },
    45913
  );

  await scenario('session creation is rate limited', async () => {
    const target = `?_px=${encodeURIComponent(encodeTarget(UPSTREAM_ORIGIN))}`;
    const first = await fetch(`http://127.0.0.1:45913/${target}`);
    const second = await fetch(`http://127.0.0.1:45913/${target}`);
    const third = await fetch(`http://127.0.0.1:45913/${target}`);

    assert.strictEqual(first.status, 200);
    assert.strictEqual(second.status, 200);
    assert.strictEqual(third.status, 429);
    assert.strictEqual((await third.json()).error, 'rate_limited');
    assert.ok(third.headers.get('retry-after'), 'Retry-After header missing');
  });

  await scenario('a spoofed forwarding header cannot move the rate-limit bucket', async () => {
    const target = `?_px=${encodeURIComponent(encodeTarget(UPSTREAM_ORIGIN))}`;
    // Modelled the way a trusted edge behaves: the client prepends a claim,
    // the edge appends the address it actually saw. With one trusted hop the
    // proxy reads the appended value, so the claim cannot change the bucket.
    const spoofed = await fetch(`http://127.0.0.1:45913/${target}`, {
      headers: { 'X-Forwarded-For': '203.0.113.7, 127.0.0.1' },
    });
    assert.strictEqual(
      spoofed.status,
      429,
      'a spoofed forwarding header bypassed the rate limit'
    );
  });

  await stopProxyChild(rateChild);

  // ---------------------------------------------------------------- //

  for (const socket of upstreamSockets) socket.destroy();
  if (typeof proxy.closeAllConnections === 'function') proxy.closeAllConnections();
  if (typeof upstream.closeAllConnections === 'function') upstream.closeAllConnections();
  await new Promise((resolve) => proxy.close(resolve));
  await new Promise((resolve) => upstream.close(resolve));

  console.log(`\n${passed} passed, ${failures.length} failed`);
  if (failures.length > 0) {
    for (const failure of failures) {
      console.error(`\n${failure.name}\n${failure.error.stack}`);
    }
    process.exit(1);
  }
  process.exit(0);
}

main().catch((error) => {
  console.error('test harness failure:', error);
  process.exit(1);
});
