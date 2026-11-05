'use strict';

/**
 * Load benchmark for the proxy.
 *
 * The proxy runs as a separate child process so the load generator's own
 * overhead is not attributed to it. The server's cumulative CPU time and
 * resident memory are sampled directly, which makes before/after comparisons
 * between revisions meaningful.
 *
 * Usage: node test/benchmark.js [requests] [concurrency]
 */

const http = require('http');
const path = require('path');
const { spawn, execFileSync } = require('child_process');

const REQUESTS = Number(process.argv[2]) || 400;
const CONCURRENCY = Number(process.argv[3]) || 20;

const UPSTREAM_PORT = 45801;
const PROXY_PORT = 45802;
const UPSTREAM_ORIGIN = `http://127.0.0.1:${UPSTREAM_PORT}`;
const PROXY_ORIGIN = `http://127.0.0.1:${PROXY_PORT}`;
const SERVER_PATH = path.join(__dirname, '..', 'server.js');

/** Cumulative CPU seconds and resident memory of a running process. */
function sampleProcess(pid) {
  const output = execFileSync('ps', ['-o', 'time=,rss=', '-p', String(pid)], {
    encoding: 'utf8',
  }).trim();

  const [time, rss] = output.split(/\s+/);
  const parts = time.split(':');
  const cpuSeconds = parts
    .map((part) => Number(part))
    .reduce((total, part) => total * 60 + part, 0);

  return { cpuSeconds, rssKb: Number(rss) };
}

function startUpstream() {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, UPSTREAM_ORIGIN);
    if (url.pathname === '/asset') {
      res.writeHead(200, { 'Content-Type': 'application/javascript', 'Content-Length': '64' });
      res.end('console.log("asset");'.padEnd(64, ' '));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<html><body>root</body></html>');
  });
  return new Promise((resolve) => server.listen(UPSTREAM_PORT, '127.0.0.1', () => resolve(server)));
}

function startProxyChild() {
  return new Promise((resolve, reject) => {
    const child = spawn(
      process.execPath,
      ['--max-old-space-size=256', SERVER_PATH],
      {
        env: {
          ...process.env,
          PORT: String(PROXY_PORT),
          NODE_ENV: 'benchmark',
          ALLOWED_ORIGINS: UPSTREAM_ORIGIN,
          ALLOW_PRIVATE_TARGETS: 'true',
          RATE_LIMIT_MAX: '0',
          LOG_LEVEL: 'info',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      }
    );

    let output = '';
    const onData = (chunk) => {
      output += chunk.toString('utf8');
      if (output.includes('server listening')) resolve(child);
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('error', reject);
    setTimeout(() => reject(new Error('proxy did not start')), 10000).unref();
  });
}

async function main() {
  const upstream = await startUpstream();
  const child = await startProxyChild();

  const encoded = Buffer.from(UPSTREAM_ORIGIN, 'utf8').toString('base64');
  const open = await fetch(`${PROXY_ORIGIN}/?_px=${encodeURIComponent(encoded)}`);
  const cookie = open.headers
    .getSetCookie()
    .map((entry) => entry.split(';')[0])
    .join('; ');

  // Warm up the connection pool and the JIT.
  for (let i = 0; i < 25; i += 1) {
    await fetch(`${PROXY_ORIGIN}/asset`, { headers: { Cookie: cookie } });
  }

  const before = sampleProcess(child.pid);

  let issued = 0;
  let completed = 0;
  let failures = 0;
  const startedAt = process.hrtime.bigint();

  await new Promise((resolve) => {
    const worker = async () => {
      while (issued < REQUESTS) {
        issued += 1;
        try {
          const res = await fetch(`${PROXY_ORIGIN}/asset`, { headers: { Cookie: cookie } });
          await res.arrayBuffer();
          if (!res.ok) failures += 1;
        } catch {
          failures += 1;
        }
        completed += 1;
        if (completed === REQUESTS) resolve();
      }
    };
    for (let i = 0; i < CONCURRENCY; i += 1) worker();
  });

  const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6;
  const after = sampleProcess(child.pid);

  const serverCpuSeconds = Number((after.cpuSeconds - before.cpuSeconds).toFixed(3));
  const cpuMsPerRequest = Number(((serverCpuSeconds * 1000) / REQUESTS).toFixed(3));

  console.log(
    JSON.stringify(
      {
        requests: REQUESTS,
        concurrency: CONCURRENCY,
        failures,
        wallClockMs: Number(elapsedMs.toFixed(1)),
        requestsPerSecond: Number(((REQUESTS / elapsedMs) * 1000).toFixed(1)),
        serverCpuSeconds,
        serverCpuMsPerRequest: cpuMsPerRequest,
        serverRssBeforeMb: Number((before.rssKb / 1024).toFixed(1)),
        serverRssAfterMb: Number((after.rssKb / 1024).toFixed(1)),
        serverRssGrowthMb: Number(((after.rssKb - before.rssKb) / 1024).toFixed(1)),
      },
      null,
      2
    )
  );

  child.kill('SIGKILL');
  if (typeof upstream.closeAllConnections === 'function') upstream.closeAllConnections();
  await new Promise((resolve) => upstream.close(resolve));
  process.exit(0);
}

main().catch((error) => {
  console.error('benchmark failed:', error);
  process.exit(1);
});
