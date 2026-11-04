require('dotenv').config();
const http = require('http');
const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

function getConfig() {
  return {
    PORT: process.env.PORT || 3000,
    HOST: process.env.HOST || '0.0.0.0',
    DEFAULT_TARGET: process.env.TARGET_URL || '',
    QUERY_PARAM_KEY: process.env.QUERY_PARAM_KEY || 'url',
    PROXY_SECRET: process.env.PROXY_SECRET || '',
    DEFAULT_USER_AGENT: process.env.DEFAULT_USER_AGENT ||
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
  };
}

function createApp() {
  const config = getConfig();
  const app = express();

  // Stealth: Disable Express signature
  app.disable('x-powered-by');

  // Strip/scrub server signature headers on all responses
  app.use((req, res, next) => {
    res.removeHeader('X-Powered-By');
    res.removeHeader('Server');
    res.removeHeader('Via');
    res.removeHeader('X-Proxied-By');
    next();
  });

  // Health check endpoint for uptime monitor / cron pinging
  app.get('/health', (req, res) => {
    res.setHeader('Content-Type', 'text/plain');
    res.status(200).send('OK');
  });

  // Authentication check helper
  function isAuthorized(req) {
    if (!config.PROXY_SECRET) {
      return true;
    }
    const headerToken = req.headers['x-proxy-secret'] || req.headers['x-proxy-token'];
    const queryToken = req.query ? (req.query.secret || req.query.token) : undefined;
    return (headerToken === config.PROXY_SECRET) || (queryToken === config.PROXY_SECRET);
  }

  // Handle CORS preflight OPTIONS requests across any endpoint
  app.use((req, res, next) => {
    if (req.method === 'OPTIONS') {
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH');
      res.setHeader('Access-Control-Allow-Headers', '*');
      res.setHeader('Access-Control-Max-Age', '86400');
      return res.sendStatus(204);
    }
    next();
  });

  // Dynamic router and proxy middleware
  const proxyMiddleware = createProxyMiddleware({
    router: (req) => {
      // 1. Dynamic query parameter takes precedence
      const dynamicUrl = req.query ? req.query[config.QUERY_PARAM_KEY] : undefined;
      if (dynamicUrl && typeof dynamicUrl === 'string') {
        try {
          const parsed = new URL(dynamicUrl);
          return `${parsed.protocol}//${parsed.host}`;
        } catch (e) {
          return undefined;
        }
      }

      // 2. Fallback to TARGET_URL environment variable
      if (config.DEFAULT_TARGET) {
        return config.DEFAULT_TARGET;
      }

      return undefined;
    },
    pathRewrite: (path, req) => {
      const dynamicUrl = req.query ? req.query[config.QUERY_PARAM_KEY] : undefined;
      if (dynamicUrl && typeof dynamicUrl === 'string') {
        try {
          const parsed = new URL(dynamicUrl);
          // Retain target path and any original search params
          const searchParams = new URLSearchParams(parsed.search);
          const finalSearch = searchParams.toString();
          return parsed.pathname + (finalSearch ? `?${finalSearch}` : '');
        } catch (e) {
          return path;
        }
      }
      return path;
    },
    changeOrigin: true,
    ws: true,
    xfwd: false, // Inconspicuous: do NOT append X-Forwarded-For headers
    secure: false, // Allow upstream self-signed/proxy chains if needed
    on: {
      proxyReq: (proxyReq, req, res) => {
        // Strip internal forwarding headers to remain stealthy
        proxyReq.removeHeader('x-forwarded-for');
        proxyReq.removeHeader('x-forwarded-host');
        proxyReq.removeHeader('x-forwarded-proto');
        proxyReq.removeHeader('x-forwarded-port');
        proxyReq.removeHeader('x-forwarded-server');
        proxyReq.removeHeader('x-real-ip');
        proxyReq.removeHeader('x-proxy-secret');
        proxyReq.removeHeader('x-proxy-token');

        // Upstream Host header spoofing
        const dynamicUrl = req.query ? req.query[config.QUERY_PARAM_KEY] : undefined;
        if (dynamicUrl) {
          try {
            const parsed = new URL(dynamicUrl);
            proxyReq.setHeader('host', parsed.host);
          } catch (e) {}
        } else if (config.DEFAULT_TARGET) {
          try {
            const parsed = new URL(config.DEFAULT_TARGET);
            proxyReq.setHeader('host', parsed.host);
          } catch (e) {}
        }

        // Realistic standard browser User-Agent injection if not provided or generic
        const clientUa = req.headers['user-agent'];
        if (!clientUa || clientUa.includes('axios') || clientUa.includes('curl') || clientUa.includes('node')) {
          proxyReq.setHeader('user-agent', config.DEFAULT_USER_AGENT);
        }
      },
      proxyRes: (proxyRes, req, res) => {
        // Strip server signatures from upstream
        delete proxyRes.headers['x-powered-by'];
        delete proxyRes.headers['server'];
        delete proxyRes.headers['via'];
        delete proxyRes.headers['x-proxied-by'];

        // Inject permissive CORS headers
        proxyRes.headers['access-control-allow-origin'] = '*';
        proxyRes.headers['access-control-allow-methods'] = 'GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH';
        proxyRes.headers['access-control-allow-headers'] = '*';
        proxyRes.headers['access-control-expose-headers'] = '*';
      },
      error: (err, req, res) => {
        // Handle both HTTP Response and raw Net.Socket (WebSocket upgrade error)
        if (res && typeof res.writeHead === 'function' && !res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 502, message: 'Bad Gateway' }));
        } else if (res && typeof res.destroy === 'function') {
          res.destroy();
        }
      }
    }
  });

  // Routing gate: check auth & check if target is valid
  app.use((req, res, next) => {
    // Check authorization if PROXY_SECRET is set
    if (!isAuthorized(req)) {
      // Inconspicuous 404 response to reveal nothing about the service
      return res.status(404).send('Cannot GET ' + req.path);
    }

    const hasDynamicUrl = Boolean(req.query && req.query[config.QUERY_PARAM_KEY]);
    const hasDefaultTarget = Boolean(config.DEFAULT_TARGET);

    // If no target provided and no default target, serve bland benign landing
    if (!hasDynamicUrl && !hasDefaultTarget) {
      // Benign landing page
      return res.status(200).send('Service operational');
    }

    // Dynamic URL syntax validation
    if (hasDynamicUrl) {
      try {
        new URL(req.query[config.QUERY_PARAM_KEY]);
      } catch (e) {
        return res.status(400).send('Invalid target URL');
      }
    }

    return proxyMiddleware(req, res, next);
  });

  return { app, proxyMiddleware, isAuthorized };
}

function startServer(port, host) {
  const config = getConfig();
  const serverPort = port !== undefined ? port : config.PORT;
  const serverHost = host !== undefined ? host : config.HOST;

  const { app, proxyMiddleware, isAuthorized } = createApp();
  const server = http.createServer(app);

  // Upgrade WebSocket connections cleanly
  if (proxyMiddleware.upgrade) {
    server.on('upgrade', (req, socket, head) => {
      // Check auth if configured
      if (!isAuthorized(req)) {
        socket.write('HTTP/1.1 404 Not Found\r\n\r\n');
        socket.destroy();
        return;
      }
      proxyMiddleware.upgrade(req, socket, head);
    });
  }

  server.listen(serverPort, serverHost, () => {
    // Inconspicuous minimal stdout
    console.log(`Server listening on ${serverHost}:${serverPort}`);
  });

  return server;
}

if (require.main === module) {
  startServer();
}

module.exports = { createApp, startServer };
