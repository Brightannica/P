const assert = require('assert');
const http = require('http');
const request = require('supertest');
const { WebSocketServer, WebSocket } = require('ws');

describe('Render Reverse Proxy Test Suite', () => {
  let targetServer;
  let targetPort;
  let receivedHeaders = {};
  let receivedMethod = '';
  let receivedBody = '';
  let receivedUrl = '';

  before((done) => {
    // Upstream mock server
    targetServer = http.createServer((req, res) => {
      receivedHeaders = req.headers;
      receivedMethod = req.method;
      receivedUrl = req.url;

      let body = '';
      req.on('data', chunk => {
        body += chunk;
      });
      req.on('end', () => {
        receivedBody = body;
        // Set server signature headers that proxy should scrub
        res.setHeader('Server', 'MockServer/1.0');
        res.setHeader('X-Powered-By', 'MockEngine');
        res.setHeader('Via', '1.0 mock');
        res.setHeader('Content-Type', 'application/json');

        if (req.url === '/chunked') {
          res.writeHead(200, { 'Content-Type': 'text/plain', 'Transfer-Encoding': 'chunked' });
          res.write('chunk-1\n');
          setTimeout(() => {
            res.write('chunk-2\n');
            res.end();
          }, 20);
          return;
        }

        res.statusCode = 200;
        res.end(JSON.stringify({ status: 'success', echoUrl: req.url }));
      });
    });

    targetServer.listen(0, '127.0.0.1', () => {
      targetPort = targetServer.address().port;
      done();
    });
  });

  after((done) => {
    targetServer.close(done);
  });

  beforeEach(() => {
    receivedHeaders = {};
    receivedMethod = '';
    receivedBody = '';
    receivedUrl = '';
    // Clear relevant env vars
    delete process.env.TARGET_URL;
    delete process.env.PROXY_SECRET;
    delete process.env.QUERY_PARAM_KEY;
  });

  describe('Health Check Endpoint', () => {
    it('should respond to /health with 200 OK', async () => {
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const res = await request(app).get('/health');
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.text, 'OK');
      assert.strictEqual(res.headers['x-powered-by'], undefined);
    });
  });

  describe('Inconspicuous Landing Page', () => {
    it('should return 200 Service operational when accessed without target', async () => {
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const res = await request(app).get('/');
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.text, 'Service operational');
      assert.strictEqual(res.headers['x-powered-by'], undefined);
      assert.strictEqual(res.headers['server'], undefined);
    });
  });

  describe('Secret Password / Access Control', () => {
    it('should deny unauthorized requests with an inconspicuous 404 when PROXY_SECRET is set', async () => {
      process.env.PROXY_SECRET = 'my-super-secret-key';
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const targetUrl = `http://127.0.0.1:${targetPort}/test`;
      const res = await request(app).get(`/?url=${encodeURIComponent(targetUrl)}`);
      assert.strictEqual(res.statusCode, 404);
      assert.strictEqual(res.headers['x-powered-by'], undefined);
    });

    it('should allow authorized requests when secret is provided in query param', async () => {
      process.env.PROXY_SECRET = 'my-super-secret-key';
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const targetUrl = `http://127.0.0.1:${targetPort}/test`;
      const res = await request(app).get(`/?url=${encodeURIComponent(targetUrl)}&secret=my-super-secret-key`);
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(JSON.parse(res.text).status, 'success');
    });

    it('should allow authorized requests when secret is provided in header', async () => {
      process.env.PROXY_SECRET = 'my-super-secret-key';
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const targetUrl = `http://127.0.0.1:${targetPort}/test`;
      const res = await request(app)
        .get(`/?url=${encodeURIComponent(targetUrl)}`)
        .set('X-Proxy-Secret', 'my-super-secret-key');
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(JSON.parse(res.text).status, 'success');
      // Secret header should NOT be forwarded to upstream
      assert.strictEqual(receivedHeaders['x-proxy-secret'], undefined);
    });
  });

  describe('Dynamic Target Proxying & HTTP Methods', () => {
    it('should proxy GET requests to dynamic ?url target and spoof headers', async () => {
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const targetUrl = `http://127.0.0.1:${targetPort}/api/resource?foo=bar`;
      const res = await request(app).get(`/?url=${encodeURIComponent(targetUrl)}`);

      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(receivedUrl, '/api/resource?foo=bar');
      assert.strictEqual(receivedHeaders['host'], `127.0.0.1:${targetPort}`);
      assert.strictEqual(receivedHeaders['x-forwarded-for'], undefined);
      assert.ok(receivedHeaders['user-agent'].includes('Mozilla/5.0'));

      // Inconspicuous response headers
      assert.strictEqual(res.headers['x-powered-by'], undefined);
      assert.strictEqual(res.headers['server'], undefined);
      assert.strictEqual(res.headers['via'], undefined);
      assert.strictEqual(res.headers['access-control-allow-origin'], '*');
    });

    it('should proxy POST requests with body to dynamic ?url target', async () => {
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const targetUrl = `http://127.0.0.1:${targetPort}/post-endpoint`;
      const postPayload = JSON.stringify({ item: 'gadget', count: 5 });

      const res = await request(app)
        .post(`/?url=${encodeURIComponent(targetUrl)}`)
        .set('Content-Type', 'application/json')
        .send(postPayload);

      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(receivedMethod, 'POST');
      assert.strictEqual(receivedBody, postPayload);
    });

    it('should handle OPTIONS preflight requests cleanly with CORS headers', async () => {
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const res = await request(app).options('/');
      assert.strictEqual(res.statusCode, 204);
      assert.strictEqual(res.headers['access-control-allow-origin'], '*');
      assert.ok(res.headers['access-control-allow-methods'].includes('POST'));
    });
  });

  describe('Static TARGET_URL Fallback', () => {
    it('should proxy requests to TARGET_URL when dynamic query param is absent', async () => {
      process.env.TARGET_URL = `http://127.0.0.1:${targetPort}`;
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const res = await request(app).get('/static/path?q=1');
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(receivedUrl, '/static/path?q=1');
      assert.strictEqual(receivedHeaders['host'], `127.0.0.1:${targetPort}`);
    });
  });

  describe('Streaming & Media Handling', () => {
    it('should stream chunked responses cleanly without truncation', async () => {
      delete require.cache[require.resolve('../src/index.js')];
      const { createApp } = require('../src/index.js');
      const { app } = createApp();

      const targetUrl = `http://127.0.0.1:${targetPort}/chunked`;
      const res = await request(app).get(`/?url=${encodeURIComponent(targetUrl)}`);
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(res.text, 'chunk-1\nchunk-2\n');
    });
  });

  describe('WebSocket Proxying', () => {
    let wsServer;
    let wsPort;
    let proxyHttpServer;
    let proxyPort;

    before((done) => {
      // Mock Upstream WebSocket Server
      const dummyHttp = http.createServer();
      wsServer = new WebSocketServer({ server: dummyHttp });
      wsServer.on('connection', (ws) => {
        ws.on('message', (msg) => {
          ws.send('echo:' + msg.toString());
        });
      });

      dummyHttp.listen(0, '127.0.0.1', () => {
        wsPort = dummyHttp.address().port;

        // Start Proxy Server with TARGET_URL
        process.env.TARGET_URL = `http://127.0.0.1:${wsPort}`;
        delete require.cache[require.resolve('../src/index.js')];
        const { startServer } = require('../src/index.js');
        proxyHttpServer = startServer(0, '127.0.0.1');
        proxyHttpServer.on('listening', () => {
          proxyPort = proxyHttpServer.address().port;
          done();
        });
      });
    });

    after((done) => {
      proxyHttpServer.close(() => {
        wsServer.close(done);
      });
    });

    it('should upgrade and proxy WebSocket messages back and forth', (done) => {
      const client = new WebSocket(`ws://127.0.0.1:${proxyPort}/ws`);

      client.on('open', () => {
        client.send('ping-render');
      });

      client.on('message', (data) => {
        assert.strictEqual(data.toString(), 'echo:ping-render');
        client.close();
        done();
      });

      client.on('error', (err) => {
        done(err);
      });
    });
  });
});
