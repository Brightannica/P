const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET || ''; // Optional secret token

// Disable Express fingerprinting
app.disable('x-powered-by');

// Dynamic proxy handler middleware
const dynamicProxy = (req, res, next) => {
    // Extract the raw URL string after ?url= to preserve nested query params like ?s=1&e=5
    let targetUrl = process.env.TARGET_URL;
    const urlMatch = req.url.match(/[?&]url=([^&]+)/);
    
    if (urlMatch && urlMatch[1]) {
        try {
            targetUrl = decodeURIComponent(urlMatch[1]);
        } catch (e) {
            targetUrl = urlMatch[1];
        }
    }

    // If no target URL is provided anywhere, show benign 404 landing page
    if (!targetUrl || req.url === '/' || req.url === '') {
        return res.status(404).send('Not Found');
    }

    // Optional Security Token Check
    if (PROXY_SECRET) {
        const clientSecret = req.query.secret || req.headers['x-proxy-secret'];
        if (clientSecret !== PROXY_SECRET) {
            return res.status(403).json({ error: 'Forbidden' });
        }
    }

    // Ensure URL has a protocol
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
        targetUrl = 'https://' + targetUrl;
    }

    try {
        const parsedTarget = new URL(targetUrl);
        
        const proxy = createProxyMiddleware({
            target: parsedTarget.origin,
            changeOrigin: true,
            ws: true,
            xfwd: true,
            pathRewrite: (path, req) => {
                // Forward the exact target pathname and its query string
                return parsedTarget.pathname + parsedTarget.search;
            },
            on: {
                proxyReq: (proxyReq, req, res) => {
                    proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');
                    proxyReq.setHeader('Accept-Language', 'en-US,en;q=0.9');
                    proxyReq.removeHeader('X-Powered-By');
                },
                proxyRes: (proxyRes, req, res) => {
                    delete proxyRes.headers['x-powered-by'];
                    delete proxyRes.headers['server'];
                    delete proxyRes.headers['via'];
                    delete proxyRes.headers['x-proxied-by'];

                    // Permissive CORS for embedding / iframes
                    proxyRes.headers['Access-Control-Allow-Origin'] = '*';
                    proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
                    proxyRes.headers['Access-Control-Allow-Headers'] = '*';
                },
                error: (err, req, res) => {
                    console.error('Proxy Error:', err.message);
                    if (!res.headersSent) {
                        res.status(502).send('Bad Gateway');
                    }
                }
            }
        });

        return proxy(req, res, next);
    } catch (err) {
        return res.status(400).json({ error: 'Invalid target URL format' });
    }
};

// Route all incoming requests through the dynamic proxy logic
app.use('/', dynamicProxy);

app.listen(PORT, () => {
    console.log(`Stealth proxy running on port ${PORT}`);
});
