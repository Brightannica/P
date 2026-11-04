const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET || '';

app.disable('x-powered-by');

// Simple cookie parser helper
const parseCookies = (cookieHeader) => {
    const list = {};
    if (!cookieHeader) return list;
    cookieHeader.split(`;`).forEach(cookie => {
        let [key, ...val] = cookie.split(`=`);
        key = key?.trim();
        let value = val.join(`=`)?.trim();
        if (key) list[key] = decodeURIComponent(value);
    });
    return list;
};

const dynamicProxy = (req, res, next) => {
    let targetUrl = process.env.TARGET_URL;
    let targetOrigin = null;

    // 1. Check for explicit ?q= (Base64) or ?url=
    const qMatch = req.url.match(/[?&]q=([^&]+)/);
    const urlMatch = req.url.match(/[?&]url=([^&]+)/);

    if (qMatch && qMatch[1]) {
        try {
            targetUrl = Buffer.from(qMatch[1], 'base64').toString('utf8');
        } catch (e) {
            return res.status(400).json({ error: 'Invalid encoded target' });
        }
    } else if (urlMatch && urlMatch[1]) {
        try {
            targetUrl = decodeURIComponent(urlMatch[1]);
        } catch (e) {
            targetUrl = urlMatch[1];
        }
    } else {
        // 2. Fall back to sticky session cookie for background sub-requests
        const cookies = parseCookies(req.headers.cookie);
        if (cookies._px_target) {
            targetOrigin = cookies._px_target;
            targetUrl = targetOrigin + req.url;
        }
    }

    if (!targetUrl || (req.url === '/' && !urlMatch && !qMatch && !targetOrigin)) {
        return res.status(404).send('Not Found');
    }

    if (PROXY_SECRET) {
        const clientSecret = req.query.secret || req.headers['x-proxy-secret'];
        if (clientSecret !== PROXY_SECRET) {
            return res.status(403).json({ error: 'Forbidden' });
        }
    }

    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
        targetUrl = 'https://' + targetUrl;
    }

    try {
        const parsedTarget = new URL(targetUrl);
        const origin = parsedTarget.origin;

        // Set sticky cookie for background sub-requests
        res.cookie('_px_target', origin, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            maxAge: 3600000 // 1 hour session
        });

        const proxy = createProxyMiddleware({
            target: origin,
            changeOrigin: true,
            ws: true,
            xfwd: true,
            cookieDomainRewrite: { '*': '' },
            pathRewrite: () => parsedTarget.pathname + parsedTarget.search,
            on: {
                proxyReq: (proxyReq) => {
                    // Spoof browser headers tailored for media streaming & YouTube
                    const fakeUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36';
                    proxyReq.setHeader('User-Agent', fakeUserAgent);
                    proxyReq.setHeader('Accept-Language', 'en-US,en;q=0.9');
                    proxyReq.setHeader('Origin', origin);
                    proxyReq.setHeader('Referer', origin + '/');
                    proxyReq.setHeader('Sec-Ch-Ua', '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"');
                    proxyReq.setHeader('Sec-Ch-Ua-Mobile', '?0');
                    proxyReq.setHeader('Sec-Ch-Ua-Platform', '"Windows"');
                    proxyReq.setHeader('Sec-Fetch-Dest', 'iframe');
                    proxyReq.setHeader('Sec-Fetch-Mode', 'navigate');
                    proxyReq.setHeader('Sec-Fetch-Site', 'cross-site');
                    
                    // Scrub identifying headers
                    proxyReq.removeHeader('X-Powered-By');
                },
                proxyRes: (proxyRes) => {
                    // Scrub server fingerprint headers
                    delete proxyRes.headers['x-powered-by'];
                    delete proxyRes.headers['server'];
                    delete proxyRes.headers['via'];
                    delete proxyRes.headers['x-proxied-by'];

                    // CRITICAL: Strip strict CSP and frame restrictions so YouTube/embeds load inside iframes
                    delete proxyRes.headers['content-security-policy'];
                    delete proxyRes.headers['x-frame-options'];
                    delete proxyRes.headers['cross-origin-opener-policy'];
                    delete proxyRes.headers['cross-origin-embedder-policy'];

                    // Permissive CORS headers for cross-origin playback
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
        console.error('URL Parse Error:', err.message);
        return res.status(400).json({ error: 'Invalid target URL format' });
    }
};

app.use('/', dynamicProxy);

app.listen(PORT, () => {
    console.log(`Media-Ready Stealth proxy running on port ${PORT}`);
});
