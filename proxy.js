const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;
const PROXY_SECRET = process.env.PROXY_SECRET || '';

app.disable('x-powered-by');

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

    // Check for dedicated Base64 control parameter ?_px=
    const pxMatch = req.url.match(/[?&]_px=([^&]+)/);

    if (pxMatch && pxMatch[1]) {
        try {
            let b64 = pxMatch[1].split('&')[0];
            targetUrl = Buffer.from(b64, 'base64').toString('utf8');
        } catch (e) {
            return res.status(400).json({ error: 'Invalid encoded target format' });
        }
    } else {
        // Fall back to sticky session cookie for background sub-requests, video chunks, and API calls
        const cookies = parseCookies(req.headers.cookie);
        if (cookies._px_target) {
            targetOrigin = cookies._px_target;
            targetUrl = targetOrigin + req.url;
        }
    }

    if (!targetUrl || (req.url === '/' && !pxMatch && !targetOrigin)) {
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
        const currentHost = req.headers['host'];

        // Set sticky session cookie for subsequent sub-requests
        res.cookie('_px_target', origin, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            maxAge: 7200000 // 2 hours
        });

        const proxy = createProxyMiddleware({
            target: origin,
            changeOrigin: true,
            ws: true,
            xfwd: true,
            pathRewrite: () => parsedTarget.pathname + parsedTarget.search,
            on: {
                proxyReq: (proxyReq) => {
                    // Spoof robust browser headers tailored for media streaming
                    proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36');
                    proxyReq.setHeader('Accept-Language', 'en-US,en;q=0.9');
                    proxyReq.setHeader('Origin', origin);
                    proxyReq.setHeader('Referer', origin + '/');
                    proxyReq.setHeader('Sec-Ch-Ua', '"Chromium";v="123", "Not:A-Brand";v="8", "Google Chrome";v="123"');
                    proxyReq.setHeader('Sec-Ch-Ua-Mobile', '?0');
                    proxyReq.setHeader('Sec-Ch-Ua-Platform', '"Windows"');
                    proxyReq.removeHeader('X-Powered-By');
                },
                proxyRes: (proxyRes, req, res) => {
                    // Scrub proxy footprints
                    delete proxyRes.headers['x-powered-by'];
                    delete proxyRes.headers['server'];
                    delete proxyRes.headers['via'];
                    delete proxyRes.headers['x-proxied-by'];

                    // Strip strict security headers that block iframe embedding
                    delete proxyRes.headers['content-security-policy'];
                    delete proxyRes.headers['x-frame-options'];
                    delete proxyRes.headers['cross-origin-opener-policy'];
                    delete proxyRes.headers['cross-origin-embedder-policy'];

                    // Permissive CORS headers
                    proxyRes.headers['Access-Control-Allow-Origin'] = '*';
                    proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
                    proxyRes.headers['Access-Control-Allow-Headers'] = '*';

                    // Rewrite redirect locations to keep traffic inside the proxy domain
                    if (proxyRes.headers['location']) {
                        let loc = proxyRes.headers['location'];
                        if (loc.startsWith(origin)) {
                            proxyRes.headers['location'] = `https://${currentHost}${loc.substring(origin.length)}`;
                        } else if (loc.startsWith('/')) {
                            proxyRes.headers['location'] = `https://${currentHost}${loc}`;
                        }
                    }

                    // Sanitize Set-Cookie headers so target session tokens work across domains
                    if (proxyRes.headers['set-cookie']) {
                        proxyRes.headers['set-cookie'] = proxyRes.headers['set-cookie'].map(cookie => {
                            return cookie
                                .replace(/;\s*secure/gi, '')
                                .replace(/;\s*samesite=[^;]+/gi, '')
                                .replace(/domain=[^;]+/gi, '') + '; SameSite=None; Secure';
                        });
                    }
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
});

app.use('/', dynamicProxy);

app.listen(PORT, () => {
    console.log(`Ultimate Stealth Proxy running on port ${PORT}`);
});
