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

// Sleek dark-mode launcher UI for root visits
const renderLandingPage = (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gateway Terminal</title>
    <style>
        body { background: #0f172a; color: #f8fafc; font-family: system-ui, -apple-system, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .card { background: #1e293b; padding: 2rem; border-radius: 12px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.3); width: 100%; max-width: 480px; border: 1px solid #334155; }
        h2 { margin-top: 0; font-size: 1.25rem; color: #38bdf8; display: flex; align-items: center; gap: 8px; }
        p { color: #94a3b8; font-size: 0.875rem; margin-bottom: 1.5rem; }
        input { width: 100%; padding: 0.75rem; border-radius: 6px; border: 1px solid #475569; background: #0f172a; color: #fff; font-size: 0.9rem; box-sizing: border-box; margin-bottom: 1rem; outline: none; }
        input:focus { border-color: #38bdf8; }
        button { width: 100%; padding: 0.75rem; border-radius: 6px; border: none; background: #38bdf8; color: #0f172a; font-weight: 600; font-size: 0.9rem; cursor: pointer; transition: background 0.2s; }
        button:hover { background: #7dd3fc; }
        .footer { margin-top: 1rem; text-align: center; font-size: 0.75rem; color: #64748b; }
    </style>
</head>
<body>
    <div class="card">
        <h2>🔒 Secure Gateway</h2>
        <p>Enter a target URL to route through the stealth proxy session.</p>
        <form onsubmit="launchProxy(event)">
            <input type="text" id="targetInput" placeholder="https://example.com or cinesrc.st..." required autocomplete="off">
            <button type="submit">Launch Session</button>
        </form>
        <div class="footer">Encrypted Tunnel Active</div>
    </div>
    <script>
        function launchProxy(e) {
            e.preventDefault();
            let val = document.getElementById('targetInput').value.trim();
            if (!/^https?:\/\//i.test(val)) {
                val = 'https://' + val;
            }
            const encoded = btoa(val);
            window.location.href = '/?_px=' + encoded;
        }
    </script>
</body>
</html>`);
};

const dynamicProxy = (req, res, next) => {
    let targetUrl = process.env.TARGET_URL;
    let targetOrigin = null;

    // Check for dedicated Base64 control parameter ?_px=
    const pxMatch = req.url.match(/[?&]_px=([^&]+)/);

    if (pxMatch && pxMatch[1]) {
        try {
            let b64 = pxMatch[1].split('&')[0];
            // Fix spaces turned into '+' or missing padding
            b64 = b64.replace(/ /g, '+');
            while (b64.length % 4) {
                b64 += '=';
            }
            targetUrl = Buffer.from(b64, 'base64').toString('utf8');
        } catch (e) {
            return res.status(400).json({ error: 'Invalid encoded target format', details: e.message });
        }
    } else {
        // Fall back to sticky session cookie for sub-requests and API calls
        const cookies = parseCookies(req.headers.cookie);
        if (cookies._px_target) {
            targetOrigin = cookies._px_target;
            targetUrl = targetOrigin + req.url;
        }
    }

    // If root path and no active session or parameter, render launcher UI
    if (!targetUrl || (req.url === '/' && !pxMatch && !targetOrigin)) {
        return renderLandingPage(req, res);
    }

    if (PROXY_SECRET) {
        const clientSecret = req.query.secret || req.headers['x-proxy-secret'];
        if (clientSecret !== PROXY_SECRET) {
            return res.status(403).json({ error: 'Forbidden' });
        }
    }

    // Case-insensitive protocol check & fix
    if (!/^https?:\/\//i.test(targetUrl)) {
        targetUrl = 'https://' + targetUrl;
    }

    try {
        const parsedTarget = new URL(targetUrl);
        const origin = parsedTarget.origin;
        const currentHost = req.headers['host'];

        // Set sticky session cookie for subsequent sub-requests (2 hours)
        res.cookie('_px_target', origin, {
            httpOnly: true,
            secure: true,
            sameSite: 'None',
            maxAge: 7200000
        });

        const proxy = createProxyMiddleware({
            target: origin,
            changeOrigin: true,
            ws: true,
            xfwd: true,
            pathRewrite: () => parsedTarget.pathname + parsedTarget.search,
            on: {
                proxyReq: (proxyReq) => {
                    // Spoof robust browser headers for anti-bot & media streaming bypass
                    proxyReq.setHeader('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36');
                    proxyReq.setHeader('Accept-Language', 'en-US,en;q=0.9');
                    proxyReq.setHeader('Origin', origin);
                    proxyReq.setHeader('Referer', origin + '/');
                    proxyReq.setHeader('Sec-Ch-Ua', '"Chromium";v="123", "Not:A-Brand";v="8", "Google Chrome";v="123"');
                    proxyReq.setHeader('Sec-Ch-Ua-Mobile', '?0');
                    proxyReq.setHeader('Sec-Ch-Ua-Platform', '"Windows"');
                    
                    proxyReq.removeHeader('accept-encoding');
                    proxyReq.removeHeader('X-Powered-By');
                },
                proxyRes: (proxyRes, req, res) => {
                    delete proxyRes.headers['x-powered-by'];
                    delete proxyRes.headers['server'];
                    delete proxyRes.headers['via'];
                    delete proxyRes.headers['x-proxied-by'];

                    // Strip strict security headers that block iframe embedding
                    delete proxyRes.headers['content-security-policy'];
                    delete proxyRes.headers['x-frame-options'];
                    delete proxyRes.headers['cross-origin-opener-policy'];
                    delete proxyRes.headers['cross-origin-embedder-policy'];

                    proxyRes.headers['Access-Control-Allow-Origin'] = '*';
                    proxyRes.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
                    proxyRes.headers['Access-Control-Allow-Headers'] = '*';

                    // Rewrite redirect locations to keep traffic inside proxy domain
                    if (proxyRes.headers['location']) {
                        let loc = proxyRes.headers['location'];
                        if (loc.startsWith(origin)) {
                            proxyRes.headers['location'] = `https://${currentHost}${loc.substring(origin.length)}`;
                        } else if (loc.startsWith('/')) {
                            proxyRes.headers['location'] = `https://${currentHost}${loc}`;
                        }
                    }

                    // Sanitize Set-Cookie headers for cross-site compatibility
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
                    console.error(`[Proxy Error] Code: ${err.code} | Message: ${err.message} | Target: ${targetUrl}`);
                    if (!res.headersSent) {
                        res.status(502).json({
                            error: 'Bad Gateway',
                            details: err.message,
                            code: err.code,
                            target: targetUrl
                        });
                    }
                }
            }
        });

        return proxy(req, res, next);
    } catch (err) {
        console.error('URL Parse Error:', err.message);
        return res.status(400).json({ error: 'Invalid target URL format', details: err.message });
    }
};

app.use('/', dynamicProxy);

const server = app.listen(PORT, () => {
    console.log(`Hardened Stealth Proxy running on port ${PORT}`);
});

server.on('upgrade', (req, socket, head) => {
    // WebSocket upgrade handling managed via http-proxy-middleware ws: true
});
