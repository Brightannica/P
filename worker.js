export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const host = url.host;

    // Helper to parse cookies
    const getCookie = (name, cookieHeader) => {
      if (!cookieHeader) return null;
      const match = cookieHeader.match(new RegExp('(^| )' + name + '=([^;]+)'));
      return match ? decodeURIComponent(match[2]) : null;
    };

    let targetUrl = null;
    const pxParam = url.searchParams.get('_px');

    if (pxParam) {
      try {
        let b64 = pxParam.replace(/ /g, '+');
        while (b64.length % 4) b64 += '=';
        targetUrl = atob(b64);
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Invalid encoded target format', details: e.message }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }
    } else {
      const cookieHeader = request.headers.get('cookie');
      const savedOrigin = getCookie('_px_target', cookieHeader);
      if (savedOrigin) {
        targetUrl = savedOrigin + url.pathname + url.search;
      }
    }

    // If no target and hitting root, render sleek dark-mode launcher UI
    if (!targetUrl || (url.pathname === '/' && !pxParam && !getCookie('_px_target', request.headers.get('cookie')))) {
      return new Response(getLandingHTML(), {
        headers: { 'Content-Type': 'text/html;charset=UTF-8' }
      });
    }

    if (!/^https?:\/\//i.test(targetUrl)) {
      targetUrl = 'https://' + targetUrl;
    }

    let parsedTarget;
    try {
      parsedTarget = new URL(targetUrl);
    } catch (e) {
      return new Response(JSON.stringify({ error: 'Invalid target URL format', details: e.message }), {
        status: 400,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const origin = parsedTarget.origin;
    const fetchUrl = parsedTarget.toString();

    // Clone incoming headers and spoof robust browser fingerprint
    const newHeaders = new Headers(request.headers);
    newHeaders.set('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36');
    newHeaders.set('Accept-Language', 'en-US,en;q=0.9');
    newHeaders.set('Origin', origin);
    newHeaders.set('Referer', origin + '/');
    newHeaders.delete('Host');
    newHeaders.delete('accept-encoding'); // Prevent upstream compression corruption

    let response;
    try {
      response = await fetch(fetchUrl, {
        method: request.method,
        headers: newHeaders,
        body: ['GET', 'HEAD'].includes(request.method) ? null : request.body,
        redirect: 'manual'
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: 'Bad Gateway', details: err.message, target: fetchUrl }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Sanitize and build response headers
    const newResponseHeaders = new Headers(response.headers);
    newResponseHeaders.delete('x-powered-by');
    newResponseHeaders.delete('server');
    newResponseHeaders.delete('via');
    newResponseHeaders.delete('x-proxied-by');
    
    // Strip strict security headers that block iframe embedding
    newResponseHeaders.delete('content-security-policy');
    newResponseHeaders.delete('x-frame-options');
    newResponseHeaders.delete('cross-origin-opener-policy');
    newResponseHeaders.delete('cross-origin-embedder-policy');

    // Permissive CORS headers
    newResponseHeaders.set('Access-Control-Allow-Origin', '*');
    newResponseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    newResponseHeaders.set('Access-Control-Allow-Headers', '*');

    // Rewrite redirects to keep traffic inside your custom domain
    if (response.status >= 300 && response.status < 400 && newResponseHeaders.has('location')) {
      let loc = newResponseHeaders.get('location');
      if (loc.startsWith(origin)) {
        newResponseHeaders.set('location', `https://${host}${loc.substring(origin.length)}`);
      } else if (loc.startsWith('/')) {
        newResponseHeaders.set('location', `https://${host}${loc}`);
      }
    }

    // Set sticky session cookie for sub-requests (2 hours)
    newResponseHeaders.append('Set-Cookie', `_px_target=${origin}; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=7200`);

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: newResponseHeaders
    });
  }
};

function getLandingHTML() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Edge Gateway Terminal</title>
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
        <h2>⚡ Edge Stealth Gateway</h2>
        <p>Enter a target URL to route through the ultra-fast edge proxy.</p>
        <form onsubmit="launchProxy(event)">
            <input type="text" id="targetInput" placeholder="https://example.com or cinesrc.st..." required autocomplete="off">
            <button type="submit">Launch Edge Session</button>
        </form>
        <div class="footer">Cloudflare Edge Tunnel Active</div>
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
</html>`;
}
