# Inconspicuous Reverse Proxy (Render Free Tier)

A lightweight, stealthy, high-performance reverse proxy designed specifically to run seamlessly within Render's free tier limits (512MB RAM, instant cold boots, zero-config deployment).

## Features

- **Resource Efficient & Stream-Piped**: Native stream piping via `http-proxy-middleware` prevents buffering media, video embeds, and large payloads into memory.
- **Inconspicuous & Stealthy**:
  - Response headers identifying the runtime (`X-Powered-By`, `Server`, `Via`, `X-Proxied-By`) are completely stripped.
  - Upstream request headers like internal proxy traces (`X-Forwarded-*`, `X-Real-IP`) are removed.
  - Injects realistic standard browser `User-Agent` and dynamically updates the `Host` header to match upstream.
  - Visiting root `/` without targets yields a bland, benign status message revealing nothing about being a proxy.
- **Render Free Tier Optimized**:
  - Automatically respects `$PORT` assigned by Render.
  - Dedicated `/health` endpoint for free uptime monitors (e.g. UptimeRobot, Cron-Job.org) to ping every 10–14 minutes, preventing free-tier sleep mode.
  - Included `render.yaml` Blueprint for 1-click zero-configuration deployment.
- **Hybrid Routing**:
  - **Dynamic Routing**: Pass target URLs dynamically via `?url=https://example.com/path` (parameter name customizable via `QUERY_PARAM_KEY`).
  - **Static Upstream Fallback**: Set a default `TARGET_URL` environment variable.
- **Security & Password Protection**:
  - Optional `PROXY_SECRET` environment variable. When set, only requests with the matching secret (via `?secret=YOUR_TOKEN` query parameter or `X-Proxy-Secret` header) are permitted. Unauthorized requests return an inconspicuous 404.
- **Full Protocol Support**:
  - Supports all HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `OPTIONS`, `HEAD`).
  - Permissive CORS headers automatically injected into responses (`Access-Control-Allow-Origin: *`).
  - WebSocket upgrade proxying enabled (`ws: true`).

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | `3000` | Port the proxy listens on (Render sets this automatically). |
| `TARGET_URL` | *empty* | Default upstream server fallback URL (e.g., `https://api.example.com`). |
| `QUERY_PARAM_KEY` | `url` | Name of the query parameter for dynamic destination forwarding. |
| `PROXY_SECRET` | *empty* | Optional secret password/token required to use the proxy. |
| `DEFAULT_USER_AGENT` | *Modern Chrome UA* | User-Agent header spoofed when forwarding to upstream. |

---

## Deployment to Render

### Option A: Render Blueprint (Recommended)
1. Fork or push this repository to GitHub/GitLab.
2. In the Render Dashboard, click **New +** -> **Blueprint**.
3. Connect your repository. Render reads `render.yaml` and configures everything automatically.
4. (Optional) Set `TARGET_URL` or review generated `PROXY_SECRET` in the Environment settings.

### Option B: Manual Web Service
1. Click **New +** -> **Web Service**.
2. Connect your repository.
3. Settings:
   - **Runtime**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Plan**: `Free`
   - **Health Check Path**: `/health`

---

## Preventing Free Tier Sleep

Render spins down free web services after 15 minutes of inactivity. To keep your proxy warm 24/7 at no cost:
1. Sign up for a free uptime monitoring service like [UptimeRobot](https://uptimerobot.com) or [Cron-Job.org](https://cron-job.org).
2. Create an **HTTP monitor** pointing to:
   ```
   https://<your-render-app-name>.onrender.com/health
   ```
3. Set the monitoring interval to **10 minutes**.

---

## Usage Examples

### 1. Dynamic Proxying
Forward a request dynamically to any site or stream:
```
https://<your-proxy>.onrender.com/?url=https://example.com/media/video.mp4
```

With authentication enabled (`PROXY_SECRET=mysecretkey`):
```
https://<your-proxy>.onrender.com/?url=https://example.com/media/video.mp4&secret=mysecretkey
```
or pass the header:
```bash
curl -H "X-Proxy-Secret: mysecretkey" "https://<your-proxy>.onrender.com/?url=https://example.com/api/data"
```

### 2. Static Upstream
If `TARGET_URL=https://api.example.com` is configured:
```
GET https://<your-proxy>.onrender.com/v1/users
```
forwards cleanly to:
```
GET https://api.example.com/v1/users
```

---

## Local Development & Testing

```bash
# Install dependencies
npm install

# Run locally
npm start

# Run test suite
npm test
```
