# Stealth Calc

A fast, fully working calculator that doubles as a private web browser.

- **Calculator mode** — iOS-style dark keypad with full arithmetic (+, -, ×, ÷), parentheses, percent, sign toggle, and memory (MC / MR / M+ / M-). Keyboard input supported.
- **Secret entry** — type a web address into the display (`google.com`, `https://example.org`, `url:youtube.com/watch?v=...`) and press `=` or Enter (or tap the sliding Go button). The calculator seamlessly becomes a browser viewport.
- **URL normalization** — bare domains are auto-upgraded: `reddit.com` becomes `https://www.reddit.com`. `url:` prefix forces URL interpretation.
- **Scrambled URL bar** — the browser chrome shows a character-scrambled address at rest; it only shows plaintext while you're editing (or via the eye toggle).

## How it works

| Piece | Path | Role |
| --- | --- | --- |
| Proxy engine | `app/api/proxy/[...path]/route.ts` | Streams any http(s) resource through the server. Forwards Range/cookies/UA, follows nothing out-of-band, rewrites redirects back into the proxy namespace, strips `X-Frame-Options`/CSP/COOP/CORP, and namespaces proxied cookies (`__p_` prefix) so they never clobber app state. |
| Rewriter | `lib/rewrite.ts` | Rewrites `href/src/action/srcset/url()` into proxy URLs, drops CSP meta tags and SRI `integrity` attributes, rewrites HLS playlists (`.m3u8`) and CSS, and injects a client shim that patches `fetch`/`XHR`/`window.open` and dynamically-inserted elements so JS-heavy sites stay inside the proxy. Disables target-site service workers. |
| Browse viewport | `app/browse/[encodedUrl]/page.tsx` | Browser chrome (back / forward / refresh / scrambled URL bar / exit-to-calculator) over an iframe pointed at the proxy. |
| Calculator | `app/page.tsx` | The stealth UI + URL detection (`lib/urls.ts`) and a safe expression evaluator (`lib/calc.ts`, shunting-yard — no `eval`). |

Binary media (MP4, images, fonts, JSON) is passed through untouched as a `ReadableStream`, so `<video>` seeking, YouTube embeds and other framed content keep working.

## Run locally

```bash
npm install
npm run dev        # http://localhost:3000
```

## Deploy to Render

The app is configured for Render as a long-running Node service (`render.yaml`):

```bash
# Option A: dashboard — create a "Web Service" from this repo, defaults are read from render.yaml
# Option B: CLI
npm i -g @render/cli
render launch
```

Or manually in the Render dashboard:

- **Runtime:** Node
- **Build command:** `npm install && npm run build`
- **Start command:** `npm run start`

Render injects a `PORT` env var, which `next start` honors automatically. A long-running server (unlike serverless) means streamed video and downloads are not cut off by function timeouts.

## Notes & limitations

- YouTube **embeds** (`youtube.com/embed/...`) load and stay inside the proxy; the full youtube.com site is aggressively frame-hostile and may break out of the viewport.
- The viewport iframe is sandboxed (`sandbox="allow-scripts allow-forms allow-popups allow-same-origin allow-downloads allow-presentation"`), which blocks target sites from frame-busting the top-level app while keeping scripts, media, and storage working.
- Some sites with aggressive bot detection, heavy CSP, or login flows that pin cookies to specific domains may not fully work through the proxy.
- WebSocket traffic is not proxied; sites requiring live sockets (some chats, games) will fall back to polling or fail.
- This is a personal utility; don't use it to bypass access controls you don't have permission to bypass.

## Verified behavior

Tested end-to-end in a real browser (Playwright/Chromium):

- Calculator: arithmetic with precedence and parentheses (`12+7*3 = 33`), percent, sign toggle, memory (M+/MR/MC), keyboard input, mobile 375px layout.
- Secret entry: typing `example.com` + Enter resolves to `https://www.example.com`; bare domains get `https://www.` prepended; `url:` prefix forces URL mode; sliding Go button.
- Proxy: HTML/CSS/HLS rewriting (224 links rewritten on a Wikipedia page), redirects kept inside the proxy namespace, cookies namespaced (`__p_` prefix) and round-tripped, `X-Frame-Options`/CSP stripped, error pages styled.
- Media: MP4 streams with working Range requests (HTTP 206, `Content-Range`), HLS playlists rewritten, HTML5 `<video>` loads and plays through the proxy.
- Browser chrome: back/forward/refresh (deterministic navigation stack), scrambled URL bar at rest, eye toggle reveal, exit wipes state and halts streams.
