/**
 * Single public entry point for the container.
 *
 * WHAT IT SERVES
 * --------------
 *   GET /                -> the upstream renderer (the real Chat2API UI)
 *   /assets/*, static    -> files from out/renderer
 *   POST /__ipc          -> dispatch into upstream's ipcMain.handle registry
 *   GET  /__ipc/events   -> webContents.send events, streamed over SSE
 *   GET  /__preload.js   -> the browser bridge + upstream's preload bundle
 *   GET  /__login        -> guided add-account page
 *   POST /__login/finish -> validate + store the credential it collected
 *   /management/*        -> rewritten to /v0/management/*, then to the proxy
 *   everything else      -> upstream's HTTP handler (the API)
 *
 * ADDING ACCOUNTS
 * ---------------
 * Upstream's web login opens an Electron window and reads tokens out of it; a
 * container cannot. The /__login page therefore walks the user through copying
 * the credential themselves, then this server validates and stores it.
 *
 * Storage itself is upstream's: every account keeps its own credentials, so N
 * accounts for one provider coexist and are scheduled by the proxy. Whether the
 * browser is still signed in afterwards is irrelevant.
 */

'use strict'

const http = require('http')
const fs = require('fs')
const path = require('path')

const APP_DIR = process.env.CHAT2API_APP_DIR || path.join(__dirname, '..')
const SHIM_PATH = process.env.CHAT2API_SHIM || path.join(APP_DIR, 'shim', 'electron-shim.js')
const RENDERER_DIR = process.env.CHAT2API_RENDERER_DIR || path.join(APP_DIR, 'upstream', 'renderer')
const PRELOAD_FILE = process.env.CHAT2API_PRELOAD_FILE || path.join(APP_DIR, 'upstream', 'preload', 'index.js')
const BRIDGE_FILE = process.env.CHAT2API_BRIDGE_FILE || path.join(__dirname, 'preload-bridge.js')
const LOGIN_PAGE = process.env.CHAT2API_LOGIN_PAGE || path.join(__dirname, 'login.html')

const PUBLIC_PORT = parseInt(process.env.CHAT2API_PORT || '8082', 10)
const PUBLIC_HOST = process.env.CHAT2API_HOST || '0.0.0.0'
const SECRET_FILE = process.env.CHAT2API_SECRET_FILE
  || path.join(process.env.CHAT2API_HOME || '/data/.chat2api', '.management-secret')

const UPSTREAM_MGMT = '/v0/management'
const ALIAS_MGMT = '/management'

/* ------------------------------------------------------------------ *
 * Optional UI password gate.
 *
 * Enabled only when CHAT2API_UI_PASSWORD is set (non-empty). When
 * unset, the whole gate is a no-op and every request passes through
 * exactly as before.
 * ------------------------------------------------------------------ */
const UI_PASSWORD = process.env.CHAT2API_UI_PASSWORD || ''
const AUTH_COOKIE = 'chat2api_ui_auth'

function parseCookies(req) {
  const out = {}
  const raw = req.headers.cookie || ''
  for (const part of raw.split(';')) {
    const i = part.indexOf('=')
    if (i < 0) continue
    const k = part.slice(0, i).trim()
    const v = part.slice(i + 1).trim()
    try { out[k] = decodeURIComponent(v) } catch { out[k] = v }
  }
  return out
}

function hasUiAuth(req) {
  if (!UI_PASSWORD) return true
  return parseCookies(req)[AUTH_COOKIE] === UI_PASSWORD
}

function hasApiAuth(req) {
  // API clients may authenticate via Authorization header (API key / Bearer).
  return typeof req.headers.authorization === 'string' && req.headers.authorization.length > 0
}

const LOGIN_HTML = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Chat2API 登录</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
    background: radial-gradient(1200px 700px at 50% -10%, #1e293b 0%, #0f172a 55%, #020617 100%);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "PingFang SC", "Microsoft YaHei", sans-serif;
    color: #e2e8f0;
  }
  .card {
    width: 100%; max-width: 360px; padding: 36px 32px; margin: 20px;
    background: rgba(15, 23, 42, 0.75); border: 1px solid rgba(148, 163, 184, 0.18);
    border-radius: 16px; box-shadow: 0 24px 60px rgba(0,0,0,0.5); backdrop-filter: blur(12px);
  }
  h1 { margin: 0 0 6px; font-size: 22px; font-weight: 700; letter-spacing: 0.5px; }
  .sub { margin: 0 0 28px; font-size: 13px; color: #94a3b8; }
  label { display: block; font-size: 13px; color: #cbd5e1; margin-bottom: 8px; }
  input {
    width: 100%; padding: 12px 14px; font-size: 15px; color: #f1f5f9;
    background: rgba(2, 6, 23, 0.6); border: 1px solid rgba(148, 163, 184, 0.25);
    border-radius: 10px; outline: none; transition: border-color .15s, box-shadow .15s;
  }
  input:focus { border-color: #38bdf8; box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.18); }
  button {
    width: 100%; margin-top: 18px; padding: 12px; font-size: 15px; font-weight: 600;
    color: #0b1120; background: linear-gradient(180deg, #38bdf8, #0ea5e9);
    border: none; border-radius: 10px; cursor: pointer; transition: transform .06s, filter .15s;
  }
  button:hover { filter: brightness(1.06); }
  button:active { transform: translateY(1px); }
  .err { display: none; margin-top: 14px; font-size: 13px; color: #fca5a5; }
  .err.show { display: block; }
</style>
</head>
<body>
  <form class="card" id="f">
    <h1>Chat2API</h1>
    <p class="sub">请输入访问密码</p>
    <label for="pwd">密码</label>
    <input type="password" id="pwd" autocomplete="current-password" autofocus>
    <button type="submit">登 录</button>
    <div class="err" id="err">密码错误，请重试</div>
  </form>
  <script>
    document.getElementById('f').addEventListener('submit', async (e) => {
      e.preventDefault();
      const pwd = document.getElementById('pwd').value;
      const res = await fetch('/__auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: pwd })
      });
      if (res.ok) { location.href = '/'; return; }
      document.getElementById('err').classList.add('show');
    });
  </script>
</body>
</html>`

function sendLoginPage(res, status) {
  res.writeHead(status || 200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store'
  })
  res.end(LOGIN_HTML)
}

function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' })
  res.end(JSON.stringify(obj))
}

/* ------------------------------------------------------------------ *
 * Bridge access
 * ------------------------------------------------------------------ */
let shim = null
try {
  shim = require(SHIM_PATH)
} catch (err) {
  console.error('[front] could not load the electron shim, UI bridge disabled:', err.message)
}

function handlerCount() {
  return shim && shim.__ipcHandlers ? shim.__ipcHandlers.size : 0
}
function bridgeReady() {
  return handlerCount() > 0
}

function proxyHandler() {
  if (!shim || typeof shim.__httpHandler !== 'function') return null
  try {
    return shim.__httpHandler() || null
  } catch (err) {
    console.warn('[front] could not read the captured handler:', err.message)
    return null
  }
}

const streamClients = new Set()
if (shim && shim.__eventBus) {
  const bus = shim.__eventBus
  const originalEmit = bus.emit.bind(bus)
  bus.emit = (channel, ...rest) => {
    const args = Array.isArray(rest[0]) ? rest[0] : rest
    for (const client of streamClients) client(channel, args)
    return originalEmit(channel, ...rest)
  }
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.ico': 'image/x-icon',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.eot': 'application/vnd.ms-fontobject',
  '.map': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.txt': 'text/plain; charset=utf-8',
}

const API_PREFIXES = ['/v0/', '/v1/', '/api/', ALIAS_MGMT]

/* ------------------------------------------------------------------ *
 * UI
 * ------------------------------------------------------------------ */
function readSecret() {
  if (process.env.CHAT2API_MANAGEMENT_SECRET) return process.env.CHAT2API_MANAGEMENT_SECRET
  try {
    return fs.readFileSync(SECRET_FILE, 'utf8').trim()
  } catch {
    return ''
  }
}

function injectConsoleHtml(html) {
  let out = html
  if (!/<base\s/i.test(out)) {
    out = out.replace(/<head([^>]*)>/i, '<head$1><base href="/">')
  }
  if (!out.includes('/__preload.js')) {
    out = out.replace(/<head([^>]*)>/i, '<head$1><script src="/__preload.js"></script>')
  }
  return out
}

function sendFile(res, file, type, inject) {
  fs.readFile(file, (err, buf) => {
    if (err) {
      console.error('[front] cannot read', file, '-', err.message)
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('Missing file in this image: ' + file + '\n')
      return
    }
    const body = inject ? injectConsoleHtml(buf.toString('utf8')) : buf
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'no-store' })
    res.end(body)
  })
}

function serveIndex(res) {
  sendFile(res, path.join(RENDERER_DIR, 'index.html'), 'text/html; charset=utf-8', true)
}

/* ------------------------------------------------------------------ *
 * Preload bundle, wrapped for a browser
 * ------------------------------------------------------------------ */
function servePreload(res) {
  let bundle
  let bridge
  try {
    bundle = fs.readFileSync(PRELOAD_FILE, 'utf8')
    bridge = fs.readFileSync(BRIDGE_FILE, 'utf8')
  } catch (err) {
    console.error('[front] cannot read preload files:', err.message)
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
    res.end('preload bundle not found')
    return
  }

  if (/^\s*(import|export)\s/m.test(bundle)) {
    console.error('[front] preload bundle looks like ESM; the CJS wrapper will not work')
  }

  const js = bridge
    + '\n;(function (require, module, exports, process) {\n'
    + bundle
    + '\n}).call(window, window.__c2a_require, window.__c2a_module, window.__c2a_module.exports, window.__c2a_process);\n'

  res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' })
  res.end(js)
}

/* ------------------------------------------------------------------ *
 * IPC endpoints
 * ------------------------------------------------------------------ */
function readBody(req, limit = 8 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let size = 0
    const chunks = []
    req.on('data', (c) => {
      size += c.length
      if (size > limit) { reject(new Error('request body too large')); req.destroy(); return }
      chunks.push(c)
    })
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')))
    req.on('error', reject)
  })
}

async function callIpc(channel, args) {
  if (!shim || !shim.__ipcHandlers) throw new Error('IPC bridge is not available')
  const handler = shim.__ipcHandlers.get(channel)
  if (!handler) throw new Error(`no handler registered for channel: ${channel}`)
  return await handler({ sender: null, senderFrame: null }, ...(args || []))
}

async function handleIpc(req, res) {
  const send = (status, payload) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify(payload))
  }

  if (!shim || !shim.__ipcHandlers) {
    send(503, { ok: false, error: 'IPC bridge is not available in this container' })
    return
  }

  let body
  try {
    body = JSON.parse(await readBody(req))
  } catch (err) {
    send(400, { ok: false, error: 'invalid request: ' + err.message })
    return
  }

  const channel = body && body.channel
  const args = Array.isArray(body && body.args) ? body.args : []
  const handler = shim.__ipcHandlers.get(channel)
  if (!handler) {
    send(404, { ok: false, error: `no handler registered for channel: ${channel}` })
    return
  }

  try {
    const result = await handler({ sender: null, senderFrame: null }, ...args)
    send(200, { ok: true, result: result === undefined ? null : result })
  } catch (err) {
    console.error('[front] ipc error on', channel, err && err.message)
    send(200, { ok: false, error: (err && err.message) || String(err) })
  }
}

/* ------------------------------------------------------------------ *
 * Add-account page: validation and storage
 *
 * Storing is upstream's job, so this forwards to upstream's own channels rather
 * than writing to the store. That keeps credential encryption and any
 * de-duplication in one place.
 * ------------------------------------------------------------------ */
async function handleLoginFinish(req, res) {
  const send = (status, payload) => {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' })
    res.end(JSON.stringify(payload))
  }

  let body
  try {
    body = JSON.parse(await readBody(req, 256 * 1024))
  } catch (err) {
    send(400, { ok: false, error: 'invalid request: ' + err.message })
    return
  }

  const providerId = body && body.providerId
  const providerType = (body && body.providerType) || providerId
  const credentials = (body && body.credentials) || null
  const providedName = ((body && body.name) || '').toString().trim()

  if (!providerId || !credentials || !Object.keys(credentials).length) {
    send(400, { ok: false, error: '缺少 providerId 或 credentials' })
    return
  }

  // 1) Validate exactly as the UI's own "login with token" path does, so a
  //    mistyped or expired token fails here instead of becoming a dead account.
  let validation
  try {
    validation = await callIpc('oauth:validateToken', [{ providerId, providerType, credentials }])
  } catch (err) {
    send(200, { ok: false, error: '无法验证凭证：' + err.message })
    return
  }

  if (!validation || validation.valid !== true) {
    send(200, { ok: false, error: (validation && validation.error) || '凭证无效或已过期' })
    return
  }

  // 2) Store through upstream's account channel. The user-supplied name wins,
  //    because with several accounts per provider the display name is the only
  //    way to tell them apart.
  const info = validation.accountInfo || {}
  const name = providedName
    || info.name
    || info.email
    || `${providerId}-${new Date().toISOString().slice(5, 19).replace(/[-:T]/g, '')}`

  let saved
  try {
    saved = await callIpc('accounts:add', [{
      providerId,
      name,
      email: info.email || undefined,
      credentials,
    }])
  } catch (err) {
    send(200, { ok: false, error: '验证通过但保存失败：' + err.message })
    return
  }

  // Report how many this provider now has, so the page can show progress.
  let count = null
  try {
    const all = await callIpc('accounts:getAll', [false])
    if (Array.isArray(all)) {
      count = all.filter((a) => a && a.providerId === providerId).length
    }
  } catch {
    /* the count is a nicety; storing already succeeded */
  }

  console.log(`[front] stored account "${name}" for ${providerId} (now ${count ?? '?'})`)
  send(200, {
    ok: true,
    account: { name, email: info.email || null, id: saved && saved.id },
    providerAccountCount: count,
  })
}

function handleEvents(req, res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  })
  res.write(': connected\n\n')

  const client = (channel, args) => {
    try { res.write(`data: ${JSON.stringify({ channel, args })}\n\n`) } catch { /* closing */ }
  }
  streamClients.add(client)

  if (shim && typeof shim.__replayPendingOpens === 'function') {
    shim.__replayPendingOpens()
  }

  const heartbeat = setInterval(() => {
    try { res.write(': hb\n\n') } catch { /* closing */ }
  }, 25000)

  const cleanup = () => {
    clearInterval(heartbeat)
    streamClients.delete(client)
  }
  req.on('close', cleanup)
  res.on('close', cleanup)
}

/* ------------------------------------------------------------------ *
 * Static renderer files
 * ------------------------------------------------------------------ */
function serveStatic(res, urlPath) {
  const rel = decodeURIComponent(urlPath).replace(/^\/+/, '')
  const target = path.resolve(RENDERER_DIR, rel)
  if (!target.startsWith(path.resolve(RENDERER_DIR) + path.sep)) return false

  let stat
  try {
    stat = fs.statSync(target)
  } catch {
    return false
  }
  if (!stat.isFile()) return false

  const type = MIME[path.extname(target).toLowerCase()] || 'application/octet-stream'
  res.writeHead(200, {
    'Content-Type': type,
    'Content-Length': stat.size,
    'Cache-Control': 'public, max-age=3600',
  })
  fs.createReadStream(target).pipe(res)
  return true
}

/* ------------------------------------------------------------------ *
 * Request forwarding to upstream
 * ------------------------------------------------------------------ */
function isManagementPath(urlPath) {
  return urlPath === ALIAS_MGMT || urlPath.startsWith(ALIAS_MGMT + '/')
    || urlPath.startsWith(UPSTREAM_MGMT)
}

function prepareForGateway(req, urlPath) {
  if (!isManagementPath(urlPath)) return

  const secret = readSecret()
  if (secret) {
    req.headers.authorization = `Bearer ${secret}`
  } else {
    console.warn('[front] management secret unavailable at', SECRET_FILE)
  }

  if (!urlPath.startsWith(UPSTREAM_MGMT)) {
    req.url = UPSTREAM_MGMT + req.url.slice(ALIAS_MGMT.length)
  }
}

function dispatch(req, res, urlPath) {
  prepareForGateway(req, urlPath)

  const handler = proxyHandler()
  if (!handler) {
    console.error('[front] no proxy handler captured; cannot serve', urlPath)
    res.writeHead(503, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({
      error: {
        message: 'The proxy handler is not available yet. Check the container log for '
          + '"captured the HTTP request handler".',
        type: 'proxy_unavailable',
      },
    }))
    return
  }

  try {
    handler(req, res)
  } catch (err) {
    console.error('[front] in-process dispatch failed:', err && err.message)
    if (res.headersSent) { res.end(); return }
    res.writeHead(500, { 'Content-Type': 'application/json; charset=utf-8' })
    res.end(JSON.stringify({
      error: { message: (err && err.message) || 'internal error', type: 'dispatch_failed' },
    }))
  }
}

/* ------------------------------------------------------------------ *
 * Router
 * ------------------------------------------------------------------ */
function createServer() {
  return http.createServer((req, res) => {
    const urlPath = (req.url || '/').split('?')[0]

    /* --- optional UI password gate --- */
    if (urlPath === '/__auth/login' && req.method === 'POST') {
      let body = ''
      req.on('data', (c) => { body += c; if (body.length > 1024) req.destroy() })
      req.on('end', () => {
        let ok = false
        try { ok = UI_PASSWORD && JSON.parse(body).password === UI_PASSWORD } catch {}
        if (ok) {
          res.writeHead(200, {
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': AUTH_COOKIE + '=' + encodeURIComponent(UI_PASSWORD)
              + '; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000'
          })
          res.end('{"ok":true}')
        } else {
          sendJson(res, 401, { ok: false, error: 'wrong password' })
        }
      })
      return
    }
    if (urlPath === '/health') { dispatch(req, res, urlPath); return }
    if (urlPath === '/favicon.ico') { res.writeHead(204); res.end(); return }

    // Anything carrying an Authorization header is an API client: pass through.
    if (hasApiAuth(req)) {
      // fall through to the normal router below
    } else if (!hasUiAuth(req)) {
      // Browser without a valid session cookie: show the login page.
      if (urlPath === '/' || urlPath === '/index.html' || req.method === 'GET') {
        sendLoginPage(res, 200)
      } else {
        sendJson(res, 401, { ok: false, error: 'unauthorized' })
      }
      return
    }

    if (urlPath === '/__ipc' && req.method === 'POST') { void handleIpc(req, res); return }
    if (urlPath === '/__ipc/events') { handleEvents(req, res); return }
    if (urlPath === '/__preload.js') { servePreload(res); return }

    if (urlPath === '/__login') {
      sendFile(res, LOGIN_PAGE, 'text/html; charset=utf-8', false)
      return
    }
    if (urlPath === '/__login/finish' && req.method === 'POST') {
      void handleLoginFinish(req, res)
      return
    }

    if (urlPath === '/health' || urlPath === '/stats'
        || API_PREFIXES.some((p) => urlPath.startsWith(p))) {
      dispatch(req, res, urlPath)
      return
    }

    if (req.method === 'GET' || req.method === 'HEAD') {
      if (urlPath === '/' || urlPath === '/index.html') { serveIndex(res); return }
      if (serveStatic(res, urlPath)) return
      if (!path.extname(urlPath)) { serveIndex(res); return }
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' })
      res.end('Not found: ' + urlPath)
      return
    }

    dispatch(req, res, urlPath)
  })
}

function start() {
  const server = createServer()
  server.listen(PUBLIC_PORT, PUBLIC_HOST, () => {
    console.log(`[front] Chat2API ready on http://${PUBLIC_HOST}:${PUBLIC_PORT} (the only port)`)
    if (bridgeReady()) {
      console.log(`[front] UI: upstream renderer, IPC bridge active (${handlerCount()} channels)`)
    } else {
      console.warn('[front] UI: IPC bridge has NO registered channels - the page will not function.')
    }
    if (proxyHandler()) {
      console.log('[front] API: served in-process, no second port')
    } else {
      console.warn('[front] API: no proxy handler yet; API calls get 503 until it is captured')
    }
  })

  const shutdown = (sig) => {
    console.log(`[front] received ${sig}, closing`)
    server.close(() => process.exit(0))
    setTimeout(() => process.exit(0), 3000).unref()
  }
  for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => shutdown(sig))

  return server
}

module.exports = { start }

if (require.main === module) start()
