#!/usr/bin/env node
'use strict';
// Ominous Security: analiza repos de GitHub antes de clonarlos.
// Uso: node server.js   →   http://localhost:8080

const http = require('http');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

// Caché de OSV, EPSS y deps.dev en la carpeta temporal (en Docker, un volumen que sobrevive a
// reinicios). Se fija antes de cargar los módulos: los hilos de análisis la heredan.
//   OMINOUS_NET_CACHE=0  sin caché
if (process.env.OMINOUS_NET_CACHE !== '0' && !process.env.OMINOUS_NET_CACHE_DIR) process.env.OMINOUS_NET_CACHE_DIR = path.join(os.tmpdir(), 'ominous-cache');
require('./lib/gitsafe').cleanStaleTemp();
try { require('./lib/netcache').prune(); } catch { /* sin caché */ }
const { applyAutoFixes } = require('./lib/analyzer');
const { summarizeDiff } = require('./lib/summary');
const { Watch } = require('./lib/watch');
const ai = require('./lib/ai');
const conn = require('./lib/connection');
const { parseGithubUrl, repoMetaFrom, parseScorecard } = require('./lib/github');
const { git, gitPatched, checkGit } = require('./lib/gitsafe');
const { scanRepo, ANALYSIS_TIMEOUT } = require('./lib/pipeline');
const { remoteScan, checkScan } = require('./lib/scanclient');
const WATCH = process.env.OMINOUS_WATCH !== '0';
const WATCH_HOURS = Number(process.env.OMINOUS_WATCH_HOURS) || 24;

const PORT = Number(process.env.PORT) || 8080;
const HOST = process.env.HOST || '127.0.0.1';
const CLONE_DIR = process.env.CLONE_DIR || path.join(os.homedir(), 'ominous-clones');
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const SCANNER_URL = process.env.OMINOUS_SCANNER_URL || '';
// Detrás de la pasarela (Docker): la IP real llega por PROXY protocol y solo se aceptan
// conexiones de la pasarela o locales (lib/proxyproto.js).
const PROXY_FROM = process.env.OMINOUS_PROXY_FROM || '';
const clientIp = (req) => req.socket.clientAddress || req.socket.remoteAddress;
const analyses = new Map(); // id -> { repo, commit, result, at }
const watch = new Watch(CLONE_DIR);
const MAX_ANALYSES = 50;
const MAX_REPO_MB = Number(process.env.MAX_REPO_MB) || 1024;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT) || 2;
const RATE_LIMIT = Number(process.env.RATE_LIMIT) || 30; // análisis por IP cada 10 minutos
const ALLOW_ANY_DEST = process.env.ALLOW_ANY_DEST === '1';
const TOKEN = process.env.OMINOUS_TOKEN || '';
const LOOPBACK = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i;
const allowedHosts = new Set([`localhost:${PORT}`, `127.0.0.1:${PORT}`, `[::1]:${PORT}`,
  ...String(process.env.ALLOWED_HOSTS || '').split(',').map((h) => h.trim().toLowerCase()).filter(Boolean)]);
// Expuesta = acepta peticiones dirigidas a un nombre que no es de esta máquina.
const EXPOSED = !!process.env.ALLOW_ANY_HOST || [...allowedHosts].some((h) => !LOOPBACK.test(h));


async function gh(pathname) {
  try {
    const r = await fetch(`https://api.github.com${pathname}`, {
      headers: { 'user-agent': 'ominous-security', accept: 'application/vnd.github+json', ...(GITHUB_TOKEN ? { authorization: `Bearer ${GITHUB_TOKEN}` } : {}) },
      signal: AbortSignal.timeout(10000),
    });
    return r.ok ? r.json() : null;
  } catch { return null; }
}

// OpenSSF Scorecard: puntuación pública (0-10) de las prácticas de seguridad del repo
// (revisión de código, ramas protegidas, dependencias fijadas, CI peligroso…).
async function scorecard(owner, repo) {
  try {
    const r = await fetch(`https://api.securityscorecards.dev/projects/github.com/${owner}/${repo}`, { headers: { 'user-agent': 'ominous-security' }, signal: AbortSignal.timeout(8000) });
    if (!r.ok) return null;
    return parseScorecard(await r.json());
  } catch { return null; }
}

async function repoMeta(owner, repo) {
  const r = await gh(`/repos/${owner}/${repo}`);
  if (!r) return null;
  const [u, sc, rel] = await Promise.all([gh(`/users/${owner}`), scorecard(owner, repo), gh(`/repos/${owner}/${repo}/releases?per_page=5`)]);
  return repoMetaFrom(r, u, sc, rel || []);
}

async function analyze(url) {
  const ref = parseGithubUrl(url);
  if (!ref) throw Object.assign(new Error('URL no válida. Usa algo como https://github.com/usuario/repositorio'), { status: 400 });
  const until = Date.now() + ANALYSIS_TIMEOUT;
  const meta = await repoMeta(ref.owner, ref.repo);
  if (meta && meta.size_kb > MAX_REPO_MB * 1024) {
    throw Object.assign(new Error(`El repositorio ocupa ${Math.round(meta.size_kb / 1024)} MB y el límite es ${MAX_REPO_MB} MB (MAX_REPO_MB).`), { status: 413 });
  }
  const log = (m) => console.log(`  [${ref.owner}/${ref.repo}] ${m}`);
  // Con OMINOUS_SCANNER_URL (Docker), el repo se clona y se analiza en otro contenedor, sin tu
  // carpeta de clones ni tus claves; lo que devuelve se comprueba antes de usarlo.
  const scan = checkScan(SCANNER_URL ? await remoteScan(SCANNER_URL, { ref, meta, until }) : await scanRepo({ ref, meta, until, log }), ref);
  const { aiContext, ...result } = scan.result;
  const id = crypto.randomUUID();
  const payload = {
    id, repo: { owner: ref.owner, name: ref.repo, branch: scan.branch, commit: scan.commit, url: `https://github.com/${ref.owner}/${ref.repo}`, meta }, ...result,
    ai: { available: ai.available(), files: aiContext.docs.length, decoded: aiContext.decoded.length, chars: aiContext.chars },
    analyzedAt: new Date().toISOString(),
  };
  analyses.set(id, { ref: { ...ref, branch: scan.branch }, commit: scan.commit, payload, aiContext, at: Date.now() });
  for (const [k, v] of analyses) if (Date.now() - v.at > 6 * 3600e3 || analyses.size > MAX_ANALYSES) analyses.delete(k);
  return payload;
}

// El destino del clon queda dentro de CLONE_DIR: si se pudiera elegir cualquier
// ruta, un clon en ~/.vim/pack/x/start, ~/.config/autostart o similares se
// ejecutaría solo. ALLOW_ANY_DEST=1 lo permite, pero nunca con la app expuesta.
function resolveDest(dest, repoName) {
  const raw = dest && String(dest).trim() ? String(dest).trim() : repoName;
  if (raw.includes('\0')) throw Object.assign(new Error('Destino no válido'), { status: 400 });
  const expanded = raw.replace(/^~(?=$|[\\/])/, os.homedir());
  const target = path.resolve(CLONE_DIR, expanded);
  if (ALLOW_ANY_DEST && !EXPOSED) return target;
  const rel = path.relative(path.resolve(CLONE_DIR), target);
  if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
    throw Object.assign(new Error(`El destino tiene que estar dentro de ${CLONE_DIR}. Escribe solo el nombre de la carpeta.`), { status: 400 });
  }
  return target;
}

function assertInsideCloneDir(dir) {
  if (ALLOW_ANY_DEST && !EXPOSED) return;
  const base = fs.realpathSync.native(CLONE_DIR);
  const real = fs.realpathSync.native(dir);
  if (real !== base && !real.startsWith(base + path.sep)) throw Object.assign(new Error('El destino sale de la carpeta de clones (enlace simbólico).'), { status: 400 });
}

async function clone({ id, dest, acknowledged, applyFixes }) {
  const a = analyses.get(id);
  if (!a) throw Object.assign(new Error('Análisis no encontrado o caducado. Vuelve a analizar el repositorio.'), { status: 404 });
  const aiRaised = !!(a.aiReview && a.aiReview.raises);
  if ((a.payload.summary.overall !== 'green' || aiRaised) && acknowledged !== true) {
    throw Object.assign(new Error(aiRaised && a.payload.summary.overall === 'green'
      ? 'La revisión con IA ha encontrado problemas graves: marca la casilla de confirmación para clonar.'
      : 'El análisis no está en verde: marca la casilla de confirmación para clonar.'), { status: 409 });
  }
  const target = resolveDest(dest, a.ref.repo);
  // .ominous guarda la lista de vigilancia: un repo con ese nombre podría escribirla.
  if (path.relative(path.resolve(CLONE_DIR), target).split(path.sep)[0] === '.ominous') throw Object.assign(new Error('Ese nombre de carpeta está reservado. Elige otro destino.'), { status: 400 });
  if (fs.existsSync(target)) throw Object.assign(new Error(`La carpeta ya existe: ${target}`), { status: 409 });
  // Se comprueba antes de crear nada: si no, un enlace dentro de otro clon crearía carpetas fuera.
  fs.mkdirSync(CLONE_DIR, { recursive: true });
  let existing = path.dirname(target);
  while (!fs.existsSync(existing)) existing = path.dirname(existing);
  assertInsideCloneDir(existing);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  assertInsideCloneDir(path.dirname(target));
  // Solo la rama analizada y sin tocar el disco hasta fijar el commit analizado: así no llega
  // a escribirse ni un fichero de otra rama o de un commit posterior al análisis.
  const args = ['clone', '--no-recurse-submodules', '--single-branch', '--no-checkout', '--config', 'core.protectNTFS=true', '--config', 'core.protectHFS=true'];
  if (a.ref.branch) args.push('--branch', a.ref.branch);
  args.push('--', a.ref.cloneUrl, target);
  await git(args, { timeout: 600000 });
  const head = await git(['-C', target, 'rev-parse', 'HEAD']);
  const pinned = head !== a.commit;
  const branchName = await git(['-C', target, 'symbolic-ref', '--short', 'HEAD']).catch(() => null);
  if (pinned) await git(['-C', target, 'fetch', '--no-tags', 'origin', a.commit], { timeout: 600000 }).catch(() => {});
  await git(['-C', target, 'checkout', '-q', ...(branchName ? ['-B', branchName] : ['--detach']), a.commit]);
  const fixes = applyFixes ? applyAutoFixes(fs.realpathSync.native(target), a.payload.vulnerabilities) : [];
  let diff = '';
  let summary = null;
  if (fixes.length) {
    diff = await git(['-C', target, 'diff', '--no-color', '--no-ext-diff', '-U3']);
    summary = await summarizeDiff({ diff, fixes, repo: `${a.ref.owner}/${a.ref.repo}` });
  }
  a.clonedTo = target;
  if (WATCH) {
    try {
      const deps = [...a.payload.vulnerabilities, ...a.payload.threats].filter((f) => f.rule === 'dep-vuln' || f.rule === 'malicious-package');
      watch.add({ owner: a.ref.owner, repo: a.ref.repo, commit: a.commit, dest: fs.realpathSync.native(target), findings: deps });
    } catch (e) { console.error(`✗ vigilancia: ${e.message}`); }
  }
  return { path: target, commit: a.commit, pinnedToAnalyzedCommit: pinned, fixesApplied: fixes, diff: diff.slice(0, 400000), diffTruncated: diff.length > 400000, summary };
}

// Segunda opinión de Claude sobre los ficheros de más riesgo. Solo añade avisos.
async function reviewWithAi({ id }) {
  const a = analyses.get(id);
  if (!a) throw Object.assign(new Error('Análisis no encontrado o caducado. Vuelve a analizar el repositorio.'), { status: 404 });
  if (a.aiReview) return a.aiReview;
  const r = await ai.aiReview({ repo: a.payload.repo, ctx: a.aiContext });
  a.aiReview = r;
  return r;
}

// Deshace los arreglos automáticos: deja el clon tal cual está en GitHub (commit analizado).
async function revert({ id }) {
  const a = analyses.get(id);
  if (!a || !a.clonedTo) throw Object.assign(new Error('No hay ningún clon de este análisis que deshacer.'), { status: 404 });
  await git(['-C', a.clonedTo, 'checkout', '--', '.']);
  return { path: a.clonedTo, reverted: true };
}

// ---------- HTTP ----------

const page = require('./lib/page');
const FONTS = path.join(page.PUBLIC, 'fonts');
const CSP = page.CSP;
const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer', 'cache-control': 'no-store',
  'x-frame-options': 'DENY', 'cross-origin-opener-policy': 'same-origin', 'cross-origin-resource-policy': 'same-origin',
  'permissions-policy': 'camera=(), microphone=(), geolocation=(), usb=(), payment=()',
};

function send(res, status, body, type = 'application/json; charset=utf-8', extraHeaders = {}) {
  res.writeHead(status, { 'content-type': type, ...SECURITY_HEADERS, ...(/^text\/html/.test(type) ? { 'content-security-policy': CSP } : {}), ...extraHeaders });
  res.end(typeof body === 'string' || Buffer.isBuffer(body) ? body : JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 64 * 1024) { reject(Object.assign(new Error('Petición demasiado grande'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(Object.assign(new Error('JSON inválido'), { status: 400 })); } });
  });
}

// Token de acceso: obligatorio si la app está expuesta. Se entrega una vez por
// URL (/?token=...) y se guarda en una cookie HttpOnly + SameSite=Strict.
function tokenOk(req) {
  if (!TOKEN) return true;
  const given = (req.headers.authorization || '').replace(/^Bearer\s+/i, '')
    || (String(req.headers.cookie || '').match(/(?:^|;\s*)ominous_token=([^;]+)/) || [])[1] || '';
  return sameSecret(given, TOKEN);
}

function sameSecret(x, y) {
  const a = crypto.createHash('sha256').update(String(x)).digest();
  const b = crypto.createHash('sha256').update(String(y)).digest();
  return crypto.timingSafeEqual(a, b);
}

// Límite de análisis por IP y de análisis simultáneos (cada uno clona y ocupa CPU y disco).
const hits = new Map();
let running = 0;
function rateLimited(ip) {
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < 10 * 60e3);
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 10000) hits.clear();
  return list.length > RATE_LIMIT;
}

const server = http.createServer(async (req, res) => {
  // Bloquea DNS rebinding y peticiones de otras webs (este servidor escribe en tu disco).
  if (!allowedHosts.has(String(req.headers.host)) && !process.env.ALLOW_ANY_HOST) return send(res, 403, { error: 'Host no permitido' });
  const origin = req.headers.origin;
  // Origen exacto, con su esquema: https solo detrás de un proxy con TLS (x-forwarded-proto).
  const scheme = req.headers['x-forwarded-proto'] === 'https' ? 'https' : 'http';
  if (req.method === 'POST' && origin && origin !== `${scheme}://${req.headers.host}`) return send(res, 403, { error: 'Origen no permitido' });

  const url = new URL(req.url, `http://${req.headers.host}`);
  if (TOKEN && req.method === 'GET' && url.pathname === '/' && url.searchParams.has('token')) {
    if (!sameSecret(url.searchParams.get('token'), TOKEN)) return send(res, 401, { error: 'Token incorrecto' });
    const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
    return send(res, 303, '', 'text/plain', { location: '/', 'set-cookie': `ominous_token=${encodeURIComponent(TOKEN)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000${secure}` });
  }
  // La comprobación de salud no exige token (la usan Docker y los scripts), pero sin él no da detalles.
  if (req.method === 'GET' && url.pathname === '/api/health') {
    return send(res, 200, { ok: true, mode: 'live', ...(tokenOk(req) ? { cloneDir: EXPOSED ? path.basename(CLONE_DIR) : CLONE_DIR, ai: ai.available(), aiConnection: conn.status() } : {}) });
  }
  if (!tokenOk(req)) {
    if (req.method === 'GET' && url.pathname === '/') return send(res, 401, '<!doctype html><meta charset="utf-8"><title>Ominous Security</title><p>Acceso protegido. Abre la URL con <code>?token=TU_TOKEN</code>.</p>', 'text/html; charset=utf-8');
    return send(res, 401, { error: 'Falta el token de acceso' });
  }
  try {
    if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
      return send(res, 200, page.HTML, 'text/html; charset=utf-8');
    }
    // Analizador para el navegador: en la app local solo da las fichas a la demo.
    if (req.method === 'GET' && url.pathname === '/analyzer.js') {
      return send(res, 200, fs.readFileSync(path.join(page.PUBLIC, 'analyzer.js')), 'text/javascript; charset=utf-8');
    }
    // Fuentes autoalojadas: solo los .woff2 de public/fonts, sin rutas.
    const fm = req.method === 'GET' && url.pathname.match(/^\/fonts\/([a-z0-9-]+\.woff2)$/);
    if (fm) {
      const file = path.join(FONTS, fm[1]);
      if (!fs.existsSync(file)) return send(res, 404, { error: 'No encontrado' });
      return send(res, 200, fs.readFileSync(file), 'font/woff2', { 'cache-control': 'public, max-age=604800, immutable' });
    }
    if (req.method === 'POST' && url.pathname === '/api/analyze') {
      if (!/application\/json/.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'Se espera JSON' });
      const body = await readJson(req);
      if (rateLimited(clientIp(req))) return send(res, 429, { error: 'Demasiados análisis seguidos. Espera unos minutos.' });
      if (running >= MAX_CONCURRENT) return send(res, 503, { error: 'Ya hay análisis en curso. Inténtalo en un momento.' });
      console.log(`→ Analizando ${String(body.url).slice(0, 200)}`);
      running++;
      try { return send(res, 200, await analyze(body.url)); } finally { running--; }
    }
    if (req.method === 'POST' && url.pathname === '/api/clone') {
      if (!/application\/json/.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'Se espera JSON' });
      const body = await readJson(req);
      const r = await clone(body);
      console.log(`✓ Clonado en ${r.path}`);
      return send(res, 200, r);
    }
    if (req.method === 'POST' && url.pathname === '/api/ai-review') {
      if (!/application\/json/.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'Se espera JSON' });
      const body = await readJson(req);
      if (rateLimited(clientIp(req))) return send(res, 429, { error: 'Demasiadas peticiones seguidas. Espera unos minutos.' });
      console.log('→ Revisión con IA');
      return send(res, 200, await reviewWithAi(body));
    }
    if (req.method === 'GET' && url.pathname === '/api/ai-connection') return send(res, 200, conn.status());
    if (req.method === 'POST' && url.pathname === '/api/ai-connection') {
      if (!/application\/json/.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'Se espera JSON' });
      const body = await readJson(req);
      if (rateLimited(clientIp(req))) return send(res, 429, { error: 'Demasiadas peticiones seguidas. Espera unos minutos.' });
      // La clave solo viaja desde este equipo o por HTTPS (detrás de un proxy con TLS).
      const secureChannel = !EXPOSED || req.headers['x-forwarded-proto'] === 'https';
      const r = body.verify ? await conn.verify() : await conn.configure(body, { secureChannel });
      console.log(`→ Conexión con Claude: ${r.method || 'ninguna'} ${r.connected ? '✓' : '✗'}`);
      return send(res, 200, r);
    }
    // Expuesta a la red: no se enseñan rutas completas del disco (como cloneDir en /api/health).
    const watchView = (w) => (EXPOSED ? { ...w, repos: w.repos.map((r) => ({ ...r, dest: path.relative(CLONE_DIR, r.dest) })) } : w);
    if (req.method === 'GET' && url.pathname === '/api/watch') return send(res, 200, { enabled: WATCH, hours: WATCH_HOURS, ...watchView(watch.list()) });
    if (req.method === 'POST' && /^\/api\/watch\/(check|forget|read)$/.test(url.pathname)) {
      if (!/application\/json/.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'Se espera JSON' });
      const body = await readJson(req);
      if (!WATCH) return send(res, 409, { error: 'La vigilancia está desactivada (OMINOUS_WATCH=0).' });
      if (url.pathname.endsWith('/forget')) return send(res, 200, watch.forget(String(body.id || '')));
      if (url.pathname.endsWith('/read')) { watch.markRead(); return send(res, 200, watchView(watch.list())); }
      if (rateLimited(clientIp(req))) return send(res, 429, { error: 'Demasiadas peticiones seguidas. Espera unos minutos.' });
      console.log('→ Comprobando los clones vigilados');
      return send(res, 200, watchView(await watch.check((m) => console.log(`  ${m}`))));
    }
    if (req.method === 'POST' && url.pathname === '/api/revert') {
      if (!/application\/json/.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'Se espera JSON' });
      return send(res, 200, await revert(await readJson(req)));
    }
    send(res, 404, { error: 'No encontrado' });
  } catch (e) {
    console.error(`✗ ${e.message}`);
    if (!res.headersSent) send(res, e.status || 500, { error: e.status ? e.message : 'Error interno' });
  }
});
// El análisis entero puede durar hasta ANALYSIS_TIMEOUT; las cabeceras, poco.
server.requestTimeout = ANALYSIS_TIMEOUT + 60000;
server.headersTimeout = 15000;

if (require.main === module) {
  if (EXPOSED && TOKEN.length < 24) {
    console.error('\n  La app acepta peticiones desde otros equipos (ALLOWED_HOSTS/ALLOW_ANY_HOST) y no tiene token.');
    console.error('  Define OMINOUS_TOKEN con al menos 24 caracteres, por ejemplo: OMINOUS_TOKEN=$(openssl rand -hex 24)\n');
    process.exit(1);
  }
  fs.mkdirSync(CLONE_DIR, { recursive: true });
  (PROXY_FROM ? require('./lib/proxyproto').proxyServer(server, PROXY_FROM) : server).listen(PORT, HOST, () => {
    console.log(`\n  Ominous Security escuchando en http://localhost:${PORT}`);
    console.log(`  Los clones se guardan en ${CLONE_DIR}\n`);
  });
  checkGit();
  if (WATCH) {
    // Vigilancia de los clones: al poco de arrancar y luego cada WATCH_HOURS horas.
    const tick = () => watch.check((m) => console.log(`  ${m}`)).catch((e) => console.error(`✗ vigilancia: ${e.message}`));
    setTimeout(tick, 60000).unref();
    setInterval(tick, WATCH_HOURS * 3600e3).unref();
  }
}

module.exports = { parseGithubUrl, resolveDest, server, gitPatched };
