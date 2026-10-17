#!/usr/bin/env node
'use strict';
// Contenedor de análisis: clona el repo ajeno y lo analiza (lib/pipeline.js) lejos de la app.
// No tiene tu carpeta de clones, ni GITHUB_TOKEN, ni la clave de Anthropic, corre con otro
// usuario y solo sale a Internet por la pasarela. Si un repo explotara un fallo de git, Semgrep
// o CodeQL, se quedaría aquí: no puede leer tus clones, ni las claves de la app, ni hablar con
// ella (la app solo acepta conexiones que vienen de la pasarela).
//
// Una sola ruta, POST /scan { ref: { owner, repo, branch, path }, meta, until }, y GET /health.
//   SCANNER_PORT     puerto (8090)
//   MAX_CONCURRENT   análisis a la vez (2)
const http = require('http');
const { scanRepo, ANALYSIS_TIMEOUT } = require('./pipeline');
const { parseGithubUrl } = require('./github');
const { checkGit, cleanStaleTemp } = require('./gitsafe');
require('./netcache');

const PORT = Number(process.env.SCANNER_PORT) || 8090;
const MAX_CONCURRENT = Number(process.env.MAX_CONCURRENT) || 2;
const NAME = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
const REPO = /^[A-Za-z0-9._-]{1,100}$/;
let running = 0;

function send(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > 4 * 1024 * 1024) { reject(Object.assign(new Error('Petición demasiado grande'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(Object.assign(new Error('JSON inválido'), { status: 400 })); } });
  });
}

// La URL que se clona se construye aquí desde owner y repo (nunca se acepta una URL): lo que se
// clona es siempre https://github.com/<owner>/<repo>.git.
function refFrom(body) {
  const r = body && body.ref;
  if (!r || !NAME.test(String(r.owner)) || !REPO.test(String(r.repo)) || /^\.+$/.test(String(r.repo))) throw Object.assign(new Error('Repositorio no válido'), { status: 400 });
  const tail = r.branch ? `/tree/${String(r.branch)}${r.path ? `/${String(r.path)}` : ''}` : '';
  const ref = parseGithubUrl(`https://github.com/${r.owner}/${r.repo}${tail}`);
  if (!ref || ref.owner !== r.owner || ref.repo !== r.repo) throw Object.assign(new Error('Repositorio no válido'), { status: 400 });
  return ref;
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') return send(res, 200, { ok: true, running });
    if (req.method !== 'POST' || req.url !== '/scan') return send(res, 404, { error: 'No encontrado' });
    if (!/application\/json/.test(req.headers['content-type'] || '')) return send(res, 415, { error: 'Se espera JSON' });
    const body = await readJson(req);
    const ref = refFrom(body);
    if (running >= MAX_CONCURRENT) return send(res, 503, { error: 'Ya hay análisis en curso. Inténtalo en un momento.' });
    const until = Math.min(Number(body.until) || Infinity, Date.now() + ANALYSIS_TIMEOUT);
    running++;
    // Respuesta en líneas JSON: { log } con cada paso (la página enseña el progreso real) y al
    // final { scan } o { error, status }.
    res.writeHead(200, { 'content-type': 'application/x-ndjson; charset=utf-8', 'cache-control': 'no-store' });
    const line = (o) => { if (!res.destroyed) res.write(`${JSON.stringify(o)}\n`); };
    try {
      const log = (m) => { console.log(`  [${ref.owner}/${ref.repo}] ${m}`); line({ log: String(m).slice(0, 300) }); };
      console.log(`→ Analizando ${ref.owner}/${ref.repo}`);
      const r = await scanRepo({ ref, meta: body.meta && typeof body.meta === 'object' ? body.meta : null, until, log });
      line({ scan: { ref: { owner: r.ref.owner, repo: r.ref.repo }, commit: r.commit, branch: r.branch, result: r.result } });
    } catch (e) {
      console.error(`✗ ${e.message}`);
      line({ error: e.status ? e.message : `Error en el análisis: ${String(e.message).slice(0, 300)}`, status: e.status || 500 });
    } finally { running--; res.end(); }
  } catch (e) {
    console.error(`✗ ${e.message}`);
    if (!res.headersSent) send(res, e.status || 500, { error: e.status ? e.message : `Error en el análisis: ${String(e.message).slice(0, 300)}` });
  }
});
server.requestTimeout = 0; // el análisis entero puede durar ANALYSIS_TIMEOUT_MS
server.headersTimeout = 30000;

if (require.main === module) {
  cleanStaleTemp();
  checkGit();
  server.listen(PORT, '0.0.0.0', () => console.log(`\n  Contenedor de análisis escuchando en el puerto ${PORT}\n`));
}

module.exports = { server, refFrom };
