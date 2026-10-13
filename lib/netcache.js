'use strict';
// Caché de las consultas a servicios públicos de datos (OSV, EPSS, deps.dev): el mismo paquete
// en la misma versión da la misma respuesta durante horas, y un análisis grande pregunta por
// cientos. Solo se guardan respuestas correctas; los errores se vuelven a preguntar.
//
// Está apagada salvo que alguien la active: el servidor la activa con disco (en su carpeta
// temporal, que sobrevive a reinicios del contenedor) y la página, solo en memoria.
// Nunca se cachea nada que lleve credenciales: solo se usa con estas URL públicas.
const MAX_MEM = 3000;
const mem = new Map(); // clave → { at, status, type, body }
let enabled = false;
let dir = null;

function enable(opts = {}) {
  enabled = true;
  dir = opts.dir || null;
  if (dir) {
    const fs = require('fs'); // eslint-disable-line global-require
    try { fs.mkdirSync(dir, { recursive: true, mode: 0o700 }); } catch { dir = null; }
  }
}
function disable() { enabled = false; dir = null; mem.clear(); }

function fileOf(key) {
  const crypto = require('crypto'); // eslint-disable-line global-require
  const path = require('path'); // eslint-disable-line global-require
  return path.join(dir, `${crypto.createHash('sha256').update(key).digest('hex')}.json`);
}

function remember(key, entry) {
  if (mem.size >= MAX_MEM) mem.delete(mem.keys().next().value);
  mem.set(key, entry);
  if (dir) { try { require('fs').writeFileSync(fileOf(key), JSON.stringify(entry), { mode: 0o600 }); } catch { /* sin disco: solo memoria */ } } // eslint-disable-line global-require
}

function recall(key, ttl) {
  let e = mem.get(key);
  if (!e && dir) { try { e = JSON.parse(require('fs').readFileSync(fileOf(key), 'utf8')); } catch { /* no está */ } } // eslint-disable-line global-require
  return e && Date.now() - e.at < ttl ? e : null;
}

// Como fetch, con la misma respuesta si ya se preguntó lo mismo hace menos de ttl.
async function cachedFetch(url, opts = {}, ttl = 12 * 3600e3) {
  if (!enabled) return fetch(url, opts);
  const key = `${opts.method || 'GET'} ${url} ${typeof opts.body === 'string' ? opts.body : ''}`;
  const hit = recall(key, ttl);
  if (hit) return new Response(hit.body, { status: hit.status, headers: { 'content-type': hit.type } });
  const r = await fetch(url, opts);
  if (!r.ok) return r;
  const body = await r.text();
  const entry = { at: Date.now(), status: r.status, type: r.headers.get('content-type') || 'application/json', body };
  remember(key, entry);
  return new Response(body, { status: entry.status, headers: { 'content-type': entry.type } });
}

// Borra del disco lo caducado (al arrancar el servidor)
function prune(maxAge = 24 * 3600e3) {
  if (!dir) return 0;
  const fs = require('fs'); // eslint-disable-line global-require
  const path = require('path'); // eslint-disable-line global-require
  let n = 0;
  for (const f of fs.readdirSync(dir)) {
    try { const p = path.join(dir, f); if (Date.now() - fs.statSync(p).mtimeMs > maxAge) { fs.rmSync(p, { force: true }); n++; } } catch { /* sigue */ }
  }
  return n;
}

// El servidor la activa con OMINOUS_NET_CACHE_DIR: así también la tienen sus hilos de trabajo
// (análisis y vigilancia), que heredan las variables de entorno.
if (typeof process !== 'undefined' && process.env && process.env.OMINOUS_NET_CACHE_DIR) enable({ dir: process.env.OMINOUS_NET_CACHE_DIR });

module.exports = { cachedFetch, enable, disable, prune };
