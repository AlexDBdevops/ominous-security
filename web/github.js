'use strict';
// Descarga de un repo público de GitHub desde el navegador, sin servidor:
// metadatos y árbol por la API (api.github.com, con CORS) y el contenido de cada
// fichero desde raw.githubusercontent.com, todo en el commit exacto analizado.
// Nada se ejecuta: los ficheros solo se cargan en el sistema de ficheros en memoria.
const fs = require('fs');
const { repoMetaFrom, parseScorecard } = require('../lib/github');
const { parseGitmodules } = require('../lib/extra');

const ROOT = '/repo';
const MAX_FILES = 3000;
const MAX_FILE = 2 * 1024 * 1024;
const MAX_TOTAL = 60 * 1024 * 1024;
const CONCURRENCY = 12;

class GhError extends Error {
  constructor(message, { status = 0, reasons = [], hint = null } = {}) {
    super(message);
    this.status = status;
    this.reasons = reasons;
    this.hint = hint;
  }
}

const enc = (p) => p.split('/').map(encodeURIComponent).join('/');

async function get(url, { accept = 'application/vnd.github+json', timeout = 15000, f = fetch } = {}) {
  let r;
  try {
    r = await f(url, { headers: { accept }, signal: AbortSignal.timeout(timeout), credentials: 'omit', referrerPolicy: 'no-referrer' });
  } catch (e) {
    throw new GhError('No se pudo conectar con GitHub.', {
      reasons: [
        'Tu conexión a internet o un bloqueador (extensión, cortafuegos, proxy de empresa) impide llegar a api.github.com o raw.githubusercontent.com.',
        'Si abres la página dentro de claude.ai, el visor de artefactos puede bloquear las conexiones a otras webs. Ábrela en la web publicada o en el servidor local.',
        'GitHub puede estar caído: mira githubstatus.com.',
      ],
    });
  }
  return r;
}

function rateLimited(r) {
  return (r.status === 403 || r.status === 429) && r.headers.get('x-ratelimit-remaining') === '0';
}
function rateError(r) {
  const reset = Number(r.headers.get('x-ratelimit-reset'));
  const at = reset ? new Date(reset * 1000).toLocaleTimeString('es', { hour: '2-digit', minute: '2-digit' }) : null;
  return new GhError('Has llegado al límite de consultas a GitHub.', {
    status: 429,
    reasons: [
      'Sin iniciar sesión, GitHub permite 60 consultas por hora a cada dirección IP. Cada análisis usa unas 5, y la IP puede ser compartida (red de empresa, universidad, VPN).',
      at ? `El límite se renueva a las ${at}.` : 'El límite se renueva en menos de una hora.',
    ],
    hint: 'Si lo necesitas sin límites, usa el servidor local: puede usar tu token de GitHub.',
  });
}

async function api(path, opts = {}) {
  const r = await get(`https://api.github.com${path}`, opts);
  if (rateLimited(r)) throw rateError(r);
  let json = null;
  if (opts.accept === 'application/vnd.github.sha') json = r.ok ? (await r.text()).trim() : null;
  else { try { json = await r.json(); } catch { json = null; } }
  return { status: r.status, ok: r.ok, json };
}

// Explica por qué GitHub responde 404 (u otro error) al pedir el repositorio.
async function repoError(status, json, owner, repo, f) {
  const name = `${owner}/${repo}`;
  if (status === 404) {
    const u = await api(`/users/${encodeURIComponent(owner)}`, { f }).catch(() => null);
    if (u && u.status === 404) {
      return new GhError(`La cuenta «${owner}» no existe en GitHub.`, {
        status: 404,
        reasons: [
          'El nombre del usuario u organización está mal escrito (revisa guiones y letras cambiadas; las mayúsculas dan igual).',
          'La cuenta se ha borrado o ha cambiado de nombre. GitHub no redirige los nombres de usuario antiguos.',
          'GitHub ha suspendido la cuenta, algo habitual con cuentas que publican malware.',
        ],
      });
    }
    return new GhError(`GitHub no muestra ningún repositorio público llamado ${name}.`, {
      status: 404,
      reasons: [
        'El nombre está mal escrito o la URL está incompleta.',
        'Es privado. GitHub responde 404 en lugar de «sin permiso» para no revelar que existe, y esta página solo puede leer repos públicos.',
        'Se ha borrado, o GitHub lo ha retirado (por ejemplo, por malware o por infringir sus normas).',
        'Ha cambiado de nombre o de dueño y la redirección del nombre antiguo se ha perdido (pasa si alguien crea otro repo con el nombre antiguo).',
      ],
    });
  }
  if (status === 451) {
    return new GhError(`GitHub ha bloqueado ${name} por motivos legales.`, { status, reasons: ['Suele ser una retirada por DMCA o una orden judicial. El contenido no está disponible.'] });
  }
  if (status === 403 && json && json.block) {
    return new GhError(`GitHub ha bloqueado el acceso a ${name}.`, { status, reasons: [`Motivo indicado por GitHub: ${json.block.reason || 'no especificado'}.`, 'Suele ocurrir cuando el repo infringe las normas de GitHub, por ejemplo por distribuir malware.'] });
  }
  return new GhError(`GitHub ha respondido con un error (${status}) al pedir ${name}.`, { status, reasons: [json && json.message ? `Mensaje de GitHub: ${json.message}` : 'Prueba de nuevo en unos minutos.'] });
}

async function pool(items, n, fn) {
  let i = 0;
  const run = async () => { while (i < items.length) { const k = i++; await fn(items[k], k); } };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, run));
}

// Descarga el repo al sistema de ficheros en memoria y devuelve lo que necesita el análisis.
async function fetchRepo(ref, { log = () => {}, f = fetch } = {}) {
  const { owner, repo } = ref;
  const base = `/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`;
  log('Consultando el repositorio en GitHub…');
  const r = await api(base, { f });
  if (!r.ok) throw await repoError(r.status, r.json, owner, repo, f);
  const info = r.json;
  // Si el repo cambió de nombre, GitHub redirige: se usa el nombre real.
  const [o2, n2] = String(info.full_name || `${owner}/${repo}`).split('/');
  const real = `/repos/${encodeURIComponent(o2)}/${encodeURIComponent(n2)}`;

  const branch = ref.branch || info.default_branch;
  const c = await api(`${real}/commits/${enc(branch)}`, { f, accept: 'application/vnd.github.sha' });
  if (c.status === 409) throw new GhError(`${o2}/${n2} está vacío.`, { status: 409, reasons: ['El repositorio existe pero no tiene ningún commit: no hay código que analizar.'] });
  if (!c.ok || !/^[0-9a-f]{40}$/.test(c.json || '')) {
    throw new GhError(`La rama «${branch}» no existe en ${o2}/${n2}.`, { status: c.status || 404, reasons: [`Revisa el nombre de la rama. La rama principal de este repo es «${info.default_branch}».`, 'La rama puede haberse borrado o fusionado.'] });
  }
  const commit = c.json;

  log('Leyendo la lista de ficheros…');
  const [t, user, rel, sc] = await Promise.all([
    api(`${real}/git/trees/${commit}?recursive=1`, { f, timeout: 30000 }),
    api(`/users/${encodeURIComponent(o2)}`, { f }).then((x) => (x.ok ? x.json : null)).catch(() => null),
    api(`${real}/releases?per_page=5`, { f }).then((x) => (x.ok ? x.json : null)).catch(() => null),
    get(`https://api.securityscorecards.dev/projects/github.com/${encodeURIComponent(o2)}/${encodeURIComponent(n2)}`, { f, timeout: 8000, accept: 'application/json' })
      .then(async (x) => (x.ok ? parseScorecard(await x.json()) : null)).catch(() => null),
  ]);
  if (!t.ok || !t.json || !Array.isArray(t.json.tree)) throw new GhError('GitHub no ha devuelto la lista de ficheros.', { status: t.status, reasons: ['Puede ser un fallo temporal de GitHub. Prueba de nuevo.'] });
  const meta = repoMetaFrom(info, user, sc, Array.isArray(rel) ? rel : null);

  fs.__vfs.reset();
  const blobs = t.json.tree.filter((e) => e.type === 'blob');
  const submodules = t.json.tree.filter((e) => e.type === 'commit').map((e) => ({ path: e.path, sha: e.sha }));
  let budget = MAX_TOTAL;
  const wanted = [];
  let skipped = 0;
  for (const e of blobs) {
    if (wanted.length >= MAX_FILES) { skipped++; continue; }
    if (e.mode === '120000') { wanted.push(e); continue; } // enlace simbólico: el contenido es el destino
    if (e.size > MAX_FILE || e.size > budget) { fs.__vfs.putFile(`${ROOT}/${e.path}`, null, e.size); skipped++; continue; }
    budget -= e.size;
    wanted.push(e);
  }

  log(`Descargando ${wanted.length} ficheros del commit ${commit.slice(0, 10)}…`);
  let done = 0;
  let failed = 0;
  await pool(wanted, CONCURRENCY, async (e) => {
    const url = `https://raw.githubusercontent.com/${encodeURIComponent(o2)}/${encodeURIComponent(n2)}/${commit}/${enc(e.path)}`;
    try {
      const x = await get(url, { f, accept: '*/*', timeout: 30000 });
      if (!x.ok) throw new Error(String(x.status));
      const data = new Uint8Array(await x.arrayBuffer());
      if (e.mode === '120000') fs.__vfs.putFile(`${ROOT}/${e.path}`, null, 0, new TextDecoder().decode(data));
      else fs.__vfs.putFile(`${ROOT}/${e.path}`, data, data.length);
    } catch {
      failed++;
      fs.__vfs.putFile(`${ROOT}/${e.path}`, null, e.size || 0);
    }
    done++;
    if (done % 100 === 0) log(`Descargados ${done} de ${wanted.length} ficheros…`);
  });

  const extra = { vulns: [], threats: [], coverage: [] };
  extra.coverage.push({ label: 'Historial de git', status: 'skip', detail: 'no disponible en la versión web: GitHub no permite descargar el historial desde el navegador. Úsalo con el servidor local.' });
  submodulePass(ref, submodules, extra);
  if (t.json.truncated || skipped || failed) {
    extra.coverage.push({ label: 'Descarga de ficheros', status: 'partial', detail: [t.json.truncated && 'GitHub ha recortado la lista de ficheros (repo muy grande)', skipped && `${skipped} ficheros no descargados por tamaño (más de 2 MB o más de 60 MB en total) o por superar ${MAX_FILES} ficheros`, failed && `${failed} no se pudieron descargar`].filter(Boolean).join('; ') });
  }
  return { root: ROOT, meta, commit, branch, owner: o2, name: n2, extra };
}

// Submódulos: en la web no se descargan, pero se comprueba a dónde apuntan.
function submodulePass(ref, submodules, extra) {
  let subs = [];
  try { subs = parseGitmodules(ROOT); } catch { subs = []; }
  if (!subs.length && !submodules.length) return;
  for (const sm of subs) {
    const url = sm.url;
    const bad = /^(ext::|file:|\/|[a-z]:\\)/i.test(url) ? 'high' : /^http:\/\//i.test(url) ? 'medium' : null;
    if (bad) extra.threats.push({ kind: 'threat', rule: 'submodule-url', severity: bad, title: `Submódulo con URL peligrosa: ${sm.path}`, description: `Apunta a ${url}. Las URL ext::, file:// o http:// permiten ejecutar comandos o suplantar el contenido.`, file: '.gitmodules', line: null });
  }
  const n = Math.max(subs.length, submodules.length);
  extra.coverage.push({ label: 'Submódulos', status: 'skip', detail: `${n} sin analizar: la versión web no los descarga. Revísalos con el servidor local.` });
}

module.exports = { fetchRepo, GhError, ROOT };
