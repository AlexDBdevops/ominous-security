'use strict';
// Vigilancia de los repos ya clonados (solo servidor local). Al clonar, se apunta el repo
// y los avisos de seguridad que tenían sus dependencias. Cada día (y con el botón
// "Comprobar ahora") se vuelven a leer sus ficheros de dependencias, se consultan en
// OSV.dev y se avisa de las vulnerabilidades publicadas después del clon.
// Solo se leen ficheros de dependencias; nada del repo se ejecuta. La lista vive en
// CLONE_DIR/.ominous/watch.json y nunca sale del equipo (a OSV.dev solo van nombres y
// versiones de paquetes, igual que en el análisis).
//   OMINOUS_WATCH=0           sin vigilancia
//   OMINOUS_WATCH_HOURS=24    cada cuántas horas se comprueba
//   OMINOUS_WATCH_TIMEOUT_MS  tiempo máximo de cada comprobación (10 minutos)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { Worker } = require('worker_threads');
const { auditDependencies, exploitSignals } = require('./deps');

const TIMEOUT = Number(process.env.OMINOUS_WATCH_TIMEOUT_MS) || 10 * 60 * 1000;

const MANIFEST = /(^|\/)(package(-lock)?\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|requirements[\w.-]*\.txt|poetry\.lock|uv\.lock|pdm\.lock|Pipfile\.lock|Cargo\.lock|Gemfile\.lock|composer\.lock|go\.(mod|sum)|pom\.xml|build\.gradle(\.kts)?|gradle\.lockfile|pubspec\.lock|packages\.lock\.json|[^/]+\.(cs|fs|vb)proj|mix\.lock|renv\.lock)$/;
const SKIP = new Set(['node_modules', '.git', 'vendor', 'dist', 'build', '.venv', 'venv']);
const MAX_REPOS = 200;
const MAX_ALERTS = 50;

// Ficheros de dependencias del clon, sin seguir enlaces simbólicos.
function manifests(dir) {
  const out = [];
  const stack = [['', 0]];
  let seen = 0;
  while (stack.length && seen < 20000) {
    const [rel, depth] = stack.pop();
    let entries;
    try { entries = fs.readdirSync(path.join(dir, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      seen++;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory() && !SKIP.has(e.name) && depth < 6) stack.push([r, depth + 1]);
      else if (e.isFile() && MANIFEST.test(r)) out.push(r);
    }
  }
  return out.sort();
}

// Identificadores de aviso de un resultado de dependencias: CVE/GHSA de las vulnerables
// y MAL- de las maliciosas.
function advisoryIds(findings) {
  const ids = new Map();
  for (const f of findings) {
    for (const id of f.advisories || []) if (!ids.has(id)) ids.set(id, f);
    for (const m of String(f.description || '').matchAll(/\bMAL-\d{4}-\d+\b/g)) if (!ids.has(m[0])) ids.set(m[0], f);
  }
  return ids;
}

// Comprueba un repo de la lista y devuelve su entrada actualizada (corre en el worker).
async function checkRepo(base, entry, log = () => {}) {
  const r = { ...entry, seen: [...entry.seen], alerts: [...entry.alerts] };
  let real;
  try { real = fs.realpathSync.native(r.dest); } catch { r.status = 'missing'; return { repo: r, added: 0 }; }
  if (!real.startsWith(base + path.sep)) { r.status = 'outside'; return { repo: r, added: 0 }; }
  const files = manifests(real);
  if (!files.length) { r.status = 'ok'; r.checkedAt = new Date().toISOString(); r.detail = 'sin ficheros de dependencias'; return { repo: r, added: 0 }; }
  const res = await auditDependencies(real, files);
  if (!res.summary.osvAvailable) { r.status = 'skip'; r.detail = `no se pudo consultar OSV.dev (${res.summary.osvError || 'sin conexión'})`; return { repo: r, added: 0 }; }
  const malicious = res.threats.filter((t) => t.rule === 'malicious-package');
  await exploitSignals(res.findings);
  const ids = advisoryIds([...res.findings, ...malicious]);
  const known = new Set(r.seen);
  const added = [...ids].filter(([id]) => !known.has(id));
  for (const [id, f] of added) {
    r.alerts.unshift({ at: new Date().toISOString(), id, title: f.title, severity: f.severity, file: f.file, kev: (f.osv || []).some((a) => a.kev && (a.id === id || (a.aliases || []).includes(id))) || undefined });
    r.seen.push(id);
  }
  r.alerts = r.alerts.slice(0, MAX_ALERTS);
  r.status = 'ok';
  r.detail = `${res.summary.checked} paquetes consultados`;
  r.checkedAt = new Date().toISOString();
  if (added.length) log(`vigilancia: ${added.length} aviso${added.length === 1 ? '' : 's'} nuevo${added.length === 1 ? '' : 's'} en ${r.repo}`);
  return { repo: r, added: added.length };
}

// Un repo que falla no para la comprobación de los demás.
async function checkRepoSafe(base, entry, log) {
  try { return await checkRepo(base, entry, log); } catch (e) {
    return { repo: { ...entry, status: 'skip', detail: `no se pudo comprobar (${e.message})` }, added: 0 };
  }
}

async function checkInline(base, repos, log) {
  const results = new Map();
  for (const r of repos) results.set(r.id, await checkRepoSafe(base, r, log));
  return { results, cut: null };
}

// En un hilo aparte: leer los ficheros de dependencias de muchos clones no bloquea el
// servidor, y si un lockfile preparado para atascar el análisis lo cuelga, se corta.
// Cada repo se entrega en cuanto se termina, así que al cortar no se pierde lo hecho.
function checkInWorker(base, repos, log, timeoutMs) {
  return new Promise((resolve) => {
    const results = new Map();
    const w = new Worker(path.join(__dirname, 'watch-worker.js'), { workerData: { base, repos } });
    let over = false;
    const finish = (cut) => {
      if (over) return;
      over = true;
      clearTimeout(timer);
      w.terminate();
      if (cut) log(`vigilancia: ${cut.replace(/^saltado: /, '')}`);
      resolve({ results, cut });
    };
    const timer = setTimeout(() => finish(`saltado: la comprobación superó ${Math.round(timeoutMs / 60000)} minutos y se cortó (OMINOUS_WATCH_TIMEOUT_MS)`), timeoutMs);
    w.on('message', (m) => {
      if (m.log) log(m.log);
      else if (m.result) results.set(m.result.repo.id, m.result);
      else if (m.done) finish(null);
    });
    w.on('error', (e) => finish(`saltado: la comprobación falló (${e.message})`));
    w.on('exit', () => finish(`saltado: la comprobación se detuvo antes de terminar`));
  });
}

class Watch {
  // inline: sin worker (los tests sustituyen fetch en este mismo hilo).
  constructor(cloneDir, { inline = false, timeoutMs = TIMEOUT } = {}) {
    this.root = cloneDir;
    this.file = path.join(cloneDir, '.ominous', 'watch.json');
    this.running = null;
    this.inline = inline;
    this.timeoutMs = timeoutMs;
  }

  load() {
    try {
      const j = JSON.parse(fs.readFileSync(this.file, 'utf8'));
      return Array.isArray(j.repos) ? j : { repos: [] };
    } catch { return { repos: [] }; }
  }

  save(data) {
    fs.mkdirSync(path.dirname(this.file), { recursive: true, mode: 0o700 });
    const tmp = `${this.file}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify(data, null, 1), { mode: 0o600 });
    fs.renameSync(tmp, this.file);
  }

  // Apunta un clon con los avisos que ya tenía (esos no se vuelven a notificar).
  add({ owner, repo, commit, dest, findings = [] }) {
    const data = this.load();
    const id = crypto.createHash('sha256').update(dest).digest('hex').slice(0, 16);
    data.repos = data.repos.filter((r) => r.id !== id);
    data.repos.unshift({ id, repo: `${owner}/${repo}`, url: `https://github.com/${owner}/${repo}`, commit, dest, clonedAt: new Date().toISOString(), checkedAt: null, status: 'pending', seen: [...advisoryIds(findings).keys()], alerts: [] });
    data.repos = data.repos.slice(0, MAX_REPOS);
    this.save(data);
    return id;
  }

  forget(id) {
    const data = this.load();
    const before = data.repos.length;
    data.repos = data.repos.filter((r) => r.id !== id);
    this.save(data);
    return { removed: before - data.repos.length };
  }

  list() {
    const data = this.load();
    return {
      checkedAt: data.checkedAt || null,
      repos: data.repos.map(({ seen, ...r }) => ({ ...r, known: seen.length, newAlerts: r.alerts.filter((a) => !a.read).length })),
    };
  }

  markRead() {
    const data = this.load();
    for (const r of data.repos) for (const a of r.alerts) a.read = true;
    this.save(data);
  }

  // Una sola comprobación a la vez; si ya hay una en curso, se espera a esa.
  check(log = () => {}) {
    if (!this.running) this.running = this._check(log).finally(() => { this.running = null; });
    return this.running;
  }

  async _check(log) {
    const data = this.load();
    const base = fs.realpathSync.native(this.root);
    const { results, cut } = this.inline ? await checkInline(base, data.repos, log) : await checkInWorker(base, data.repos, log, this.timeoutMs);
    let fresh = 0;
    // Los que no llegaron a comprobarse (tiempo agotado o fallo del worker) se marcan
    // como saltados; sus avisos anteriores se quedan como estaban.
    data.repos = data.repos.map((r) => {
      const x = results.get(r.id);
      if (x) { fresh += x.added; return x.repo; }
      return cut ? { ...r, status: 'skip', detail: cut } : r;
    });
    // Mientras se comprobaba se pudo clonar u olvidar algún repo: se respeta la lista actual.
    const now = this.load();
    const done = new Map(data.repos.map((r) => [r.id, r]));
    now.repos = now.repos.map((r) => (done.has(r.id) && done.get(r.id).clonedAt === r.clonedAt ? { ...done.get(r.id), alerts: done.get(r.id).alerts.map((a) => ({ ...a, read: a.read || (r.alerts.find((b) => b.id === a.id) || {}).read })) } : r));
    now.checkedAt = new Date().toISOString();
    this.save(now);
    return { newAlerts: fresh, ...this.list() };
  }
}

module.exports = { Watch, manifests, advisoryIds, checkRepoSafe };
