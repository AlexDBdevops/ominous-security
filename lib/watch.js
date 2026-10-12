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
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { auditDependencies, exploitSignals } = require('./deps');

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

class Watch {
  constructor(cloneDir) {
    this.root = cloneDir;
    this.file = path.join(cloneDir, '.ominous', 'watch.json');
    this.running = null;
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
    let fresh = 0;
    for (const r of data.repos) {
      let real;
      try { real = fs.realpathSync.native(r.dest); } catch { r.status = 'missing'; continue; }
      if (!real.startsWith(base + path.sep)) { r.status = 'outside'; continue; }
      const files = manifests(real);
      if (!files.length) { r.status = 'ok'; r.checkedAt = new Date().toISOString(); r.detail = 'sin ficheros de dependencias'; continue; }
      const res = await auditDependencies(real, files);
      if (!res.summary.osvAvailable) { r.status = 'skip'; r.detail = `no se pudo consultar OSV.dev (${res.summary.osvError || 'sin conexión'})`; continue; }
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
      fresh += added.length;
      if (added.length) log(`vigilancia: ${added.length} aviso${added.length === 1 ? '' : 's'} nuevo${added.length === 1 ? '' : 's'} en ${r.repo}`);
    }
    // Mientras se comprobaba se pudo clonar u olvidar algún repo: se respeta la lista actual.
    const now = this.load();
    const done = new Map(data.repos.map((r) => [r.id, r]));
    now.repos = now.repos.map((r) => (done.has(r.id) && done.get(r.id).clonedAt === r.clonedAt ? { ...done.get(r.id), alerts: done.get(r.id).alerts.map((a) => ({ ...a, read: a.read || (r.alerts.find((b) => b.id === a.id) || {}).read })) } : r));
    now.checkedAt = new Date().toISOString();
    this.save(now);
    return { newAlerts: fresh, ...this.list() };
  }
}

module.exports = { Watch, manifests, advisoryIds };
