'use strict';
// El análisis de un repo de principio a fin: clonar (superficial y endurecido), historial,
// submódulos, herramientas externas y el analizador. Toca contenido de un repo ajeno, así que
// en Docker corre en su propio contenedor (lib/scanner.js), sin tu carpeta de clones ni tus
// claves; sin contenedor aparte (node server.js), corre dentro del servidor.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { Worker } = require('worker_threads');
const { git, GIT_SAFE, GIT_ENV, gitVersionCoverage, msLeft } = require('./gitsafe');
const { scanHistory } = require('./history');
const { parseGitmodules } = require('./extra');
const { externalPass } = require('./external');
const { parseGithubUrl, resolveBranch, releasePass, movedPass, scorecardCoverage } = require('./github');

const HISTORY_COMMITS = Number(process.env.HISTORY_COMMITS) || 300;
const MAX_SUBMODULES = 8;
// Un solo límite para todo el análisis: clonar, historial, submódulos, herramientas
// externas y código. Las fases previas paran antes para dejar tiempo al código
// (CODE_RESERVE), y el analizador para solo un poco antes del corte duro (SOFT_MARGIN)
// para devolver lo revisado en vez de un error. El corte duro queda para un fichero
// que lo cuelgue. Lo que se salta por tiempo aparece en la cobertura.
const ANALYSIS_TIMEOUT = Number(process.env.ANALYSIS_TIMEOUT_MS) || 20 * 60 * 1000;
const CODE_RESERVE = Math.min(6 * 60 * 1000, ANALYSIS_TIMEOUT * 0.4);
const SOFT_MARGIN = Math.min(2 * 60 * 1000, ANALYSIS_TIMEOUT * 0.15);

// Análisis en un hilo aparte hasta la hora límite `until`: el analizador para solo un
// poco antes y, si algo lo cuelga, se corta al llegar.
function runAnalysis(root, meta, log, extra, until) {
  if (!Number.isFinite(until)) until = Date.now() + ANALYSIS_TIMEOUT;
  return new Promise((resolve, reject) => {
    const soft = until - Math.min(SOFT_MARGIN, (until - Date.now()) / 4);
    const w = new Worker(path.join(__dirname, 'worker.js'), { workerData: { root, meta, extra: { ...extra, deadline: soft } } });
    const timer = setTimeout(() => {
      w.terminate();
      reject(Object.assign(new Error(`El análisis se quedó bloqueado y se ha cortado al llegar al tiempo máximo (${Math.round(ANALYSIS_TIMEOUT / 60000)} minutos en total, ANALYSIS_TIMEOUT_MS). Suele ser un fichero diseñado para bloquear analizadores: trátalo como sospechoso.`), { status: 504 }));
    }, msLeft(until));
    w.on('message', (m) => {
      if (m.log) log(m.log);
      else { clearTimeout(timer); w.terminate(); if (m.error) reject(new Error(m.error)); else resolve(m.result); }
    });
    w.on('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

// Historial: amplía el clon superficial y busca secretos/malware en líneas borradas.
async function historyPass(dir, extra, log, until) {
  log(`Descargando historial (hasta ${HISTORY_COMMITS} commits)…`);
  let deepened = true;
  try { await git(['-C', dir, 'fetch', '--deepen', String(HISTORY_COMMITS - 1), '--no-tags', '--no-recurse-submodules', 'origin'], { timeout: msLeft(until, 120000) }); } catch { deepened = false; }
  const h = await scanHistory(GIT_SAFE, dir, { commits: HISTORY_COMMITS, env: GIT_ENV, timeoutMs: msLeft(until, 120000) });
  for (const f of h.findings) (f.kind === 'vuln' ? extra.vulns : extra.threats).push(f);
  extra.coverage.push({
    label: 'Historial de git', status: !deepened || h.truncated || h.error || h.scanned >= HISTORY_COMMITS ? 'partial' : 'ok',
    detail: `${h.scanned} commit${h.scanned === 1 ? '' : 's'} revisado${h.scanned === 1 ? '' : 's'}${!deepened ? ' (no se pudo descargar más historial)' : ''}${h.truncated ? ' (límite de tamaño o tiempo alcanzado)' : ''}${h.scanned >= HISTORY_COMMITS ? ` (hay más commits antiguos sin revisar; HISTORY_COMMITS=${HISTORY_COMMITS})` : ''}`,
  });
}

// Submódulos: comprueba a dónde apuntan y analiza los de GitHub en el commit exacto que fija el repo.
async function submodulePass(root, tmp, ref, extra, log, deadline) {
  const subs = parseGitmodules(root);
  if (!subs.length) return;
  let analyzed = 0;
  for (const sm of subs) {
    let url = sm.url;
    if (/^\.\.?\//.test(url)) url = new URL(url, `https://github.com/${ref.owner}/${ref.repo}/`).href;
    const bad = /^(ext::|file:|\/|[a-z]:\\)/i.test(url) ? 'high' : /^http:\/\//i.test(url) ? 'medium' : null;
    if (bad) { extra.threats.push({ kind: 'threat', rule: 'submodule-url', severity: bad, title: `Submódulo con URL peligrosa: ${sm.path}`, description: `Apunta a ${url}. Las URL ext::, file:// o http:// permiten ejecutar comandos o suplantar el contenido.`, file: '.gitmodules', line: null }); continue; }
    const sub = parseGithubUrl(url.replace(/^git@github\.com:/, 'https://github.com/'), { short: false });
    if (!sub) { extra.threats.push({ kind: 'threat', rule: 'submodule-external', severity: 'low', title: `Submódulo fuera de GitHub: ${sm.path}`, description: `Apunta a ${url}. No se ha analizado.`, file: '.gitmodules', line: null }); continue; }
    if (analyzed >= MAX_SUBMODULES || Date.now() > deadline) continue;
    let sha = null;
    try { const ls = await git(['-C', root, 'ls-tree', 'HEAD', '--', sm.path]); sha = (ls.match(/^160000 commit ([0-9a-f]{40})/) || [])[1] || null; } catch { /* sin gitlink */ }
    const sdir = path.join(tmp, `sub${analyzed}`);
    try {
      log(`Analizando submódulo ${sm.path}…`);
      await git(['init', '-q', sdir]);
      await git(['-C', sdir, 'remote', 'add', 'origin', sub.cloneUrl]);
      await git(['-C', sdir, 'fetch', '--depth', '1', '--no-tags', 'origin', sha || 'HEAD'], { timeout: msLeft(deadline, 120000) });
      await git(['-C', sdir, 'checkout', '-q', 'FETCH_HEAD']);
      const r = await runAnalysis(fs.realpathSync.native(sdir), null, () => {}, {}, deadline);
      const pre = (f) => ({ ...f, file: f.file ? `${sm.path}/${f.file}` : sm.path, title: `${f.title} [submódulo]` });
      extra.vulns.push(...r.vulnerabilities.map(pre));
      extra.threats.push(...r.threats.map(pre));
      analyzed++;
    } catch (e) {
      extra.threats.push({ kind: 'threat', rule: 'submodule-fail', severity: 'low', title: `No se pudo analizar el submódulo ${sm.path}`, description: e.message, file: '.gitmodules', line: null });
    }
  }
  extra.coverage.push({ label: 'Submódulos', status: analyzed === subs.length ? 'ok' : 'partial', detail: `${analyzed} de ${subs.length} analizados${subs.length > MAX_SUBMODULES ? ` (máximo ${MAX_SUBMODULES})` : ''}` });
}

// Analiza ref (de parseGithubUrl) con los metadatos ya pedidos a GitHub. Devuelve la rama
// resuelta, el commit analizado y el resultado del analizador (con aiContext).
async function scanRepo({ ref, meta = null, until = Date.now() + ANALYSIS_TIMEOUT, log = () => {} }) {
  const prepUntil = until - CODE_RESERVE;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ominous-'));
  const dir = path.join(tmp, 'repo');
  try {
    // Enlace a una carpeta o a un fichero (/tree/rama/carpeta): la rama más larga que exista.
    ref = await resolveBranch(ref, async () => {
      const out = await git(['ls-remote', '--heads', '--tags', '--', ref.cloneUrl], { timeout: msLeft(prepUntil, 60000) });
      return out.split('\n').map((l) => (l.split('\t')[1] || '').replace(/^refs\/(heads|tags)\//, '').replace(/\^\{\}$/, ''));
    });
    const args = ['clone', '--depth', '1', '--no-tags', '--single-branch', '--no-recurse-submodules'];
    if (ref.branch) args.push('--branch', ref.branch);
    args.push('--', ref.cloneUrl, dir);
    try { await git(args, { timeout: msLeft(prepUntil) }); } catch (e) {
      throw Object.assign(new Error(`No se pudo descargar el repositorio (¿existe y es público?${Date.now() > prepUntil ? ' La descarga no terminó a tiempo.' : ''}). ${e.message}`), { status: 422 });
    }
    const commit = await git(['-C', dir, 'rev-parse', 'HEAD']);
    const branch = ref.branch || await git(['-C', dir, 'rev-parse', '--abbrev-ref', 'HEAD']);
    // remote: descarga (sin ejecutar) los scripts que el repo manda ejecutar con curl | sh y similares
    const extra = { vulns: [], threats: [], coverage: [], ref: { owner: ref.owner, repo: ref.repo, commit }, remote: true };
    movedPass(ref, meta, extra);
    scorecardCoverage(meta, extra);
    const timed = async (label, fn) => {
      if (Date.now() > prepUntil) { extra.coverage.push({ label, status: 'skip', detail: 'saltado: se acabó el tiempo del análisis (ANALYSIS_TIMEOUT_MS)' }); return; }
      await fn();
    };
    gitVersionCoverage(extra);
    await timed('Historial de git', () => historyPass(dir, extra, log, prepUntil));
    await timed('Submódulos', () => submodulePass(fs.realpathSync.native(dir), tmp, ref, extra, log, prepUntil));
    await timed('Herramientas externas', () => externalPass(fs.realpathSync.native(dir), tmp, extra, log, prepUntil));
    releasePass(meta, extra);
    const result = await runAnalysis(fs.realpathSync.native(dir), meta, log, extra, until);
    return { ref, commit, branch, result };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

module.exports = { scanRepo, ANALYSIS_TIMEOUT };
