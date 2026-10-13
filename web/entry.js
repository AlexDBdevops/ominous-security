'use strict';
// Paquete web del analizador. El mismo fichero sirve de dos formas:
// - como Web Worker: descarga el repo de GitHub y lo analiza fuera del hilo de la
//   página (la página lo corta si tarda demasiado, por ejemplo con un fichero
//   diseñado para colgar expresiones regulares);
// - como script normal: expone window.Ominous (fichas explicativas y, si el
//   navegador no deja crear el worker, el mismo análisis en la página).
const fs = require('fs');
const path = require('path');
const { analyzeTree, applyAutoFixes } = require('../lib/analyzer');
const { explain } = require('../lib/explain');
const { impactOf } = require('../lib/review');
// En la página, la caché de OSV y deps.dev vive en la memoria de la pestaña: volver a analizar
// el mismo repo (o uno con las mismas dependencias) no repite cientos de consultas.
require('../lib/netcache').enable();
const { parseGithubUrl, movedPass, scorecardCoverage, releasePass } = require('../lib/github');
const ai = require('../lib/ai');
const { fetchRepo, GhError } = require('./github');

let last = null; // { root, files tocados por arreglos }

// La página pasa un plazo (hora límite): el analizador para solo entre fichero y fichero
// y devuelve lo revisado. En la página (sin Web Worker) nadie puede cortarlo desde fuera,
// así que además se lee menos de cada fichero.
const IN_PAGE_MAX_TEXT = 1.5 * 1024 * 1024;

async function analyze(url, log = () => {}, token = null, { deadline = 0, inPage = false, signal = null } = {}) {
  const ref = parseGithubUrl(url);
  if (!ref) throw new GhError('URL no válida. Usa algo como https://github.com/usuario/repositorio', { status: 400 });
  const got = await fetchRepo(ref, { log, token });
  const extra = { vulns: [], threats: [], coverage: [], ref: { owner: got.owner, repo: got.name, commit: got.commit } };
  movedPass(ref, got.meta, extra);
  scorecardCoverage(got.meta, extra);
  releasePass(got.meta, extra);
  extra.coverage.push(...got.extra.coverage);
  extra.threats.push(...got.extra.threats);
  if (deadline) extra.deadline = deadline;
  if (signal) extra.signal = signal;
  if (inPage) {
    extra.maxTextBytes = IN_PAGE_MAX_TEXT;
    extra.coverage.push({ label: 'Corte por tiempo', status: 'partial', detail: 'Este navegador no deja usar un Web Worker y el análisis corre en la propia página: se para entre fichero y fichero cuando se acaba el plazo y lee como mucho 1,5 MB de cada fichero de código, pero un solo fichero preparado para colgar el análisis no se puede cortar a medias.' });
  }
  log('Analizando el código…');
  const { aiContext, ...result } = await analyzeTree(got.root, got.meta, log, extra);
  last = { root: got.root };
  return {
    id: `web-${got.commit.slice(0, 12)}`,
    web: true,
    repo: { owner: got.owner, name: got.name, branch: got.branch, commit: got.commit, url: `https://github.com/${got.owner}/${got.name}`, meta: got.meta },
    ...result,
    ai: { available: false, files: aiContext.docs.length, decoded: aiContext.decoded.length, chars: aiContext.chars },
    aiPrompt: { system: ai.SYSTEM, prompt: ai.buildPrompt({ owner: got.owner, name: got.name, commit: got.commit, meta: got.meta }, aiContext), files: aiContext.docs.length, decoded: aiContext.decoded.length, chars: aiContext.chars },
    analyzedAt: new Date().toISOString(),
  };
}

// Diff unificado de los arreglos automáticos (para descargar como parche y aplicarlo
// con git apply en el clon). Los ficheros en memoria vuelven a su estado original.
function patch(findings) {
  if (!last) throw new Error('No hay ningún análisis en memoria.');
  const root = last.root;
  const files = [...new Set(findings.map((f) => f.file).filter(Boolean))];
  const before = new Map();
  for (const rel of files) { try { before.set(rel, fs.readFileSync(path.join(root, rel), 'utf8')); } catch { /* no existe */ } }
  const applied = applyAutoFixes(root, findings);
  const out = [];
  for (const [rel, old] of before) {
    const now = fs.readFileSync(path.join(root, rel), 'utf8');
    if (now !== old) out.push(fileDiff(rel, old, now));
    fs.writeFileSync(path.join(root, rel), old);
  }
  return { applied, diff: out.join('') };
}

// Los arreglos sustituyen líneas sin añadir ni quitar ninguna: basta comparar línea a línea.
function fileDiff(rel, oldText, newText) {
  if (/[\u0000-\u001f\u007f"\\]/.test(rel)) return ''; // git entrecomilla estas rutas: mejor no incluirlas
  const eol = oldText.endsWith('\n');
  const lines = (t) => { const l = t.split('\n'); if (t.endsWith('\n')) l.pop(); return l; };
  const a = lines(oldText);
  const b = lines(newText);
  const last = a.length - 1;
  const NOEOL = '\\ No newline at end of file\n';
  const changed = [];
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) changed.push(i);
  const hunks = [];
  for (const i of changed) {
    const s = Math.max(0, i - 3);
    const e = Math.min(last, i + 3);
    const h = hunks[hunks.length - 1];
    if (h && s <= h.e + 1) h.e = e; else hunks.push({ s, e });
  }
  let txt = `diff --git a/${rel} b/${rel}\n--- a/${rel}\n+++ b/${rel}\n`;
  const line = (sign, text, i) => `${sign}${text}\n${!eol && i === last ? NOEOL : ''}`;
  for (const { s, e } of hunks) {
    const n = e - s + 1;
    txt += `@@ -${s + 1},${n} +${s + 1},${n} @@\n`;
    let dels = [];
    let adds = [];
    const flush = () => { txt += dels.map(([t, i]) => line('-', t, i)).join('') + adds.map(([t, i]) => line('+', t, i)).join(''); dels = []; adds = []; };
    for (let i = s; i <= e; i++) {
      if (a[i] === b[i]) { flush(); txt += line(' ', a[i], i); } else { dels.push([a[i], i]); adds.push([b[i], i]); }
    }
    flush();
  }
  return txt;
}

function errInfo(e) {
  return { message: e.message, status: e.status || 0, reasons: e.reasons || [], hint: e.hint || null };
}

// Mismo protocolo en el worker y en la página: { type, url | findings } → { log } | { result } | { error }.
async function handle(msg, post) {
  try {
    if (msg.type === 'analyze') post({ result: await analyze(msg.url, (m) => post({ log: m }), msg.token || null, { deadline: Number(msg.deadline) || 0, inPage: msg.inPage === true, signal: msg.signal || null }) });
    else if (msg.type === 'patch') post({ result: patch(msg.findings || []) });
    else post({ error: { message: 'Mensaje desconocido' } });
  } catch (e) {
    post({ error: errInfo(e) });
  }
}

const isWorker = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope; // eslint-disable-line no-undef
if (isWorker) {
  self.onmessage = (ev) => handle(ev.data || {}, (m) => self.postMessage(m));
} else if (typeof window !== 'undefined') {
  window.Ominous = Object.freeze({ explain, impactOf, parseGithubUrl, handle });
}

module.exports = { analyze, patch, fileDiff, handle };
