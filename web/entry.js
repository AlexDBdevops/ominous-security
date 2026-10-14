'use strict';
// Paquete web del analizador. El mismo fichero sirve de dos formas:
// - como Web Worker: descarga el repo de GitHub y lo analiza fuera del hilo de la
//   página (la página lo corta si tarda demasiado, por ejemplo con un fichero
//   diseñado para colgar expresiones regulares);
// - como script normal: expone window.Ominous (fichas explicativas y, si el
//   navegador no deja crear el worker, el mismo análisis en la página).
const { analyzeTree } = require('../lib/analyzer');
const { explain } = require('../lib/explain');
const { impactOf } = require('../lib/review');
const { tr } = require('../lib/i18n');
// En la página, la caché de OSV y deps.dev vive en la memoria de la pestaña: volver a analizar
// el mismo repo (o uno con las mismas dependencias) no repite cientos de consultas.
require('../lib/netcache').enable();
const { parseGithubUrl, movedPass, scorecardCoverage, releasePass } = require('../lib/github');
const ai = require('../lib/ai');
const { fetchRepo, GhError } = require('./github');

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

function errInfo(e) {
  return { message: e.message, status: e.status || 0, reasons: e.reasons || [], hint: e.hint || null };
}

// Mismo protocolo en el worker y en la página: { type, url | findings } → { log } | { result } | { error }.
async function handle(msg, post) {
  try {
    if (msg.type === 'analyze') post({ result: await analyze(msg.url, (m) => post({ log: m }), msg.token || null, { deadline: Number(msg.deadline) || 0, inPage: msg.inPage === true, signal: msg.signal || null }) });
    else post({ error: { message: 'Mensaje desconocido' } });
  } catch (e) {
    post({ error: errInfo(e) });
  }
}

const isWorker = typeof WorkerGlobalScope !== 'undefined' && self instanceof WorkerGlobalScope; // eslint-disable-line no-undef
if (isWorker) {
  self.onmessage = (ev) => handle(ev.data || {}, (m) => self.postMessage(m));
} else if (typeof window !== 'undefined') {
  window.Ominous = Object.freeze({ explain, impactOf, parseGithubUrl, handle, tr });
}

module.exports = { analyze, handle };
