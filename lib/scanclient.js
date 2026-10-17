'use strict';
// La app y el contenedor de análisis (lib/scanner.js). El scanner toca el repo ajeno: si un fallo
// de git, de Semgrep o de CodeQL lo comprometiera, lo único que puede hacer es mentir en lo que
// devuelve. Por eso la respuesta se comprueba entera antes de usarla (checkScan): tipos, tamaños
// y, sobre todo, el commit y la rama, que después llegan a git en el clon final de tu carpeta.
const http = require('http');

const SEV = new Set(['critical', 'high', 'medium', 'low', 'info']);
const STATUS = new Set(['green', 'yellow', 'red']);
const COVER = new Set(['ok', 'partial', 'skip']);
const IMPACT = new Set(['open', 'install', 'run', 'copy', 'deploy', 'docs', 'author']);
const MAX_RESPONSE = 64 * 1024 * 1024;

const bad = (why) => Object.assign(new Error(`El contenedor de análisis devolvió algo no válido (${why}).`), { status: 502 });
const str = (v, max = 2000) => (v == null ? undefined : String(v).slice(0, max));
const int = (v) => (Number.isInteger(v) && v >= 0 && v < 1e9 ? v : null);

// Rama que puede llegar a "git clone --branch": sin opciones disfrazadas ni rutas raras
function validBranch(b) {
  return typeof b === 'string' && b.length > 0 && b.length <= 255 && /^[\w.+/-]+$/.test(b) && !b.startsWith('-') && !b.includes('..') && !b.includes('//') && !/\.lock$|\/$|^\//.test(b);
}

function finding(f, kind) {
  if (!f || typeof f !== 'object') return null;
  const out = {
    kind, rule: /^[\w.-]{1,80}$/.test(f.rule) ? f.rule : 'desconocida',
    severity: SEV.has(f.severity) ? f.severity : 'high', // ante la duda, que se vea
    title: str(f.title, 300) || '(sin título)', description: str(f.description, 4000), detail: str(f.detail, 2000),
    file: str(f.file, 1000), line: int(f.line), snippet: str(f.snippet, 2000),
    impact: IMPACT.has(f.impact) ? f.impact : undefined, context: f.context === 'doc' ? 'doc' : f.context === 'code' ? 'code' : undefined,
    history: f.history === true || undefined, dev: f.dev === true || undefined,
  };
  if (kind === 'vuln') {
    out.fixable = f.fixable === true;
    if (f.fix && typeof f.fix === 'object') out.fix = { text: str(f.fix.text, 1000), auto: f.fix.auto === true };
    out.notFixableReason = str(f.notFixableReason, 1000);
  }
  if (f.review && typeof f.review === 'object') out.review = { from: SEV.has(f.review.from) ? f.review.from : undefined, to: SEV.has(f.review.to) ? f.review.to : undefined, why: str(f.review.why, 1000) };
  if (f.explain && typeof f.explain === 'object') {
    const e = f.explain;
    out.explain = {
      name: str(e.name, 300), why: str(e.why, 2000), check: str(e.check, 2000),
      cwe: e.cwe && typeof e.cwe === 'object' ? { id: str(e.cwe.id, 20), url: str(e.cwe.url, 300) } : undefined,
      flow: Array.isArray(e.flow) ? e.flow.slice(0, 40).map((x) => ({ file: str(x && x.file, 500), line: int(x && x.line), text: str(x && x.text, 300) })) : undefined,
    };
  }
  if (Array.isArray(f.osv)) {
    out.osv = f.osv.slice(0, 20).map((a) => (a && typeof a === 'object' ? {
      id: str(a.id, 80), aliases: (Array.isArray(a.aliases) ? a.aliases : []).slice(0, 5).map((x) => str(x, 40)), summary: str(a.summary, 500), details: str(a.details, 1000),
      severity: SEV.has(a.severity) ? a.severity : undefined, fixed: a.fixed == null ? null : str(a.fixed, 80), published: a.published == null ? null : str(a.published, 10),
      url: str(a.url, 300), refs: (Array.isArray(a.refs) ? a.refs : []).slice(0, 5).map((x) => str(x, 300)),
      epss: a.epss && typeof a.epss === 'object' && Number.isFinite(a.epss.score) && Number.isFinite(a.epss.pct) ? { score: Math.min(1, Math.max(0, a.epss.score)), pct: Math.min(1, Math.max(0, a.epss.pct)) } : undefined,
      kev: a.kev ? str(a.kev, 20) : undefined,
    } : null)).filter(Boolean);
  }
  if (f.decoded && typeof f.decoded === 'object') out.decoded = sanitizeDecoded(f.decoded);
  if (f.remote && typeof f.remote === 'object') out.remote = { url: str(f.remote.url, 500), ok: f.remote.ok === true, sha256: str(f.remote.sha256, 64), lines: int(f.remote.lines), kind: str(f.remote.kind, 40) };
  if (f.pkg && typeof f.pkg === 'object') out.pkg = { name: str(f.pkg.name, 200), ecosystem: str(f.pkg.ecosystem, 40) };
  // Identificadores de OSV (GHSA-…, CVE-…, PYSEC-…): la vigilancia los guarda como conocidos al clonar
  if (Array.isArray(f.advisories)) out.advisories = f.advisories.filter((x) => typeof x === 'string' && /^[A-Za-z][\w.:-]{2,79}$/.test(x)).slice(0, 10);
  for (const k of Object.keys(out)) if (out[k] === undefined) delete out[k];
  return out;
}

function sanitizeDecoded(d) {
  return {
    layers: Array.isArray(d.layers) ? d.layers.slice(0, 20).map((x) => str(x, 80)) : [],
    preview: d.preview == null ? null : str(d.preview, 1500), binaryType: d.binaryType == null ? null : str(d.binaryType, 40),
    innerFindings: Array.isArray(d.innerFindings) ? d.innerFindings.slice(0, 20).map((x) => ({ severity: SEV.has(x && x.severity) ? x.severity : 'high', title: str(x && x.title, 300), snippet: str(x && x.snippet, 500) })) : [],
  };
}

// Comprueba y limpia lo que devuelve el análisis (también el local: así ambos caminos dan lo mismo).
function checkScan(scan, ref) {
  if (!scan || typeof scan !== 'object' || !scan.result || typeof scan.result !== 'object') throw bad('sin resultado');
  if (!/^[0-9a-f]{40}$/.test(String(scan.commit))) throw bad('commit');
  if (!validBranch(scan.branch)) throw bad('rama');
  if (scan.ref && (scan.ref.owner !== ref.owner || scan.ref.repo !== ref.repo)) throw bad('otro repositorio');
  const r = scan.result;
  if (!Array.isArray(r.vulnerabilities) || !Array.isArray(r.threats)) throw bad('hallazgos');
  const a = r.aiContext && typeof r.aiContext === 'object' ? r.aiContext : {};
  const result = {
    vulnerabilities: r.vulnerabilities.slice(0, 20000).map((f) => finding(f, 'vuln')).filter(Boolean),
    threats: r.threats.slice(0, 20000).map((f) => finding(f, 'threat')).filter(Boolean),
    coverage: (Array.isArray(r.coverage) ? r.coverage : []).slice(0, 100).map((c) => ({ label: str(c && c.label, 200), status: COVER.has(c && c.status) ? c.status : 'partial', detail: str(c && c.detail, 1000) })),
    stats: { files: int(r.stats && r.stats.files) || 0, bytes: int(r.stats && r.stats.bytes) || 0, truncated: !!(r.stats && r.stats.truncated), topTypes: (r.stats && Array.isArray(r.stats.topTypes) ? r.stats.topTypes : []).slice(0, 6).map((x) => [str(x && x[0], 40), int(x && x[1]) || 0]) },
    dependencies: r.dependencies && typeof r.dependencies === 'object' ? JSON.parse(JSON.stringify(r.dependencies, (k, v) => (typeof v === 'string' ? v.slice(0, 500) : v))) : {},
    trust: (Array.isArray(r.trust) ? r.trust : []).slice(0, 30).map((t) => ({ label: str(t && t.label, 200), value: str(t && t.value, 300), ok: !!(t && t.ok) })),
    summary: {
      vulnStatus: STATUS.has(r.summary && r.summary.vulnStatus) ? r.summary.vulnStatus : 'red',
      threatStatus: STATUS.has(r.summary && r.summary.threatStatus) ? r.summary.threatStatus : 'red',
      overall: STATUS.has(r.summary && r.summary.overall) ? r.summary.overall : 'red',
      fixable: int(r.summary && r.summary.fixable) || 0, autoFixable: int(r.summary && r.summary.autoFixable) || 0,
      notFixable: int(r.summary && r.summary.notFixable) || 0, hiddenPayloads: int(r.summary && r.summary.hiddenPayloads) || 0,
    },
    aiContext: {
      // Solo se mandan a Claude como texto: se copian con las cadenas acotadas
      findings: Array.isArray(a.findings) ? JSON.parse(JSON.stringify(a.findings.slice(0, 500), (k, v) => (typeof v === 'string' ? v.slice(0, 1000) : v))) : [],
      tree: (Array.isArray(a.tree) ? a.tree : []).slice(0, 5000).map((x) => str(x, 500)),
      docs: (Array.isArray(a.docs) ? a.docs : []).slice(0, 50).map((d) => ({ file: str(d && d.file, 500), why: str(d && d.why, 100), text: str(d && d.text, 60000) })),
      decoded: (Array.isArray(a.decoded) ? a.decoded : []).slice(0, 50).map((d) => ({ file: str(d && d.file, 500), line: int(d && d.line), layers: (d && Array.isArray(d.layers) ? d.layers : []).slice(0, 20).map((x) => str(x, 80)), text: str(d && d.text, 20000) })),
      chars: int(a.chars) || 0,
    },
  };
  return { commit: scan.commit, branch: scan.branch, result };
}

// Pide el análisis al scanner. Llega en líneas JSON: { log } con cada paso (se pasan a onLog para
// que la página enseñe el progreso real) y al final { scan } o { error, status }.
function remoteScan(base, { ref, meta, until, onLog = () => {} }) {
  const body = JSON.stringify({ ref: { owner: ref.owner, repo: ref.repo, branch: ref.branch || null, path: ref.path || null }, meta, until });
  const u = new URL('/scan', base);
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (e) => { if (!settled) { settled = true; reject(e); } };
    const req = http.request(u, { method: 'POST', agent: false, headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) }, timeout: Math.max(1000, until - Date.now() + 30000) }, (res) => {
      let buf = '';
      let size = 0;
      const onLine = (l) => {
        if (!l.trim()) return;
        let j;
        try { j = JSON.parse(l); } catch { return fail(bad('JSON')); }
        if (res.statusCode !== 200) return fail(Object.assign(new Error(str(j && j.error, 500) || `Error del contenedor de análisis (${res.statusCode})`), { status: [400, 413, 422, 503, 504].includes(res.statusCode) ? res.statusCode : 502 }));
        if (typeof j.log === 'string') return onLog(j.log.slice(0, 300));
        if (j.error) return fail(Object.assign(new Error(str(j.error, 500)), { status: [400, 413, 422, 504].includes(j.status) ? j.status : 502 }));
        if (j.scan && !settled) { settled = true; resolve(j.scan); }
      };
      res.setEncoding('utf8');
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_RESPONSE) { req.destroy(); return fail(bad('respuesta demasiado grande')); }
        buf += c;
        let i;
        while ((i = buf.indexOf('\n')) >= 0) { onLine(buf.slice(0, i)); buf = buf.slice(i + 1); }
      });
      res.on('end', () => { onLine(buf); fail(bad('respuesta sin resultado')); });
      res.on('error', fail);
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('El contenedor de análisis no respondió a tiempo.'), { status: 504 })));
    req.on('error', (e) => fail(e.status ? e : Object.assign(new Error(`No se pudo contactar con el contenedor de análisis (${e.code || e.message}).`), { status: 502 })));
    req.end(body);
  });
}

module.exports = { checkScan, remoteScan, validBranch };
