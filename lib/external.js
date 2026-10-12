'use strict';
// Herramientas externas opcionales (solo en el servidor local). Si Gitleaks, Semgrep,
// Trivy o CodeQL están instalados, se pasan sobre el clon temporal y sus hallazgos se
// suman a los de las reglas propias, con la explicación que da cada herramienta.
// Ninguna ejecuta código del repo: solo leen ficheros (y Gitleaks, el historial de git).
// CodeQL solo se usa en lenguajes que no hay que compilar, porque compilar ejecuta
// código del repo (plugins de Maven o Gradle, scripts de build).
// Se lanzan sin shell, con tiempo máximo y un entorno mínimo.
//   OMINOUS_EXTERNAL=0         no usar ninguna
//   OMINOUS_<TOOL>_BIN=ruta    ruta del ejecutable (por defecto, el del PATH)
//   OMINOUS_SEMGREP_CONFIG     reglas de Semgrep, separadas por comas (por defecto p/default;
//                              valen ficheros o carpetas locales, como un clon de semgrep-rules)
//   OMINOUS_CODEQL_TIMEOUT_MS  tiempo máximo de CodeQL por lenguaje
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const TIMEOUT = Number(process.env.OMINOUS_EXTERNAL_TIMEOUT_MS) || 4 * 60 * 1000;
const CODEQL_TIMEOUT = Number(process.env.OMINOUS_CODEQL_TIMEOUT_MS) || 8 * 60 * 1000;
const MAX_PER_TOOL = 200;
const SEV = { CRITICAL: 'critical', HIGH: 'high', ERROR: 'high', MEDIUM: 'medium', WARNING: 'medium', LOW: 'low', INFO: 'low', UNKNOWN: 'low' };

const bin = (id) => process.env[`OMINOUS_${id.toUpperCase()}_BIN`] || id;
const env = () => ({ PATH: process.env.PATH, HOME: process.env.HOME || '/tmp', SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0', TRIVY_NO_PROGRESS: 'true' });

function run(file, args, cwd, timeout = TIMEOUT) {
  return new Promise((resolve) => {
    execFile(file, args, { cwd, env: env(), timeout, maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, missing: !!(err && err.code === 'ENOENT'), killed: !!(err && err.killed), stdout, stderr: String(stderr || '') });
    });
  });
}

const cweOf = (list) => {
  const m = String((Array.isArray(list) ? list[0] : list) || '').match(/CWE-(\d+)/);
  return m ? { id: `CWE-${m[1]}`, url: `https://cwe.mitre.org/data/definitions/${m[1]}.html` } : null;
};
const clip = (s, n = 600) => { s = String(s || '').trim(); return s.length > n ? `${s.slice(0, n)}…` : s; };
const rel = (dir, p) => { const r = path.isAbsolute(String(p)) ? path.relative(dir, p) : String(p || ''); return r.replace(/\\/g, '/').replace(/^\.\//, '') || null; };

// ---------- Gitleaks: secretos en el código y en todo el historial descargado ----------
async function gitleaks(dir, tmp) {
  const out = path.join(tmp, 'gitleaks.json');
  // Configuración y lista de ignorados propias: si no, gitleaks usaría el .gitleaks.toml y el
  // .gitleaksignore del repo analizado, y el autor podría silenciar sus propios secretos.
  const cfg = path.join(tmp, 'gitleaks.toml');
  const ignore = path.join(tmp, 'gitleaksignore');
  fs.writeFileSync(cfg, '[extend]\nuseDefault = true\n');
  fs.writeFileSync(ignore, '');
  const common = ['--config', cfg, '--gitleaks-ignore-path', ignore, '--report-format', 'json', '--report-path', out, '--redact', '--no-banner', '--exit-code', '0'];
  let r = await run(bin('gitleaks'), ['git', ...common, dir], tmp);
  if (r.missing) return null;
  if (r.code !== 0) r = await run(bin('gitleaks'), ['detect', '--source', dir, ...common], tmp); // versiones < 8.19
  if (r.code !== 0) throw new Error(r.killed ? 'tiempo agotado' : clip(r.stderr, 200) || `código ${r.code}`);
  const list = JSON.parse(fs.readFileSync(out, 'utf8') || '[]');
  return list.map((x) => ({
    kind: 'vuln', rule: 'ext-gitleaks', severity: 'high', title: `Secreto: ${x.Description || x.RuleID} [Gitleaks]`,
    description: x.Commit ? `En el commit ${String(x.Commit).slice(0, 10)}${x.Date ? ` (${String(x.Date).slice(0, 10)})` : ''}. Aunque ya no esté en el código, sigue en el historial.` : 'Credencial escrita en el código.',
    file: rel(dir, x.File), line: x.StartLine || null, snippet: x.Match ? clip(x.Match, 200) : undefined,
    fixable: false, notFixableReason: 'Hay que revocar la credencial en el servicio que la emitió; solo puede hacerlo el autor.',
    explain: { cwe: { id: 'CWE-798', url: 'https://cwe.mitre.org/data/definitions/798.html' }, name: `Gitleaks · regla ${x.RuleID}`, why: x.Description || 'Patrón de credencial conocido.', check: 'Comprueba si la credencial es real y sigue activa. Si lo es, hay que revocarla aunque se borre del código.' },
  }));
}

// ---------- Semgrep: miles de reglas de la comunidad, muchos lenguajes ----------
async function semgrep(dir, tmp) {
  const configs = String(process.env.OMINOUS_SEMGREP_CONFIG || 'p/default').split(',').map((c) => c.trim()).filter(Boolean);
  const r = await run(bin('semgrep'), ['scan', ...configs.flatMap((c) => ['--config', c]), '--json', '--metrics=off', '--quiet', '--disable-nosem', '--disable-version-check', '--timeout', '30', '--max-target-bytes', '1500000', dir], tmp);
  if (r.missing) return null;
  let j;
  try { j = JSON.parse(r.stdout); } catch { throw new Error(r.killed ? 'tiempo agotado' : clip(r.stderr, 200) || `código ${r.code}`); }
  return (j.results || []).map((x) => {
    const m = (x.extra && x.extra.metadata) || {};
    const name = String(x.check_id || '').split('.').pop();
    const refs = (Array.isArray(m.references) ? m.references : []).filter((u) => /^https:\/\//.test(u)).slice(0, 2);
    return {
      kind: 'vuln', rule: 'ext-semgrep', severity: SEV[String(x.extra && x.extra.severity).toUpperCase()] || 'medium', title: `${name} [Semgrep]`,
      description: clip(x.extra && x.extra.message), file: rel(dir, x.path), line: (x.start && x.start.line) || null,
      snippet: x.extra && x.extra.lines && x.extra.lines !== 'requires login' ? clip(x.extra.lines, 220) : undefined,
      fixable: false, notFixableReason: 'Detectado por Semgrep: revisa el arreglo que propone su regla.',
      explain: { cwe: cweOf(m.cwe), name: `Semgrep · ${x.check_id}`, why: clip(x.extra && x.extra.message, 800), check: refs.length ? `Más información: ${refs.join(' · ')}` : 'Revisa la línea señalada y de dónde vienen sus datos.' },
    };
  });
}

// ---------- Trivy: secretos y errores de configuración (Docker, Kubernetes, Terraform…) ----------
async function trivy(dir, tmp) {
  const r = await run(bin('trivy'), ['fs', '--scanners', 'secret,misconfig', '--format', 'json', '--quiet', dir], tmp);
  if (r.missing) return null;
  let j;
  try { j = JSON.parse(r.stdout); } catch { throw new Error(r.killed ? 'tiempo agotado' : clip(r.stderr, 200) || `código ${r.code}`); }
  const out = [];
  for (const res of j.Results || []) {
    const file = rel(dir, res.Target);
    for (const s of res.Secrets || []) {
      out.push({
        kind: 'vuln', rule: 'ext-trivy', severity: SEV[s.Severity] || 'high', title: `Secreto: ${s.Title || s.RuleID} [Trivy]`, description: `Categoría: ${s.Category || 'credencial'}.`,
        file, line: s.StartLine || null, snippet: s.Match ? clip(s.Match, 200) : undefined,
        fixable: false, notFixableReason: 'Hay que revocar la credencial en el servicio que la emitió; solo puede hacerlo el autor.',
        explain: { cwe: { id: 'CWE-798', url: 'https://cwe.mitre.org/data/definitions/798.html' }, name: `Trivy · ${s.RuleID}`, why: `Trivy reconoce el formato de esta credencial (${s.Title || s.RuleID}).`, check: 'Comprueba si es real y sigue activa; si lo es, hay que revocarla.' },
      });
    }
    for (const c of res.Misconfigurations || []) {
      if (c.Status && c.Status !== 'FAIL') continue;
      out.push({
        kind: 'vuln', rule: 'ext-trivy', severity: SEV[c.Severity] || 'medium', title: `${c.Title || c.ID} [Trivy]`, description: clip(c.Message || c.Description),
        file, line: (c.CauseMetadata && c.CauseMetadata.StartLine) || null,
        fixable: !!c.Resolution, fix: c.Resolution ? { text: clip(c.Resolution, 400), auto: false } : undefined, notFixableReason: c.Resolution ? undefined : 'Revisión manual.',
        explain: { cwe: null, name: `Trivy · ${c.AVDID || c.ID}`, why: clip(c.Description, 800), check: c.PrimaryURL && /^https:\/\//.test(c.PrimaryURL) ? `Más información: ${c.PrimaryURL}` : 'Revisa la configuración señalada.' },
      });
    }
  }
  return out;
}


// ---------- CodeQL: recorridos de datos entre funciones y ficheros ----------
// Sigue cada valor desde donde entra (una petición, un argumento, un fichero) hasta donde
// hace daño (exec, SQL, eval…). Solo lenguajes que se analizan sin compilar.
const CODEQL_LANGS = {
  javascript: { label: 'JavaScript/TypeScript', ext: /\.(m|c)?(j|t)sx?$|\.vue$/i },
  python: { label: 'Python', ext: /\.py$/i },
  ruby: { label: 'Ruby', ext: /\.(rb|erb)$/i },
};
const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build']);

function languagesIn(dir) {
  const found = new Set();
  const stack = [dir];
  let n = 0;
  while (stack.length && n < 20000) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      n++;
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(path.join(d, e.name)); continue; }
      if (!e.isFile()) continue;
      for (const [lang, { ext }] of Object.entries(CODEQL_LANGS)) if (ext.test(e.name)) found.add(lang);
    }
  }
  return [...found];
}

const sevFromScore = (score, level) => {
  const x = Number(score);
  if (x >= 9) return 'critical';
  if (x >= 7) return 'high';
  if (x >= 4) return 'medium';
  if (x > 0) return 'low';
  return level === 'error' ? 'high' : level === 'note' ? 'low' : 'medium';
};
const plain = (t) => String(t || '').replace(/\[([^\]]*)\]\(\d+\)/g, '$1').replace(/^ControlFlowNode for /, '');
const where = (loc) => {
  const p = loc && loc.physicalLocation;
  if (!p) return null;
  return { file: String((p.artifactLocation && p.artifactLocation.uri) || '').replace(/^\.\//, '') || null, line: (p.region && p.region.startLine) || null };
};

// Convierte un SARIF de CodeQL en hallazgos, con el recorrido de cada uno.
function fromSarif(sarif, label) {
  const out = [];
  for (const runRes of (sarif && sarif.runs) || []) {
    const rules = new Map();
    const tool = runRes.tool || {};
    for (const r of [...((tool.driver && tool.driver.rules) || []), ...(tool.extensions || []).flatMap((e) => e.rules || [])]) rules.set(r.id, r);
    for (const x of runRes.results || []) {
      const rule = rules.get(x.ruleId) || {};
      const props = rule.properties || {};
      const tags = props.tags || [];
      if (!tags.includes('security')) continue; // solo seguridad, no estilo
      const at = where(x.locations && x.locations[0]) || {};
      const steps = (((x.codeFlows || [])[0] || {}).threadFlows || [])[0];
      const flow = steps ? steps.locations.map((l) => ({ ...where(l.location), text: clip(plain(l.location && l.location.message && l.location.message.text), 120) })).filter((s) => s.file) : [];
      const cweTag = tags.find((t) => /^external\/cwe\/cwe-\d+$/.test(t));
      const cwe = cweTag ? cweOf(`CWE-${Number(cweTag.split('-').pop())}`) : null;
      const first = flow[0];
      const last = flow[flow.length - 1];
      out.push({
        kind: 'vuln', rule: 'ext-codeql', severity: sevFromScore(props['security-severity'], x.level || (rule.defaultConfiguration && rule.defaultConfiguration.level)),
        title: `${(rule.shortDescription && rule.shortDescription.text) || x.ruleId} [CodeQL]`,
        description: clip(plain(x.message && x.message.text)) + (flow.length > 1 ? ` Recorrido de ${flow.length} pasos: entra en ${first.file}:${first.line} y llega a ${last.file}:${last.line}.` : ''),
        file: at.file, line: at.line,
        fixable: false, notFixableReason: flow.length > 1 ? 'Hay que validar o escapar el dato en algún punto del recorrido; depende de la lógica del proyecto.' : 'Revisión manual: depende de la lógica del proyecto.',
        explain: {
          cwe, name: `CodeQL · ${x.ruleId} (${label})`,
          why: clip((rule.fullDescription && rule.fullDescription.text) || props.description, 800),
          check: flow.length > 1 ? 'Sigue el recorrido: si en algún paso el dato se valida o se escapa, puede ser un falso positivo.' : 'Revisa la línea señalada y de dónde vienen sus datos.',
          flow: flow.length > 1 ? flow.slice(0, 12) : undefined,
        },
      });
    }
  }
  return out;
}

async function codeql(dir, tmp) {
  const exe = bin('codeql');
  const probe = await run(exe, ['resolve', 'languages', '--format=json'], tmp, 60000);
  if (probe.missing) return null;
  let installed = {};
  try { installed = JSON.parse(probe.stdout); } catch { throw new Error(clip(probe.stderr, 200) || 'no responde'); }
  const langs = languagesIn(dir).filter((l) => installed[l]);
  if (!langs.length) return { list: [], note: 'ningún lenguaje compatible (JavaScript/TypeScript, Python o Ruby)' };
  const list = [];
  const done = [];
  const failed = [];
  for (const lang of langs) {
    const { label } = CODEQL_LANGS[lang];
    const db = path.join(tmp, `codeql-${lang}`);
    const sarif = path.join(tmp, `codeql-${lang}.sarif`);
    const why = (r) => (r.killed ? 'tiempo agotado' : clip(r.stderr.split('\n').filter((l) => /error/i.test(l)).pop() || r.stderr, 160) || `código ${r.code}`);
    let r = await run(exe, ['database', 'create', db, `--language=${lang}`, `--source-root=${dir}`, '--overwrite', '--quiet', '--threads=0'], tmp, CODEQL_TIMEOUT);
    if (r.code === 0) r = await run(exe, ['database', 'analyze', db, `${lang}-security-extended.qls`, '--format=sarif-latest', `--output=${sarif}`, '--quiet', '--threads=0'], tmp, CODEQL_TIMEOUT);
    fs.rmSync(db, { recursive: true, force: true });
    if (r.code !== 0) { failed.push(`${label}: ${why(r)}`); continue; }
    list.push(...fromSarif(JSON.parse(fs.readFileSync(sarif, 'utf8')), label));
    done.push(label);
  }
  if (!done.length) throw new Error(failed.join(' · '));
  return { list, note: done.join(', ') + (failed.length ? ` · sin revisar: ${failed.join(' · ')}` : ''), partial: failed.length > 0 };
}

const TOOLS = [
  { id: 'gitleaks', label: 'Gitleaks (secretos, también en el historial)', fn: gitleaks },
  { id: 'semgrep', label: 'Semgrep (reglas de la comunidad)', fn: semgrep },
  { id: 'trivy', label: 'Trivy (secretos y configuración)', fn: trivy },
  { id: 'codeql', label: 'CodeQL (recorridos de datos)', fn: codeql },
];

// Pasa las herramientas instaladas y añade sus hallazgos y su cobertura a `extra`.
async function externalPass(dir, tmp, extra, log = () => {}) {
  if (process.env.OMINOUS_EXTERNAL === '0') return;
  const seen = new Set([...extra.vulns, ...extra.threats].filter((f) => f.file && f.line).map((f) => `${f.file}:${f.line}`));
  const results = await Promise.all(TOOLS.map(async (t) => {
    try { return { t, list: await t.fn(dir, tmp) }; } catch (e) { return { t, error: e.message }; }
  }));
  for (const { t, list: res, error } of results) {
    if (res === null) continue; // no instalada
    const list = Array.isArray(res) ? res : res && res.list;
    const note = res && !Array.isArray(res) && res.note ? ` · ${res.note}` : '';
    if (error) { extra.coverage.push({ label: t.label, status: 'skip', detail: `ha fallado: ${error}` }); continue; }
    log(`${t.id}: ${list.length} hallazgo${list.length === 1 ? '' : 's'}`);
    let added = 0;
    for (const f of list) {
      const k = f.file && f.line ? `${f.file}:${f.line}` : null;
      if (f.rule !== 'ext-semgrep' && k && seen.has(k)) continue; // el mismo secreto que otra herramienta
      if (added >= MAX_PER_TOOL) break;
      if (k) seen.add(k);
      extra.vulns.push(f);
      added++;
    }
    extra.coverage.push({ label: t.label, status: list.length > MAX_PER_TOOL || (res && res.partial) ? 'partial' : 'ok', detail: `${added} hallazgo${added === 1 ? '' : 's'}${list.length > MAX_PER_TOOL ? ` (se muestran ${MAX_PER_TOOL} de ${list.length})` : ''}${note}` });
  }
}

module.exports = { externalPass, TOOLS, fromSarif, languagesIn };
