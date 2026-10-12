'use strict';
// Herramientas externas opcionales (solo en el servidor local). Si Gitleaks, Semgrep
// o Trivy están instalados, se pasan sobre el clon temporal y sus hallazgos se suman
// a los de las reglas propias, con la explicación que da cada herramienta.
// Ninguna de las tres ejecuta código del repo: solo leen ficheros (y Gitleaks, el
// historial de git). Se lanzan sin shell, con tiempo máximo y un entorno mínimo.
//   OMINOUS_EXTERNAL=0         no usar ninguna
//   OMINOUS_<TOOL>_BIN=ruta    ruta del ejecutable (por defecto, el del PATH)
//   OMINOUS_SEMGREP_CONFIG     reglas de Semgrep (por defecto p/default; puede ser un fichero local)
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const TIMEOUT = Number(process.env.OMINOUS_EXTERNAL_TIMEOUT_MS) || 4 * 60 * 1000;
const MAX_PER_TOOL = 200;
const SEV = { CRITICAL: 'critical', HIGH: 'high', ERROR: 'high', MEDIUM: 'medium', WARNING: 'medium', LOW: 'low', INFO: 'low', UNKNOWN: 'low' };

const bin = (id) => process.env[`OMINOUS_${id.toUpperCase()}_BIN`] || id;
const env = () => ({ PATH: process.env.PATH, HOME: process.env.HOME || '/tmp', SEMGREP_SEND_METRICS: 'off', SEMGREP_ENABLE_VERSION_CHECK: '0', TRIVY_NO_PROGRESS: 'true' });

function run(file, args, cwd) {
  return new Promise((resolve) => {
    execFile(file, args, { cwd, env: env(), timeout: TIMEOUT, maxBuffer: 64 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
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
  const common = ['--report-format', 'json', '--report-path', out, '--redact', '--no-banner', '--exit-code', '0'];
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
  const r = await run(bin('semgrep'), ['scan', '--config', process.env.OMINOUS_SEMGREP_CONFIG || 'p/default', '--json', '--metrics=off', '--quiet', '--disable-version-check', '--timeout', '30', '--max-target-bytes', '1500000', dir], tmp);
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

const TOOLS = [
  { id: 'gitleaks', label: 'Gitleaks (secretos, también en el historial)', fn: gitleaks },
  { id: 'semgrep', label: 'Semgrep (reglas de la comunidad)', fn: semgrep },
  { id: 'trivy', label: 'Trivy (secretos y configuración)', fn: trivy },
];

// Pasa las herramientas instaladas y añade sus hallazgos y su cobertura a `extra`.
async function externalPass(dir, tmp, extra, log = () => {}) {
  if (process.env.OMINOUS_EXTERNAL === '0') return;
  const seen = new Set([...extra.vulns, ...extra.threats].filter((f) => f.file && f.line).map((f) => `${f.file}:${f.line}`));
  const results = await Promise.all(TOOLS.map(async (t) => {
    try { return { t, list: await t.fn(dir, tmp) }; } catch (e) { return { t, error: e.message }; }
  }));
  for (const { t, list, error } of results) {
    if (list === null) continue; // no instalada
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
    extra.coverage.push({ label: t.label, status: list.length > MAX_PER_TOOL ? 'partial' : 'ok', detail: `${added} hallazgo${added === 1 ? '' : 's'}${list.length > MAX_PER_TOOL ? ` (se muestran ${MAX_PER_TOOL} de ${list.length})` : ''}` });
  }
}

module.exports = { externalPass, TOOLS };
