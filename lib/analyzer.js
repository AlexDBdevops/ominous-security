'use strict';
// Analiza un repositorio ya descargado (sin ejecutar nada de él).

const fs = require('fs');
const path = require('path');
const { vulnRules, threatRules, CODE, JS } = require('./rules');
const { findHiddenPayloads, sniffBinary, entropy } = require('./decoder');
const { auditDependencies, typosquatCheck } = require('./deps');
const { extraChecks, homoglyphs } = require('./extra');

const MAX_FILES = 8000;
const MAX_FILE_BYTES = 1.5 * 1024 * 1024;
const SKIP_DIRS = new Set(['.git']);
const LOCKFILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|composer\.lock|go\.sum|Gemfile\.lock)$/;
const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|bmp|tiff?|woff2?|ttf|otf|eot|mp[34]|wav|ogg|webm|mov|avi|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|exe|dll|so|dylib|bin|o|a|lib|pyc|pyo|wasm|node|db|sqlite)$/i;
const EXEC_EXT = /\.(exe|dll|so|dylib|scr|msi|node|jar|pyc)$/i;
const INNOCENT_EXT = /\.(png|jpe?g|gif|ico|bmp|txt|md|json|css|svg|csv|ya?ml|xml|html?|woff2?|ttf)$/i;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/;
const ZW = /[\u200B-\u200D\u2060\uFEFF]/;
const RTL = /[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFC]/;
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function walk(root, exclude = []) {
  const files = [];
  const symlinks = [];
  const stack = [''];
  while (stack.length && files.length < MAX_FILES) {
    const rel = stack.pop();
    let entries;
    try { entries = fs.readdirSync(path.join(root, rel), { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (exclude.some((x) => r === x || r.startsWith(x.endsWith('/') ? x : `${x}/`))) continue;
      if (e.isSymbolicLink()) { symlinks.push(r); continue; }
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(r); continue; }
      if (e.isFile()) files.push(r);
    }
  }
  return { files, symlinks, truncated: files.length >= MAX_FILES };
}

function snippet(line) {
  const s = line.trim();
  return s.length > 220 ? `${s.slice(0, 220)}…` : s;
}

function finding(kind, rule, file, line, text, extra = {}) {
  return {
    kind,
    rule: rule.id,
    severity: rule.severity,
    title: rule.title,
    description: rule.desc,
    file,
    line,
    snippet: text != null ? snippet(text) : undefined,
    ...(kind === 'vuln' ? {
      fixable: !!rule.fix,
      fix: rule.fix ? { text: rule.fix.text, auto: !!rule.fix.auto } : undefined,
      notFixableReason: rule.fix ? undefined : (rule.why || 'Necesita revisión manual del autor.'),
    } : {}),
    ...extra,
  };
}

function scanTextFile(rel, content, out) {
  const lines = content.split('\n');
  const isMin = /\.min\.(js|css)$|[-.]bundle\.js$|(^|\/)dist\//.test(rel);
  const perRuleCount = new Map();
  const cap = (id) => { const n = (perRuleCount.get(id) || 0) + 1; perRuleCount.set(id, n); return n <= 5; };

  for (const rule of vulnRules) {
    if (!rule.ext.test(rel)) continue;
    if (isMin && rule.id.startsWith('js-')) continue;
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (l.length > 4000) continue;
      if (rule.re.test(l) && !(rule.skipIf && rule.skipIf.test(l)) && cap(rule.id)) {
        out.vulns.push(finding('vuln', rule, rel, i + 1, l));
      }
    }
  }

  for (const rule of threatRules) {
    if (!rule.ext.test(rel)) continue;
    if (rule.countRe) {
      const n = (content.match(rule.countRe) || []).length;
      if (n >= rule.minCount) out.threats.push(finding('threat', rule, rel, null, null, { detail: `${n} identificadores ofuscados` }));
      continue;
    }
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i].length > 20000 ? lines[i].slice(0, 20000) : lines[i];
      if (rule.skipComments && /^\s*(\/\/|#|\*|\/\*|<!--|;|--)/.test(l)) continue;
      if (rule.re.test(l) && cap(rule.id)) out.threats.push(finding('threat', rule, rel, i + 1, l));
    }
  }

  const vendored = isMin || /(^|\/)(vendor|third_party|node_modules)\//.test(rel);
  if (!vendored && (CODE.test(rel) || /\.(json|ya?ml|toml|cfg|ini)$/.test(rel))) {
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      if (BIDI.test(l) && !RTL.test(l)) { // en textos en árabe/hebreo los caracteres bidi son legítimos
        out.threats.push({ kind: 'threat', rule: 'trojan-source', severity: 'high', title: 'Caracteres Unicode bidireccionales ocultos (Trojan Source)', description: 'El código que ves no es el que se ejecuta: caracteres invisibles reordenan el texto.', file: rel, line: i + 1, snippet: snippet(l.replace(/[\u202A-\u202E\u2066-\u2069]/g, (c) => `<U+${c.charCodeAt(0).toString(16).toUpperCase()}>`)) });
        break;
      }
    }
    for (let i = 0; i < lines.length; i++) {
      const noStrings = lines[i].slice(i === 0 ? 1 : 0).replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, '');
      if (ZW.test(noStrings) && CODE.test(rel)) { // solo fuera de cadenas: dentro de textos suele ser legítimo
        out.threats.push({ kind: 'threat', rule: 'zero-width', severity: 'medium', title: 'Caracteres invisibles de ancho cero en el código', description: 'Pueden crear identificadores que parecen iguales pero no lo son (homoglifos).', file: rel, line: i + 1, snippet: snippet(lines[i].replace(/[\u200B-\u200D\u2060\uFEFF]/g, '<ZW>')) });
        break;
      }
    }
  }

  if (CODE.test(rel) && !vendored) homoglyphs(rel, content, out);

  if (CODE.test(rel) && !isMin) {
    for (let i = 0; i < lines.length; i++) {
      const l = lines[i];
      // Código empujado fuera de la pantalla con cientos de espacios
      const pad = l.match(/\S(\s{150,})(\S.{3,})/);
      if (pad && !/^\s*(\/\/|#|\*)/.test(pad[2])) {
        out.threats.push({ kind: 'threat', rule: 'hidden-whitespace', severity: 'critical', title: 'Código escondido tras cientos de espacios', description: `Hay código desplazado ${pad[1].length} columnas a la derecha para que no se vea en el editor.`, file: rel, line: i + 1, snippet: snippet(pad[2]) });
        break;
      }
    }
    const longLine = lines.findIndex((l) => l.length > 3000 && !/sourceMappingURL=/.test(l) && entropy(l.slice(0, 3000)) > 4.8);
    if (longLine >= 0) {
      out.threats.push({ kind: 'threat', rule: 'long-line', severity: 'medium', title: 'Línea extremadamente larga en código fuente', description: `Línea de ${lines[longLine].length} caracteres en un fichero que no es minificado. Puede ocultar un payload.`, file: rel, line: longLine + 1, snippet: snippet(lines[longLine].slice(0, 200)) });
    }
  }

  // Ingeniería inversa de blobs codificados / cifrados
  if (!LOCKFILES.test(rel) && !/\.(svg|css|map|ipynb|lock)$/i.test(rel) && (CODE.test(rel) || /\.(json|txt|cfg|toml|ya?ml|html?)$/i.test(rel))) {
    const payloads = findHiddenPayloads(content, { isMinified: isMin });
    for (const p of payloads) {
      const inner = { vulns: [], threats: [] };
      if (p.text) scanTextFile(rel, p.text, inner);
      const innerThreats = inner.threats;
      let severity = 'medium';
      let title = 'Contenido oculto codificado';
      if (p.final === 'binary') { severity = 'critical'; title = `Ejecutable oculto dentro del código (${p.binaryType})`; }
      else if (innerThreats.some((t) => SEV_ORDER[t.severity] >= 3)) { severity = 'critical'; title = 'Script oculto malicioso (decodificado)'; }
      else if (p.text && p.layers.length >= 2) { severity = 'high'; title = 'Script oculto con varias capas de codificación'; }
      else if (p.final === 'opaque') { severity = p.layers[0] === 'Token Fernet cifrado' || p.layers[0] === 'blob cifrado' ? 'high' : 'medium'; title = 'Payload cifrado que no se pudo descifrar'; }
      out.threats.push({
        kind: 'threat', rule: 'hidden-payload', severity, title,
        description: p.note || (p.text ? 'He decodificado el contenido estáticamente (sin ejecutarlo). Revisa el resultado abajo.' : 'Datos binarios ocultos dentro de una cadena.'),
        file: rel, line: p.line, snippet: p.raw,
        decoded: {
          layers: p.layers,
          preview: p.text ? p.text.slice(0, 1500) : null,
          binaryType: p.binaryType || null,
          innerFindings: innerThreats.map((t) => ({ title: t.title, severity: t.severity, snippet: t.snippet })),
        },
      });
    }
  }
}

function structuralChecks(root, files, symlinks, out) {
  for (const s of symlinks) {
    try {
      const target = fs.readlinkSync(path.join(root, s));
      const resolved = path.resolve(path.dirname(path.join(root, s)), target);
      if (!resolved.startsWith(root + path.sep) && resolved !== root) {
        out.threats.push({ kind: 'threat', rule: 'symlink-escape', severity: 'high', title: 'Enlace simbólico que apunta fuera del repositorio', description: `Apunta a ${target}. Herramientas que sigan el enlace leerán o escribirán ficheros de tu sistema.`, file: s, line: null });
      }
    } catch { /* ignorar */ }
  }

  for (const rel of files) {
    const base = path.basename(rel);
    if (/^\.env(\.(local|prod|production))?$/.test(base)) {
      out.vulns.push({ kind: 'vuln', rule: 'env-file', severity: 'high', title: 'Fichero .env versionado', description: 'Suele contener credenciales reales.', file: rel, line: null, fixable: true, fix: { text: 'Añadirlo a .gitignore y dejar un .env.example sin valores.', auto: false } });
    }
    if (/^\.vscode\/tasks\.json$/.test(rel)) {
      const c = safeRead(path.join(root, rel));
      if (c && /"runOn"\s*:\s*"folderOpen"/.test(c)) {
        out.threats.push({ kind: 'threat', rule: 'vscode-autorun', severity: 'critical', title: 'Tarea de VS Code que se ejecuta al abrir la carpeta', description: 'Abrir el repo en VS Code (si confías en la carpeta) ejecuta este comando automáticamente.', file: rel, line: lineOf(c, /folderOpen/), snippet: snippet((c.match(/"command"\s*:\s*"[^"]*"/) || [''])[0]) });
      }
    }
    if (/^\.devcontainer\/.*\.json$/.test(rel)) {
      const c = safeRead(path.join(root, rel));
      const m = c && c.match(/"(postCreateCommand|postStartCommand|initializeCommand|postAttachCommand)"\s*:\s*("[^"]*"|\[[^\]]*\])/);
      if (m) out.threats.push({ kind: 'threat', rule: 'devcontainer', severity: /curl|wget|http|base64|eval/.test(m[2]) ? 'high' : 'low', title: 'Comando automático del devcontainer', description: `Se ejecuta al abrir el proyecto en un contenedor (${m[1]}).`, file: rel, line: lineOf(c, new RegExp(m[1])), snippet: snippet(m[0]) });
    }
    if (/^(\.githooks|\.husky)\//.test(rel) && !/\/_\//.test(rel)) {
      const c = safeRead(path.join(root, rel));
      if (c && /curl|wget|http|base64|nc\s/.test(c)) out.threats.push({ kind: 'threat', rule: 'git-hook', severity: 'high', title: 'Git hook con acceso a red', description: 'Este hook se instala al preparar el proyecto y se ejecuta en cada commit/push.', file: rel, line: null });
    }

    let buf = null;
    if (EXEC_EXT.test(rel) || INNOCENT_EXT.test(rel) || /\.(com|bin)$/i.test(rel) || !/\.\w+$/.test(base)) {
      try { const fd = fs.openSync(path.join(root, rel), 'r'); buf = Buffer.alloc(8); fs.readSync(fd, buf, 0, 8, 0); fs.closeSync(fd); } catch { buf = null; }
    }
    const magic = buf && sniffBinary(buf);
    if (magic && /Ejecutable|Bytecode/.test(magic) && INNOCENT_EXT.test(rel)) {
      out.threats.push({ kind: 'threat', rule: 'disguised-binary', severity: 'critical', title: 'Ejecutable disfrazado', description: `${base} tiene extensión inocente pero es un ${magic}.`, file: rel, line: null });
    } else if ((EXEC_EXT.test(rel) || (magic && /Ejecutable/.test(magic))) && !/(gradle|maven)-wrapper\.jar$/.test(rel)) {
      out.threats.push({ kind: 'threat', rule: 'binary', severity: 'medium', title: 'Binario precompilado en el repositorio', description: `${magic || 'Fichero binario ejecutable'}: no se puede revisar su código fuente.`, file: rel, line: null });
    }
  }
}

function packageScripts(root, files, out) {
  for (const rel of files.filter((f) => /(^|\/)package\.json$/.test(f) && !/node_modules\//.test(f))) {
    let pkg;
    try { pkg = JSON.parse(safeRead(path.join(root, rel))); } catch { continue; }
    for (const hook of ['preinstall', 'install', 'postinstall', 'prepare', 'preprepare', 'postprepare']) {
      const cmd = pkg.scripts && pkg.scripts[hook];
      if (!cmd) continue;
      const bad = /curl|wget|http|node\s+-e|base64|eval|\|\s*sh|powershell|\.exe|nc\s/i.test(cmd);
      const benign = /^(husky( install)?|npm run build|tsc|node-gyp rebuild|patch-package|ngcc|lerna bootstrap|is-ci \|\| husky install)$/i.test(cmd.trim());
      out.threats.push({ kind: 'threat', rule: 'npm-lifecycle', severity: bad ? 'high' : benign ? 'info' : 'low', title: `Script "${hook}" de npm`, description: bad ? 'Se ejecuta solo al hacer npm install y contiene llamadas sospechosas.' : 'Se ejecuta automáticamente al hacer npm install. Revisa qué hace el fichero al que llama.', file: rel, line: null, snippet: snippet(`"${hook}": "${cmd}"`) });
    }
  }
  for (const rel of files.filter((f) => /(^|\/)setup\.py$/.test(f))) {
    const c = safeRead(path.join(root, rel)) || '';
    const hits = [/urllib|requests\.|http\.client|socket\./, /subprocess|os\.system|os\.popen/, /exec\(|eval\(/, /base64|zlib|marshal/].filter((r) => r.test(c)).length;
    if (/cmdclass\s*=/.test(c) || hits >= 2) {
      out.threats.push({ kind: 'threat', rule: 'setup-py', severity: hits >= 2 ? 'high' : 'low', title: 'setup.py ejecuta código al instalar', description: hits >= 2 ? 'Combina red, ejecución de comandos o decodificación dentro del instalador.' : 'Define comandos de instalación personalizados (cmdclass).', file: rel, line: null });
    }
  }
}

function safeRead(p) {
  try { const st = fs.statSync(p); if (st.size > MAX_FILE_BYTES) return null; return fs.readFileSync(p, 'utf8'); } catch { return null; }
}
function lineOf(content, re) { const i = content.search(re); return i < 0 ? null : content.slice(0, i).split('\n').length; }

function statusOf(list, { redAt = 3, yellowAt = 2 } = {}) {
  const max = list.reduce((m, f) => Math.max(m, SEV_ORDER[f.severity] || 0), 0);
  return max >= redAt ? 'red' : max >= yellowAt ? 'yellow' : 'green';
}

async function analyzeTree(root, meta, log = () => {}, extra = {}) {
  const out = { vulns: [], threats: [] };
  log('Recorriendo ficheros…');
  const { files, symlinks, truncated } = walk(root, extra.exclude);
  const langs = {};
  let bytes = 0;
  log(`Escaneando ${files.length} ficheros…`);
  for (const rel of files) {
    const ext = (path.extname(rel) || path.basename(rel)).toLowerCase();
    let st;
    try { st = fs.statSync(path.join(root, rel)); } catch { continue; }
    bytes += st.size;
    langs[ext] = (langs[ext] || 0) + 1;
    if (BINARY_EXT.test(rel) || st.size > MAX_FILE_BYTES) continue;
    const content = safeRead(path.join(root, rel));
    if (content == null || content.includes('\u0000')) continue;
    scanTextFile(rel, content, out);
  }
  structuralChecks(root, files, symlinks, out);
  packageScripts(root, files, out);
  extraChecks(root, files, out);

  log('Revisando dependencias…');
  const deps = await auditDependencies(root, files);
  out.vulns.push(...deps.findings);
  out.threats.push(...deps.threats, ...typosquatCheck(deps.names));

  // Hallazgos que llegan de fuera del árbol de trabajo (historial de git, submódulos, releases)
  out.vulns.push(...(extra.vulns || []));
  out.threats.push(...(extra.threats || []));

  // Señales de confianza del autor
  const trust = [];
  if (meta) {
    const days = (d) => d ? Math.floor((Date.now() - new Date(d).getTime()) / 86400000) : null;
    const repoAge = days(meta.created_at);
    const ownerAge = days(meta.owner_created_at);
    trust.push({ label: 'Estrellas', value: meta.stargazers_count, ok: meta.stargazers_count >= 20 });
    trust.push({ label: 'Antigüedad del repo', value: repoAge != null ? `${repoAge} días` : '—', ok: repoAge == null || repoAge > 30 });
    if (ownerAge != null) trust.push({ label: 'Antigüedad de la cuenta del autor', value: `${ownerAge} días`, ok: ownerAge > 60 });
    trust.push({ label: 'Licencia', value: meta.license || 'ninguna', ok: !!meta.license });
    trust.push({ label: 'Archivado', value: meta.archived ? 'sí' : 'no', ok: !meta.archived });
    if (meta.fork) trust.push({ label: 'Es un fork de', value: meta.parent || 'otro repo', ok: true });
    if (meta.scorecard) trust.push({ label: 'OpenSSF Scorecard', value: `${meta.scorecard.score}/10${meta.scorecard.weak.length ? ` (flojo en ${meta.scorecard.weak.slice(0, 3).join(', ')})` : ''}`, ok: meta.scorecard.score >= 5 });
    if (ownerAge != null && ownerAge < 30 && meta.stargazers_count > 200) {
      out.threats.push({ kind: 'threat', rule: 'fake-stars', severity: 'medium', title: 'Cuenta muy nueva con muchas estrellas', description: `La cuenta tiene ${ownerAge} días y el repo ${meta.stargazers_count} estrellas: patrón habitual de estrellas compradas para repos con malware.`, file: null, line: null });
    } else if (repoAge != null && repoAge < 14) {
      out.threats.push({ kind: 'threat', rule: 'new-repo', severity: 'low', title: 'Repositorio muy reciente', description: `Creado hace ${repoAge} días. No hay historial que permita confiar en él.`, file: null, line: null });
    }
  }

  // En tests/ejemplos/docs una vulnerabilidad no afecta a quien usa el código: se rebaja a informativa.
  const NON_PROD = /(^|\/)(test|tests|__tests__|spec|specs|fixtures?|examples?|docs?|benchmarks?|testdata|[\w-]*vectors[\w-]*)\//i;
  const CI_ONLY = /(^|\/)(\.github|\.circleci|\.gitlab|ci|\.buildkite)\//i;
  for (const v of out.vulns) {
    if (v.file && NON_PROD.test(v.file) && v.rule !== 'dep-vuln') {
      v.severity = 'info';
      v.title += ' (en tests o ejemplos)';
    }
  }
  for (const t of out.threats) {
    if (!t.file) continue;
    // Scripts de CI: se ejecutan en los servidores de CI, no en tu máquina al clonar.
    if (CI_ONLY.test(t.file) && t.severity === 'high' && !t.history) { t.severity = 'medium'; t.description += ' (Está en la configuración de CI: se ejecuta en los servidores de integración, no en tu máquina.)'; }
    if (!NON_PROD.test(t.file)) continue;
    if (t.severity === 'medium' || t.severity === 'low') t.severity = t.severity === 'medium' ? 'low' : 'info';
    else if (/^archive/.test(t.rule) || (t.rule === 'hidden-payload' && t.severity === 'high')) t.severity = 'low'; // datos de prueba
  }

  const sortFn = (a, b) => (SEV_ORDER[b.severity] - SEV_ORDER[a.severity]) || String(a.file).localeCompare(String(b.file));
  out.vulns.sort(sortFn);
  out.threats.sort(sortFn);

  const vulnStatus = statusOf(out.vulns, { redAt: 4, yellowAt: 2 });
  const threatStatus = statusOf(out.threats, { redAt: 3, yellowAt: 2 });
  const overall = [vulnStatus, threatStatus].includes('red') ? 'red' : [vulnStatus, threatStatus].includes('yellow') ? 'yellow' : 'green';

  const count = (rule) => out.threats.filter((t) => t.rule === rule).length;
  const dep = deps.summary;
  const coverage = [
    { label: 'Código del último commit', status: truncated ? 'partial' : 'ok', detail: `${files.length} ficheros${truncated ? ' (límite alcanzado: análisis parcial)' : ''}` },
    { label: 'Dependencias (OSV.dev)', status: !dep.total ? 'ok' : dep.osvAvailable ? 'ok' : 'skip', detail: !dep.total ? 'sin ficheros de dependencias' : dep.osvAvailable ? `${dep.checked} de ${dep.total} con versión exacta consultadas` : `no se pudo consultar (${dep.osvError || 'sin conexión'})` },
    ...(extra.coverage || []),
    ...(count('lfs') ? [{ label: 'Ficheros en Git LFS', status: 'skip', detail: `${count('lfs')} no descargados` }] : []),
    ...(count('archive') ? [{ label: 'Archivos comprimidos', status: 'partial', detail: `${count('archive')} listados pero no extraídos` }] : []),
  ];

  return {
    coverage,
    stats: { files: files.length, bytes, truncated, topTypes: Object.entries(langs).sort((a, b) => b[1] - a[1]).slice(0, 6) },
    vulnerabilities: out.vulns,
    threats: out.threats,
    dependencies: deps.summary,
    trust,
    summary: {
      vulnStatus, threatStatus, overall,
      fixable: out.vulns.filter((v) => v.fixable).length,
      autoFixable: out.vulns.filter((v) => v.fix && v.fix.auto && v.severity !== 'info').length,
      notFixable: out.vulns.filter((v) => !v.fixable).length,
      hiddenPayloads: out.threats.filter((t) => t.rule === 'hidden-payload').length,
    },
  };
}

// Aplica los arreglos mecánicos (fix.auto) sobre un clon.
function applyAutoFixes(root, findings) {
  const rulesById = new Map(vulnRules.map((r) => [r.id, r]));
  const applied = [];
  const byFile = new Map();
  for (const f of findings) {
    const rule = rulesById.get(f.rule);
    if (!rule || !rule.fix || !rule.fix.auto || !f.file || !f.line || f.severity === 'info') continue; // no tocar tests/ejemplos
    if (!byFile.has(f.file)) byFile.set(f.file, []);
    byFile.get(f.file).push({ line: f.line, rule });
  }
  for (const [rel, items] of byFile) {
    const abs = path.resolve(root, rel);
    if (!abs.startsWith(root + path.sep)) continue;
    let st;
    try { st = fs.lstatSync(abs); } catch { continue; }
    if (!st.isFile()) continue;
    const lines = fs.readFileSync(abs, 'utf8').split('\n');
    for (const { line, rule } of items) {
      const before = lines[line - 1];
      if (before == null) continue;
      const after = before.replace(rule.fix.auto.from, rule.fix.auto.to);
      if (after !== before) { lines[line - 1] = after; applied.push({ file: rel, line, rule: rule.id, before: before.trim(), after: after.trim() }); }
    }
    fs.writeFileSync(abs, lines.join('\n'));
  }
  return applied;
}

module.exports = { analyzeTree, applyAutoFixes };
