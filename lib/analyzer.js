'use strict';
// Analiza un repositorio ya descargado (sin ejecutar nada de él).

const fs = require('fs');
const path = require('path');
// La de libc: la de Node normaliza ".." sobre el texto antes de seguir los enlaces.
const realpath = (p) => (fs.realpathSync.native || fs.realpathSync)(p);
const { vulnRules, threatRules, CODE, JS, REMOTE_NET, REMOTE_RUN, REMOTE_SRC } = require('./rules');
const { findHiddenPayloads, sniffBinary, entropy, looksLikeCode } = require('./decoder');
const { auditDependencies, typosquatCheck, exploitSignals } = require('./deps');
const { beyondRepo } = require('./beyond');
const { buildAiContext } = require('./ai');
const { extraChecks, homoglyphs, AI_FILES } = require('./extra');
const { surfaceChecks, gitSymlinks, configChecks } = require('./surfaces');
const { explain } = require('./explain');
const { findRemoteRuns } = require('./remote');
const { review } = require('./review');
const { commentLines } = require('./comments');

const MAX_FILES = 8000; // ficheros cuyo contenido se analiza
const MAX_LISTED = 60000; // ficheros que se recorren (nombres, tipos, enlaces)
const MAX_FILE_BYTES = 1.5 * 1024 * 1024;
const MAX_TEXT_BYTES = 8 * 1024 * 1024; // un fichero de código más grande se analiza por el principio y el final
const WINDOW = 20000; // las líneas muy largas se analizan por ventanas solapadas
const SKIP_DIRS = new Set(['.git']);
const LOCKFILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lock|poetry\.lock|uv\.lock|pdm\.lock|Pipfile\.lock|Cargo\.lock|composer\.lock|go\.sum|Gemfile\.lock|pubspec\.lock|packages\.lock\.json|mix\.lock|renv\.lock|gradle\.lockfile)$/;
const BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|bmp|tiff?|woff2?|ttf|otf|eot|mp[34]|wav|ogg|webm|mov|avi|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|exe|dll|so|dylib|bin|o|a|lib|pyc|pyo|wasm|node|db|sqlite)$/i;
const EXEC_EXT = /\.(exe|dll|so|dylib|scr|msi|node|jar|pyc)$/i;
const INNOCENT_EXT = /\.(png|jpe?g|gif|ico|bmp|txt|md|json|css|svg|csv|ya?ml|xml|html?|woff2?|ttf)$/i;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/;
const ZW = /[\u200B-\u200D\u2060\uFEFF]/;
// Caracteres invisibles con los que se esconde código o texto para IA: selectores de variación
// (GlassWorm), rellenos de Hangul ("invisible JS"), guion blando y separador mongol.
const INVISIBLE_RUN = /(?:[\uFE00-\uFE0F]|[\u{E0100}-\u{E01EF}]){3,}|[\u{E0100}-\u{E01EF}]|[\u3164\u115F\u1160\uFFA0\u180E]/u;
const HANGUL = /[\uAC00-\uD7AF\u1100-\u11FF\u3130-\u318F]/;
const RTL = /[\u0590-\u08FF\uFB1D-\uFDFF\uFE70-\uFEFC]/;
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// Primero lo que puede ejecutarse (código, configuración, ficheros sin extensión); los datos
// al final. Así, rellenar el repo con miles de ficheros basura no deja fuera el malicioso.
function priority(rel) {
  if (/(^|\/)node_modules\//.test(rel)) return 3;
  if (CODE.test(rel) || !/\.\w+$/.test(path.basename(rel)) || /(^|\/)\.|\.(json|ya?ml|toml|cfg|ini|xml|gradle|properties|ipynb|md)$/i.test(rel)) return 0;
  if (BINARY_EXT.test(rel)) return 2;
  return 1;
}

function walk(root, exclude = []) {
  let files = [];
  const symlinks = [];
  const stack = [''];
  while (stack.length && files.length < MAX_LISTED) {
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
  const listedAll = !stack.length;
  files = files.map((f, i) => [priority(f), i, f]).sort((a, b) => a[0] - b[0] || a[1] - b[1]).map((x) => x[2]);
  return { files, symlinks, truncated: !listedAll || files.length > MAX_FILES, listedAll };
}

function mostlyText(s) {
  const sample = s.slice(0, 65536);
  let bad = 0;
  for (let i = 0; i < sample.length; i++) { const c = sample.charCodeAt(i); if ((c < 32 && c !== 9 && c !== 10 && c !== 13) || c === 0xfffd) bad++; }
  return bad / Math.max(1, sample.length) < 0.01;
}

// Lee un fichero de texto entero (hasta MAX_TEXT_BYTES) o, si es mayor, el principio y el final.
function readText(abs, size, max = MAX_TEXT_BYTES) {
  try {
    if (size <= max) return { content: fs.readFileSync(abs, 'utf8'), partial: false };
    const fd = fs.openSync(abs, 'r');
    const half = Math.floor(max / 2);
    const a = Buffer.alloc(half), b = Buffer.alloc(half);
    fs.readSync(fd, a, 0, half, 0);
    fs.readSync(fd, b, 0, half, size - half);
    fs.closeSync(fd);
    return { content: `${a.toString('utf8')}\n${b.toString('utf8')}`, partial: true };
  } catch { return null; }
}

function snippet(line) {
  const s = line.trim();
  return s.length > 220 ? `${s.slice(0, 220)}…` : s;
}

// Trozos solapados de una línea larga (si no, bastaría con empujar el código a la columna 20001).
function windows(line, size) {
  if (line.length <= size) return [line];
  const out = [];
  for (let i = 0; i < line.length && out.length < 60; i += size - 1000) out.push(line.slice(i, i + size));
  return out;
}

// Bajar un script a un fichero y ejecutarlo después: no cabe en una regla de una sola línea.
const DOWNLOAD_RUN = { id: 'download-run', severity: 'high', title: 'Descarga un script y lo ejecuta', desc: 'Lo guarda en un fichero y lo ejecuta en las líneas siguientes: es código que no está en el repositorio y que el autor puede cambiar en cualquier momento.' };

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
  // dist/ solo cuenta como minificado si de verdad lo parece (líneas larguísimas de media):
  // si no, un atacante metería ahí el código para saltarse las reglas.
  // También por contenido (líneas de más de 1000 caracteres de media): bundles como el Yarn de
  // .yarn/releases o los plugins de un paquete publicado. Los payloads se siguen decodificando.
  const isMin = /[.-]min\.(js|css)$|[-.]bundle\.js$/.test(rel) || (/\.(c|m)?js$/.test(rel) && content.length > 20000 && content.length / lines.length > 1000) || (/(^|\/)dist\//.test(rel) && content.length / lines.length > 300);
  const isDoc = /\.(md|markdown|mdx|rst|txt|adoc|asciidoc|textile|org|html?)$/i.test(rel);
  const comment = commentLines(rel, lines);
  const perRuleCount = new Map();
  const cap = (id) => { const n = (perRuleCount.get(id) || 0) + 1; perRuleCount.set(id, n); return n <= 5; };

  for (const rule of vulnRules) {
    if (!rule.ext.test(rel)) continue;
    if (isMin && rule.id.startsWith('js-')) continue;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].length > 4000 && isMin) continue;
      // Un fallo de seguridad en un comentario no se ejecuta ("no usamos dangerouslySetInnerHTML").
      // Un secreto sí sigue expuesto aunque esté comentado.
      if (!rule.id.startsWith('secret-') && comment[i]) continue;
      for (const l of windows(lines[i], 4000)) {
        if (rule.re.test(l) && !(rule.skipIf && rule.skipIf.test(l)) && cap(rule.id)) { out.vulns.push(finding('vuln', rule, rel, i + 1, l)); break; }
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
      // 'code': fuera de la documentación (en un README, "# …" es un título y "* …" una lista)
      if (rule.skipComments && comment[i] && (rule.skipComments === true || !isDoc)) continue;
      for (const l of windows(lines[i], WINDOW)) {
        if (rule.re.test(l) && cap(rule.id)) { out.threats.push(finding('threat', rule, rel, i + 1, l)); break; }
      }
    }
  }
  if (!isMin) for (const r of findRemoteRuns(content)) if (r.kind === 'download-run' && cap('download-run')) out.threats.push(finding('threat', DOWNLOAD_RUN, rel, r.line, r.snippet));

  const vendored = isMin || /(^|\/)(vendor|third_party|node_modules)\//.test(rel);
  const aiFile = AI_FILES.test(rel) || /\.mdc$/.test(rel);
  if (!vendored && (CODE.test(rel) || aiFile || /\.(json|ya?ml|toml|cfg|ini)$/.test(rel))) {
    for (let i = 0; i < lines.length; i++) {
      const m = lines[i].match(INVISIBLE_RUN);
      if (m && !(/^[\u3164\u115F\u1160\uFFA0]$/.test(m[0]) && HANGUL.test(lines[i].replace(m[0], '')))) {
        const run = (lines[i].match(/(?:[\uFE00-\uFE0F\u3164\u115F\u1160\uFFA0\u00AD\u180E]|[\u{E0100}-\u{E01EF}])+/gu) || []).reduce((a, x) => Math.max(a, [...x].length), 0);
        out.threats.push({ kind: 'threat', rule: 'invisible-code', severity: run >= 10 ? 'critical' : 'high', title: aiFile ? 'Texto invisible en instrucciones para IA' : 'Caracteres invisibles que esconden código', description: aiFile ? 'Hay caracteres que no se ven en pantalla pero el agente de IA sí lee: pueden ser órdenes ocultas.' : `Hay ${run} caracteres invisibles seguidos (selectores de variación o rellenos de Hangul). Con ellos se codifica un programa entero que no se ve en el editor ni en GitHub, como hizo GlassWorm en 2025.`, file: rel, line: i + 1, snippet: snippet(lines[i].replace(/[\uFE00-\uFE0F\u3164\u115F\u1160\uFFA0\u00AD\u180E]|[\u{E0100}-\u{E01EF}]/gu, '·')) });
        break;
      }
    }
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

  // Segunda fase: descarga algo de Internet y lo ejecuta unas líneas más abajo.
  if (CODE.test(rel) && !isMin) {
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].length > 4000 || !REMOTE_NET.test(lines[i]) || comment[i]) continue;
      const near = lines.slice(i, i + 7).join('\n');
      if (REMOTE_RUN.test(near) && REMOTE_SRC.test(near)) {
        out.threats.push({ kind: 'threat', rule: 'remote-stage', severity: 'high', title: 'Descarga código y lo ejecuta', description: 'Pide algo a Internet y pocas líneas después lo pasa a eval, exec o new Function. Así funcionan los cargadores de segunda fase: el código malicioso no está en el repo y el autor puede cambiarlo cuando quiera.', file: rel, line: i + 1, snippet: snippet(lines[i]) });
        break;
      }
    }
  }

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
    const longLine = lines.findIndex((l) => l.length > 3000 && !/sourceMappingURL=/.test(l) && (l.length > 1000000 || entropy(l.slice(0, 3000)) > 4.8 || /(\S)\1{500,}|\s{500,}|\/\*[^*]{2000,}\*\//.test(l)));
    if (longLine >= 0) {
      const ll = lines[longLine];
      // CSS minificado en una plantilla, o un WebAssembly / data: URI en base64 dentro de un bundle
      // (undici trae así su parser): son datos, no código escondido. Los blobs se siguen decodificando.
      const css = /^\s*(\/\*!|@layer\b|@import\b|@charset\b|:root\s*\{)/.test(ll) && !/\b(eval|Function|require|import\s*\(|child_process|exec)\b/.test(ll);
      const blob = /(AGFzbQ[A-Za-z0-9+/]{1000,}|data:[\w/+.-]+;base64,[A-Za-z0-9+/=]{1000,})/.test(ll);
      out.threats.push({ kind: 'threat', rule: 'long-line', severity: css || blob ? 'low' : 'medium', title: 'Línea extremadamente larga en código fuente', description: css ? `Línea de ${ll.length} caracteres de CSS minificado: estilos, no código que se ejecute.` : blob ? `Línea de ${ll.length} caracteres con un binario en base64 (WebAssembly o data: URI), habitual en bundles; su contenido se ha decodificado y revisado aparte.` : `Línea de ${ll.length} caracteres en un fichero que no es minificado. Puede ocultar un payload.`, file: rel, line: longLine + 1, snippet: snippet(ll.slice(0, 200)) });
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

// A dónde apunta de verdad un enlace: el sistema sigue cada enlace intermedio antes de aplicar
// "..", así que calcularlo sobre el texto no basta (a/b/s -> ../.. y luego x -> a/b/s/../../..).
function linkTarget(root, rel) {
  const target = fs.readlinkSync(path.join(root, rel));
  try { return { target, resolved: realpath(path.join(root, rel)) }; } catch { /* roto: se calcula sobre el texto */ }
  return { target, resolved: path.resolve(realpath(path.dirname(path.join(root, rel))), target) };
}

function structuralChecks(root, files, symlinks, out) {
  const realRoot = realpath(root);
  for (const s of symlinks) {
    try {
      const { target, resolved } = linkTarget(root, s);
      if (!resolved.startsWith(realRoot + path.sep) && resolved !== realRoot) {
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

function reviewStats(s) {
  return [
    s.test && `${s.test} dato${s.test === 1 ? '' : 's'} de prueba en tests`,
    s.vendor && `${s.vendor} en código de terceros`,
    s.ip && `${s.ip} IP de documentación o privadas`,
    s.remote && `${s.remote} script${s.remote === 1 ? '' : 's'} remoto${s.remote === 1 ? '' : 's'} descargado${s.remote === 1 ? '' : 's'} y leído${s.remote === 1 ? '' : 's'}`,
    s.typosquat && `${s.typosquat} nombre${s.typosquat === 1 ? '' : 's'} de paquete comprobado${s.typosquat === 1 ? '' : 's'} en deps.dev`,
    s.docsDeps && `${s.docsDeps} dependencia${s.docsDeps === 1 ? '' : 's'} solo de docs o ejemplos`,
    s.docs && `${s.docs} ejemplo${s.docs === 1 ? '' : 's'} dentro de la documentación`,
    s.locale && `${s.locale} en ficheros de traducción`,
    s.comment && `${s.comment} carácter${s.comment === 1 ? '' : 'es'} invisible${s.comment === 1 ? '' : 's'} en comentarios`,
    s.publicKey && `${s.publicKey} clave${s.publicKey === 1 ? '' : 's'} pública${s.publicKey === 1 ? '' : 's'} de búsqueda`,
    s.example && `${s.example} ruta${s.example === 1 ? '' : 's'} de ejemplo`,
    s.config && `${s.config} lectura${s.config === 1 ? '' : 's'} de configuración sin envío`,
    s.noisy && `${s.noisy} aviso${s.noisy === 1 ? '' : 's'} de reglas generales de Semgrep`,
    s.author && `${s.author} que solo afecta${s.author === 1 ? '' : 'n'} al autor (sus claves o su CI)`,
    s.deploy && `${s.deploy} que solo afecta${s.deploy === 1 ? '' : 'n'} al desplegarlo`,
    s.docsSite && `${s.docsSite} en la web de documentación`,
  ].filter(Boolean).join(' · ') + '. Cada aviso revisado dice por qué cambió su gravedad.';
}

function statusOf(list, { redAt = 3, yellowAt = 2 } = {}) {
  const max = list.reduce((m, f) => Math.max(m, SEV_ORDER[f.severity] || 0), 0);
  return max >= redAt ? 'red' : max >= yellowAt ? 'yellow' : 'green';
}

async function analyzeTree(root, meta, log = () => {}, extra = {}) {
  const out = { vulns: [], threats: [] };
  log('Recorriendo ficheros…');
  const { files, symlinks, truncated, listedAll } = walk(root, extra.exclude);
  const langs = {};
  let bytes = 0;
  log(`Escaneando ${files.length} ficheros…`);
  const scanned = files.slice(0, MAX_FILES);
  // Con plazo (versión web cuando el navegador no deja usar un Web Worker y el análisis
  // corre en la propia página): se cede el hilo a la página cada poco y, si se acaba el
  // tiempo, se para entre fichero y fichero en vez de colgar la pestaña.
  const deadline = extra.deadline || Infinity;
  const maxText = extra.maxTextBytes || MAX_TEXT_BYTES;
  const late = () => Date.now() > deadline;
  let lastYield = Date.now();
  let unread = 0; // ficheros que se quedan sin leer porque se acabó el tiempo
  for (let i = 0; i < scanned.length; i++) {
    if (extra.signal && extra.signal.aborted) throw new Error('Análisis cancelado.');
    if (deadline !== Infinity) {
      if (Date.now() - lastYield > 50) { await new Promise((r) => setTimeout(r, 0)); lastYield = Date.now(); }
      if (late()) { unread = scanned.length - i; break; }
    }
    const rel = scanned[i];
    const ext = (path.extname(rel) || path.basename(rel)).toLowerCase();
    let st;
    try { st = fs.statSync(path.join(root, rel)); } catch { continue; }
    bytes += st.size;
    langs[ext] = (langs[ext] || 0) + 1;
    if (BINARY_EXT.test(rel)) {
      // Extensión de binario pero contenido de texto: código disfrazado para que nadie lo lea.
      if (/\.(png|jpe?g|gif|webp|ico|bmp|tiff?|woff2?|ttf|otf|eot|mp[34]|wav|ogg|webm|mov|avi|pdf)$/i.test(rel) || st.size > MAX_FILE_BYTES) continue;
      const c = safeRead(path.join(root, rel));
      if (c == null || c.includes('\u0000') || !looksLikeCode(c.slice(0, 20000))) continue;
      out.threats.push({ kind: 'threat', rule: 'text-as-binary', severity: 'medium', title: 'Código con extensión de fichero binario', description: `${path.basename(rel)} parece un binario por la extensión, pero es texto con código. Así se esconde un script de quien revisa el repo por encima.`, file: rel, line: null });
      scanTextFile(`${rel}.txt`, c, out);
      continue;
    }
    // Más de 1,5 MB solo se lee si es código (en datos grandes, como CSV o TSV, sobra).
    if (st.size > MAX_FILE_BYTES && !CODE.test(rel)) continue;
    const read = readText(path.join(root, rel), st.size, maxText);
    if (!read) continue;
    let content = read.content;
    if (read.partial && CODE.test(rel)) out.threats.push({ kind: 'threat', rule: 'oversized-source', severity: 'low', title: 'Fichero de código enorme', description: `${path.basename(rel)} ocupa ${(st.size / 1048576).toFixed(1)} MB. Se ha analizado el principio y el final; un fichero de código así de grande puede ser relleno para esconder algo en medio.`, file: rel, line: null });
    if (content.includes('\u0000')) {
      // Un NUL suelto no convierte un script en binario: se quita y se analiza el resto.
      // Fuera del código, solo si el resto es texto (no imágenes HDR, modelos 3D…).
      // UTF-16 con BOM (FF FE / FE FF, que en UTF-8 se leen como dos U+FFFD) lleva un NUL tras
      // cada carácter ASCII: es texto normal (PowerShell lo guarda así). EPS y AI llevan una
      // vista previa binaria dentro.
      const utf16 = content.startsWith('\uFFFD\uFFFD') && (content.slice(0, 2000).match(/\u0000/g) || []).length > Math.min(2000, content.length) * 0.3;
      if (!utf16 && !CODE.test(rel) && !mostlyText(content)) continue;
      // Unos pocos NUL dentro de cadenas (un separador como `${a}\0${b}` escrito tal cual) son
      // datos. Aquí se lee el fichero igualmente, así que lo que importa es si esconden algo.
      const nulLines = content.split('\n').map((l, i) => ({ l, i })).filter((x) => x.l.includes('\u0000'));
      const inStrings = nulLines.length <= 3 && nulLines.every(({ l }) => { const b = l.slice(0, l.indexOf('\u0000')); return ['"', "'", '`'].some((q) => (b.split(q).length - 1) % 2 === 1); });
      content = content.replace(/\u0000/g, '');
      if (utf16) content = content.slice(2);
      if (!utf16 && !/\.(eps|ai|ps|pdf)$/i.test(rel) && (CODE.test(rel) || looksLikeCode(content.slice(0, 20000)))) {
        out.threats.push(inStrings
          ? { kind: 'threat', rule: 'nul-in-source', severity: 'low', title: 'Byte nulo dentro de una cadena del código', description: 'Hay un carácter NUL escrito tal cual dentro de una cadena, normalmente como separador. Algunas herramientas tratarán el fichero como binario; aquí se ha leído entero.', file: rel, line: nulLines[0].i + 1 }
          : { kind: 'threat', rule: 'nul-in-source', severity: 'high', title: 'Bytes nulos dentro de un fichero de código', description: 'Un fichero de texto no lleva bytes NUL. Se añaden para que las herramientas lo traten como binario y no lo lean.', file: rel, line: null });
      }
    }
    scanTextFile(rel, content, out);
  }
  // Si lo que queda sin leer no es código ni configuración (imágenes, datos, documentos), pesa poco.
  const unreadCode = listedAll ? files.slice(MAX_FILES).filter((f) => priority(f) === 0).length : null;
  if (truncated) out.threats.push({ kind: 'threat', rule: 'partial-scan', severity: unreadCode === 0 ? 'low' : 'medium', title: 'Análisis incompleto: el repo tiene demasiados ficheros', description: `${listedAll ? `Hay ${files.length} ficheros y se ha leído el contenido de ${MAX_FILES}` : `Se han recorrido ${files.length} ficheros y quedan más`} (primero el código y la configuración). ${unreadCode === 0 ? 'Todo el código y la configuración se han leído; lo que queda son datos, imágenes o documentos.' : `${unreadCode == null ? 'Puede quedar código sin leer' : `Quedan ${unreadCode} ficheros de código o configuración sin leer`}: un repo inflado con miles de ficheros puede esconder algo en ellos.`}`, file: null, line: null });
  if (unread) out.threats.push({ kind: 'threat', rule: 'partial-scan', severity: 'medium', title: 'Análisis incompleto: se acabó el tiempo', description: `Se acabó el tiempo y ${unread} fichero${unread === 1 ? '' : 's'} se ${unread === 1 ? 'ha' : 'han'} quedado sin leer (primero se leen el código y la configuración). Un repo preparado para ralentizar el análisis puede esconder algo justo en lo que no se ha leído: trátalo como sospechoso.`, file: null, line: null });
  structuralChecks(root, files, symlinks, out);
  gitSymlinks(root, symlinks, out);
  packageScripts(root, files, out);
  // Estas comprobaciones vuelven a leer ficheros: sin tiempo, se saltan y la cobertura lo dice.
  const skipped = [];
  for (const [label, fn] of [
    ['Comprobaciones extra (homoglifos, ficheros para IA…)', () => extraChecks(root, files, out)],
    ['Configuración de herramientas y editores', () => configChecks(root, files, out)],
    ['Lo que se ejecuta al compilar o abrir el proyecto', () => surfaceChecks(root, files, out, (rel, content) => { const o = { vulns: [], threats: [] }; scanTextFile(rel, content, o); return o; })],
  ]) {
    if (late()) skipped.push(label); else fn();
  }

  // Las consultas por la red también se saltan sin tiempo: el plazo deja margen para
  // terminar la que esté en curso antes del corte duro.
  const LATE = 'saltado: se acabó el tiempo del análisis';
  let deps;
  if (late()) deps = { findings: [], threats: [], names: [], summary: { total: 0, checked: 0, vulnerable: 0, osvAvailable: false, osvError: LATE, skipped: true } };
  else { log('Revisando dependencias…'); deps = await auditDependencies(root, files); }
  out.vulns.push(...deps.findings);
  out.threats.push(...deps.threats, ...typosquatCheck(deps.names));

  // Lo que no está en el código descargado: el paquete publicado y los avisos del proyecto
  let beyond;
  if (late()) beyond = { vulns: [], threats: [], coverage: [{ label: 'Paquete publicado y avisos del proyecto', status: 'skip', detail: LATE }] };
  else {
    log('Comparando con el paquete publicado y buscando avisos del proyecto…');
    beyond = await beyondRepo(root, extra.ref, (rel, content) => { const o = { vulns: [], threats: [] }; scanTextFile(rel, content, o); return o; });
  }
  out.vulns.push(...beyond.vulns);
  out.threats.push(...beyond.threats);
  const exploit = late() ? { checked: 0 } : await exploitSignals(out.vulns);

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
  const NON_PROD = /(^|\/)(test|tests|__tests__|spec|specs|fixtures?|examples?|docs?|benchmarks?|testdata|playgrounds?|[\w-]*vectors[\w-]*)\//i;
  const TEST_NOISE = /^(archive|binary|lfs|image-trailing|long-line|zero-width|homoglyph|hidden-payload|win-exec|r-serialized|svg-script|pdf-active|wrapper-jar|case-collision|dep-url|alt-registry|insecure-registry|ai-file|text-as-binary|oversized-source|anti-vm|vm-env|geofence|ip-recon|stego-lib|trojan-source|unicode-tags|invisible-code|office-macro|pickle-exec|browser-ext\w*|vscode-ext-startup|dep-install-scripts)$/;
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
    // Solo se rebaja lo que es ruido normal en datos de prueba; descargar, ejecutar o
    // sacar datos es igual de peligroso en examples/ (la gente ejecuta los ejemplos).
    if (!TEST_NOISE.test(t.rule)) continue;
    if (t.severity === 'medium' || t.severity === 'low') t.severity = t.severity === 'medium' ? 'low' : 'info';
    else if (/^archive/.test(t.rule) || (t.rule === 'hidden-payload' && t.severity === 'high')) t.severity = 'low'; // datos de prueba
  }

  // Revisión de falsos positivos: dónde está cada aviso y qué hace de verdad (lib/review.js).
  // Los scripts remotos solo se descargan en el servidor (extra.remote).
  const reviewed = await review(out, {
    root, online: process.env.OMINOUS_OFFLINE !== '1', remote: !!extra.remote && process.env.OMINOUS_REMOTE !== '0' && process.env.OMINOUS_OFFLINE !== '1',
    scan: (rel, content) => { const o = { vulns: [], threats: [] }; scanTextFile(rel, content, o); return o; }, late, log,
  });

  // Ficha explicativa sin IA para cada hallazgo
  for (const f of [...out.vulns, ...out.threats]) if (!f.explain) f.explain = explain(f.rule, f.kind);

  const sortFn = (a, b) => (SEV_ORDER[b.severity] - SEV_ORDER[a.severity]) || String(a.file).localeCompare(String(b.file));
  out.vulns.sort(sortFn);
  out.threats.sort(sortFn);

  const vulnStatus = statusOf(out.vulns, { redAt: 4, yellowAt: 2 });
  const threatStatus = statusOf(out.threats, { redAt: 3, yellowAt: 2 });
  const overall = [vulnStatus, threatStatus].includes('red') ? 'red' : [vulnStatus, threatStatus].includes('yellow') ? 'yellow' : 'green';

  const count = (rule) => out.threats.filter((t) => t.rule === rule).length;
  const dep = deps.summary;
  const coverage = [
    { label: 'Código del último commit', status: truncated || unread ? 'partial' : 'ok', detail: `${scanned.length - unread} ficheros leídos${truncated || unread ? ` de ${files.length}${listedAll ? '' : '+'} (${unread ? 'se acabó el tiempo' : 'límite alcanzado'}: análisis parcial)` : ''}` },
    ...skipped.map((label) => ({ label, status: 'skip', detail: LATE })),
    dep.skipped ? { label: 'Dependencias (OSV.dev)', status: 'skip', detail: LATE } : { label: 'Dependencias (OSV.dev)', status: !dep.total ? 'ok' : dep.osvAvailable ? 'ok' : 'skip', detail: !dep.total ? 'sin ficheros de dependencias' : dep.osvAvailable ? `${dep.checked} de ${dep.total} con versión exacta consultadas` : `no se pudo consultar (${dep.osvError || 'sin conexión'})` },
    ...(dep.transitive ? [{ label: 'Dependencias indirectas sin lockfile (deps.dev)', status: dep.transitive.status, detail: dep.transitive.detail }] : []),
    ...(exploit.checked ? [{ label: '¿Se están explotando? (CISA KEV y EPSS)', status: exploit.epss == null ? 'partial' : 'ok', detail: `${exploit.checked} CVE revisada${exploit.checked === 1 ? '' : 's'}: ${exploit.kev} en el catálogo de CISA (${exploit.catalog})${exploit.epss == null ? ` · EPSS no disponible (${exploit.epssError})` : ''}` }] : []),
    ...beyond.coverage,
    ...reviewed.coverage,
    ...(Object.values(reviewed.stats).some(Boolean) ? [{ label: 'Revisión de falsos positivos', status: 'ok', detail: reviewStats(reviewed.stats) }] : []),
    ...(extra.coverage || []),
    ...(count('lfs') ? [{ label: 'Ficheros en Git LFS', status: 'skip', detail: `${count('lfs')} no descargados` }] : []),
    ...(count('archive') ? [{ label: 'Archivos comprimidos', status: 'partial', detail: `${count('archive')} listados pero no extraídos` }] : []),
  ];

  // Lo que se enviaría a Claude si se pide la revisión con IA (no sale del servidor).
  const aiContext = buildAiContext(root, files, out);

  return {
    aiContext,
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
  const realRoot = realpath(root);
  for (const [rel, items] of byFile) {
    const abs = path.resolve(root, rel);
    if (!abs.startsWith(root + path.sep)) continue;
    let st;
    try { st = fs.lstatSync(abs); } catch { continue; }
    if (!st.isFile()) continue;
    // Ninguna carpeta del camino puede ser un enlace que saque el fichero del clon.
    let real;
    try { real = realpath(abs); } catch { continue; }
    if (real !== path.join(realRoot, rel)) continue;
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
