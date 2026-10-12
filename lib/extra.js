'use strict';
// Chequeos adicionales: ficheros que se ejecutan solos, ficheros para agentes de IA,
// lockfiles manipulados, señuelos en el README, archivos comprimidos, dobles extensiones,
// Git LFS, wrappers de build, registros de paquetes alternativos y homoglifos.

const fs = require('fs');
const path = require('path');

const SUSP = /\bcurl\b|\bwget\b|https?:\/\/|socket|subprocess|os\.system|os\.popen|child_process|exec\(|eval\(|base64|b64decode|atob\(|powershell|Invoke-|nc\s+-|\/dev\/tcp|urllib|requests\.|fetch\(|marshal|zlib\.decompress|Function\(/i;
const MAX = 1.5 * 1024 * 1024;
// Igual que SUSP pero sin contar una URL suelta (en ficheros de configuración es normal enlazar repos).
// Para configs de JS (webpack, eslint…) solo cuentan señales fuertes: son ficheros largos donde aparecen palabras como base64.
const SUSP_STRONG = /\bchild_process\b|\bexecSync\b|\bspawnSync?\(|\beval\(|new Function\(|\bfetch\(\s*["'`]https?:|https?\.(get|request)\(\s*["'`]http|\bcurl\b|\bwget\b|powershell|\/dev\/tcp|Buffer\.from\([^)]*base64|\batob\(/i;
const SUSP_EXEC = new RegExp(SUSP.source.replace('https?:\\/\\/|', ''), 'i');

const SYSTEM_CMDS = new Set(['node', 'npm', 'npx', 'yarn', 'pnpm', 'git', 'ssh', 'scp', 'sudo', 'su', 'sh', 'bash', 'zsh', 'ls', 'cd', 'cp', 'mv', 'rm', 'cat', 'curl', 'wget', 'python', 'python3', 'pip', 'pip3', 'docker', 'kubectl', 'gh', 'code', 'make', 'gcc', 'tar', 'gpg', 'open', 'which', 'env', 'chmod', 'chown', 'ps', 'kill', 'aws', 'gcloud', 'az']);

// Bytes que siguen al final real de una imagen PNG (chunk IEND) o JPEG (marcador EOI).
function imageTrailer(root, rel) {
  let buf;
  try { const p = path.join(root, rel); const st = fs.lstatSync(p); if (!st.isFile() || st.size > 30 * 1024 * 1024) return null; buf = fs.readFileSync(p); } catch { return null; }
  let end = -1;
  if (buf.length > 8 && buf.readUInt32BE(0) === 0x89504e47) {
    const i = buf.lastIndexOf(Buffer.from('IEND', 'latin1'));
    if (i > 0) end = i + 8; // tipo (4) + CRC (4)
  } else if (buf.length > 4 && buf[0] === 0xff && buf[1] === 0xd8) {
    const i = buf.lastIndexOf(Buffer.from([0xff, 0xd9]));
    if (i > 0) end = i + 2;
  }
  if (end < 0 || end >= buf.length) return null;
  const data = buf.subarray(end);
  if (data.every((b) => b === 0)) return null; // relleno con ceros
  return { bytes: data.length, data: data.subarray(0, 1024 * 1024) };
}

function read(root, rel) {
  try { const p = path.join(root, rel); const st = fs.lstatSync(p); if (!st.isFile() || st.size > MAX) return null; return fs.readFileSync(p, 'utf8'); } catch { return null; }
}
function lineOf(content, re) { const i = content.search(re); return i < 0 ? null : content.slice(0, i).split('\n').length; }
function snip(s) { s = String(s).trim(); return s.length > 220 ? `${s.slice(0, 220)}…` : s; }
function firstSusp(c) { const l = c.split('\n').find((x) => SUSP.test(x)); return l ? snip(l) : undefined; }

// Ficheros que alguna herramienta ejecuta sin que tú lo pidas explícitamente.
const AUTOEXEC = [
  { strong: true, re: /(^|\/)conftest\.py$/, when: 'al ejecutar pytest' },
  { re: /(^|\/)(sitecustomize|usercustomize)\.py$/, when: 'al arrancar cualquier intérprete de Python que tenga esta carpeta en el path', base: 'medium' },
  { strong: true, re: /(^|\/)build\.rs$/, when: 'al compilar con cargo (también lo lanza rust-analyzer al abrir el proyecto en el editor)' },
  { re: /(^|\/)(build|settings)\.gradle(\.kts)?$/, when: 'al importar el proyecto en IntelliJ/Android Studio o al ejecutar Gradle' },
  { re: /(^|\/)\.envrc$/, when: 'al entrar en la carpeta si usas direnv', base: 'medium' },
  { re: /(^|\/)\.pre-commit-config\.ya?ml$/, when: 'en cada commit si instalas pre-commit' },
  { re: /(^|\/)(Rakefile|Gemfile)$/, when: 'al ejecutar bundle/rake' },
  { strong: true, re: /(^|\/)(\.mocharc\.[\w.]+|jest\.config\.[cm]?[jt]s|vitest\.config\.[cm]?[jt]s|vite\.config\.[cm]?[jt]s|webpack\.config\.[cm]?[jt]s|eslint\.config\.[cm]?js|\.eslintrc\.c?js|babel\.config\.c?js|postcss\.config\.c?js|tailwind\.config\.c?js|next\.config\.m?js|nuxt\.config\.[jt]s)$/, when: 'al ejecutar tests, el linter o el build (y algunos editores los cargan al abrir el proyecto)' },
  { re: /(^|\/)\.idea\/(workspace|runConfigurations\/[^/]+)\.xml$/, when: 'si lanzas la configuración de ejecución en IntelliJ' },
  { re: /(^|\/)\.claude\/settings(\.local)?\.json$/, when: 'como hooks de Claude Code al abrir el proyecto con él', base: 'medium', key: /"hooks"\s*:/ },
  { re: /(^|\/)(\.mcp\.json|\.cursor\/mcp\.json|\.vscode\/mcp\.json|\.gemini\/settings\.json)$/, when: 'al abrir el proyecto con un agente de IA que arranca servidores MCP del proyecto', base: 'medium', key: /"command"\s*:/ },
];

const AI_FILES = /(^|\/)(CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|copilot-instructions\.md|\.cursor\/rules\/[^/]+|\.github\/instructions\/[^/]+|\.claude\/(commands|agents|skills)\/.+)$/i;
const AI_BAD = /ignore (all |any )?(previous|prior|above) instructions|do not (tell|inform|mention)[^.\n]*(user|human)|without (asking|telling)[^.\n]*(user|human)|never (mention|reveal)|(curl|wget)\s[^\n]*\|\s*(ba)?sh|base64\s+(-d|--decode)|~\/\.ssh|\.aws\/credentials|\.env\b[^\n]*(send|post|upload)|exfiltrat|disable[^\n]*(sandbox|permission|safety)|--dangerously|bypassPermissions|auto-?approve/i;

function zipEntries(buf) {
  // Lee el directorio central de un ZIP (sin descomprimir nada).
  const out = [];
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 65557); i--) if (buf.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) return null;
  const count = buf.readUInt16LE(eocd + 10);
  let off = buf.readUInt32LE(eocd + 16);
  for (let n = 0; n < count && n < 5000 && off + 46 <= buf.length; n++) {
    if (buf.readUInt32LE(off) !== 0x02014b50) break;
    const flags = buf.readUInt16LE(off + 8);
    const nameLen = buf.readUInt16LE(off + 28), extraLen = buf.readUInt16LE(off + 30), commentLen = buf.readUInt16LE(off + 32);
    out.push({ name: buf.toString('utf8', off + 46, off + 46 + nameLen), encrypted: !!(flags & 1), method: buf.readUInt16LE(off + 10), size: buf.readUInt32LE(off + 20), local: buf.readUInt32LE(off + 42) });
    off += 46 + nameLen + extraLen + commentLen;
  }
  return out;
}

function extraChecks(root, files, out) {
  const T = (o) => out.threats.push({ kind: 'threat', line: null, ...o });
  const V = (o) => out.vulns.push({ kind: 'vuln', line: null, ...o });

  for (const rel of files) {
    const base = path.basename(rel);

    // 1. Ficheros que se ejecutan solos
    for (const a of AUTOEXEC) {
      if (!a.re.test(rel)) continue;
      const c = read(root, rel);
      if (c == null) break;
      if (a.key && !a.key.test(c)) break;
      const SRE = a.strong ? SUSP_STRONG : SUSP_EXEC;
      const codeLines = c.split('\n').filter((x) => !/^\s*(\/\/|#|\*|\/\*)/.test(x));
      const hit = codeLines.find((x) => SRE.test(x));
      const susp = !!hit;
      T({ rule: 'autoexec', severity: susp ? 'high' : (a.base || 'info'), title: `${base} se ejecuta automáticamente`, description: `Este fichero se ejecuta ${a.when}.${susp ? ' Contiene llamadas de red, ejecución de comandos o decodificación: revísalo antes.' : ''}`, file: rel, line: susp ? c.split('\n').indexOf(hit) + 1 : null, snippet: susp ? snip(hit) : undefined });
      break;
    }
    if (/\.pth$/.test(rel)) {
      const c = read(root, rel) || '';
      if (/^\s*import\s/m.test(c)) T({ rule: 'pth-exec', severity: 'high', title: 'Fichero .pth con código ejecutable', description: 'Python ejecuta las líneas "import" de los .pth instalados cada vez que arranca el intérprete. Es una técnica de persistencia.', file: rel, line: lineOf(c, /^\s*import\s/m), snippet: snip(c.split('\n').find((l) => /^\s*import\s/.test(l))) });
    }
    if (base === 'pyproject.toml') {
      const c = read(root, rel) || '';
      if (/backend-path\s*=/.test(c)) T({ rule: 'pyproject-backend', severity: 'medium', title: 'Backend de build propio en pyproject.toml', description: 'pip ejecuta código del propio repo para construir el paquete (pip install .).', file: rel, line: lineOf(c, /backend-path/) });
    }
    if (base === 'pom.xml') {
      const c = read(root, rel) || '';
      if (/exec-maven-plugin|maven-antrun-plugin|groovy-maven-plugin/.test(c)) T({ rule: 'maven-exec', severity: SUSP.test(c) ? 'high' : 'low', title: 'Maven ejecuta comandos durante el build', description: 'Plugins exec/antrun lanzan programas arbitrarios al compilar.', file: rel, line: lineOf(c, /exec-maven-plugin|maven-antrun-plugin|groovy-maven-plugin/) });
    }
    if (/gradle-wrapper\.properties$/.test(rel)) {
      const c = read(root, rel) || '';
      const m = c.match(/distributionUrl\s*=\s*(\S+)/);
      if (m && !/services\.gradle\.org/.test(m[1])) T({ rule: 'gradle-wrapper-url', severity: 'high', title: 'Gradle wrapper descarga Gradle de un sitio no oficial', description: `La primera ejecución de ./gradlew descargará y ejecutará ${m[1].replace(/\\:/g, ':')}.`, file: rel, line: lineOf(c, /distributionUrl/) });
    }
    if (base === '.yarnrc.yml') {
      const c = read(root, rel) || '';
      const m = c.match(/yarnPath\s*:\s*(\S+)/);
      if (m && !/^\.yarn\/releases\/yarn-[\d.]+(-[\w.]+)?\.c?js$/.test(m[1])) T({ rule: 'yarnpath', severity: 'high', title: 'yarnPath apunta a un script del repo', description: `Cualquier comando yarn ejecuta ${m[1]} en lugar de Yarn.`, file: rel, line: lineOf(c, /yarnPath/) });
    }
    if (/(^|\/)(\.npmrc|\.yarnrc(\.yml)?|pip\.conf|\.pypirc|pip\.ini)$/.test(rel) || base === 'requirements.txt') {
      const c = read(root, rel) || '';
      const m = c.match(/(registry\s*=|npmRegistryServer\s*:|index-url\s*=|--index-url\s+|--extra-index-url\s+)\s*["']?(https?:\/\/[^\s"']+)/);
      if (m && !/registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org|files\.pythonhosted\.org/.test(m[2])) T({ rule: 'alt-registry', severity: /extra-index-url/.test(m[1]) ? 'high' : 'medium', title: 'Registro de paquetes no oficial', description: `Las dependencias se descargan de ${m[2]}.${/extra-index-url/.test(m[1]) ? ' Con --extra-index-url pip puede elegir un paquete homónimo malicioso (dependency confusion).' : ''}`, file: rel, line: lineOf(c, /registry|index-url/) });
    }
    if (/^\.vscode\/settings\.json$/.test(rel)) {
      const c = read(root, rel) || '';
      const m = c.match(/"(python\.defaultInterpreterPath|python\.pythonPath|eslint\.runtime|typescript\.tsdk|git\.path|terminal\.integrated\.(shell|profiles|env|shellArgs)[\w.]*|php\.validate\.executablePath|go\.alternateTools|rust-analyzer\.server\.path|npm\.packageManager)"\s*:\s*("[^"]*"|\{)/);
      if (m) T({ rule: 'vscode-exec-setting', severity: 'medium', title: 'Ajuste de VS Code que apunta a un ejecutable', description: 'Si confías en la carpeta, VS Code o sus extensiones ejecutarán el programa indicado en este ajuste.', file: rel, line: lineOf(c, new RegExp(m[1].replace(/\./g, '\\.'))), snippet: snip(m[0]) });
    }

    // 2. Ficheros de instrucciones para agentes de IA (inyección de prompts)
    if (AI_FILES.test(rel)) {
      const c = read(root, rel) || '';
      const bad = c.split('\n').findIndex((l) => AI_BAD.test(l));
      if (bad >= 0) T({ rule: 'ai-injection', severity: 'high', title: 'Instrucciones peligrosas para agentes de IA', description: 'Si abres el repo con Claude Code, Cursor, Copilot u otro agente, leerá este fichero como instrucciones. Contiene órdenes para ejecutar comandos, ocultar acciones o tocar credenciales.', file: rel, line: bad + 1, snippet: snip(c.split('\n')[bad]) });
      else T({ rule: 'ai-file', severity: 'info', title: 'Fichero de instrucciones para agentes de IA', description: 'Los agentes de IA lo leen automáticamente. No contiene nada sospechoso.', file: rel });
    }

    // 3. Lockfiles con dependencias de orígenes no oficiales
    if (/(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/.test(rel) && !/node_modules\//.test(rel)) {
      const c = read(root, rel) || '';
      const hosts = new Map();
      for (const m of c.matchAll(/(?:"resolved"\s*:\s*"|resolved\s+"|tarball:\s*)(https?:\/\/[^/"\s]+)[^"\s]*/g)) hosts.set(m[1], (hosts.get(m[1]) || 0) + 1);
      for (const [h, n] of hosts) {
        if (/registry\.npmjs\.org|registry\.yarnpkg\.com|registry\.npmmirror\.com|codeload\.github\.com/.test(h)) continue;
        T({ rule: 'lockfile-host', severity: 'high', title: 'Lockfile descarga paquetes de un servidor no oficial', description: `${n} paquete${n > 1 ? 's' : ''} del lockfile se descargan de ${h}. Es la técnica de "lockfile injection": el package.json parece normal pero npm instala otra cosa.`, file: rel, line: lineOf(c, new RegExp(h.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'))) });
      }
    }

    // 3b. Lo mismo en los lockfiles de otros ecosistemas
    const LOCK_HOSTS = { 'Cargo.lock': /source\s*=\s*"(?:registry\+|sparse\+|git\+)?(https?:\/\/[^/"\s?#]+)/g, 'poetry.lock': /^url\s*=\s*"(https?:\/\/[^/"\s]+)/gm, 'uv.lock': /registry\s*=\s*"(https?:\/\/[^/"\s]+)|url\s*=\s*"(https?:\/\/[^/"\s]+)/g, 'Pipfile.lock': /"url"\s*:\s*"(https?:\/\/[^/"\s]+)/g, 'composer.lock': /"url"\s*:\s*"(https?:\/\/[^/"\s]+)/g, 'Gemfile.lock': /^\s*remote:\s*(https?:\/\/[^/\s]+)/gm };
    if (LOCK_HOSTS[base] && !/node_modules\//.test(rel)) {
      const c = read(root, rel) || '';
      const hosts = new Set([...c.matchAll(LOCK_HOSTS[base])].map((m) => m[1] || m[2]).filter(Boolean));
      for (const h of hosts) {
        if (/^https:\/\/(github\.com|codeload\.github\.com|api\.github\.com|gitlab\.com|bitbucket\.org|index\.crates\.io|pypi\.org|files\.pythonhosted\.org|repo\.packagist\.org|packagist\.org|rubygems\.org|static\.crates\.io)$/.test(h)) continue;
        T({ rule: 'lockfile-host', severity: /^http:/.test(h) ? 'high' : 'medium', title: 'Lockfile con paquetes de un servidor no habitual', description: `${base} descarga algún paquete de ${h}. Si no es un registro privado conocido de la empresa, es una forma de colar otra versión con el mismo nombre.`, file: rel, line: lineOf(c, new RegExp(h.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'))) });
      }
    }
    if (base === '.gitattributes') {
      const c = read(root, rel) || '';
      const m = c.match(/^[^#\n]*\b(filter|diff|merge)=(?!lfs\b)([\w.-]+)/m);
      if (m) T({ rule: 'gitattributes-driver', severity: 'info', title: `.gitattributes usa un "${m[1]}" propio (${m[2]})`, description: 'Git solo lo ejecuta si alguien define ese driver en su configuración local, pero algunos proyectos piden hacerlo en el README. Si te lo piden, revisa qué ejecuta.', file: rel, line: lineOf(c, new RegExp(`${m[1]}=${m[2]}`)) });
    }

    // 4. README con señuelos (descargas externas protegidas con contraseña)
    if (/^readme(\.\w+)?$/i.test(base) && !rel.includes('/')) {
      const c = read(root, rel) || '';
      const lure = c.match(/https?:\/\/[^\s)"']*(mediafire\.com|mega\.nz|mega\.co\.nz|dropbox\.com|drive\.google\.com|anonfiles|gofile\.io|pixeldrain|transfer\.sh|bit\.ly|tinyurl|cutt\.ly|github\.com\/[^/]+\/[^/]+\/releases\/download\/[^\s)]+\.(zip|rar|7z|exe))[^\s)"']*/i);
      const pwd = /(password|contraseña|pass)\s*[:=]\s*\S+/i.test(c);
      if (lure && (pwd || /\.(exe|zip|rar|7z)\b/i.test(lure[0]))) T({ rule: 'readme-lure', severity: pwd ? 'critical' : 'high', title: 'El README te pide descargar un fichero externo', description: `Enlaza a ${lure[1]}${pwd ? ' y da una contraseña para abrirlo' : ''}. Es el patrón más común de los repos falsos que distribuyen malware: el código del repo es un señuelo y lo malicioso está en la descarga.`, file: rel, line: lineOf(c, /https?:\/\//), snippet: snip(lure[0]) });
      const pipe = c.match(/(curl|wget|iwr|irm)\s[^\n`]*\|\s*(sudo\s+)?(ba|z)?sh|iex\s*\(|irm\s[^\n]*\|\s*iex/i);
      if (pipe) T({ rule: 'readme-pipe', severity: 'medium', title: 'El README pide ejecutar un script remoto', description: 'La instalación recomendada descarga y ejecuta un script que no está en el repo.', file: rel, line: lineOf(c, /(curl|wget|iwr|irm)\s/i), snippet: snip(pipe[0]) });
    }

    // 5. Doble extensión y formatos de Windows peligrosos
    if (/\.(pdf|docx?|xlsx?|jpe?g|png|txt|mp4|zip)\.(exe|scr|bat|cmd|com|pif|vbs|js|jse|hta|lnk|ps1)$/i.test(base)) T({ rule: 'double-ext', severity: 'critical', title: 'Fichero con doble extensión', description: `${base} se hace pasar por un documento pero es ejecutable.`, file: rel });
    else if (/\.(lnk|scr|hta|vbs|vbe|jse|wsf|pif|cpl|msc|reg|iso|img|vhdx?)$/i.test(base)) T({ rule: 'win-exec', severity: 'medium', title: 'Fichero ejecutable de Windows poco habitual en código fuente', description: `${base}: formato muy usado para distribuir malware.`, file: rel });

    // 5b. Imágenes con datos añadidos tras el final del fichero (polyglots / esteganografía burda)
    if (/\.(png|jpe?g)$/i.test(base) && !/node_modules\//.test(rel)) {
      const tail = imageTrailer(root, rel);
      if (tail && tail.bytes >= 64) {
        const t = tail.data;
        const kind = t.subarray(0, 2).toString('latin1') === 'MZ' || t.includes(Buffer.from('MZ\x90\x00', 'latin1')) ? 'un ejecutable de Windows'
          : t.includes(Buffer.from([0x7f, 0x45, 0x4c, 0x46])) ? 'un ejecutable de Linux (ELF)'
          : t.includes(Buffer.from('PK\x03\x04', 'latin1')) ? 'un ZIP'
          : SUSP_EXEC.test(t.toString('latin1')) ? 'código' : null;
        if (kind) T({ rule: 'image-payload', severity: 'high', title: 'Imagen con un fichero escondido al final', description: `${base} lleva ${tail.bytes} bytes después del final de la imagen que contienen ${kind}. Es una forma de colar un payload que otro script extrae y ejecuta.`, file: rel });
        else if (tail.bytes >= 4096) T({ rule: 'image-trailing', severity: 'low', title: 'Imagen con datos de más al final', description: `${base} lleva ${tail.bytes} bytes después del final de la imagen. Puede ser inofensivo (algunos editores lo hacen), pero también un payload cifrado.`, file: rel });
      }
    }

    // 5c. package.json que instala comandos con nombre de herramientas del sistema
    if (base === 'package.json' && !/node_modules\//.test(rel)) {
      let pkg = null;
      try { pkg = JSON.parse(read(root, rel) || 'null'); } catch { /* json roto */ }
      const bins = pkg && pkg.bin ? (typeof pkg.bin === 'string' ? [String(pkg.name || '').replace(/^@[^/]+\//, '')] : Object.keys(pkg.bin)) : [];
      const hijack = bins.filter((b) => SYSTEM_CMDS.has(b));
      if (hijack.length) T({ rule: 'npm-bin-hijack', severity: 'high', title: 'El paquete instala comandos que suplantan herramientas del sistema', description: `Declara en "bin" ${hijack.map((b) => `"${b}"`).join(', ')}. Si se instala de forma global o con npx, tu terminal ejecutará su script en lugar de la herramienta real.`, file: rel });
    }

    // 5d. Dockerfile que deja el contenedor corriendo como root
    if (/(^|\/)Dockerfile[^/]*$/.test(rel) && !/node_modules\//.test(rel)) {
      const c = read(root, rel) || '';
      if (/^\s*FROM\s/im.test(c) && !/^\s*FROM\s+scratch\b/im.test(c)) {
        const users = [...c.matchAll(/^\s*USER\s+(\S+)/gim)].map((m) => m[1]);
        const last = users[users.length - 1];
        if (!last || /^(root|0)(:|$)/.test(last)) V({ rule: 'docker-root', severity: 'low', title: 'El contenedor se ejecuta como root', description: 'Sin una instrucción USER, el proceso del contenedor corre como root: si alguien lo compromete, le resulta mucho más fácil salir al host.', file: rel, fixable: true, fix: { text: 'Crear un usuario sin privilegios (RUN adduser …) y añadir USER <usuario> antes de CMD.', auto: false } });
      }
    }

    // 6. Archivos comprimidos: se listan sin extraer
    if (/\.(zip|jar|apk|nupkg|whl|vsix|crx|xpi)$/i.test(base)) {
      let buf = null;
      try { const st = fs.lstatSync(path.join(root, rel)); if (st.isFile() && st.size < 50 * 1024 * 1024) buf = fs.readFileSync(path.join(root, rel)); } catch { /* nada */ }
      const entries = buf && zipEntries(buf);
      if (!entries) T({ rule: 'archive', severity: 'low', title: 'Archivo comprimido no analizable', description: `${base} no se ha podido listar.`, file: rel });
      else {
        const enc = entries.some((e) => e.encrypted);
        const exe = entries.filter((e) => /\.(exe|dll|scr|bat|cmd|ps1|vbs|js|lnk|hta|msi|jar|com)$/i.test(e.name));
        const isWrapper = /(gradle|maven)-wrapper\.jar$/.test(rel);
        if (enc) T({ rule: 'archive-encrypted', severity: 'critical', title: 'Archivo comprimido con contraseña', description: `${base} está cifrado: los antivirus y esta herramienta no pueden ver su contenido. Es la forma habitual de colar malware.`, file: rel, snippet: entries.slice(0, 6).map((e) => e.name).join(', ') });
        else if (exe.length && !isWrapper && !/\.(jar|apk|whl|nupkg|vsix|crx|xpi)$/i.test(base)) T({ rule: 'archive-exec', severity: 'high', title: 'Archivo comprimido con ejecutables dentro', description: `${base} contiene ${exe.length} fichero${exe.length > 1 ? 's' : ''} ejecutable${exe.length > 1 ? 's' : ''}.`, file: rel, snippet: exe.slice(0, 6).map((e) => e.name).join(', ') });
        else if (isWrapper) T({ rule: 'wrapper-jar', severity: 'info', title: 'Wrapper de Gradle/Maven precompilado', description: 'Es habitual, pero es un binario que se ejecuta al usar ./gradlew o ./mvnw. Compara su checksum con el oficial si desconfías del repo.', file: rel });
        else T({ rule: 'archive', severity: 'low', title: 'Archivo comprimido en el repositorio', description: `${base} (${entries.length} ficheros). Su contenido no se ha analizado en detalle.`, file: rel, snippet: entries.slice(0, 6).map((e) => e.name).join(', ') });
      }
    }
    if (/\.(7z|rar|tar|tgz|gz|bz2|xz|cab)$/i.test(base)) T({ rule: 'archive', severity: 'low', title: 'Archivo comprimido no analizado', description: `${base}: este formato no se puede listar sin herramientas externas.`, file: rel });

    // 7. Ficheros en Git LFS (no se descargan, así que no se analizan)
    if (!/\.(md|txt)$/.test(base)) {
      try {
        const st = fs.lstatSync(path.join(root, rel));
        if (st.isFile() && st.size < 200) {
          const c = fs.readFileSync(path.join(root, rel), 'utf8');
          if (c.startsWith('version https://git-lfs.github.com/spec/')) T({ rule: 'lfs', severity: 'low', title: 'Fichero en Git LFS no analizado', description: `${base} se guarda en Git LFS y no se ha descargado. Al clonar con LFS activo se bajará sin revisar.`, file: rel });
        }
      } catch { /* nada */ }
    }
  }
}

// Homoglifos: letras cirílicas/griegas mezcladas con latinas en identificadores (fuera de cadenas y comentarios).
const TOKEN = /[\p{L}\p{N}_$]{2,}/gu;
const LATIN = /[A-Za-z]/;
const GREEK_CYR = /[\u0370-\u03FF\u0400-\u04FF]/;
function homoglyphs(rel, content, out) {
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].length > 3000) continue;
    const code = lines[i].replace(/(["'`])(?:\\.|(?!\1)[^\\])*\1/g, '').replace(/(\/\/|#).*$/, '');
    const tok = GREEK_CYR.test(code) ? (code.match(TOKEN) || []).find((t) => LATIN.test(t) && GREEK_CYR.test(t)) : null;
    const m = tok ? [tok] : null;
    if (m) {
      out.threats.push({ kind: 'threat', rule: 'homoglyph', severity: 'high', title: 'Identificador con letras de otro alfabeto (homoglifo)', description: `"${m[0]}" mezcla letras latinas con cirílicas o griegas que se ven iguales. Sirve para crear una variable o función que parece otra.`, file: rel, line: i + 1, snippet: snip(lines[i]) });
      return;
    }
  }
}

// .gitmodules: dónde apuntan los submódulos
function parseGitmodules(root) {
  const c = read(root, '.gitmodules');
  if (!c) return [];
  const subs = [];
  let cur = null;
  for (const line of c.split('\n')) {
    const h = line.match(/^\s*\[submodule\s+"([^"]+)"\]/);
    if (h) { cur = { name: h[1] }; subs.push(cur); continue; }
    const kv = line.match(/^\s*(path|url|branch)\s*=\s*(.+?)\s*$/);
    if (kv && cur) cur[kv[1]] = kv[2];
  }
  return subs.filter((s) => s.path && s.url);
}

module.exports = { extraChecks, homoglyphs, parseGitmodules, zipEntries, read, lineOf, snip, SUSP, SUSP_EXEC, SUSP_STRONG, AI_FILES, AI_BAD };
