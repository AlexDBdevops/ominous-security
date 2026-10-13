'use strict';
// Más sitios desde los que un repo puede ejecutar código en tu máquina sin que lo pidas, y
// ficheros que se cargan solos según el tipo de proyecto: Visual Studio/MSBuild, Xcode,
// Unity/Godot, CMake/autotools, Composer, Cargo, Maven, pnpm/Yarn/Bun, node-gyp, R,
// devcontainers, VS Code, configuración de agentes de IA, modelos de ML (pickle),
// macros de Office, extensiones de navegador y trucos de git.
// Como el resto del análisis: solo se leen ficheros, nada se ejecuta.

const fs = require('fs');
const path = require('path');
// La de libc: la de Node normaliza ".." sobre el texto antes de seguir los enlaces.
const realpath = (p) => (fs.realpathSync.native || fs.realpathSync)(p);
const zlib = require('zlib');
const { read, lineOf, snip, SUSP_EXEC, SUSP_STRONG, zipEntries, parseGitmodules } = require('./extra');
const { vulnRules, threatRules } = require('./rules');

const RULES = new Map([...vulnRules, ...threatRules].map((r) => [r.id, r]));

// Lo que delata a un comando de build malicioso: descargar, decodificar o lanzar algo con
// las herramientas de Windows que usa el malware. Copiar DLLs o llamar a un .ps1 es normal.
const BUILD_SUSP = /\bcurl\b|\bwget\b|\/dev\/tcp|\bnc\s+-|base64|b64decode|certutil\s+-(urlcache|decode)|\b(bitsadmin|rundll32|regsvr32|mshta|wscript|cscript)\b|\s-(e|en|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\biex\b|Invoke-(Expression|WebRequest)|\biwr\s|Download(String|File)|\|\s*(ba|z)?sh\b|\beval\b|https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;
const MAX_MODEL = 100 * 1024 * 1024;

function bytes(root, rel, max) {
  try { const p = path.join(root, rel); const st = fs.lstatSync(p); if (!st.isFile() || st.size > max) return null; return fs.readFileSync(p); } catch { return null; }
}
const lineAt = (c, i) => c.slice(0, i).split('\n').length;

// ---------- pickle: qué funciones importa un fichero al cargarse ----------
// pickle guarda "importa módulo.nombre y llámalo con estos argumentos". Un modelo normal
// solo importa clases de torch, numpy o collections; uno malicioso importa os.system,
// subprocess, eval… Se leen los opcodes GLOBAL/INST (protocolos 0-3) y STACK_GLOBAL (4-5).
const PICKLE_BAD = /^(os|posix|nt|subprocess|socket|runpy|webbrowser|shutil|sys|pty|importlib|marshal|types|ctypes|commands|platform|code|pdb|requests|urllib(\.\w+)?|http\.client)$/;
const BUILTIN_BAD = /^(eval|exec|compile|getattr|__import__|open|execfile|apply|globals|setattr|breakpoint)$/;
const IDENT = /^[A-Za-z_][\w.]{0,120}$/;

function pickleGlobals(buf) {
  const out = [];
  const s = buf.toString('latin1');
  for (const m of s.matchAll(/[ci]([A-Za-z_][\w.]{0,120})\n([A-Za-z_][\w.]{0,120})\n/g)) out.push(`${m[1]}.${m[2]}`);
  const recent = [];
  for (let i = 0; i < buf.length; i++) {
    const op = buf[i];
    if (op === 0x8c && i + 1 < buf.length) { // SHORT_BINUNICODE
      const len = buf[i + 1];
      const str = buf.toString('latin1', i + 2, i + 2 + len);
      if (IDENT.test(str)) { recent.push({ str, end: i + 2 + len }); if (recent.length > 2) recent.shift(); }
      i += 1 + len;
    } else if (op === 0x93 && recent.length === 2 && i - recent[1].end <= 2 && recent[1].end - (recent[0].end + 2) <= recent[1].str.length + 2) {
      out.push(`${recent[0].str}.${recent[1].str}`);
      recent.length = 0;
    }
  }
  return [...new Set(out)];
}

function dangerousGlobals(globals) {
  return globals.filter((g) => {
    const i = g.lastIndexOf('.');
    const mod = g.slice(0, i);
    const name = g.slice(i + 1);
    if (/^(builtins|__builtin__)$/.test(mod)) return BUILTIN_BAD.test(name);
    return PICKLE_BAD.test(mod) || PICKLE_BAD.test(mod.split('.')[0]);
  });
}

// Los .pt/.pth/.ckpt de PyTorch son un ZIP con un data.pkl dentro.
function picklesIn(buf) {
  if (buf.length > 4 && buf.readUInt32LE(0) === 0x04034b50) {
    const out = [];
    for (const e of zipEntries(buf) || []) {
      if (!/(^|\/)[^/]*\.pkl$/.test(e.name) || e.size > 50 * 1024 * 1024) continue;
      try {
        const start = e.local + 30 + buf.readUInt16LE(e.local + 26) + buf.readUInt16LE(e.local + 28);
        const raw = buf.subarray(start, start + e.size);
        out.push({ name: e.name, data: e.method === 8 ? zlib.inflateRawSync(raw, { maxOutputLength: 200 * 1024 * 1024 }) : raw });
      } catch { /* entrada rota */ }
    }
    return out;
  }
  // pickle suelto: empieza por PROTO (0x80) o por un opcode de protocolo 0
  if (buf[0] === 0x80 || /^[(c\]}]/.test(buf.toString('latin1', 0, 1))) return [{ name: null, data: buf }];
  return [];
}

function modelFile(root, rel, T) {
  const buf = bytes(root, rel, MAX_MODEL);
  if (!buf) return;
  const base = path.basename(rel);
  for (const p of picklesIn(buf)) {
    const bad = dangerousGlobals(pickleGlobals(p.data));
    if (bad.length) {
      T({ rule: 'pickle-exec', severity: 'critical', title: 'Modelo o fichero pickle que ejecuta código al cargarse', description: `${base}${p.name ? ` (${p.name})` : ''} llama a ${bad.slice(0, 4).join(', ')} en cuanto alguien lo abre con pickle.load, torch.load o joblib.load. Es la técnica de los modelos maliciosos publicados en Hugging Face.`, file: rel, snippet: bad.join(', ') });
      return;
    }
  }
}

// ---------- utilidades para comandos en ficheros de configuración ----------
function verdict(cmd) {
  return BUILD_SUSP.test(cmd) ? 'high' : null;
}

function jsonish(c) {
  // JSON con comentarios (devcontainer, VS Code): se quitan // y /* */ fuera de cadenas.
  try { return JSON.parse(c.replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m, str) => str || '').replace(/,(\s*[}\]])/g, '$1')); } catch { return null; }
}
const flat = (v) => (v == null ? '' : typeof v === 'string' ? v : Array.isArray(v) ? v.map(flat).join(' ') : typeof v === 'object' ? Object.values(v).map(flat).join(' ; ') : String(v));

function surfaceChecks(root, files, out, scan) {
  const T = (o) => out.threats.push({ kind: 'threat', line: null, ...o });
  const lower = new Map();

  for (const rel of files) {
    const base = path.basename(rel);
    if (/(^|\/)node_modules\//.test(rel)) continue;

    // Rutas que chocan entre sí en discos que no distinguen mayúsculas (Windows, macOS)
    const k = rel.toLowerCase();
    if (lower.has(k) && lower.get(k) !== rel) T({ rule: 'case-collision', severity: 'medium', title: 'Dos ficheros con el mismo nombre salvo mayúsculas', description: `${lower.get(k)} y ${rel} son el mismo fichero en Windows y macOS: al clonar, uno pisa al otro y lo que ves en GitHub no es lo que queda en tu disco. Es la base de varios fallos de git (CVE-2024-32002).`, file: rel });
    else lower.set(k, rel);
    if (rel.split('/').slice(0, -1).some((d) => d !== '.git' && /^\.git(\W|~\d|$)/i.test(d.trim()))) T({ rule: 'git-dir-alias', severity: 'high', title: 'Carpeta que se hace pasar por .git', description: `La ruta ${rel} contiene una carpeta que en algunos sistemas equivale a .git (mayúsculas, nombre corto de Windows o espacios). Se usa para colar hooks o configuración de git.`, file: rel });

    // 1. Visual Studio / MSBuild: eventos de compilación y tareas Exec
    if (/\.(cs|vb|fs|vcx)proj$|\.(props|targets)$/i.test(base)) {
      const c = read(root, rel) || '';
      let worst = null;
      for (const m of c.matchAll(/<(PreBuildEvent|PostBuildEvent|PreLinkEvent)>([^<]+)<|<Exec\b[^>]*\bCommand\s*=\s*"([^"]+)"|<Import\b[^>]*Project\s*=\s*"(https?:[^"]+)"/g)) {
        const cmd = (m[2] || m[3] || m[4] || '').replace(/&quot;/g, '"').replace(/&amp;/g, '&');
        const sev = m[4] ? 'high' : verdict(cmd);
        if (sev && !worst) worst = { cmd, line: lineAt(c, m.index) };
      }
      if (worst) T({ rule: 'msbuild-exec', severity: 'high', title: 'El proyecto de Visual Studio ejecuta un comando sospechoso al compilar', description: 'Visual Studio, Rider y dotnet build ejecutan los eventos de compilación y las tareas Exec; algunos IDE compilan solo con abrir el proyecto. Así atacó Lazarus a investigadores de seguridad en 2021.', file: rel, line: worst.line, snippet: snip(worst.cmd) });
    }

    // 2. Xcode: fases "Run Script"
    if (/\.xcodeproj\/project\.pbxproj$/.test(rel)) {
      const c = read(root, rel) || '';
      for (const m of c.matchAll(/shellScript\s*=\s*"((?:\\.|[^"\\])*)";/g)) {
        const script = m[1].replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\"/g, '"').replace(/\\\\/g, '\\');
        if (/\$\{?PODS_ROOT\}?\/|swiftlint|Crashlytics\/run|FirebaseCrashlytics/.test(script) && !/base64|curl|wget|osascript/.test(script)) continue;
        const inner = scan ? scan(`${rel}.sh`, script) : { threats: [] };
        const bad = inner.threats.find((t) => /high|critical/.test(t.severity)) || (/(base64\s+-[dD]|xxd\s+-r|osascript|curl|wget)[^\n]*(\|\s*(ba|z)?sh|\|\s*python|-e\s)|\beval\b/.test(script) ? { title: 'descarga, decodifica o ejecuta código' } : null);
        if (bad) {
          T({ rule: 'xcode-run-script', severity: 'high', title: 'Fase "Run Script" de Xcode sospechosa', description: `Xcode la ejecuta en cada compilación (${bad.title}). XcodeSpy y XCSSET infectan proyectos de Xcode justo así.`, file: rel, line: lineAt(c, m.index), snippet: snip(script) });
          break;
        }
      }
    }

    // 3. Unity y Godot: código que corre al abrir el proyecto en el editor
    if (/\.cs$/i.test(base)) {
      const c = read(root, rel) || '';
      if (/\[(InitializeOnLoad|InitializeOnLoadMethod|DidReloadScripts)\b/.test(c) && /Process\.Start|WebClient|HttpClient|UnityWebRequest|Assembly\.Load\(|File\.WriteAllBytes/.test(c)) T({ rule: 'unity-autorun', severity: 'high', title: 'Script de Unity que se ejecuta al abrir el proyecto y usa red o procesos', description: 'Unity ejecuta las clases marcadas con [InitializeOnLoad] en cuanto abres el proyecto en el editor. Este script además lanza procesos, descarga algo o carga código.', file: rel, line: lineOf(c, /InitializeOnLoad|DidReloadScripts/) });
    }
    if (/\.gd$/i.test(base)) {
      const c = read(root, rel) || '';
      if (/^@?tool\b/m.test(c) && /OS\.(execute|execute_with_pipe|create_process)\(|HTTPRequest/.test(c)) T({ rule: 'godot-tool', severity: 'high', title: 'Script de Godot que se ejecuta en el editor y lanza procesos', description: 'Los scripts con @tool se ejecutan dentro del editor de Godot al abrir la escena.', file: rel, line: lineOf(c, /OS\.|HTTPRequest/) });
    }

    // 4. CMake y autotools (los IDE lanzan la configuración al abrir el proyecto)
    if (base === 'CMakeLists.txt' || /\.cmake$/i.test(base)) {
      const c = read(root, rel) || '';
      for (const m of c.matchAll(/execute_process\s*\(|file\s*\(\s*DOWNLOAD|include\s*\(\s*https?:/gi)) {
        const block = c.slice(m.index, m.index + 400).split(')')[0];
        if (verdict(block)) {
          T({ rule: 'cmake-exec', severity: 'high', title: 'CMake ejecuta un comando sospechoso al configurar', description: 'CLion y la extensión CMake Tools de VS Code configuran el proyecto al abrirlo, y eso ejecuta execute_process.', file: rel, line: lineAt(c, m.index), snippet: snip(block) });
          break;
        }
      }
    }
    if (/\.(m4|ac|am)$/.test(base) || /^configure(\.sh)?$/.test(base)) {
      const c = read(root, rel) || '';
      const m = c.match(/(xz|unxz|gzip|bzip2|lzma)\s+-[dc][^\n]*(tests?|testdata)\/[^\n]*\|\s*(ba)?sh|\|\s*(ba)?sh[^\n]*(tests?|testdata)\/[^\n]*\.(xz|gz|lzma|bz2)|eval\s+\$\(\s*(tr|sed|head|tail)\b/);
      if (m) T({ rule: 'autotools-backdoor', severity: 'critical', title: 'Script de build que extrae y ejecuta datos de "tests"', description: 'Descomprime ficheros de pruebas y los ejecuta durante ./configure o make. Es exactamente cómo funcionaba la puerta trasera de xz-utils (CVE-2024-3094).', file: rel, line: lineOf(c, new RegExp(m[0].slice(0, 20).replace(/[.*+?^${}()|[\]\\/]/g, '\\$&'))), snippet: snip(m[0]) });
    }

    // 5. Composer: scripts que corren con composer install
    if (base === 'composer.json') {
      let j = null;
      try { j = JSON.parse(read(root, rel) || 'null'); } catch { /* json roto */ }
      for (const [hook, v] of Object.entries((j && j.scripts) || {})) {
        if (!/^(pre|post)-(install|update|autoload-dump|root-package-install|create-project|package-install|package-update)(-cmd)?$/.test(hook)) continue;
        const cmd = flat(v);
        const bad = /curl|wget|base64|\beval\b|https?:|\|\s*(ba)?sh|powershell|shell_exec|passthru|system\(|proc_open/i.test(cmd);
        const benign = !bad && [].concat(v).every((x) => typeof x === 'string' && /^(@php artisan |@php -r "file_exists\('\.env'\)|Illuminate\\\\Foundation\\\\ComposerScripts::|@composer |@putenv )/.test(x));
        if (!benign) T({ rule: 'composer-script', severity: bad ? 'high' : 'low', title: `Script "${hook}" de Composer`, description: bad ? 'Se ejecuta solo al hacer composer install/update y descarga o ejecuta código.' : 'Se ejecuta automáticamente al hacer composer install/update. Revisa qué hace.', file: rel, snippet: snip(`"${hook}": ${JSON.stringify(v)}`) });
      }
      const repos = (j && j.repositories) || [];
      for (const r of Array.isArray(repos) ? repos : Object.values(repos)) {
        if (r && r.url && !/repo\.packagist\.org|packagist\.org/.test(r.url) && r.packagist !== false) T({ rule: 'alt-registry', severity: 'medium', title: 'Composer instala paquetes de fuera de Packagist', description: `Repositorio de tipo ${r.type || '?'}: ${r.url}. Su contenido no pasa por Packagist.`, file: rel, snippet: snip(r.url) });
      }
      if (j && j.config && j.config['secure-http'] === false) T({ rule: 'insecure-registry', severity: 'medium', title: 'Composer descarga paquetes por HTTP', description: 'secure-http: false permite descargas sin cifrar que cualquiera en la red puede cambiar.', file: rel });
    }

    // 6. Cargo: wrappers del compilador y registros alternativos
    if (/(^|\/)\.cargo\/config(\.toml)?$/.test(rel)) {
      const c = read(root, rel) || '';
      const m = c.match(/^\s*(runner|rustc-wrapper|rustc-workspace-wrapper|rustc|linker)\s*=\s*\[?\s*"([^"]+)"/m);
      if (m && /^(\.|[\w-]+\/)/.test(m[2]) && !/^(cc|gcc|clang|lld|rust-lld|ld|mold|sccache|ccache)$/.test(m[2])) T({ rule: 'cargo-wrapper', severity: 'high', title: `.cargo/config sustituye el compilador (${m[1]})`, description: `cargo build ejecutará ${m[2]}, un programa del propio repo. rust-analyzer también compila al abrir el proyecto.`, file: rel, line: lineOf(c, new RegExp(`^\\s*${m[1]}`, 'm')), snippet: snip(m[0]) });
      if (/replace-with\s*=|^\s*\[registries\./m.test(c)) T({ rule: 'alt-registry', severity: 'medium', title: 'Cargo descarga crates de un registro alternativo', description: 'El proyecto sustituye crates.io por otra fuente.', file: rel, line: lineOf(c, /replace-with|\[registries\./) });
    }

    // 7. Maven y Gradle: extensiones, agentes de la JVM y wrappers
    if (/(^|\/)\.mvn\/extensions\.xml$/.test(rel)) T({ rule: 'maven-extension', severity: 'low', title: 'Extensiones de Maven del proyecto', description: 'Maven descarga y carga estas extensiones al empezar cualquier build, antes que nada.', file: rel });
    if (/(^|\/)\.mvn\/(jvm|maven)\.config$|(^|\/)gradle\.properties$/.test(rel)) {
      const c = read(root, rel) || '';
      if (/-javaagent|-agentpath|-agentlib/.test(c)) T({ rule: 'jvm-agent', severity: 'high', title: 'El build carga un agente en la JVM', description: 'Un -javaagent ejecuta su código dentro de Maven o Gradle con acceso a todo el build.', file: rel, line: lineOf(c, /-javaagent|-agentpath|-agentlib/) });
    }
    if (/maven-wrapper\.properties$/.test(rel)) {
      const c = read(root, rel) || '';
      for (const m of c.matchAll(/(distributionUrl|wrapperUrl)\s*=\s*(\S+)/g)) {
        if (!/^https:\/\/(repo\.maven\.apache\.org|repo1\.maven\.org)\//.test(m[2].replace(/\\:/g, ':'))) { T({ rule: 'maven-wrapper-url', severity: 'high', title: 'El wrapper de Maven descarga de un sitio no oficial', description: `./mvnw descargará y ejecutará ${m[2].replace(/\\:/g, ':')}.`, file: rel, line: lineAt(c, m.index) }); break; }
      }
    }
    if (base === 'pom.xml' || /(^|\/)(\.mvn\/)?settings\.xml$/.test(rel)) {
      const c = read(root, rel) || '';
      const m = c.match(/<(repository|pluginRepository|mirror)>[\s\S]*?<url>\s*(http:\/\/[^<\s]+)/);
      if (m) T({ rule: 'insecure-registry', severity: 'medium', title: 'Maven descarga dependencias por HTTP', description: `${m[2]} no usa HTTPS: cualquiera en la red puede cambiar lo que se descarga.`, file: rel, line: lineOf(c, /<url>\s*http:\/\//) });
    }

    // 8. pnpm, Yarn, Bun y .npmrc
    if (/(^|\/)\.pnpmfile\.[cm]?js$/.test(rel)) {
      const c = read(root, rel) || '';
      const hit = c.split('\n').find((l) => SUSP_STRONG.test(l));
      T({ rule: 'autoexec', severity: hit ? 'high' : 'low', title: `${base} se ejecuta automáticamente`, description: `pnpm ejecuta este fichero en cada pnpm install y puede cambiar qué paquetes se instalan.${hit ? ' Contiene llamadas de red o ejecución de comandos.' : ''}`, file: rel, snippet: hit ? snip(hit) : undefined });
    }
    if (base === '.yarnrc.yml') {
      const c = read(root, rel) || '';
      for (const m of c.matchAll(/^\s*-?\s*(?:path|spec)\s*:\s*["']?(\S+?)["']?\s*$/gm)) {
        if (/^\.yarn\/plugins\/@yarnpkg\//.test(m[1]) || /^@yarnpkg\//.test(m[1])) continue;
        T({ rule: 'yarn-plugin', severity: /^https?:/.test(m[1]) ? 'high' : 'medium', title: 'Plugin de Yarn que no es oficial', description: `Yarn carga ${m[1]} en cada comando.`, file: rel, line: lineAt(c, m.index), snippet: snip(m[0]) });
        break;
      }
    }
    if (base === 'bunfig.toml') {
      const c = read(root, rel) || '';
      if (/^\s*preload\s*=/m.test(c)) T({ rule: 'bun-preload', severity: 'medium', title: 'Bun precarga scripts del repo', description: 'preload ejecuta esos ficheros antes de cada bun run o bun test.', file: rel, line: lineOf(c, /^\s*preload/m) });
      const r = c.match(/registry\s*=\s*["'{]?\s*(?:url\s*=\s*)?["']?(https?:\/\/[^"'\s,}]+)/);
      if (r && !/registry\.npmjs\.org/.test(r[1])) T({ rule: 'alt-registry', severity: 'medium', title: 'Registro de paquetes no oficial', description: `Bun descarga las dependencias de ${r[1]}.`, file: rel });
    }
    if (base === '.npmrc') {
      const c = read(root, rel) || '';
      const m = c.match(/^\s*(node-options\s*=.*--(require|import|loader|experimental-loader)\b.*|script-shell\s*=.*|git\s*=.*|strict-ssl\s*=\s*false|onload-script\s*=.*)$/m);
      if (m) T({ rule: 'npmrc-exec', severity: /strict-ssl/.test(m[1]) ? 'medium' : 'high', title: '.npmrc cambia cómo npm ejecuta cosas', description: /strict-ssl/.test(m[1]) ? 'Desactiva la comprobación de certificados: las descargas de npm se pueden interceptar.' : 'Con este ajuste, cualquier npm install o npm run de esta carpeta ejecuta un programa elegido por el repo.', file: rel, line: lineOf(c, new RegExp(`^\\s*${m[1].split(/\s*=/)[0].replace(/[-]/g, '\\-')}`, 'm')), snippet: snip(m[1]) });
    }

    // 9. node-gyp: <!(comando) se ejecuta durante npm install
    if (base === 'binding.gyp' || /\.gypi$/.test(base)) {
      const c = read(root, rel) || '';
      const m = [...c.matchAll(/<!@?\(([^)]*)\)/g)].find((x) => verdict(x[1]));
      if (m) T({ rule: 'gyp-exec', severity: 'high', title: 'binding.gyp ejecuta un comando sospechoso al instalar', description: 'node-gyp ejecuta lo que va dentro de <!( ) al compilar el módulo, es decir, durante npm install.', file: rel, line: lineAt(c, m.index), snippet: snip(m[0]) });
    }

    // 10. Otros ecosistemas
    if (/\.podspec$|(^|\/)Podfile$/.test(rel)) {
      const c = read(root, rel) || '';
      const m = c.match(/(prepare_command|script_phases?)\s*[=:(][^\n]*/);
      if (m) {
        const block = c.slice(c.indexOf(m[0]), c.indexOf(m[0]) + 600);
        T({ rule: 'cocoapods-script', severity: verdict(block) ? 'high' : 'low', title: 'CocoaPods ejecuta un script', description: 'prepare_command se ejecuta al instalar el pod y script_phase en cada compilación de Xcode.', file: rel, line: lineOf(c, /prepare_command|script_phase/), snippet: snip(m[0]) });
      }
    }
    if (base === 'Gemfile') {
      const c = read(root, rel) || '';
      const m = c.match(/^\s*source\s+["'](http:\/\/[^"']+|https?:\/\/(?!rubygems\.org|gems\.ruby-china)[^"']+)["']/m);
      if (m) T({ rule: 'alt-registry', severity: /^http:/.test(m[1]) ? 'high' : 'medium', title: 'Bundler instala gemas de fuera de rubygems.org', description: `Las gemas se descargan de ${m[1]}.`, file: rel, line: lineOf(c, /^\s*source\s/m) });
    }
    if (/(^|\/)src\/Makevars(\.win)?$/.test(rel)) {
      const c = read(root, rel) || '';
      const m = [...c.matchAll(/\$\(shell\s+([^)]*)\)/g)].find((x) => verdict(x[1]));
      if (m) T({ rule: 'r-makevars', severity: 'high', title: 'El paquete de R ejecuta un comando sospechoso al instalarse', description: 'Makevars se usa al compilar el paquete con install.packages o R CMD INSTALL.', file: rel, line: lineAt(c, m.index), snippet: snip(m[0]) });
    }
    if (/\.(RData|rda|rds|rdb)$/i.test(base)) T({ rule: 'r-serialized', severity: 'low', title: 'Datos serializados de R', description: `${base} se carga con load() o readRDS(). En R anterior a 4.4.0 abrirlo puede ejecutar código (CVE-2024-27322).`, file: rel });

    // 11. Hooks de build de Python declarados en pyproject.toml
    if (base === 'pyproject.toml') {
      const c = read(root, rel) || '';
      const hooks = [
        [/\[tool\.hatch\.build(\.targets\.\w+)?\.hooks\.custom\]([^[]*)/, 'hatch_build.py', /path\s*=\s*"([^"]+)"/],
        [/\[tool\.poetry\.build\]([^[]*)/, null, /script\s*=\s*"([^"]+)"/],
        [/\[tool\.pdm\.build\]([^[]*)/, null, /setup-script\s*=\s*"([^"]+)"/],
        [/\[tool\.setuptools\.cmdclass\]([^[]*)/, null, null],
      ];
      for (const [re, def, fileRe] of hooks) {
        const m = c.match(re);
        if (!m) continue;
        const sect = m[m.length - 1];
        const f = (fileRe && (sect.match(fileRe) || [])[1]) || def;
        const target = f && read(root, path.posix.join(path.posix.dirname(rel), f));
        if (fileRe && !f) continue;
        const hit = target && target.split('\n').find((l) => SUSP_EXEC.test(l));
        T({ rule: 'python-build-hook', severity: hit ? 'high' : 'medium', title: 'Hook de build en pyproject.toml', description: `pip install ejecuta ${f || 'código del repo'} para construir el paquete.${hit ? ' Contiene red, ejecución de comandos o decodificación.' : ''}`, file: rel, line: lineAt(c, m.index), snippet: hit ? snip(hit) : undefined });
        break;
      }
      const src = c.match(/\[\[tool\.(poetry\.source|uv\.index)\]\][^[]*url\s*=\s*"([^"]+)"/);
      if (src && !/pypi\.org|pythonhosted\.org/.test(src[2])) T({ rule: 'alt-registry', severity: 'medium', title: 'Registro de paquetes no oficial', description: `Las dependencias se buscan también en ${src[2]}.`, file: rel, line: lineOf(c, /\[\[tool\.(poetry\.source|uv\.index)\]\]/) });
    }
    if (base === 'Pipfile') {
      const c = read(root, rel) || '';
      for (const m of c.matchAll(/\[\[source\]\][^[]*url\s*=\s*"([^"]+)"/g)) if (!/pypi\.org/.test(m[1])) { T({ rule: 'alt-registry', severity: 'medium', title: 'Registro de paquetes no oficial', description: `Pipenv busca paquetes en ${m[1]}.`, file: rel, line: lineAt(c, m.index) }); break; }
    }
    if (/requirements[\w.-]*\.txt$/i.test(base) || /(^|\/)pip\.(conf|ini)$/.test(rel)) {
      const c = read(root, rel) || '';
      if (/--trusted-host|trusted-host\s*=/.test(c)) T({ rule: 'insecure-registry', severity: 'medium', title: 'pip confía en un servidor sin HTTPS', description: 'trusted-host desactiva la comprobación del certificado para ese servidor: los paquetes se pueden cambiar por el camino.', file: rel, line: lineOf(c, /trusted-host/) });
    }
    if (/(^|\/)nuget\.config$/i.test(rel)) {
      const c = read(root, rel) || '';
      const m = [...c.matchAll(/<add\s+key="[^"]*"\s+value="(https?:\/\/[^"]+)"/gi)].find((x) => !/api\.nuget\.org|pkgs\.dev\.azure\.com\/dnceng\//.test(x[1]));
      if (m) T({ rule: 'alt-registry', severity: /<clear\s*\/>/.test(c) ? 'medium' : 'high', title: 'NuGet descarga paquetes de una fuente no oficial', description: `Fuente: ${m[1]}.${/<clear\s*\/>/.test(c) ? '' : ' Sin <clear/>, se mezcla con nuget.org: un paquete homónimo puede colarse (dependency confusion).'}`, file: rel, line: lineAt(c, m.index) });
    }
    if (/(^|\/)\.bundle\/config$/.test(rel)) {
      const c = read(root, rel) || '';
      if (/BUNDLE_MIRROR/.test(c)) T({ rule: 'alt-registry', severity: 'medium', title: 'Bundler usa un espejo de gemas', description: 'Las gemas se descargan de otro servidor.', file: rel, line: lineOf(c, /BUNDLE_MIRROR/) });
    }
    if (base === '.lfsconfig') {
      const c = read(root, rel) || '';
      const m = c.match(/url\s*=\s*(\S+)/);
      if (m && !/github\.com|gitlab\.com|bitbucket\.org/.test(m[1])) T({ rule: 'lfs-url', severity: 'medium', title: 'Git LFS descarga ficheros de otro servidor', description: `Al clonar, los ficheros grandes se bajarán de ${m[1]}, no del hosting del repo.`, file: rel, line: lineOf(c, /url\s*=/) });
    }

    // 12. Terraform: data "external" se ejecuta con terraform plan
    if (/\.tf$/.test(base)) {
      const c = read(root, rel) || '';
      for (const m of c.matchAll(/data\s+"external"\s+"[^"]+"|provisioner\s+"local-exec"/g)) {
        const block = c.slice(m.index, m.index + 600);
        const sus = verdict(block.replace(/https?:\/\/\S+/g, ''));
        if (sus || /data\s+"external"/.test(m[0])) {
          T({ rule: 'terraform-exec', severity: sus ? 'high' : 'low', title: /external/.test(m[0]) ? 'Terraform ejecuta un programa local con plan' : 'Terraform ejecuta un comando local', description: /external/.test(m[0]) ? 'El data source "external" ejecuta su programa incluso con terraform plan, que la gente lanza pensando que no cambia nada.' : 'local-exec se ejecuta en tu máquina al aplicar.', file: rel, line: lineAt(c, m.index), snippet: snip(block.split('\n').slice(0, 4).join(' ')) });
          break;
        }
      }
    }
    if (base === 'ansible.cfg') {
      const c = read(root, rel) || '';
      const m = c.match(/vault_password_file\s*=\s*(\S+\.(sh|py|rb|pl|js))|^\s*(callback|action|lookup|filter|connection|strategy)_plugins\s*=\s*\.\S*/m);
      if (m) T({ rule: 'ansible-exec', severity: 'medium', title: 'ansible.cfg ejecuta scripts del repo', description: 'Ansible lee ansible.cfg de la carpeta actual y ejecuta el script de contraseña o carga los plugins que indica.', file: rel, line: lineOf(c, /vault_password_file|_plugins\s*=/) });
    }

    // 13. Extensiones de navegador y de VS Code
    if (base === 'manifest.json') {
      let j = null;
      try { j = JSON.parse(read(root, rel) || 'null'); } catch { /* nada */ }
      if (j && j.manifest_version) {
        const perms = [...(j.permissions || []), ...(j.host_permissions || []), ...((j.content_scripts || []).flatMap((s) => s.matches || []))].map(String);
        const all = perms.some((p) => /<all_urls>|^\*:\/\/\*\/\*$|^https?:\/\/\*\/\*$/.test(p));
        const strong = perms.filter((p) => /^(cookies|webRequest|webRequestBlocking|debugger|nativeMessaging|clipboardRead|scripting|management|proxy|declarativeNetRequest)$/.test(p));
        if (all && strong.length) T({ rule: 'browser-ext-perms', severity: 'low', title: 'Extensión de navegador con acceso a todas las webs', description: `Puede leer y cambiar cualquier página que visites y además pide ${strong.join(', ')}. Es lo que necesita una extensión que roba sesiones; los gestores de contraseñas también lo piden.`, file: rel });
        if (/unsafe-eval/.test(flat(j.content_security_policy))) T({ rule: 'browser-ext-eval', severity: 'medium', title: 'Extensión de navegador que permite eval', description: 'Su CSP admite unsafe-eval: puede ejecutar código descargado.', file: rel });
      }
    }
    if (base === 'package.json') {
      let j = null;
      try { j = JSON.parse(read(root, rel) || 'null'); } catch { /* nada */ }
      if (j && j.engines && j.engines.vscode && (j.activationEvents || []).some((e) => e === '*' || e === 'onStartupFinished')) {
        const main = j.main && read(root, path.posix.join(path.posix.dirname(rel), j.main));
        const hit = main && main.split('\n').find((l) => SUSP_STRONG.test(l));
        T({ rule: 'vscode-ext-startup', severity: hit ? 'medium' : 'info', title: 'Extensión de VS Code que arranca siempre', description: `Se activa al abrir VS Code, sin esperar a que la uses.${hit ? ' Su código lanza procesos o hace peticiones de red.' : ''}`, file: rel, snippet: hit ? snip(hit) : undefined });
      }
      for (const sect of ['overrides', 'resolutions', 'pnpm']) {
        const spec = flat(j && j[sect]);
        const m = spec.match(/(https?:|git(\+\w+)?:|github:|file:)[^\s;]+/);
        if (m) { T({ rule: 'dep-url', severity: 'medium', title: `"${sect}" fuerza una dependencia desde URL o fichero`, description: 'Sustituye un paquete del árbol por algo que no viene del registro de npm.', file: rel, snippet: snip(m[0]) }); break; }
      }
    }

    // 14. Macros de Office y formatos de Windows que ejecutan código
    if (/\.(docm|xlsm|pptm|xlam|dotm|potm|ppsm|docx|xlsx|pptx)$/i.test(base)) {
      const buf = bytes(root, rel, 30 * 1024 * 1024);
      const entries = buf && zipEntries(buf);
      if (entries && entries.some((e) => /vbaProject\.bin$/i.test(e.name))) T({ rule: 'office-macro', severity: 'high', title: 'Documento de Office con macros', description: `${base} lleva macros VBA. Es una de las formas más antiguas y comunes de colar malware: se ejecutan al abrir el documento si aceptas el aviso.`, file: rel });
    }
    if (/\.(doc|xls|ppt|dot|xlt)$/i.test(base)) {
      const buf = bytes(root, rel, 30 * 1024 * 1024);
      if (buf && buf.length > 8 && buf.readUInt32BE(0) === 0xd0cf11e0) {
        const s = buf.toString('latin1');
        if (/_VBA_PROJECT|Attribute VB_/.test(s)) T({ rule: 'office-macro', severity: /AutoOpen|Auto_Open|Document_Open|Workbook_Open/.test(s) ? 'critical' : 'high', title: 'Documento de Office con macros', description: `${base} lleva macros VBA${/AutoOpen|Auto_Open|Document_Open|Workbook_Open/.test(s) ? ' que se ejecutan al abrirlo' : ''}.`, file: rel });
      }
    }
    if (/\.pdf$/i.test(base)) {
      const buf = bytes(root, rel, 30 * 1024 * 1024);
      const s = buf ? buf.toString('latin1') : '';
      if (/\/Launch\b/.test(s)) T({ rule: 'pdf-active', severity: 'high', title: 'PDF que intenta lanzar un programa', description: `${base} contiene una acción /Launch: al abrirlo, algunos lectores ejecutan un programa.`, file: rel });
      else if (/\/(JavaScript|JS)\b/.test(s) && /\/OpenAction|\/AA\b/.test(s)) T({ rule: 'pdf-active', severity: 'low', title: 'PDF con JavaScript que se ejecuta al abrirlo', description: `${base} lleva JavaScript asociado a la apertura del documento.`, file: rel });
    }
    if (/\.svg$/i.test(base)) {
      const c = read(root, rel) || '';
      if (/<script\b[^>]*[^/]>\s*[^<\s]|\bon(load|error|click|mouseover|begin|end)\s*=\s*["'][^"']+|href\s*=\s*["']\s*javascript:/i.test(c)) T({ rule: 'svg-script', severity: 'medium', title: 'Imagen SVG con JavaScript', description: `${base} lleva código. Si se abre directamente en el navegador o se sirve desde tu dominio, se ejecuta (XSS, redirecciones a phishing).`, file: rel, line: lineOf(c, /<script\b|\bon\w+\s*=|javascript:/i) });
    }

    // 15. Modelos de ML y otros ficheros pickle
    if (/\.(pkl|pickle|joblib|dill|pt|pth|ckpt|bin|sav|model|npy)$/i.test(base)) {
      const head = bytes(root, rel, MAX_MODEL);
      if (head && !(/\.pth$/i.test(base) && !head.includes(0))) modelFile(root, rel, T);
    }

    // 16. Notebooks de Jupyter: el código de cada celda se analiza como Python
    if (/\.ipynb$/i.test(base) && scan) {
      let nb = null;
      try { nb = JSON.parse(read(root, rel) || 'null'); } catch { /* nada */ }
      const cells = (nb && Array.isArray(nb.cells) ? nb.cells : []).map((cell, n) => ({ cell, n })).filter((x) => x.cell && x.cell.cell_type === 'code');
      cells.forEach(({ cell, n }) => {
        const src = [].concat(cell.source || []).join('').replace(/^\s*[!%].*$/gm, (l) => `# ${l}`);
        const inner = scan(`${rel}.py`, src);
        // Solo amenazas: un eval en un notebook de análisis no es una vulnerabilidad de un servicio.
        for (const f of inner.threats) {
          if (RULES.has(f.rule) && RULES.get(f.rule).ext.test(rel)) continue; // ya lo encuentra el análisis del .ipynb
          out.threats.push({ ...f, file: rel, line: null, snippet: f.snippet ? `[celda ${n + 1}] ${f.snippet}` : `celda ${n + 1}` });
        }
      });
    }
  }

  // 17. Enlaces simbólicos hacia .git y submódulos con trucos en la ruta o la URL
  for (const s of parseGitmodules(root)) {
    if (/^-/.test(s.url) || /^-/.test(s.path) || s.path.split('/').includes('..') || /(^|\/)\.git(\/|$)/i.test(s.path)) T({ rule: 'submodule-trick', severity: 'critical', title: 'Submódulo con una ruta o URL manipulada', description: `El submódulo "${s.name}" usa ${/^-/.test(s.url) || /^-/.test(s.path) ? 'una URL o ruta que empieza por "-" (git la puede tomar como opción)' : 'una ruta que sale de su carpeta o entra en .git'}. Es el patrón de varios fallos de git que ejecutan código al clonar con --recursive (CVE-2017-1000117, CVE-2018-11235).`, file: '.gitmodules', snippet: snip(`${s.path} = ${s.url}`) });
  }
}

// Enlaces que apuntan dentro de .git (los que salen del repo ya los marca el análisis base).
function gitSymlinks(root, symlinks, out) {
  const git = path.join(realpath(root), '.git');
  for (const s of symlinks) {
    try {
      const target = fs.readlinkSync(path.join(root, s));
      let resolved;
      try { resolved = realpath(path.join(root, s)); } catch { resolved = path.resolve(realpath(path.dirname(path.join(root, s))), target); }
      if (resolved === git || resolved.startsWith(git + path.sep) || /(^|\/)\.git(\/|$)/i.test(target)) out.threats.push({ kind: 'threat', rule: 'symlink-git', severity: 'high', title: 'Enlace simbólico que apunta dentro de .git', description: `${s} apunta a ${target}. Sirve para que una herramienta escriba hooks o configuración de git sin darte cuenta.`, file: s, line: null });
    } catch { /* nada */ }
  }
}

// Ficheros de configuración JSON con comandos: devcontainer, VS Code y agentes de IA.
function configChecks(root, files, out) {
  const T = (o) => out.threats.push({ kind: 'threat', line: null, ...o });
  for (const rel of files) {
    if (/(^|\/)node_modules\//.test(rel)) continue;
    if (/^(\.devcontainer\/.*|\.devcontainer)\.json$/.test(rel) || /^\.devcontainer\/.+\.json$/.test(rel)) {
      const c = read(root, rel) || '';
      const j = jsonish(c);
      if (!j) continue;
      const keys = ['initializeCommand', 'onCreateCommand', 'updateContentCommand', 'postCreateCommand', 'postStartCommand', 'postAttachCommand'].filter((k) => j[k]);
      if (keys.length) {
        const rank = (k) => (verdict(flat(j[k]).replace(/https?:\/\/\S+/g, '')) || /curl|wget|https?:|base64|eval/.test(flat(j[k])) ? 3 : k === 'initializeCommand' ? 2 : 1);
        const worst = keys.sort((a, b) => rank(b) - rank(a))[0];
        const r = rank(worst);
        T({ rule: 'devcontainer', severity: r === 3 ? 'high' : r === 2 ? 'medium' : 'low', title: 'Comando automático del devcontainer', description: `Se ejecuta al abrir el proyecto en un contenedor (${keys.join(', ')}).${keys.includes('initializeCommand') ? ' initializeCommand se ejecuta en tu máquina, no dentro del contenedor.' : ''}`, file: rel, line: lineOf(c, new RegExp(`"${worst}"`)), snippet: snip(`${worst}: ${flat(j[worst])}`) });
      }
      const args = flat(j.runArgs) + ' ' + flat(j.mounts);
      if (/--privileged|--pid[= ]host|--net(work)?[= ]host|source=\/,|-v\s*\/:|\$\{localEnv:HOME\}|\$\{localEnv:USERPROFILE\}|docker\.sock/.test(args) || j.privileged === true) T({ rule: 'devcontainer-host', severity: 'medium', title: 'El devcontainer accede a tu máquina', description: 'Arranca con privilegios o monta tu carpeta personal, la raíz o el socket de Docker: lo que corra dentro puede tocar tu sistema.', file: rel, snippet: snip(args.trim()) });
      const feat = Object.keys(j.features || {}).find((f) => !/^ghcr\.io\/devcontainers(-contrib|-extra)?\//.test(f));
      if (feat) T({ rule: 'devcontainer-feature', severity: 'low', title: 'Feature de devcontainer de terceros', description: `${feat} se descarga y ejecuta como root al construir el contenedor.`, file: rel });
    }

    const ws = /\.code-workspace$/.test(rel);
    if (ws || /^\.vscode\/(settings|tasks)\.json$/.test(rel)) {
      const c = read(root, rel) || '';
      const j = jsonish(c) || {};
      const settings = ws ? j.settings || {} : /settings/.test(rel) ? j : {};
      const tasks = ws ? (j.tasks || {}).tasks || [] : /tasks/.test(rel) ? j.tasks || [] : [];
      if (ws) {
        const t = tasks.find((x) => x && x.runOptions && x.runOptions.runOn === 'folderOpen');
        if (t) T({ rule: 'vscode-autorun', severity: 'critical', title: 'Tarea de VS Code que se ejecuta al abrir el workspace', description: 'Abrir este .code-workspace (si confías en él) ejecuta el comando automáticamente.', file: rel, snippet: snip(flat(t.command) + ' ' + flat(t.args)) });
        const m = Object.keys(settings).find((k) => /^(python\.defaultInterpreterPath|python\.pythonPath|eslint\.runtime|typescript\.tsdk|git\.path|terminal\.integrated\.(shell|profiles|env|shellArgs|automationProfile)|php\.validate\.executablePath|go\.alternateTools|rust-analyzer\.server\.path)/.test(k));
        if (m) T({ rule: 'vscode-exec-setting', severity: 'medium', title: 'Ajuste de VS Code que apunta a un ejecutable', description: 'Si confías en el workspace, VS Code o sus extensiones ejecutarán el programa indicado en este ajuste.', file: rel, snippet: snip(`${m}: ${flat(settings[m])}`) });
      }
      const more = Object.keys(settings).find((k) => /^(jest\.jestCommandLine|cmake\.cmakePath|clangd\.path|java\.jdt\.ls\.vmargs|deno\.path|rubyLsp\.\w+Path|omnisharp\.path|docker\.dockerPath|terminal\.integrated\.automationProfile[\w.]*)$/.test(k));
      if (!ws && more) T({ rule: 'vscode-exec-setting', severity: 'medium', title: 'Ajuste de VS Code que apunta a un ejecutable', description: 'Si confías en la carpeta, la extensión ejecutará lo que indica este ajuste.', file: rel, snippet: snip(`${more}: ${flat(settings[more])}`) });
      const yolo = Object.keys(settings).find((k) => /^(chat\.tools\.autoApprove|chat\.agent\.autoApprove|github\.copilot\.chat\.agent\.autoApprove|chat\.tools\.global\.autoApprove)$/.test(k) && settings[k] === true);
      if (yolo) T({ rule: 'ai-autoapprove', severity: 'high', title: 'El repo activa la aprobación automática del agente de IA', description: `${yolo}: true deja que Copilot u otro agente ejecute comandos sin preguntarte. Combinado con una inyección de instrucciones, el repo controla tu terminal (CVE-2025-53773).`, file: rel, line: lineOf(c, new RegExp(yolo.replace(/\./g, '\\.'))) });
    }

    if (/(^|\/)\.claude\/settings(\.local)?\.json$/.test(rel)) {
      const c = read(root, rel) || '';
      const j = jsonish(c) || {};
      const p = j.permissions || {};
      const bad = [];
      if (/bypassPermissions/.test(flat(p.defaultMode))) bad.push('quita todas las confirmaciones (bypassPermissions)');
      if ((p.allow || []).some((x) => /^Bash(\(\*?\))?$/.test(String(x)))) bad.push('permite cualquier comando de terminal sin preguntar');
      if (j.enableAllProjectMcpServers === true) bad.push('arranca todos los servidores MCP del repo sin preguntar');
      const env = Object.keys(j.env || {}).filter((k) => /BASE_URL|API_URL|_PROXY$|^NODE_OPTIONS$/.test(k));
      if (env.length) bad.push(`cambia ${env.join(', ')} (tu clave de API y tus conversaciones irían a otro servidor)`);
      if (j.apiKeyHelper) bad.push('ejecuta un script para obtener la clave de API (apiKeyHelper)');
      if (j.statusLine && j.statusLine.command) bad.push('ejecuta un comando para la barra de estado');
      // Permisos preaprobados: un intérprete con cualquier argumento deja ejecutar cualquier código;
      // un script concreto del repo es más acotado, pero también corre sin preguntarte.
      const allow = (p.allow || []).map(String);
      const INTERP = /^Bash\(\s*(python3?|py|node|bun|bunx|deno|npx|npm|pnpm|yarn|sh|bash|zsh|pwsh|powershell|ruby|perl|php|curl|wget|make|go|cargo|uv|pip3?)\s*(:?\s*\*)?\s*\)$/i;
      const wide = allow.filter((x) => INTERP.test(x));
      if (wide.length) bad.push(`deja ejecutar sin preguntar cualquier cosa con ${wide.slice(0, 4).map((x) => x.replace(/^Bash\(\s*|\s*(:?\s*\*)?\s*\)$/g, '')).join(', ')}`);
      const scripts = allow.filter((x) => !INTERP.test(x) && /^Bash\(\s*((python3?|py|node|bun|deno|ruby|perl|php|sh|bash|pwsh)\s+(run\s+)?|npm\s+run\s+|pnpm\s+|yarn\s+|\.\/|make\s)/i.test(x));
      if (bad.length) T({ rule: 'ai-agent-config', severity: 'high', title: 'Configuración de agente de IA peligrosa en el repo', description: `Si abres el repo con Claude Code, esta configuración del proyecto ${bad.join('; ')}.`, file: rel });
      else if (scripts.length) T({ rule: 'ai-agent-config', severity: 'medium', title: 'El repo preaprueba que el agente de IA ejecute sus scripts', description: `Si abres el repo con Claude Code y confías en la carpeta, el agente podrá ejecutar sin preguntarte ${scripts.length} comando${scripts.length === 1 ? '' : 's'} del repo (${scripts.slice(0, 3).map((x) => x.replace(/^Bash\(|\)$/g, '')).join('; ')}${scripts.length > 3 ? '…' : ''}). No es malicioso por sí mismo, pero ese código corre en tu máquina sin confirmación: revísalo antes.`, file: rel });
    }
  }
}

module.exports = { surfaceChecks, gitSymlinks, configChecks, pickleGlobals, dangerousGlobals };
