'use strict';
// git endurecido, compartido por la app (clon final en tu carpeta) y el contenedor de análisis.
// Sin hooks, sin submódulos, sin LFS, sin preguntas, sin los protocolos file:// ni ext::, y con
// un entorno mínimo: ni GITHUB_TOKEN ni ANTHROPIC_API_KEY llegan a sus procesos.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

const NO_HOOKS = path.join(os.tmpdir(), 'ominous-no-hooks-dir');
const GIT_SAFE = ['-c', `core.hooksPath=${NO_HOOKS}`, '-c', 'protocol.file.allow=never', '-c', 'protocol.ext.allow=never', '-c', 'submodule.recurse=false', '-c', 'core.fsmonitor=false'];
const GIT_ENV_KEEP = /^(PATH|HOME|LANG|LC_\w+|TZ|TMPDIR|TEMP|TMP|SYSTEMROOT|SystemRoot|WINDIR|COMSPEC|PATHEXT|USERPROFILE|HOMEDRIVE|HOMEPATH|APPDATA|LOCALAPPDATA|PROGRAMDATA|ProgramData|https?_proxy|HTTPS?_PROXY|no_proxy|NO_PROXY|SSL_CERT_FILE|SSL_CERT_DIR|GIT_SSL_CAINFO)$/;
const GIT_ENV = { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => GIT_ENV_KEEP.test(k))), GIT_TERMINAL_PROMPT: '0', GIT_LFS_SKIP_SMUDGE: '1', GIT_ASKPASS: 'echo' };

function git(args, opts = {}) {
  return new Promise((resolve, reject) => {
    execFile('git', [...GIT_SAFE, ...args], { env: GIT_ENV, timeout: opts.timeout || 180000, maxBuffer: 8 * 1024 * 1024, cwd: opts.cwd || os.tmpdir() }, (err, stdout, stderr) => {
      if (err) reject(new Error((stderr || err.message).trim().split('\n').slice(-2).join(' ')));
      else resolve(stdout.trim());
    });
  });
}

// Versiones de git con los fallos de clonado de 2025 corregidos (CVE-2025-48384 y otros):
// 2.43.7, 2.44.4, 2.45.4, 2.46.4, 2.47.3, 2.48.2, 2.49.1 y 2.50.1 en adelante.
const GIT_FIXED = { 43: 7, 44: 4, 45: 4, 46: 4, 47: 3, 48: 2, 49: 1, 50: 1 };
let gitVersion = null;
function gitPatched(v) {
  const m = String(v).match(/(\d{1,6})\.(\d{1,6})\.(\d{1,6})/);
  if (!m) return null;
  const [maj, min, patch] = m.slice(1).map(Number);
  if (maj !== 2) return maj > 2;
  if (min > 50) return true;
  if (min < 43) return false;
  return patch >= GIT_FIXED[min];
}
function gitVersionCoverage(extra) {
  if (gitVersion && gitPatched(gitVersion) === false) extra.coverage.push({ label: 'Tu versión de git', status: 'partial', detail: `${gitVersion} tiene fallos conocidos que ejecutan código al clonar con submódulos (CVE-2025-48384). La herramienta clona sin submódulos, pero actualiza git antes de usar --recursive.` });
}
// Al arrancar: mira la versión de git y avisa si tiene fallos conocidos
function checkGit() {
  return git(['--version']).then((v) => {
    gitVersion = v.replace(/^git version\s*/, '');
    if (gitPatched(gitVersion) === false) console.warn(`  ⚠ git ${gitVersion} tiene fallos conocidos al clonar con submódulos (CVE-2025-48384): actualízalo.\n`);
  }).catch(() => console.warn('  ⚠ No encuentro git: no se podrá analizar ni clonar.\n'));
}

// Clones temporales de análisis cortados (el contenedor se paró a medias): repos ajenos que no
// deben quedarse en disco. Solo lo que lleva más de una hora.
function cleanStaleTemp() {
  try {
    for (const d of fs.readdirSync(os.tmpdir())) {
      const p = path.join(os.tmpdir(), d);
      if (/^ominous-(?!cache$|no-hooks-dir$)/.test(d) && Date.now() - fs.statSync(p).mtimeMs > 60 * 60e3) fs.rmSync(p, { recursive: true, force: true });
    }
  } catch { /* sin carpeta temporal */ }
}

const msLeft = (until, cap = Infinity) => Math.max(1000, Math.min(cap, until - Date.now()));

module.exports = { git, GIT_SAFE, GIT_ENV, gitPatched, gitVersionCoverage, checkGit, cleanStaleTemp, msLeft };
