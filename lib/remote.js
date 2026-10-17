'use strict';
// Scripts remotos que el repo manda ejecutar (curl … | sh, irm … | iex, bajar y luego sh):
// se descargan como datos, nunca se ejecutan, y se describe qué hacen. Solo en el servidor
// local: el navegador no puede pedir a cualquier dominio (CSP y CORS).
//
// La descarga está acotada: solo https, sin cookies ni credenciales, como mucho 1 MB y
// 5 redirecciones, y nunca hacia direcciones de la red local ni del propio equipo (la
// comprobación se hace al conectar, así que un DNS que cambia de respuesta no la salta).
// Se pide con el User-Agent de curl porque así lo pediría quien siga las instrucciones:
// hay servidores que a un navegador le dan una página web y a curl el script.
//   OMINOUS_REMOTE=0   no descargar scripts remotos
const crypto = require('crypto');
// Módulos de red de Node: se cargan al descargar, que solo ocurre en el servidor. La versión
// web incluye este fichero (por findRemoteRuns y describe) pero nunca descarga.
const node = (m) => require(m); // eslint-disable-line global-require
const net = { isIP: (s) => node('net').isIP(s), isIPv4: (s) => node('net').isIPv4(s) };

const MAX_BYTES = 1024 * 1024;
const MAX_SCRIPTS = 6;
const TIMEOUT = 15000;
const UA = 'curl/8.5.0';

// ---------- Dónde se manda ejecutar algo remoto ----------
// Cada patrón devuelve la URL del script que acaba ejecutándose.
const URL_RE = /https?:\/\/[^\s'"`|;)<>\]]+/;
const PIPE_RE = /\b(curl|wget|fetch)\b[^\n|;]*?(https?:\/\/[^\s'"`|;)<>\]]+)[^\n|;]*\|\s*(sudo\s+(-\S+\s+)*)?((ba|z|da|k|fi)?sh|python[23]?(\.\d+)?|node|perl|ruby|php)\b/i;
const IEX_RE = /\b(irm|iwr|Invoke-RestMethod|Invoke-WebRequest)\b[^\n|]*?(https?:\/\/[^\s'"`|;)<>\]]+|\b[a-z0-9.-]+\.[a-z]{2,}\/[^\s'"`|;)<>\]]*)[^\n|]*\|\s*(iex|Invoke-Expression)\b/i;
// La URL y el fichero de salida, en cualquier orden (curl URL -o f, curl -o f URL, wget -O f URL)
const SAVE_RE = /\b(curl|wget)\b[^\n]*?(?:(https?:\/\/[^\s'"`|;)<>\]]+)[^\n]*?(?:\s-o\s*|\s--output[=\s]|\s-O\s+)\s*["']?([^\s"'|;&]+)|(?:\s-o\s*|\s--output[=\s]|\s-O\s+)\s*["']?([^\s"'|;&]+)["']?[^\n]*?(https?:\/\/[^\s'"`|;)<>\]]+))/i;

// Busca en un fichero de texto las órdenes que ejecutan un script remoto. Devuelve
// [{ url, line, kind, snippet }]. kind: pipe | iex | download-run.
function findRemoteRuns(content) {
  const lines = String(content).split('\n');
  const out = [];
  for (let i = 0; i < lines.length && out.length < 20; i++) {
    const l = lines[i];
    if (l.length > 4000) continue;
    let m;
    if ((m = l.match(PIPE_RE))) out.push({ url: m[2], line: i + 1, kind: 'pipe', snippet: l.trim().slice(0, 300) });
    else if ((m = l.match(IEX_RE))) out.push({ url: /^https?:/i.test(m[2]) ? m[2] : `https://${m[2]}`, line: i + 1, kind: 'iex', snippet: l.trim().slice(0, 300) });
    else if ((m = l.match(SAVE_RE))) {
      // Descargado a un fichero que se ejecuta en las líneas siguientes (sh fichero, bash fichero, . fichero)
      const url = m[2] || m[5];
      const saved = m[3] || m[4];
      const file = saved.replace(/^.*\//, '');
      // Solo scripts (o ficheros sin extensión): un .spec, .tar.gz o .json descargado no se ejecuta así
      if (!file || file.length > 120 || !/(\.(sh|bash|zsh|ps1|py|pl|rb|js|mjs|cjs|php|bat|cmd)|^[^.]+)$/i.test(file)) continue;
      const esc = file.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      // Se ejecuta si se lanza con un intérprete o como ejecutable (./fichero, /ruta/fichero) al
      // principio de una orden; nombrarlo en otra orden (rpmbuild x.spec, tar xf) no cuenta.
      const run = new RegExp(`(^|[;&|(]\\s*|\\s(&&|\\|\\|)\\s*)(sudo\\s+(-\\S+\\s+)*)?(((ba|z|da|k)?sh|source|\\.|python[23]?|node|perl|ruby|php|pwsh|powershell(\\.exe)?(\\s+-\\S+)*\\s+-File)\\s+(-\\S+\\s+)*["']?\\S*${esc}\\b|["']?(\\.|~|\\$\\w+|\\$\\{\\w+\\})?\\/\\S*${esc}["']?(\\s|$))|chmod\\s+\\+x\\s+\\S*${esc}[^\\n]*(&&|;)\\s*\\S*${esc}`);
      for (let j = i; j < Math.min(lines.length, i + 6); j++) {
        const after = j === i ? l.slice(m.index + m[0].length) : lines[j];
        if (run.test(after)) { out.push({ url, line: i + 1, kind: 'download-run', snippet: l.trim().slice(0, 300) }); break; }
      }
    }
  }
  return out;
}

// ---------- Descarga acotada ----------
// Con net.BlockList y no comparando texto: una IPv6 se puede escribir de muchas formas
// (::ffff:7f00:1 es 127.0.0.1) y todas tienen que caer en el mismo rango.
// Dos listas: BlockList compara una IPv4 también contra los rangos IPv6 mapeados.
let blocked = null;
function blockLists() {
  if (blocked) return blocked;
  const { BlockList } = node('net');
  blocked = { v4: new BlockList(), v6: new BlockList() };
  for (const [a, p] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.168.0.0', 16], ['198.18.0.0', 15], ['224.0.0.0', 3]]) blocked.v4.addSubnet(a, p, 'ipv4');
  // ::/96 (IPv4 compatible, incluye :: y ::1), ::ffff:0:0/96 (IPv4 mapeada), 64:ff9b::/96 (NAT64),
  // 2002::/16 (6to4), fc00::/7 (privadas), fe80::/10 y fec0::/10 (enlace y sitio), ff00::/8 (multicast)
  for (const [a, p] of [['::', 96], ['::ffff:0:0', 96], ['64:ff9b::', 96], ['2002::', 16], ['fc00::', 7], ['fe80::', 10], ['fec0::', 10], ['ff00::', 8]]) blocked.v6.addSubnet(a, p, 'ipv6');
  return blocked;
}
function privateAddress(ip) {
  const s = String(ip).replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  if (net.isIPv4(s)) return blockLists().v4.check(s, 'ipv4');
  if (node('net').isIPv6(s)) return blockLists().v6.check(s, 'ipv6');
  return true; // lo que no es una IP válida no se deja pasar
}

// lookup que rechaza la red local en el momento de conectar
function safeLookup(host, opts, cb) {
  node('dns').lookup(host, { ...opts, all: true }, (err, list) => {
    if (err) return cb(err);
    const ok = list.filter((x) => !privateAddress(x.address));
    if (!ok.length) return cb(Object.assign(new Error('apunta a la red local'), { code: 'EPRIVATE' }));
    if (opts && opts.all) return cb(null, ok);
    cb(null, ok[0].address, ok[0].family);
  });
}

function get(url, hops = 0) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch { return reject(new Error('URL no válida')); }
    if (u.protocol !== 'https:') return reject(new Error('solo se descargan scripts por https'));
    if (u.username || u.password) return reject(new Error('URL con credenciales'));
    // Solo el puerto de HTTPS, también tras una redirección: un repo no puede mandar la descarga a
    // otro servicio (un panel en :8443, una API interna en :9200) aunque la dirección sea pública.
    if (u.port && u.port !== '443') return reject(new Error('solo se descargan scripts del puerto 443'));
    if (net.isIP(u.hostname.replace(/^\[|\]$/g, '')) && privateAddress(u.hostname.replace(/^\[|\]$/g, ''))) return reject(new Error('apunta a la red local'));
    // Con proxy de salida (la pasarela de Docker), es él quien rechaza las direcciones locales:
    // aquí la conexión va al proxy, que vive en una IP privada de la red de Docker.
    const viaProxy = !!(process.env.HTTPS_PROXY || process.env.https_proxy) && process.env.NODE_USE_ENV_PROXY === '1';
    const req = node('https').get(u, { ...(viaProxy ? {} : { lookup: safeLookup }), headers: { 'user-agent': UA, accept: '*/*' }, timeout: TIMEOUT }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        res.resume();
        if (hops >= 5) return reject(new Error('demasiadas redirecciones'));
        return resolve(get(new URL(res.headers.location, u).href, hops + 1).then((r) => ({ ...r, redirects: [u.href, ...r.redirects] })));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode}`)); }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_BYTES) { req.destroy(); reject(new Error('más de 1 MB')); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve({ body: Buffer.concat(chunks), finalUrl: u.href, type: String(res.headers['content-type'] || ''), redirects: [] }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new Error('tiempo agotado')));
    req.on('error', reject);
  });
}

// ---------- Qué hace el script ----------
const BEHAVIOURS = [
  { id: 'verifies', good: true, re: /\b(sha256sum|sha512sum|shasum\s+-a|Get-FileHash|gpg\s+--verify|gpgv\b|minisign\b|cosign\s+verify|openssl\s+dgst|signify\s+-V)/i, text: 'comprueba el checksum o la firma de lo que descarga' },
  { id: 'sudo', re: /(^|[\s;&|(])sudo\s|\bdoas\s|Start-Process[^\n]*-Verb\s+RunAs/i, text: 'pide permisos de administrador (sudo)' },
  { id: 'profile', re: /\.(bashrc|bash_profile|zshrc|zprofile|profile)\b|config\.fish|\$PROFILE\b|HKCU:\\?\\?Environment|OpenSubKey\('Environment'|SetEnvironmentVariable\([^)]*['"]Path['"]/i, text: 'modifica tu PATH o tu perfil de shell (se queda al abrir terminales nuevas)' },
  { id: 'autostart', re: /\b(crontab|systemctl\s+(--user\s+)?enable|launchctl\s+load|LaunchAgents|LaunchDaemons|schtasks\b|CurrentVersion\\Run\b|\\Startup\\|\/etc\/rc\.local|\.config\/autostart)/i, text: 'se programa para arrancar solo (cron, servicio, tarea o inicio de sesión)' },
  { id: 'registry', re: /\b(New-ItemProperty|Set-ItemProperty|New-Item\s+-Path\s+['"]?HK|reg\s+add)\b/i, text: 'escribe en el registro de Windows' },
  // Borrar sus propios temporales es normal; esto es borrar /, ~, $HOME o una variable sin
  // comillas (con un espacio en la ruta, borraría otra cosa).
  { id: 'delete', re: /\brm\s+-[a-zA-Z]*[rR][a-zA-Z]*\s+((\/|~\/?|\$HOME\/?|"\$HOME"\/?)(\s|$|;|&)|\$\{?\w+\}?(\s|$|;|&|\/))/, text: 'borra carpetas enteras con una ruta muy amplia o sin entrecomillar' },
  { id: 'nested', re: /\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b|\|\s*(iex|Invoke-Expression)\b|\birm\b[^\n]*\|\s*iex/i, text: 'a su vez descarga y ejecuta otro script' },
  { id: 'obfuscated', bad: true, re: /base64\s+(-d|--decode)[^\n]*\|\s*(ba)?sh|FromBase64String|eval\s+["']?\$\((curl|wget|echo)|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20}|-EncodedCommand|-enc\s+[A-Za-z0-9+/=]{40}/i, text: 'ejecuta código ofuscado o codificado' },
  { id: 'exfil', bad: true, re: /\b(curl|wget)\b[^\n]*\s(-d|--data[\w-]*|-F|--form|-T|--upload-file)\s[^\n]*(\$\(|`|\$\{?(HOME|USER|AWS|GITHUB|TOKEN|SECRET)|\/etc\/passwd|\.ssh|\.aws|id_rsa)|Invoke-(RestMethod|WebRequest)[^\n]*-Method\s+Post[^\n]*(\$env:|Get-Content)/i, text: 'envía datos de tu equipo a un servidor' },
  { id: 'credentials', bad: true, re: /(~|\$HOME|\$env:USERPROFILE)[/\\]\.(ssh|aws|kube|docker|gnupg|npmrc|pypirc|git-credentials)|Login Data|keychain|Cookies\b|\.config\/gh\/hosts/i, text: 'lee ficheros con credenciales (SSH, nubes, navegador…)' },
  { id: 'disable-security', bad: true, re: /Set-MpPreference[^\n]*-Disable|Add-MpPreference[^\n]*-Exclusion|setenforce\s+0|ufw\s+disable|spctl\s+--master-disable|xattr\s+-[a-z]*d[a-z]*\s+com\.apple\.quarantine/i, text: 'desactiva protecciones del sistema (antivirus, SELinux, cortafuegos, Gatekeeper)' },
];

function kindOf(text, url) {
  const head = text.slice(0, 200);
  if (/^#!.*\b(pwsh|powershell)/.test(head) || /\.ps1(\?|$)/i.test(url)) return 'PowerShell';
  if (/^#!.*python/.test(head) || /\.py(\?|$)/i.test(url)) return 'Python';
  if (/^#!.*\b(ba|z|da)?sh\b/.test(head) || /\.sh(\?|$)/i.test(url)) return 'shell';
  if (/^\s*<(!doctype|html)/i.test(head)) return 'HTML';
  return 'texto';
}

// Dominios a los que se conecta: no cuentan los que solo salen en comentarios o en mensajes.
function hostsIn(text, own) {
  const hosts = new Set();
  const code = text.split('\n').filter((l) => !/^\s*(#|\/\/|REM\b|::)|\b(echo|printf|Write-(Output|Warning|Host|Error)|info|error|warn)\b/i.test(l)).join('\n');
  for (const m of code.matchAll(/https?:\/\/([a-z0-9.-]+\.[a-z]{2,})(?=[/:'"\s`)]|$)/gi)) hosts.add(m[1].toLowerCase());
  hosts.delete(own);
  return [...hosts].slice(0, 15);
}

// ¿La línea solo muestra un texto? (info "añade esto a tu .zshrc: echo … >> ~/.zshrc" no lo hace).
// Quitando las cadenas no puede quedar una redirección ni una sustitución: echo '…' >> ~/.zshrc
// sí lo escribe, y entre comillas dobles $( … ) y `…` sin escapar se ejecutan.
function onlyShown(l = '') {
  return /^\s*(echo|printf|info|warn(ing)?|error|log|say|msg|note|print|puts|Write-(Host|Output|Warning))\s/i.test(l)
    && !/[>|`]|\$\(/.test(l.replace(/"(?:\\.|[^"\\])*"|'[^']*'/g, (s) => (s[0] === '"' && /(?<!\\)(\$\(|`)/.test(s) ? s : '""')));
}

// Descarga y describe un script. scan(rel, text) pasa las reglas del analizador sobre él.
async function inspectRemote(url, scan) {
  const r = { url, ok: false };
  let got;
  try { got = await get(url); } catch (e) { r.error = e.message; return r; }
  const text = got.body.toString('utf8');
  const u = new URL(got.finalUrl);
  Object.assign(r, {
    ok: true, finalUrl: got.finalUrl, redirects: got.redirects, sha256: crypto.createHash('sha256').update(got.body).digest('hex'),
    bytes: got.body.length, lines: text.split('\n').length, kind: kindOf(text, got.finalUrl), hosts: hostsIn(text, u.hostname),
    behaviours: BEHAVIOURS.filter((b) => b.re.test(text)).map(({ id, text: t, good, bad }) => ({ id, text: t, good: !!good, bad: !!bad })),
  });
  const scanned = scan ? scan(`(remoto) ${u.hostname}${u.pathname}`, text) : { vulns: [], threats: [] };
  const lines = text.split('\n');
  r.threats = scanned.threats.filter((t) => ['critical', 'high'].includes(t.severity) && !['curl-pipe', 'ps-pipe-iex', 'download-run'].includes(t.rule) && !(t.line && onlyShown(lines[t.line - 1])))
    .slice(0, 8).map((t) => ({ rule: t.rule, severity: t.severity, title: t.title, line: t.line, snippet: t.snippet }));
  r.bad = r.behaviours.some((b) => b.bad) || r.threats.length > 0;
  r.html = r.kind === 'HTML';
  return r;
}

// Adónde lleva un enlace (acortadores): misma descarga acotada, solo interesa la dirección final.
async function resolveUrl(url) {
  const got = await get(url);
  return { finalUrl: got.finalUrl, redirects: got.redirects };
}

// Texto para el aviso: qué hace el script, en frases cortas.
function describe(r) {
  if (!r.ok) return `No se pudo descargar para revisarlo (${r.error}).`;
  if (r.html) return 'La dirección devuelve una página web, no un script: puede depender de quién lo pida.';
  const does = r.behaviours.filter((b) => !b.good).map((b) => b.text);
  const parts = [`Descargado y revisado sin ejecutarlo: ${r.kind}, ${r.lines} líneas, sha256 ${r.sha256.slice(0, 16)}….`];
  if (r.redirects.length) parts.push(`Redirige a ${r.finalUrl}.`);
  if (r.hosts.length) parts.push(`Se conecta a: ${r.hosts.join(', ')}.`);
  parts.push(r.behaviours.some((b) => b.id === 'verifies') ? 'Comprueba checksums o firmas de lo que baja.' : 'No comprueba checksums ni firmas de lo que baja.');
  if (does.length) parts.push(`Además: ${does.join('; ')}.`);
  if (r.threats.length) parts.push(`Dentro hay avisos graves: ${r.threats.map((t) => t.title).join('; ')}.`);
  parts.push('Lo que hay en esa dirección puede cambiar después de este análisis.');
  return parts.join(' ');
}

module.exports = { findRemoteRuns, inspectRemote, resolveUrl, onlyShown, describe, privateAddress, MAX_SCRIPTS, BEHAVIOURS };
