'use strict';
// Más allá del repo: lo que no está en el código que descargas pero te afecta igual.
// - El paquete publicado en npm o PyPI con el nombre del proyecto. Es lo que instala
//   `npm install` o `pip install`, y no tiene por qué coincidir con GitHub: un atacante
//   con acceso al registro puede publicar código que nunca pasó por el repo.
// - Vulnerabilidades conocidas del propio proyecto: OSV.dev por el commit analizado y por
//   el nombre y la versión de su paquete.
// Solo se descargan y leen ficheros, nunca se ejecutan. Si algo no responde, la cobertura
// lo dice y el análisis sigue.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const { osvDetails, advisory, sevFromOsv } = require('./deps');
const { cachedFetch } = require('./netcache');

const MAX_DOWNLOAD = 25 * 1024 * 1024;
const MAX_UNPACKED = 80 * 1024 * 1024;
const MAX_FILE = 1.5 * 1024 * 1024;
const MAX_FINDINGS = 40;
const SEV_ORDER = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

async function getJson(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`${new URL(url).host} ${r.status}`);
  return r.json();
}

async function getBytes(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(60000) });
  if (!r.ok) throw new Error(`${new URL(url).host} ${r.status}`);
  if (Number(r.headers.get('content-length')) > MAX_DOWNLOAD) throw new Error('el paquete es demasiado grande');
  // Se lee por trozos y se corta al pasar del límite, aunque el servidor no diga el tamaño.
  const parts = [];
  let size = 0;
  const reader = r.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.length;
    if (size > MAX_DOWNLOAD) { reader.cancel().catch(() => {}); throw new Error('el paquete es demasiado grande'); }
    parts.push(Buffer.from(value));
  }
  return Buffer.concat(parts);
}

// Lee un .tar.gz en memoria: solo ficheros normales, sin enlaces ni rutas que salgan fuera.
function untar(gz) {
  const tar = zlib.gunzipSync(gz, { maxOutputLength: MAX_UNPACKED });
  const files = new Map();
  let longName = null;
  for (let o = 0; o + 512 <= tar.length;) {
    const h = tar.subarray(o, o + 512);
    if (h.every((b) => b === 0)) break;
    const str = (a, b) => h.toString('utf8', a, b).replace(/\0.*$/s, '');
    const size = parseInt(str(124, 136).trim() || '0', 8) || 0;
    const type = String.fromCharCode(h[156] || 48);
    const prefix = h.toString('utf8', 257, 263).startsWith('ustar') ? str(345, 500) : '';
    let name = longName || (prefix ? `${prefix}/${str(0, 100)}` : str(0, 100));
    longName = null;
    const body = tar.subarray(o + 512, o + 512 + size);
    o += 512 + Math.ceil(size / 512) * 512;
    if (type === 'L') { longName = body.toString('utf8').replace(/\0.*$/s, ''); continue; }
    if (type === 'x') { const m = body.toString('utf8').match(/\d+ path=([^\n]*)\n/); if (m) longName = m[1]; continue; }
    if (type !== '0' && type !== '\0' && type !== '7') continue;
    name = name.replace(/\\/g, '/');
    if (name.split('/').includes('..') || name.startsWith('/')) continue;
    files.set(name, body);
  }
  return files;
}

const stripTop = (files) => new Map([...files].map(([k, v]) => [k.split('/').slice(1).join('/'), v]).filter(([k]) => k));
const readRepo = (root, rel) => {
  const abs = path.resolve(root, rel);
  if (!abs.startsWith(root + path.sep)) return null;
  try { return fs.readFileSync(abs); } catch { return null; }
};
const esc = (x) => String(x).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const repoUrlMatches = (urls, ref) => urls.some((u) => new RegExp(`github\\.com[/:]${esc(ref.owner)}/${esc(ref.repo)}(\\.git)?/?($|[#?/])`, 'i').test(String(u || '')));
const isText = (b) => b.length <= MAX_FILE && !b.subarray(0, 8000).includes(0);

// Pasa las reglas sobre los ficheros del paquete que no son idénticos a los del repo.
function scanDifferent(pkgFiles, root, label, scan, filter) {
  const threats = [];
  const extraFiles = [];
  for (const [rel, buf] of pkgFiles) {
    if (!filter(rel)) continue;
    const mine = readRepo(root, rel);
    if (mine && mine.equals(buf)) continue;
    if (!mine) extraFiles.push(rel);
    if (!isText(buf)) continue;
    const out = scan(rel, buf.toString('utf8'));
    for (const t of out.threats) {
      if (SEV_ORDER[t.severity] < SEV_ORDER.medium) continue;
      threats.push({ ...t, file: `${label}/${rel}`, published: true, title: `${t.title} (en el paquete publicado${mine ? ', distinto de GitHub' : ', no está en GitHub'})` });
    }
  }
  return { threats: threats.slice(0, MAX_FINDINGS), extraFiles };
}

// ---------- npm ----------
async function npmPublished(root, ref, scan) {
  let pj;
  try { pj = JSON.parse(readRepo(root, 'package.json')); } catch { return null; }
  if (!pj || !pj.name || pj.private) return null;
  const meta = await getJson(`https://registry.npmjs.org/${pj.name.replace('/', '%2f')}/latest`);
  if (!meta) return { coverage: { status: 'ok', detail: `«${pj.name}» no está publicado en npm` } };
  const repoField = typeof meta.repository === 'string' ? meta.repository : meta.repository && meta.repository.url;
  if (!repoUrlMatches([repoField, meta.homepage, meta.bugs && meta.bugs.url], ref)) {
    return { coverage: { status: 'ok', detail: `el paquete «${pj.name}» de npm no enlaza a este repo; no se compara` }, pkg: { name: pj.name, version: pj.version } };
  }
  const tarball = meta.dist && meta.dist.tarball;
  if (!/^https:\/\/registry\.npmjs\.org\//.test(String(tarball))) throw new Error('tarball de npm inesperado');
  const files = stripTop(untar(await getBytes(tarball)));
  const label = `npm:${meta.name}@${meta.version}`;
  const threats = [];
  // Scripts que npm ejecuta al instalar el paquete publicado y que no son los de GitHub
  let pub = {};
  try { pub = JSON.parse(files.get('package.json')).scripts || {}; } catch { /* sin package.json */ }
  const mine = pj.scripts || {};
  for (const hook of ['preinstall', 'install', 'postinstall']) {
    if (!pub[hook] || pub[hook] === mine[hook]) continue;
    threats.push({
      kind: 'threat', rule: 'published-diff', severity: 'high', file: `${label}/package.json`, line: null,
      title: `El paquete de npm ejecuta "${hook}" distinto del de GitHub`,
      description: `npm install ${meta.name} ejecuta al instalar algo que no coincide con el package.json del repo${mine[hook] ? ` (en GitHub: "${mine[hook]}")` : ' (en GitHub no existe)'}. Es la técnica de los paquetes secuestrados: el código malicioso solo está en el registro.`,
      snippet: `"${hook}": "${String(pub[hook]).slice(0, 200)}"`,
    });
  }
  if (files.has('binding.gyp') && !readRepo(root, 'binding.gyp') && !pub.install) {
    threats.push({ kind: 'threat', rule: 'published-diff', severity: 'medium', file: `${label}/binding.gyp`, line: null, title: 'El paquete de npm compila código nativo que no está en GitHub', description: 'binding.gyp hace que npm ejecute node-gyp rebuild al instalar, y el repo no lo tiene.' });
  }
  const diff = scanDifferent(files, root, label, scan, (rel) => /\.(c|m)?js$|\.json$|\.sh$|\.node$/i.test(rel));
  threats.push(...diff.threats);
  if (diff.extraFiles.length) threats.push(extraFilesInfo(label, diff.extraFiles, 'npm'));
  return { threats, coverage: { status: 'ok', detail: `${label}: ${files.size} ficheros comparados con el repo` }, pkg: { name: meta.name, version: meta.version, ecosystem: 'npm' } };
}

function extraFilesInfo(label, list, registry) {
  return {
    kind: 'threat', rule: 'published-diff', severity: 'info', file: label, line: null,
    title: `El paquete de ${registry} trae ${list.length} fichero${list.length === 1 ? '' : 's'} que no está${list.length === 1 ? '' : 'n'} en GitHub`,
    description: 'Suele ser código compilado (dist/, build/) o generado al publicar. Si no es el caso, conviene saber de dónde sale.',
    snippet: list.slice(0, 10).join(', ') + (list.length > 10 ? '…' : ''),
  };
}

// ---------- PyPI ----------
function pythonName(root) {
  const txt = (f) => { const b = readRepo(root, f); return b ? b.toString('utf8') : ''; };
  const pyproject = txt('pyproject.toml');
  const sect = (name) => { const m = pyproject.match(new RegExp(`^\\[${name.replace('.', '\\.')}\\]\\s*$([\\s\\S]*?)(?=^\\[|(?![\\s\\S]))`, 'm')); return m ? m[1] : ''; };
  const fromToml = (s) => (s.match(/^name\s*=\s*["']([A-Za-z0-9._-]+)["']/m) || [])[1];
  return fromToml(sect('project')) || fromToml(sect('tool.poetry'))
    || (txt('setup.cfg').match(/^name\s*=\s*([A-Za-z0-9._-]+)\s*$/m) || [])[1]
    || (txt('setup.py').match(/\bname\s*=\s*["']([A-Za-z0-9._-]+)["']/) || [])[1] || null;
}

async function pypiPublished(root, ref, scan) {
  const name = pythonName(root);
  if (!name) return null;
  const meta = await getJson(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
  if (!meta) return { coverage: { status: 'ok', detail: `«${name}» no está publicado en PyPI` } };
  const info = meta.info || {};
  if (!repoUrlMatches([info.home_page, info.download_url, ...Object.values(info.project_urls || {})], ref)) {
    return { coverage: { status: 'ok', detail: `el paquete «${name}» de PyPI no enlaza a este repo; no se compara` } };
  }
  const label = `pypi:${info.name}@${info.version}`;
  const sdist = (meta.urls || []).find((u) => u.packagetype === 'sdist' && /\.tar\.gz$/.test(u.url));
  if (!sdist) return { coverage: { status: 'partial', detail: `${label}: sin código fuente (sdist) publicado; las wheels no se comparan` }, pkg: { name: info.name, version: info.version, ecosystem: 'PyPI' } };
  if (!/^https:\/\/files\.pythonhosted\.org\//.test(sdist.url)) throw new Error('sdist de PyPI inesperado');
  const files = stripTop(untar(await getBytes(sdist.url)));
  const threats = [];
  // setup.py se ejecuta al instalar desde el código fuente
  if (files.has('setup.py')) {
    const mine = readRepo(root, 'setup.py');
    if (!mine) threats.push({ kind: 'threat', rule: 'published-diff', severity: 'low', file: `${label}/setup.py`, line: null, title: 'El paquete de PyPI trae un setup.py que no está en GitHub', description: 'pip lo ejecuta al instalar desde el código fuente. Algunas herramientas de empaquetado lo generan solas; revisa qué hace.' });
  }
  for (const rel of files.keys()) {
    if (/\.pth$/.test(rel) && !readRepo(root, rel)) threats.push({ kind: 'threat', rule: 'published-diff', severity: 'high', file: `${label}/${rel}`, line: null, title: 'El paquete de PyPI trae un fichero .pth que no está en GitHub', description: 'Python ejecuta los .pth al arrancar, en cualquier programa del entorno donde se instale.' });
  }
  const diff = scanDifferent(files, root, label, scan, (rel) => /\.(py|pth|sh|cfg|toml)$/i.test(rel) && rel !== 'PKG-INFO');
  threats.push(...diff.threats);
  const extra = diff.extraFiles.filter((f) => !/\.egg-info\//.test(f));
  if (extra.length) threats.push(extraFilesInfo(label, extra, 'PyPI'));
  return { threats, coverage: { status: 'ok', detail: `${label}: ${files.size} ficheros comparados con el repo` }, pkg: { name: info.name, version: info.version, ecosystem: 'PyPI' } };
}

// ---------- Vulnerabilidades conocidas del propio proyecto ----------
async function ownVulns(ref, pkgs) {
  const queries = [];
  if (ref.commit && /^[0-9a-f]{40}$/.test(ref.commit)) queries.push({ q: { commit: ref.commit }, what: `el commit ${ref.commit.slice(0, 10)}` });
  for (const p of pkgs) if (p && p.ecosystem && p.version) queries.push({ q: { package: { name: p.name, ecosystem: p.ecosystem }, version: p.version }, what: `${p.name}@${p.version} (${p.ecosystem})`, pkg: p });
  if (!queries.length) return { vulns: [], detail: null };
  const r = await cachedFetch('https://api.osv.dev/v1/querybatch', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ queries: queries.map((x) => x.q) }), signal: AbortSignal.timeout(20000) });
  if (!r.ok) throw new Error(`OSV ${r.status}`);
  const j = await r.json();
  const vulns = [];
  const hits = (j.results || []).map((res, i) => ({ ...queries[i], ids: (res.vulns || []).map((v) => v.id) })).filter((h) => h.ids.length);
  const details = await osvDetails(hits.flatMap((h) => h.ids));
  for (const h of hits) {
    const mal = h.ids.filter((id) => id.startsWith('MAL-'));
    const ids = h.ids.filter((id) => !id.startsWith('MAL-'));
    if (mal.length) vulns.push({ kind: 'threat', rule: 'malicious-package', severity: 'critical', title: `El propio paquete está catalogado como malware: ${h.what}`, description: `OSV.dev lo tiene como malicioso (${mal.join(', ')}).`, file: null, line: null });
    if (!ids.length) continue;
    const ds = ids.map((id) => details.get(id)).filter(Boolean);
    const worst = ds.reduce((w, d) => (SEV_ORDER[sevFromOsv(d)] > SEV_ORDER[w] ? sevFromOsv(d) : w), 'low');
    vulns.push({
      kind: 'vuln', rule: 'repo-vuln', severity: ds.length ? worst : 'medium', file: null, line: null,
      title: `El propio proyecto tiene ${ids.length} vulnerabilidad${ids.length > 1 ? 'es' : ''} conocida${ids.length > 1 ? 's' : ''} en ${h.what}`,
      description: ds.slice(0, 3).map((d) => `${d.id}: ${d.summary || 'sin resumen'}`).join(' · ') || ids.join(', '),
      advisories: ids.slice(0, 10), osv: ds.slice(0, 10).map((d) => advisory(d, h.pkg ? h.pkg.name : '')),
      fixable: false, notFixableReason: 'Es del propio proyecto: comprueba si hay una versión o un commit posterior que lo corrija.',
    });
  }
  return { vulns, detail: `${queries.map((x) => x.what).join(' y ')} consultados en OSV.dev` };
}

// Ejecuta todo y devuelve hallazgos y cobertura. `scan(rel, texto)` pasa las reglas propias.
async function beyondRepo(root, ref, scan) {
  if (!ref || !ref.owner || process.env.OMINOUS_OFFLINE === '1') return { vulns: [], threats: [], coverage: [] };
  const out = { vulns: [], threats: [], coverage: [] };
  const pkgs = [];
  for (const [label, fn] of [['Paquete publicado en npm', npmPublished], ['Paquete publicado en PyPI', pypiPublished]]) {
    try {
      const r = await fn(root, ref, scan);
      if (!r) continue;
      out.threats.push(...(r.threats || []));
      if (r.pkg && r.pkg.ecosystem) pkgs.push(r.pkg);
      out.coverage.push({ label, ...r.coverage });
    } catch (e) {
      out.coverage.push({ label, status: 'skip', detail: `no se pudo comparar (${e.message})` });
    }
  }
  try {
    const own = await ownVulns(ref, pkgs);
    for (const f of own.vulns) (f.kind === 'vuln' ? out.vulns : out.threats).push(f);
    if (own.detail) out.coverage.push({ label: 'Vulnerabilidades del propio proyecto (OSV.dev)', status: 'ok', detail: own.detail });
  } catch (e) {
    out.coverage.push({ label: 'Vulnerabilidades del propio proyecto (OSV.dev)', status: 'skip', detail: `no se pudo consultar (${e.message})` });
  }
  return out;
}

module.exports = { beyondRepo, untar, pythonName, repoUrlMatches };
