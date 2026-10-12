'use strict';
// Dependencias: vulnerabilidades conocidas (OSV.dev), dependencias desde URL y typosquatting.
// Ecosistemas: npm (package.json, package-lock, yarn.lock), PyPI (requirements, poetry.lock,
// Pipfile.lock), Go (go.mod), crates.io (Cargo.lock), RubyGems (Gemfile.lock),
// Packagist (composer.lock) y Maven (pom.xml, build.gradle).

const fs = require('fs');
const path = require('path');
const DATA = require('../data/popular.json'); // lo refresca cada semana scripts/update-data.js
const KEV = require('../data/kev.json'); // ídem: CVE que CISA sabe que se están explotando
const { transitiveNpm } = require('./depsdev');

// Objetivos habituales de typosquatting: los más descargados más una lista a mano de
// paquetes que el malware imita a menudo (carteras, Discord, automatización).
const HAND = {
  npm: ['express', 'react', 'react-dom', 'lodash', 'axios', 'chalk', 'commander', 'debug', 'request', 'moment', 'webpack', 'typescript', 'eslint', 'prettier', 'jquery', 'vue', 'next', 'electron', 'dotenv', 'colors', 'uuid', 'yargs', 'mongoose', 'socket.io', 'body-parser', 'cross-env', 'nodemon', 'jsonwebtoken', 'bcrypt', 'cors', 'discord.js', 'puppeteer', 'ethers', 'web3', 'crypto-js', 'node-fetch', 'babel-core', 'coffee-script', 'event-stream', 'rimraf', 'glob', 'minimist', 'semver', 'ws', 'sharp', 'tailwindcss', 'vite'],
  PyPI: ['requests', 'urllib3', 'numpy', 'pandas', 'django', 'flask', 'boto3', 'setuptools', 'pyyaml', 'cryptography', 'pillow', 'scipy', 'matplotlib', 'selenium', 'beautifulsoup4', 'colorama', 'pytest', 'tensorflow', 'torch', 'opencv-python', 'discord.py', 'python-dateutil', 'jinja2', 'paramiko', 'pycryptodome', 'web3', 'openai', 'httpx', 'aiohttp', 'fastapi', 'pydantic', 'tqdm', 'click', 'rich', 'termcolor', 'pygame', 'pyautogui', 'pynput'],
};

const norm = (eco, n) => (eco === 'PyPI' ? n.toLowerCase().replace(/[._]+/g, '-') : n.toLowerCase());
const POPULAR = Object.fromEntries(Object.keys(HAND).map((eco) => [eco, [...new Set([...HAND[eco], ...((DATA[eco] && DATA[eco].targets) || [])].map((n) => norm(eco, n)))]]));
// Paquetes legítimos y muy usados que están a un carácter de otro popular (color/colors):
// los miles más descargados y unos pocos a mano.
const LEGIT = { npm: ['color', 'coffeescript'], PyPI: ['grequests'] };
const KNOWN = Object.fromEntries(Object.keys(HAND).map((eco) => [eco, new Set([...LEGIT[eco], ...((DATA[eco] && DATA[eco].known) || [])].map((n) => norm(eco, n)))]));

function lev(a, b) {
  if (Math.abs(a.length - b.length) > 1) return 9;
  const dp = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) dp[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
    dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) dp[i][j] = Math.min(dp[i][j], dp[i - 2][j - 2] + 1);
  }
  return dp[a.length][b.length];
}

function typosquatCheck(names) {
  const out = [];
  for (const { name, ecosystem, file } of names) {
    const n = norm(ecosystem, name).replace(/_/g, '-');
    if (n.length < 4) continue;
    const list = POPULAR[ecosystem] || [];
    if (list.includes(n) || (KNOWN[ecosystem] && KNOWN[ecosystem].has(n))) continue;
    const near = list.find((p) => p.length >= 4 && lev(n, p) === 1);
    if (near) out.push({ kind: 'threat', rule: 'typosquat', severity: 'high', title: `Posible typosquatting: "${name}"`, description: `Se parece mucho al paquete popular "${near}". Los paquetes con nombres casi idénticos son una vía habitual de malware.`, file, line: null });
  }
  return out;
}

const MAX_MANIFEST = 8 * 1024 * 1024;
function read(p) { try { if (fs.statSync(p).size > MAX_MANIFEST) return null; return fs.readFileSync(p, 'utf8'); } catch { return null; } }

function collect(root, files) {
  const pkgs = []; // {name, version|null, ecosystem, file, spec}
  const threats = [];
  for (const rel of files) {
    if (/node_modules\//.test(rel)) continue;
    const base = path.basename(rel);
    const abs = path.join(root, rel);
    if (base === 'package-lock.json') {
      try {
        const j = JSON.parse(read(abs));
        for (const [k, v] of Object.entries(j.packages || {})) {
          if (!k || !v.version) continue;
          pkgs.push({ name: k.replace(/^.*node_modules\//, ''), version: v.version, ecosystem: 'npm', file: rel, direct: k.split('node_modules/').length === 2 });
        }
        if (!j.packages && j.dependencies) for (const [n, v] of Object.entries(j.dependencies)) pkgs.push({ name: n, version: v.version, ecosystem: 'npm', file: rel, direct: true });
        // npm 7+ marca las dependencias que ejecutan scripts al instalarse.
        const scripted = Object.entries(j.packages || {}).filter(([k, v]) => k && v.hasInstallScript && !v.dev).map(([k]) => k.replace(/^.*node_modules\//, ''));
        if (scripted.length) {
          threats.push({ kind: 'threat', rule: 'dep-install-scripts', severity: scripted.length > 15 ? 'low' : 'info', title: `${scripted.length} dependencia${scripted.length > 1 ? 's' : ''} ejecuta${scripted.length > 1 ? 'n' : ''} código al instalarse`, description: 'npm install ejecuta sus scripts preinstall/install/postinstall en tu máquina. Suele ser legítimo (compilar código nativo, descargar un binario), pero es la vía por la que se cuela el malware de paquetes. Puedes instalar con npm install --ignore-scripts y activarlos solo para las que lo necesiten.', file: rel, line: null, snippet: scripted.slice(0, 12).join(', ') + (scripted.length > 12 ? '…' : '') });
        }
      } catch { /* lock corrupto */ }
    } else if (base === 'package.json') {
      try {
        const j = JSON.parse(read(abs));
        for (const sect of ['dependencies', 'devDependencies', 'optionalDependencies']) {
          for (const [n, spec] of Object.entries(j[sect] || {})) {
            if (typeof spec !== 'string') continue; // una entrada rota no esconde las demás
            if (/^(https?:|git(\+\w+)?:|github:|[\w-]+\/[\w.-]+(#.*)?$)/.test(spec)) {
              threats.push({ kind: 'threat', rule: 'dep-url', severity: 'medium', title: `Dependencia descargada desde URL: ${n}`, description: 'No pasa por el registro de npm: su contenido puede cambiar sin versión ni auditoría.', file: rel, line: null, snippet: `"${n}": "${spec}"` });
            }
            const exact = spec.match(/^[~^=]?(\d+\.\d+\.\d+[\w.-]*)$/);
            pkgs.push({ name: n, version: exact ? exact[1] : null, ecosystem: 'npm', file: rel, direct: true, spec });
          }
        }
      } catch { /* package.json inválido */ }
    } else if (/requirements[\w.-]*\.txt$/i.test(base)) {
      for (const line of (read(abs) || '').split('\n')) {
        const l = line.replace(/#.*/, '').trim();
        if (!l) continue;
        if (/^(-e\s+)?(git\+|https?:)/.test(l)) threats.push({ kind: 'threat', rule: 'dep-url', severity: 'medium', title: 'Dependencia Python desde URL', description: 'Se instala desde una URL en lugar de PyPI.', file: rel, line: null, snippet: l });
        const m = l.match(/^([A-Za-z0-9_.-]+)(\[[^\]]*\])?\s*(==\s*([\w.]+))?/);
        if (m && !l.startsWith('-')) pkgs.push({ name: m[1], version: m[4] || null, ecosystem: 'PyPI', file: rel, direct: true });
      }
    } else if (base === 'Cargo.lock' || base === 'poetry.lock') {
      // [[package]] con name y version (TOML)
      const eco = base === 'Cargo.lock' ? 'crates.io' : 'PyPI';
      for (const m of (read(abs) || '').matchAll(/\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g)) {
        pkgs.push({ name: m[1], version: m[2], ecosystem: eco, file: rel, direct: false });
      }
    } else if (base === 'Pipfile.lock') {
      try {
        const j = JSON.parse(read(abs));
        for (const sect of ['default', 'develop']) {
          for (const [n, v] of Object.entries(j[sect] || {})) {
            const m = String(v.version || '').match(/^==([\w.]+)$/);
            pkgs.push({ name: n, version: m ? m[1] : null, ecosystem: 'PyPI', file: rel, direct: false });
          }
        }
      } catch { /* lock corrupto */ }
    } else if (base === 'composer.lock') {
      try {
        const j = JSON.parse(read(abs));
        for (const p of [...(j.packages || []), ...(j['packages-dev'] || [])]) {
          if (p.name && p.version && !/^dev-/.test(p.version)) pkgs.push({ name: p.name, version: String(p.version).replace(/^v/, ''), ecosystem: 'Packagist', file: rel, direct: false });
        }
      } catch { /* lock corrupto */ }
    } else if (base === 'Gemfile.lock') {
      // En GEM/specs, las gemas van con 4 espacios y sus dependencias con 6.
      for (const m of (read(abs) || '').matchAll(/^ {4}([A-Za-z0-9_.-]+) \(([0-9][\w.]*)(?:-[\w-]+)?\)$/gm)) {
        pkgs.push({ name: m[1], version: m[2], ecosystem: 'RubyGems', file: rel, direct: false });
      }
    } else if (base === 'yarn.lock') {
      // yarn 1: "nombre@rango", ... + version "x"; yarn 2+: version: x. Línea a línea (sin regex
      // multilínea, que con un fichero manipulado tarda minutos).
      let name = null;
      for (const line of (read(abs) || '').split('\n')) {
        if (line.length > 2000) { name = null; continue; }
        const h = !/^\s/.test(line) && line.match(/^"?((?:@[^@\s"/]+\/)?[^@\s",]+)@/);
        if (h) { name = h[1]; continue; }
        const v = name && line.match(/^\s+version:? "?([0-9][\w.+-]*)"?\s*$/);
        if (v) { pkgs.push({ name, version: v[1], ecosystem: 'npm', file: rel, direct: false }); name = null; }
      }
    } else if (base === 'pom.xml') {
      for (const block of (read(abs) || '').split('<dependency>').slice(1)) {
        const end = block.indexOf('</dependency>');
        if (end < 0) continue;
        const m = [null, block.slice(0, Math.min(end, 4000))];
        const tag = (t) => ((m[1].match(new RegExp(`<${t}>\\s*([^<\\s]+)\\s*</${t}>`)) || [])[1]);
        const g = tag('groupId');
        const a = tag('artifactId');
        const v = tag('version');
        if (g && a) pkgs.push({ name: `${g}:${a}`, version: v && !v.includes('${') ? v : null, ecosystem: 'Maven', file: rel, direct: true });
      }
    } else if (/^build\.gradle(\.kts)?$/.test(base)) {
      for (const m of (read(abs) || '').matchAll(/["']([\w.-]+):([\w.-]+):(\d[\w.-]*)["']/g)) {
        pkgs.push({ name: `${m[1]}:${m[2]}`, version: m[3], ecosystem: 'Maven', file: rel, direct: true });
      }
    } else if (base === 'pnpm-lock.yaml') {
      // v5/v6: "  /nombre@1.2.3:" o "  /nombre/1.2.3:"; v9: "  nombre@1.2.3:" bajo packages:
      for (const line of (read(abs) || '').split('\n')) {
        const m = line.length < 400 && line.match(/^ {2}['"]?\/?((?:@[^@/\s]+\/)?[^@/\s('"]+)[@/](\d[\w.+-]*)(?:\([^)]*\))*['"]?:\s*$/);
        if (m) pkgs.push({ name: m[1], version: m[2], ecosystem: 'npm', file: rel, direct: false });
      }
    } else if (base === 'bun.lock') {
      for (const m of (read(abs) || '').matchAll(/^\s+"[^"]+":\s*\["((?:@[^@"/]+\/)?[^@"]+)@(\d[\w.+-]*)"/gm)) pkgs.push({ name: m[1], version: m[2], ecosystem: 'npm', file: rel, direct: false });
    } else if (base === 'uv.lock' || base === 'pdm.lock') {
      for (const m of (read(abs) || '').matchAll(/^\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/gm)) pkgs.push({ name: m[1], version: m[2], ecosystem: 'PyPI', file: rel, direct: false });
    } else if (base === 'pubspec.lock') {
      let name = null;
      for (const line of (read(abs) || '').split('\n')) {
        const h = line.match(/^ {2}([\w-]+):\s*$/);
        if (h) { name = h[1]; continue; }
        const v = name && line.match(/^ {4}version:\s*"?([\w.+-]+)"?/);
        if (v) { pkgs.push({ name, version: v[1], ecosystem: 'Pub', file: rel, direct: false }); name = null; }
      }
    } else if (base === 'packages.lock.json') {
      try {
        const j = JSON.parse(read(abs));
        for (const fw of Object.values(j.dependencies || {})) for (const [n, v] of Object.entries(fw || {})) if (v && v.resolved) pkgs.push({ name: n, version: v.resolved, ecosystem: 'NuGet', file: rel, direct: v.type === 'Direct' });
      } catch { /* lock corrupto */ }
    } else if (/\.(cs|fs|vb)proj$|^Directory\.Packages\.props$/i.test(base)) {
      for (const m of (read(abs) || '').matchAll(/<Package(?:Reference|Version)\s+Include="([^"]+)"\s+Version="\[?([\d][\w.+-]*)\]?"/g)) pkgs.push({ name: m[1], version: m[2], ecosystem: 'NuGet', file: rel, direct: true });
    } else if (base === 'mix.lock') {
      for (const m of (read(abs) || '').matchAll(/"([\w-]+)":\s*\{:hex,\s*:([\w-]+),\s*"([\w.+-]+)"/g)) pkgs.push({ name: m[2], version: m[3], ecosystem: 'Hex', file: rel, direct: false });
    } else if (base === 'renv.lock') {
      try {
        const j = JSON.parse(read(abs));
        for (const [n, v] of Object.entries(j.Packages || {})) if (v && v.Version && (!v.Source || v.Source === 'Repository')) pkgs.push({ name: n, version: v.Version, ecosystem: 'CRAN', file: rel, direct: false });
      } catch { /* lock corrupto */ }
    } else if (base === 'gradle.lockfile') {
      for (const m of (read(abs) || '').matchAll(/^([\w.-]+):([\w.-]+):([\w.+-]+)=/gm)) pkgs.push({ name: `${m[1]}:${m[2]}`, version: m[3], ecosystem: 'Maven', file: rel, direct: false });
    } else if (base === 'go.sum') {
      for (const m of (read(abs) || '').matchAll(/^(\S+) (v[\w.+-]+?)(?:\/go\.mod)? h1:/gm)) pkgs.push({ name: m[1], version: m[2], ecosystem: 'Go', file: rel, direct: false });
    } else if (base === 'go.mod') {
      for (const m of (read(abs) || '').matchAll(/^\s*(?:require\s+)?([\w.-]+\.[\w.-]+\/[\w./-]+)\s+(v[\w.+-]+)/gm)) {
        pkgs.push({ name: m[1], version: m[2], ecosystem: 'Go', file: rel, direct: true });
      }
    }
  }
  return { pkgs, threats };
}

async function osv(pkgs) {
  const withVer = [];
  const seen = new Set();
  for (const p of pkgs) {
    if (!p.version) continue;
    const k = `${p.ecosystem}:${p.name}@${p.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    withVer.push(p);
  }
  if (!withVer.length) return { ok: true, results: [], checked: 0 };
  if (process.env.OMINOUS_OFFLINE === '1') return { ok: false, results: [], checked: 0, error: 'modo sin conexión (OMINOUS_OFFLINE)' };
  const results = [];
  try {
    for (let i = 0; i < withVer.length; i += 500) {
      const chunk = withVer.slice(i, i + 500);
      const r = await fetch('https://api.osv.dev/v1/querybatch', {
        method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version.replace(/^v/, p.ecosystem === 'Go' ? 'v' : '') })) }),
        signal: AbortSignal.timeout(20000),
      });
      if (!r.ok) throw new Error(`OSV ${r.status}`);
      const j = await r.json();
      j.results.forEach((res, idx) => { if (res.vulns && res.vulns.length) results.push({ pkg: chunk[idx], ids: res.vulns.map((v) => v.id) }); });
    }
  } catch (e) {
    return { ok: false, error: e.message, results: [], checked: withVer.length };
  }
  // Detalles (resumen, severidad, versión corregida) de los primeros IDs
  const details = await osvDetails(results.flatMap((r) => r.ids));
  return { ok: true, results, details, checked: withVer.length };
}

function sevFromOsv(v) {
  const s = (v && v.database_specific && v.database_specific.severity || '').toUpperCase();
  if (s === 'CRITICAL') return 'critical';
  if (s === 'HIGH') return 'high';
  if (s === 'MODERATE' || s === 'MEDIUM') return 'medium';
  if (s === 'LOW') return 'low';
  return 'medium';
}

function fixedVersion(v, name) {
  for (const a of (v && v.affected) || []) {
    if (a.package && a.package.name !== name) continue;
    for (const r of a.ranges || []) for (const e of r.events || []) if (e.fixed) return e.fixed;
  }
  return null;
}

// Lo que dice el propio aviso de OSV, recortado: es la explicación sin IA de cada CVE.
function advisory(d, name) {
  const refs = (d.references || []).filter((r) => /ADVISORY|FIX|WEB|REPORT/.test(r.type || '') && /^https:\/\//.test(r.url || '')).slice(0, 3).map((r) => r.url);
  const details = String(d.details || '').replace(/\r/g, '').trim();
  return {
    id: d.id,
    aliases: (d.aliases || []).filter((a) => /^(CVE|GHSA)-/.test(a)).slice(0, 3),
    summary: String(d.summary || '').slice(0, 300),
    details: details.length > 700 ? `${details.slice(0, 700)}…` : details,
    severity: sevFromOsv(d),
    fixed: fixedVersion(d, name),
    published: d.published ? String(d.published).slice(0, 10) : null,
    url: `https://osv.dev/vulnerability/${encodeURIComponent(d.id)}`,
    refs,
  };
}

// Detalles de una lista de avisos de OSV (resumen, severidad, versión corregida).
async function osvDetails(ids) {
  const details = new Map();
  await Promise.all([...new Set(ids)].slice(0, 80).map(async (id) => {
    try {
      const r = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(15000) });
      if (r.ok) details.set(id, await r.json());
    } catch { /* sin detalle */ }
  }));
  return details;
}

// ¿Se está explotando ya? CISA KEV (lista local, se refresca cada semana) y EPSS de FIRST
// (probabilidad de explotación en los próximos 30 días, se consulta en cada análisis).
// Solo puede subir la gravedad, nunca bajarla.
async function exploitSignals(findings) {
  const withOsv = findings.filter((f) => Array.isArray(f.osv) && f.osv.length);
  const cveOf = (a) => [a.id, ...(a.aliases || [])].filter((x) => /^CVE-\d{4}-\d+$/.test(x));
  const cves = [...new Set(withOsv.flatMap((f) => f.osv.flatMap(cveOf)))];
  if (!cves.length) return { checked: 0, kev: 0, epss: null };
  let epss = new Map();
  let epssError = null;
  if (process.env.OMINOUS_OFFLINE === '1') epssError = 'modo sin conexión';
  else {
    try {
      for (let i = 0; i < cves.length; i += 50) {
        const r = await fetch(`https://api.first.org/data/v1/epss?cve=${cves.slice(i, i + 50).join(',')}`, { signal: AbortSignal.timeout(15000) });
        if (!r.ok) throw new Error(`EPSS ${r.status}`);
        for (const d of (await r.json()).data || []) epss.set(d.cve, { score: Number(d.epss), pct: Number(d.percentile) });
      }
    } catch (e) { epss = new Map(); epssError = e.message; }
  }
  let kevHits = 0;
  for (const f of withOsv) {
    let kev = null;
    let top = null;
    for (const a of f.osv) {
      for (const c of cveOf(a)) {
        if (KEV.cves[c]) { a.kev = KEV.cves[c]; kev = kev || { cve: c, date: KEV.cves[c] }; }
        const e = epss.get(c);
        if (e && Number.isFinite(e.score)) { a.epss = e; if (!top || e.score > top.score) top = { cve: c, ...e }; }
      }
    }
    if (kev) {
      kevHits++;
      if (['low', 'medium', 'info'].includes(f.severity)) f.severity = 'high';
      f.title += ' · se está explotando';
      f.description = `${kev.cve} está en el catálogo de CISA de vulnerabilidades explotadas activamente (desde ${kev.date}). ${f.description}`;
    } else if (top && top.score >= 0.5) {
      f.description = `${top.cve} tiene una probabilidad de explotación del ${Math.round(top.score * 100)} % en 30 días (EPSS). ${f.description}`;
    }
  }
  return { checked: cves.length, kev: kevHits, epss: epssError ? null : epss.size, epssError, catalog: KEV.catalogVersion };
}

async function auditDependencies(root, files) {
  const { pkgs, threats } = collect(root, files);
  const trans = await transitiveNpm(root, files, pkgs);
  pkgs.push(...trans.pkgs);
  const res = await osv(pkgs);
  const vulnFindings = [];
  for (const { pkg, ids: allIds } of res.results) {
    const mal = allIds.filter((id) => id.startsWith('MAL-'));
    if (mal.length) threats.push({ kind: 'threat', rule: 'malicious-package', severity: 'critical', title: `Dependencia maliciosa conocida: ${pkg.name}@${pkg.version}`, description: `OSV.dev la tiene catalogada como malware (${mal.join(', ')}). Instalar el proyecto la ejecuta en tu máquina.`, file: pkg.file, line: null });
    const ids = allIds.filter((id) => !id.startsWith('MAL-'));
    if (!ids.length) continue;
    const ds = ids.map((id) => res.details && res.details.get(id)).filter(Boolean);
    const worst = ds.reduce((w, d) => { const s = sevFromOsv(d); return ['low', 'medium', 'high', 'critical'].indexOf(s) > ['low', 'medium', 'high', 'critical'].indexOf(w) ? s : w; }, 'low');
    const fixes = ds.map((d) => fixedVersion(d, pkg.name)).filter(Boolean);
    const target = fixes.sort((a, b) => a.localeCompare(b, undefined, { numeric: true })).pop();
    vulnFindings.push({
      kind: 'vuln', rule: 'dep-vuln', severity: ds.length ? worst : 'medium',
      title: `${pkg.name}@${pkg.version} tiene ${ids.length} vulnerabilidad${ids.length > 1 ? 'es' : ''} conocida${ids.length > 1 ? 's' : ''}`,
      description: ds.slice(0, 3).map((d) => `${d.id}: ${d.summary || 'sin resumen'}`).join(' · ') || ids.join(', '),
      file: pkg.file, line: null, advisories: ids.slice(0, 10),
      osv: ds.slice(0, 10).map((d) => advisory(d, pkg.name)),
      fixable: !!target,
      fix: target ? { text: `Actualizar ${pkg.name} a ${target} o superior${pkg.direct === false ? ` (dependencia transitiva${pkg.via ? `, la trae ${pkg.via}` : ''}: actualiza el paquete que la trae o usa "overrides")` : ''}.`, auto: false } : undefined,
      notFixableReason: target ? undefined : 'No existe versión corregida publicada. Hay que sustituir el paquete o asumir el riesgo.',
    });
  }
  return {
    findings: vulnFindings,
    names: pkgs.filter((p) => p.direct),
    summary: { total: pkgs.length, checked: res.checked, vulnerable: res.results.length, osvAvailable: res.ok, osvError: res.error || null, transitive: trans.summary },
    threats,
  };
}

module.exports = { auditDependencies, typosquatCheck, collect, osvDetails, advisory, sevFromOsv, exploitSignals };
