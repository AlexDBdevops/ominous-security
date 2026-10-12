'use strict';
// Dependencias: vulnerabilidades conocidas (OSV.dev), dependencias desde URL y typosquatting.

const fs = require('fs');
const path = require('path');

const POPULAR = {
  npm: ['express', 'react', 'react-dom', 'lodash', 'axios', 'chalk', 'commander', 'debug', 'request', 'moment', 'webpack', 'typescript', 'eslint', 'prettier', 'jquery', 'vue', 'next', 'electron', 'dotenv', 'colors', 'uuid', 'yargs', 'mongoose', 'socket.io', 'body-parser', 'cross-env', 'nodemon', 'jsonwebtoken', 'bcrypt', 'cors', 'discord.js', 'puppeteer', 'ethers', 'web3', 'crypto-js', 'node-fetch', 'babel-core', 'coffee-script', 'event-stream', 'rimraf', 'glob', 'minimist', 'semver', 'ws', 'sharp', 'tailwindcss', 'vite'],
  PyPI: ['requests', 'urllib3', 'numpy', 'pandas', 'django', 'flask', 'boto3', 'setuptools', 'pyyaml', 'cryptography', 'pillow', 'scipy', 'matplotlib', 'selenium', 'beautifulsoup4', 'colorama', 'pytest', 'tensorflow', 'torch', 'opencv-python', 'discord.py', 'python-dateutil', 'jinja2', 'paramiko', 'pycryptodome', 'web3', 'openai', 'httpx', 'aiohttp', 'fastapi', 'pydantic', 'tqdm', 'click', 'rich', 'termcolor', 'pygame', 'pyautogui', 'pynput'],
};

// Paquetes legítimos y muy usados que están a un carácter de otro popular (color/colors).
const LEGIT = { npm: ['color', 'coffeescript'], PyPI: ['grequests'] };

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
    const n = name.toLowerCase().replace(/_/g, '-');
    if (n.length < 4) continue;
    const list = POPULAR[ecosystem] || [];
    if (list.includes(n) || (LEGIT[ecosystem] || []).includes(n)) continue;
    const near = list.find((p) => p.length >= 4 && lev(n, p) === 1);
    if (near) out.push({ kind: 'threat', rule: 'typosquat', severity: 'high', title: `Posible typosquatting: "${name}"`, description: `Se parece mucho al paquete popular "${near}". Los paquetes con nombres casi idénticos son una vía habitual de malware.`, file, line: null });
  }
  return out;
}

function read(p) { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } }

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
      } catch { /* lock corrupto */ }
    } else if (base === 'package.json') {
      try {
        const j = JSON.parse(read(abs));
        for (const sect of ['dependencies', 'devDependencies', 'optionalDependencies']) {
          for (const [n, spec] of Object.entries(j[sect] || {})) {
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
  const details = new Map();
  const ids = [...new Set(results.flatMap((r) => r.ids))].slice(0, 80);
  await Promise.all(ids.map(async (id) => {
    try {
      const r = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: AbortSignal.timeout(15000) });
      if (r.ok) details.set(id, await r.json());
    } catch { /* sin detalle */ }
  }));
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

async function auditDependencies(root, files) {
  const { pkgs, threats } = collect(root, files);
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
      fix: target ? { text: `Actualizar ${pkg.name} a ${target} o superior${pkg.direct === false ? ' (dependencia transitiva: actualiza el paquete que la trae o usa "overrides")' : ''}.`, auto: false } : undefined,
      notFixableReason: target ? undefined : 'No existe versión corregida publicada. Hay que sustituir el paquete o asumir el riesgo.',
    });
  }
  return {
    findings: vulnFindings,
    names: pkgs.filter((p) => p.direct),
    summary: { total: pkgs.length, checked: res.checked, vulnerable: res.results.length, osvAvailable: res.ok, osvError: res.error || null },
    threats,
  };
}

module.exports = { auditDependencies, typosquatCheck };
