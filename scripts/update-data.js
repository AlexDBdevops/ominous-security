#!/usr/bin/env node
'use strict';
// Refresca los datos que envejecen y que no se consultan en cada análisis:
// - data/kev.json: catálogo de CISA de vulnerabilidades que se están explotando (KEV).
// - data/popular.json: paquetes más descargados de npm y PyPI, para el typosquatting.
// Lo ejecuta cada semana .github/workflows/update-data.yml, que abre un PR si cambia algo.
// Todo lo descargado se valida (formato de cada nombre, tamaños mínimos y máximos) antes
// de escribirse: es una fuente externa y el PR solo debe contener datos con forma esperada.
//   node scripts/update-data.js [--check]   (--check: no escribe, falla si los datos no son válidos)
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');

const DATA = path.join(__dirname, '..', 'data');
const SOURCES = {
  kev: ['https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'],
  pypi: 'https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json',
  npm: 'https://registry.npmjs.org/npm-high-impact/latest',
};
const TARGETS = 150; // los que se vigilan como objetivo de typosquatting
const KNOWN = 3000; // los que se dan por legítimos aunque se parezcan a otro

async function get(url, max = 40 * 1024 * 1024) {
  const r = await fetch(url, { signal: AbortSignal.timeout(60000) });
  if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
  const buf = Buffer.from(await r.arrayBuffer());
  if (buf.length > max) throw new Error(`${url}: demasiado grande`);
  return buf;
}

async function kev() {
  let last;
  for (const url of SOURCES.kev) {
    try {
      const j = JSON.parse(await get(url));
      const cves = {};
      for (const v of j.vulnerabilities || []) {
        if (/^CVE-\d{4}-\d{4,7}$/.test(v.cveID) && /^\d{4}-\d{2}-\d{2}$/.test(v.dateAdded)) cves[v.cveID] = v.dateAdded;
      }
      const n = Object.keys(cves).length;
      if (n < 1000 || n > 20000) throw new Error(`KEV con ${n} entradas: fuera de lo esperado`);
      return { source: 'CISA Known Exploited Vulnerabilities', catalogVersion: String(j.catalogVersion || '').slice(0, 20), count: n, cves: Object.fromEntries(Object.entries(cves).sort()) };
    } catch (e) { last = e; }
  }
  throw last;
}

const NPM_NAME = /^(@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]{0,213}$/;
const PYPI_NAME = /^[a-z0-9][a-z0-9._-]{0,99}$/;

// Lee un .tgz de npm en memoria y devuelve el contenido de un fichero.
function fromTgz(buf, want) {
  const tar = zlib.gunzipSync(buf, { maxOutputLength: 50 * 1024 * 1024 });
  for (let o = 0; o + 512 <= tar.length;) {
    const name = tar.toString('utf8', o, o + 100).replace(/\0.*$/s, '');
    if (!name) break;
    const size = parseInt(tar.toString('utf8', o + 124, o + 136).replace(/\0.*$/s, '').trim() || '0', 8);
    if (name === want) return tar.toString('utf8', o + 512, o + 512 + size);
    o += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error(`no está ${want}`);
}

async function popular() {
  const pyj = JSON.parse(await get(SOURCES.pypi));
  const py = pyj.rows.map((r) => String(r.project).toLowerCase()).filter((n) => PYPI_NAME.test(n));
  const meta = JSON.parse(await get(SOURCES.npm));
  if (!/^https:\/\/registry\.npmjs\.org\//.test(meta.dist && meta.dist.tarball)) throw new Error('tarball de npm-high-impact inesperado');
  const src = fromTgz(await get(meta.dist.tarball, 10 * 1024 * 1024), 'package/lib/top-download.js');
  const npm = [...src.matchAll(/^\s*'([^']+)',?$/gm)].map((m) => m[1]).filter((n) => NPM_NAME.test(n));
  if (npm.length < KNOWN / 2 || py.length < KNOWN) throw new Error(`listas demasiado cortas (npm ${npm.length}, PyPI ${py.length})`);
  const pick = (list) => ({ targets: list.slice(0, TARGETS), known: list.slice(0, KNOWN) });
  return { source: `npm: npm-high-impact ${meta.version}; PyPI: top-pypi-packages ${String(pyj.last_update || '').slice(0, 10)}`, npm: pick(npm), PyPI: pick(py) };
}

async function main() {
  const check = process.argv.includes('--check');
  const out = { 'kev.json': await kev(), 'popular.json': await popular() };
  for (const [name, data] of Object.entries(out)) {
    const file = path.join(DATA, name);
    const text = `${JSON.stringify(data, null, 1)}\n`;
    const old = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';
    console.log(`${name}: ${old === text ? 'sin cambios' : check ? 'cambiaría' : 'actualizado'}`);
    if (!check && old !== text) fs.writeFileSync(file, text);
  }
}

main().catch((e) => { console.error(`update-data: ${e.message}`); process.exit(1); });
