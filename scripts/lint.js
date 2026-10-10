#!/usr/bin/env node
'use strict';
// Lint sin dependencias: sintaxis de todos los .js, 'use strict' en los
// módulos y nada de ficheros con caracteres invisibles o bidi (Trojan Source).
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const SKIP = new Set(['node_modules', '.git', 'site', 'coverage']);
const INVISIBLE = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]|\uDB40[\uDC00-\uDC7F]/;
let errors = 0;

function walk(dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (SKIP.has(e.name)) continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p);
    else if (/\.(js|json|md|yml|html)$/.test(e.name) || e.name === 'Dockerfile') check(p);
  }
}

function fail(file, msg) {
  console.error(`✗ ${path.relative(ROOT, file)}: ${msg}`);
  errors++;
}

function check(file) {
  const src = fs.readFileSync(file, 'utf8');
  const bad = src.split('\n').findIndex((l) => INVISIBLE.test(l));
  if (bad >= 0) fail(file, `carácter invisible o bidi en la línea ${bad + 1} (usa escapes \\u)`);
  if (/\.json$/.test(file)) { try { JSON.parse(src); } catch (e) { fail(file, e.message); } }
  if (!/\.js$/.test(file)) return;
  try { execFileSync(process.execPath, ['--check', file], { stdio: 'pipe' }); } catch (e) { fail(file, String(e.stderr).trim().split('\n').slice(0, 4).join(' ')); }
  if (!/^(#!.*\n)?'use strict';/.test(src)) fail(file, "falta 'use strict' al principio");
}

walk(ROOT);
if (errors) { console.error(`\n${errors} problema(s)`); process.exit(1); }
console.log('Lint OK');
