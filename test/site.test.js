'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { scriptHashes } = require('../lib/page');

const BUILD = path.join(__dirname, '..', 'scripts', 'build-site.js');

test('la demo estática lleva la misma CSP por hash, las fuentes y ningún recurso de terceros', (t) => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'ominous-site-'));
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));
  execFileSync(process.execPath, [BUILD, out]);
  const html = fs.readFileSync(path.join(out, 'index.html'), 'utf8');
  const headers = fs.readFileSync(path.join(out, '_headers'), 'utf8');
  assert.match(html, /^<!doctype html>/);
  for (const h of scriptHashes(html)) assert.ok(headers.includes(h), 'el hash del script está en la CSP');
  const scriptSrc = headers.match(/script-src ([^;]+)/)[1];
  assert.ok(!scriptSrc.includes('unsafe-inline'), 'scripts sin unsafe-inline');
  assert.ok(!/<(link|script|img|iframe)[^>]+(href|src)="https?:/i.test(html), 'sin recursos externos');
  assert.match(headers, /frame-ancestors 'none'/);
  assert.match(headers, /Strict-Transport-Security/);
  for (const f of ['chakra-petch-700.woff2', 'ibm-plex-sans.woff2', 'jetbrains-mono.woff2', 'OFL.txt']) assert.ok(fs.existsSync(path.join(out, 'fonts', f)), f);
});

test('no borra una carpeta que no sea una demo generada', (t) => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'ominous-site-'));
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));
  fs.writeFileSync(path.join(out, 'importante.txt'), 'x');
  assert.throws(() => execFileSync(process.execPath, [BUILD, out], { stdio: 'pipe' }));
  assert.ok(fs.existsSync(path.join(out, 'importante.txt')));
});

test('typosquatting: "color" es legítimo, "colrs" no', () => {
  const { typosquatCheck } = require('../lib/deps');
  assert.equal(typosquatCheck([{ name: 'color', ecosystem: 'npm', file: 'package-lock.json' }]).length, 0);
  assert.equal(typosquatCheck([{ name: 'colrs', ecosystem: 'npm', file: 'package.json' }]).length, 1);
});
