'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { scriptHashes } = require('../lib/page');

const BUILD = path.join(__dirname, '..', 'scripts', 'build-site.js');

test('la demo estática lleva la CSP en un meta con hashes, las fuentes y ningún recurso de terceros', (t) => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'ominous-site-'));
  t.after(() => fs.rmSync(out, { recursive: true, force: true }));
  execFileSync(process.execPath, [BUILD, out]);
  const html = fs.readFileSync(path.join(out, 'index.html'), 'utf8');
  assert.match(html, /^<!doctype html>/);
  const csp = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/)[1];
  assert.ok(html.indexOf('Content-Security-Policy') < html.indexOf('<script'), 'la CSP va antes de cualquier script');
  for (const h of scriptHashes(html)) assert.ok(csp.includes(h), 'el hash de cada script está en la CSP');
  const scriptSrc = csp.match(/script-src ([^;]+)/)[1];
  assert.ok(!scriptSrc.includes('unsafe-inline'), 'scripts sin unsafe-inline');
  assert.ok(!/frame-ancestors/.test(csp), 'frame-ancestors no vale en un meta');
  assert.match(html, /<style id="antiframe">html\{display:none!important\}<\/style>/, 'oculta la página dentro de marcos ajenos');
  assert.match(html, /<meta name="referrer" content="no-referrer">/);
  assert.ok(!/<(link|script|img|iframe)[^>]+(href|src)="https?:/i.test(html), 'sin recursos externos');
  // El analizador lleva su hash en la URL (script y worker): tras publicar no se mezcla con uno viejo
  assert.equal((html.match(/analyzer\.js\?v=[0-9a-f]{12}/g) || []).length, 2);
  assert.match(html, /const EDITION = 'web';/);
  assert.ok(fs.existsSync(path.join(out, 'analyzer.js')), 'lleva el analizador');
  const connect = csp.match(/connect-src ([^;]+)/)[1].trim().split(/\s+/).sort();
  assert.deepEqual(connect, ['https://api.deps.dev', 'https://api.first.org', 'https://api.github.com', 'https://api.osv.dev', 'https://api.securityscorecards.dev', 'https://files.pythonhosted.org', 'https://pypi.org', 'https://raw.githubusercontent.com', 'https://registry.npmjs.org']);
  assert.match(csp, /worker-src 'self'/);
  for (const f of ['chakra-petch-700.woff2', 'ibm-plex-sans.woff2', 'jetbrains-mono.woff2', 'OFL.txt']) assert.ok(fs.existsSync(path.join(out, 'fonts', f)), f);
  execFileSync(process.execPath, [BUILD, out]); // se puede regenerar encima
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
  assert.equal(typosquatCheck([{ name: 'coffeescript', ecosystem: 'npm', file: 'package-lock.json' }]).length, 0);
  assert.equal(typosquatCheck([{ name: 'grequests', ecosystem: 'PyPI', file: 'requirements.txt' }]).length, 0);
  assert.equal(typosquatCheck([{ name: 'colrs', ecosystem: 'npm', file: 'package.json' }]).length, 1);
});

test('ediciones: la local no conecta fuera y la marca de edición existe', () => {
  const page = require('../lib/page');
  assert.match(page.CSP, /connect-src 'self';/);
  assert.ok(!/worker-src/.test(page.CSP));
  for (const e of page.EDITIONS) assert.match(page.edition(e).body, new RegExp(`const EDITION = '${e}';`));
  assert.throws(() => page.edition('otra'));
});

test('la CSP sigue valiendo si index.html llega con CRLF (checkout en Windows)', () => {
  const { lf, BODY } = require('../lib/page');
  assert.equal(lf('a\r\nb\rc\n'), 'a\nb\nc\n');
  assert.ok(!BODY.includes('\r'));
});
