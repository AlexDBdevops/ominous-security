'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { analyzeTree, applyAutoFixes } = require('../lib/analyzer');
const fx = require('./helpers/fixtures');

process.env.OMINOUS_OFFLINE = '1';
const rules = (list) => new Set(list.map((f) => f.rule));

test('repo limpio sale en verde', async (t) => {
  const dir = fx.cleanRepo();
  t.after(() => fx.rm(dir));
  const r = await analyzeTree(dir, {});
  assert.equal(r.summary.overall, 'green');
  assert.equal(r.vulnerabilities.length, 0);
  assert.equal(r.threats.length, 0);
});

test('repo trampa 1: detecta todo lo plantado', async (t) => {
  const dir = fx.trapRepo();
  t.after(() => fx.rm(dir));
  const r = await analyzeTree(dir, {});
  assert.equal(r.summary.overall, 'red');
  const v = rules(r.vulnerabilities);
  for (const id of ['secret-aws', 'py-yaml', 'py-pickle', 'py-tls', 'py-flaskdebug', 'py-weakhash']) assert.ok(v.has(id), `falta ${id}`);
  const th = rules(r.threats);
  for (const id of ['vscode-autorun', 'disguised-binary', 'hidden-payload', 'hidden-whitespace', 'symlink-escape', 'curl-pipe', 'npm-lifecycle', 'typosquat', 'trojan-source']) assert.ok(th.has(id), `falta ${id}`);

  // Los cuatro payloads (charcodes, zlib, XOR, Fernet) se descifran hasta texto
  const decoded = r.threats.filter((x) => x.rule === 'hidden-payload' && /utils|scripts|src\/cc/.test(x.file));
  assert.ok(decoded.length >= 4, `solo ${decoded.length} payloads descifrados`);
  assert.ok(r.summary.autoFixable > 0);
  assert.ok(r.summary.notFixable > 0);
});

test('repo trampa 2: autoejecutables, agentes de IA, Unicode y señuelos', async (t) => {
  const dir = fx.trapRepo2();
  t.after(() => fx.rm(dir));
  const r = await analyzeTree(dir, {});
  assert.equal(r.summary.overall, 'red');
  const th = rules(r.threats);
  for (const id of ['double-ext', 'readme-lure', 'clipper', 'keylogger', 'archive-encrypted', 'autoexec', 'ai-injection', 'pth-exec', 'lockfile-host', 'homoglyph', 'unicode-tags']) assert.ok(th.has(id), `falta ${id}`);
  const v = rules(r.vulnerabilities);
  for (const id of ['c-gets', 'c-format', 'gha-unpinned']) assert.ok(v.has(id), `falta ${id}`);
});

test('repo trampa 3: contenedores, CI, esteganografía y suplantación de comandos', async (t) => {
  const dir = fx.trapRepo3();
  t.after(() => fx.rm(dir));
  const r = await analyzeTree(dir, {});
  const th = rules(r.threats);
  for (const id of ['image-payload', 'stego-loader', 'stego-lib', 'npm-bin-hijack', 'gha-secrets-dump']) assert.ok(th.has(id), `falta ${id}`);
  const v = rules(r.vulnerabilities);
  for (const id of ['compose-host-ns', 'compose-host-mount', 'compose-cap-add', 'docker-root']) assert.ok(v.has(id), `falta ${id}`);
  assert.ok(!r.threats.some((x) => x.file === 'assets/ok.png'), 'una imagen normal no es sospechosa');
  assert.equal(r.threats.find((x) => x.rule === 'npm-bin-hijack').description.includes('"git"'), true);
});

test('Scorecard de OpenSSF aparece en la confianza', async (t) => {
  const dir = fx.cleanRepo();
  t.after(() => fx.rm(dir));
  const r = await analyzeTree(dir, { stargazers_count: 100, created_at: '2020-01-01', scorecard: { score: 3.1, date: '2026-10-01', weak: ['Code-Review', 'Pinned-Dependencies'] } });
  const sc = r.trust.find((x) => x.label === 'OpenSSF Scorecard');
  assert.ok(sc);
  assert.equal(sc.ok, false);
  assert.match(sc.value, /3\.1\/10/);
});

test('el código de tests se rebaja a informativo', async (t) => {
  const dir = fx.write(fx.tmpDir('nonprod'), { 'tests/test_x.py': 'import pickle\nobj = pickle.loads(data)\n' });
  t.after(() => fx.rm(dir));
  const r = await analyzeTree(dir, {});
  assert.ok(r.vulnerabilities.length > 0);
  assert.ok(r.vulnerabilities.every((x) => x.severity === 'info'));
  assert.equal(r.summary.vulnStatus, 'green');
});

test('exclude omite rutas', async (t) => {
  const dir = fx.trapRepo();
  t.after(() => fx.rm(dir));
  const r = await analyzeTree(dir, {}, () => {}, { exclude: ['utils/', 'app.py'] });
  assert.ok(!r.vulnerabilities.some((x) => x.file === 'app.py'));
  assert.ok(!r.threats.some((x) => String(x.file).startsWith('utils/')));
});

test('applyAutoFixes cambia solo las líneas marcadas', async (t) => {
  const dir = fx.trapRepo();
  t.after(() => fx.rm(dir));
  const before = fs.readFileSync(path.join(dir, 'app.py'), 'utf8');
  const r = await analyzeTree(dir, {});
  const applied = applyAutoFixes(dir, r.vulnerabilities);
  assert.ok(applied.length > 0);
  const after = fs.readFileSync(path.join(dir, 'app.py'), 'utf8');
  assert.notEqual(after, before);
  assert.match(after, /yaml\.safe_load|verify=True|sha256|debug=False/);
  assert.equal(after.split('\n').length, before.split('\n').length);
  for (const f of applied) assert.ok(f.file && f.line && f.before !== f.after);
});
