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

// Sin enlaces simbólicos: en Windows crearlos pide permisos de administrador.
const YAML_APP = { 'app.py': 'import yaml; conf = yaml.load(open("c.yml"))' };

test('con plazo agotado para entre ficheros y lo marca como análisis incompleto', async (t) => {
  const dir = fx.write(fx.tmpDir('plazo'), YAML_APP);
  t.after(() => fx.rm(dir));
  const r = await analyzeTree(dir, {}, () => {}, { deadline: Date.now() - 1 });
  const partial = r.threats.find((x) => x.rule === 'partial-scan');
  assert.ok(partial && /tiempo/.test(partial.title), 'avisa de que se acabó el tiempo');
  assert.ok(!r.vulnerabilities.some((x) => x.file === 'app.py'), 'no ha leído el código');
  assert.ok((await analyzeTree(dir, {})).vulnerabilities.some((x) => x.rule === 'py-yaml'), 'sin plazo sí lo encuentra');
  const code = r.coverage.find((c) => c.label === 'Código del último commit');
  assert.equal(code.status, 'partial');
  assert.match(code.detail, /^0 ficheros leídos/);
  // Tres comprobaciones que releen ficheros, dependencias y paquete publicado
  assert.equal(r.coverage.filter((c) => c.status === 'skip' && /se acabó el tiempo/.test(c.detail)).length, 5);
  assert.ok(r.dependencies.skipped, 'la web dice "sin revisar", no "sin ficheros de dependencias"');
  assert.notEqual(r.summary.overall, 'green');
});

test('con plazo holgado da lo mismo que sin plazo, y se puede cancelar', async (t) => {
  const dir = fx.write(fx.tmpDir('plazo'), YAML_APP);
  t.after(() => fx.rm(dir));
  const key = (d) => [...d.vulnerabilities, ...d.threats].map((f) => `${f.rule}:${f.file}:${f.line}`).sort();
  const free = await analyzeTree(dir, {});
  const timed = await analyzeTree(dir, {}, () => {}, { deadline: Date.now() + 60000 });
  assert.deepEqual(key(timed), key(free));
  const ctl = new AbortController();
  ctl.abort();
  await assert.rejects(analyzeTree(dir, {}, () => {}, { signal: ctl.signal }), /cancelado/);
});
