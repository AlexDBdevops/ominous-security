'use strict';
// Vigilancia de los clones: solo avisa de lo publicado después del clon.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const fx = require('./helpers/fixtures');

test('vigilancia: avisa una vez de las vulnerabilidades nuevas', async (t) => {
  const root = fx.tmpDir('watch');
  const outside = fx.write(fx.tmpDir('watch-out'), { 'requirements.txt': 'jinja2==2.10\n' });
  fx.write(root, { 'app/requirements.txt': 'jinja2==2.10\n', 'app/node_modules/x/package.json': '{"name":"x","dependencies":{"evil":"1.0.0"}}', 'app/README.md': 'hola' });
  fs.symlinkSync(outside, path.join(root, 'link'));
  t.after(() => { fx.rm(root); fx.rm(outside); });
  let vulns = ['GHSA-old0-0000-0000'];
  const queried = [];
  const orig = globalThis.fetch;
  const prev = process.env.OMINOUS_OFFLINE;
  process.env.OMINOUS_OFFLINE = '0';
  globalThis.fetch = async (url, opts = {}) => {
    const u = new URL(String(url));
    if (u.pathname === '/v1/querybatch') {
      const qs = JSON.parse(opts.body).queries;
      queried.push(...qs.map((q) => q.package.name));
      return new Response(JSON.stringify({ results: qs.map(() => ({ vulns: vulns.map((id) => ({ id })) })) }));
    }
    if (u.hostname === 'api.osv.dev') { const id = decodeURIComponent(u.pathname.split('/').pop()); return new Response(JSON.stringify({ id, summary: `aviso ${id}`, database_specific: { severity: 'HIGH' } })); }
    throw new TypeError('Failed to fetch');
  };
  t.after(() => { globalThis.fetch = orig; if (prev === undefined) delete process.env.OMINOUS_OFFLINE; else process.env.OMINOUS_OFFLINE = prev; });

  const { Watch, manifests } = require('../lib/watch');
  assert.deepEqual(manifests(path.join(root, 'app')), ['requirements.txt'], 'sin node_modules');
  const w = new Watch(root, { inline: true });
  const id = w.add({ owner: 'acme', repo: 'app', commit: 'c'.repeat(40), dest: path.join(root, 'app'), findings: [{ rule: 'dep-vuln', advisories: ['GHSA-old0-0000-0000'] }] });
  w.add({ owner: 'acme', repo: 'gone', commit: 'd'.repeat(40), dest: path.join(root, 'gone') });
  w.add({ owner: 'acme', repo: 'link', commit: 'e'.repeat(40), dest: path.join(root, 'link') });
  assert.equal(fs.statSync(w.file).mode & 0o777, 0o600);

  let r = await w.check();
  const app = r.repos.find((x) => x.id === id);
  assert.equal(app.alerts.length, 0, 'lo que ya se sabía al clonar no se avisa');
  assert.equal(r.repos.find((x) => x.repo === 'acme/gone').status, 'missing');
  assert.equal(r.repos.find((x) => x.repo === 'acme/link').status, 'outside', 'un enlace que sale de la carpeta de clones no se lee');
  assert.deepEqual(queried, ['jinja2']);

  vulns = ['GHSA-old0-0000-0000', 'GHSA-new0-0000-0000'];
  r = await w.check();
  const a = r.repos.find((x) => x.id === id);
  assert.equal(a.alerts.length, 1);
  assert.equal(a.alerts[0].id, 'GHSA-new0-0000-0000');
  assert.equal(a.alerts[0].severity, 'high');
  assert.equal(a.newAlerts, 1);
  w.markRead();
  assert.equal(w.list().repos.find((x) => x.id === id).newAlerts, 0);
  r = await w.check();
  assert.equal(r.newAlerts, 0, 'cada aviso se da una vez');
  assert.deepEqual(w.forget(id), { removed: 1 });
  assert.equal(w.list().repos.length, 2);
});

// Sin enlaces simbólicos: en Windows crearlos pide permisos de administrador.
test('vigilancia: comprueba en un hilo aparte sin bloquear el servidor', async (t) => {
  const root = fx.tmpDir('watch-worker');
  fx.write(root, { 'app/requirements.txt': 'jinja2==2.10', 'docs/README.md': 'hola' });
  t.after(() => fx.rm(root));
  const prev = process.env.OMINOUS_OFFLINE;
  process.env.OMINOUS_OFFLINE = '1';
  t.after(() => { if (prev === undefined) delete process.env.OMINOUS_OFFLINE; else process.env.OMINOUS_OFFLINE = prev; });
  const { Watch } = require('../lib/watch');
  const w = new Watch(root);
  w.add({ owner: 'acme', repo: 'app', commit: 'c'.repeat(40), dest: path.join(root, 'app') });
  w.add({ owner: 'acme', repo: 'docs', commit: 'd'.repeat(40), dest: path.join(root, 'docs') });
  let ticks = 0;
  const beat = setInterval(() => { ticks++; }, 1);
  const r = await w.check();
  clearInterval(beat);
  assert.ok(ticks > 0, 'el hilo principal sigue libre mientras se comprueba');
  const app = r.repos.find((x) => x.repo === 'acme/app');
  assert.equal(app.status, 'skip');
  assert.match(app.detail, /OSV/, 'sin conexión lo dice, igual que sin worker');
  const docs = r.repos.find((x) => x.repo === 'acme/docs');
  assert.equal(docs.status, 'ok');
  assert.ok(docs.checkedAt);
  assert.ok(r.checkedAt);
});

test('vigilancia: si se pasa de tiempo se corta y los repos quedan como saltados', async (t) => {
  const root = fx.tmpDir('watch-timeout');
  fx.write(root, { 'app/requirements.txt': 'jinja2==2.10' });
  t.after(() => fx.rm(root));
  const { Watch } = require('../lib/watch');
  const w = new Watch(root, { timeoutMs: 1 });
  w.add({ owner: 'acme', repo: 'app', commit: 'c'.repeat(40), dest: path.join(root, 'app'), findings: [{ rule: 'dep-vuln', advisories: ['GHSA-old0-0000-0000'] }] });
  const logs = [];
  const r = await w.check((m) => logs.push(m));
  const app = r.repos.find((x) => x.repo === 'acme/app');
  assert.equal(app.status, 'skip');
  assert.match(app.detail, /se cortó/);
  assert.equal(app.known, 1, 'lo que ya se sabía se conserva');
  assert.ok(logs.some((m) => /superó/.test(m)));
  assert.ok(r.checkedAt);
});
