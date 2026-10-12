'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');

const PORT = 18000 + Math.floor(Math.random() * 2000);
process.env.PORT = String(PORT);
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
process.env.CLONE_DIR = path.join(os.tmpdir(), `ominous-test-clones-${process.pid}`);
const { parseGithubUrl, resolveDest, server } = require('../server');

test('el destino del clon no puede salir de CLONE_DIR', () => {
  assert.equal(resolveDest('', 'repo'), path.join(process.env.CLONE_DIR, 'repo'));
  assert.equal(resolveDest('mio/proyecto', 'repo'), path.join(process.env.CLONE_DIR, 'mio/proyecto'));
  for (const d of ['../fuera', '/etc/x', '~/.vim/pack/x/start/r', '~/.config/autostart/r', '.', 'a/../../b']) {
    assert.throws(() => resolveDest(d, 'repo'), /dentro de/, d);
  }
});

test('parseGithubUrl acepta formatos válidos', () => {
  for (const u of ['https://github.com/expressjs/express', 'github.com/expressjs/express', 'git@github.com:expressjs/express.git', 'https://github.com/expressjs/express/tree/master']) {
    const r = parseGithubUrl(u);
    assert.equal(r.owner, 'expressjs', u);
    assert.equal(r.repo, 'express', u);
  }
});

test('parseGithubUrl rechaza URLs peligrosas o ajenas', () => {
  for (const u of ['', 'https://gitlab.com/a/b', 'file:///etc/passwd', 'ext::sh -c id', 'https://github.com/a/b;rm -rf', 'https://github.com/../x', 'https://github.com/-u/x']) {
    assert.throws(() => { const r = parseGithubUrl(u); if (!r) throw new Error('null'); }, undefined, u);
  }
});

function req(method, path, headers = {}, body) {
  return new Promise((resolve, reject) => {
    const r = http.request({ host: '127.0.0.1', port: PORT, method, path, headers }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => resolve({ status: res.statusCode, body: data, headers: res.headers }));
    });
    r.on('error', reject);
    if (body) r.write(body);
    r.end();
  });
}

test('servidor HTTP', async (t) => {
  await new Promise((resolve) => server.listen(PORT, '127.0.0.1', resolve));
  t.after(() => server.close());
  const host = { host: `localhost:${PORT}` };

  await t.test('health responde', async () => {
    const r = await req('GET', '/api/health', host);
    assert.equal(r.status, 200);
  });
  await t.test('la conexión con Claude se consulta y se valida sin exponer claves', async () => {
    const g = await req('GET', '/api/ai-connection', host);
    assert.equal(g.status, 200);
    assert.ok(!/sk-ant-[A-Za-z0-9_-]{20}/.test(g.body));
    const json = { ...host, 'content-type': 'application/json' };
    const bad = await req('POST', '/api/ai-connection', json, JSON.stringify({ method: 'shell' }));
    assert.equal(bad.status, 400);
    const badKey = await req('POST', '/api/ai-connection', json, JSON.stringify({ method: 'api', key: 'no-es-una-clave' }));
    assert.equal(badKey.status, 400);
    const cross = await req('POST', '/api/ai-connection', { ...json, origin: 'https://evil.example' }, JSON.stringify({ method: 'none' }));
    assert.equal(cross.status, 403);
  });
  await t.test('la CSP autoriza el script por hash y no carga nada de terceros', async () => {
    const r = await req('GET', '/', host);
    const csp = r.headers['content-security-policy'];
    assert.match(csp, /script-src 'sha256-[A-Za-z0-9+/=]+'/);
    assert.ok(!/script-src[^;]*unsafe-inline/.test(csp), 'sin unsafe-inline en scripts');
    assert.ok(!/https?:/.test(csp), 'sin orígenes externos');
    assert.ok(!/fonts\.googleapis|fonts\.gstatic/.test(r.body));
  });
  await t.test('sirve solo las fuentes locales', async () => {
    const ok = await req('GET', '/fonts/jetbrains-mono.woff2', host);
    assert.equal(ok.status, 200);
    assert.equal(ok.headers['content-type'], 'font/woff2');
    for (const bad of ['/fonts/../server.js', '/fonts/%2e%2e%2fserver.js', '/fonts/OFL.txt', '/fonts/nope.woff2']) {
      assert.equal((await req('GET', bad, host)).status, 404, bad);
    }
  });
  await t.test('sirve la interfaz con cabeceras de seguridad', async () => {
    const r = await req('GET', '/', host);
    assert.equal(r.status, 200);
    assert.match(r.body, /<!doctype html>/i);
    assert.match(r.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.equal(r.headers['x-frame-options'], 'DENY');
    assert.equal(r.headers['x-content-type-options'], 'nosniff');
  });
  await t.test('bloquea DNS rebinding (Host ajeno)', async () => {
    const r = await req('GET', '/api/health', { host: `evil.example:${PORT}` });
    assert.equal(r.status, 403);
  });
  await t.test('bloquea peticiones desde otras webs (Origin)', async () => {
    const r = await req('POST', '/api/analyze', { ...host, origin: 'https://evil.example', 'content-type': 'application/json' }, '{}');
    assert.equal(r.status, 403);
  });
  await t.test('exige JSON', async () => {
    const r = await req('POST', '/api/analyze', { ...host, 'content-type': 'text/plain' }, 'url=x');
    assert.equal(r.status, 415);
  });
  await t.test('clonar sin análisis previo falla', async () => {
    const r = await req('POST', '/api/clone', { ...host, 'content-type': 'application/json' }, JSON.stringify({ id: 'nope' }));
    assert.ok(r.status >= 400);
  });
});

function startServer(env) {
  const child = spawn(process.execPath, [path.join(__dirname, '..', 'server.js')], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  let out = '';
  child.stdout.on('data', (c) => { out += c; });
  child.stderr.on('data', (c) => { out += c; });
  const ready = new Promise((resolve) => {
    child.on('exit', (code) => resolve({ exited: true, code, out }));
    child.stdout.on('data', () => { if (/escuchando/.test(out)) resolve({ exited: false }); });
  });
  return { child, ready };
}

test('expuesta sin token no arranca', async () => {
  const { ready } = startServer({ PORT: String(PORT + 1), ALLOWED_HOSTS: `ominous.example:${PORT + 1}`, OMINOUS_TOKEN: '' });
  const r = await ready;
  assert.equal(r.exited, true);
  assert.equal(r.code, 1);
  assert.match(r.out, /OMINOUS_TOKEN/);
});

test('expuesta con token exige el token', async (t) => {
  const port = PORT + 2;
  const tokenValue = 'x'.repeat(32);
  const { child, ready } = startServer({ PORT: String(port), ALLOWED_HOSTS: `ominous.example:${port}`, OMINOUS_TOKEN: tokenValue });
  t.after(() => child.kill());
  assert.equal((await ready).exited, false);
  const get = (headers) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: '/api/health', headers: { host: `ominous.example:${port}`, ...headers } }, (res) => { res.resume(); resolve(res.statusCode); }).on('error', reject);
  });
  assert.equal(await get({}), 200, 'la salud no exige token');
  const page = await new Promise((resolve) => http.get({ host: '127.0.0.1', port, path: '/', headers: { host: `ominous.example:${port}` } }, (res) => { res.resume(); resolve(res.statusCode); }));
  assert.equal(page, 401);
  const api = await new Promise((resolve) => { const r = http.request({ host: '127.0.0.1', port, method: 'POST', path: '/api/analyze', headers: { host: `ominous.example:${port}`, 'content-type': 'application/json' } }, (res) => { res.resume(); resolve(res.statusCode); }); r.end('{}'); });
  assert.equal(api, 401);
  const getRoot = (headers) => new Promise((resolve) => http.get({ host: '127.0.0.1', port, path: '/', headers: { host: `ominous.example:${port}`, ...headers } }, (res) => { res.resume(); resolve(res.statusCode); }));
  assert.equal(await getRoot({ authorization: 'Bearer incorrecto' }), 401);
  assert.equal(await getRoot({ authorization: `Bearer ${tokenValue}` }), 200);
  assert.equal(await getRoot({ cookie: `ominous_token=${tokenValue}` }), 200);
});
