'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');

const PORT = 18000 + Math.floor(Math.random() * 2000);
process.env.PORT = String(PORT);
const { parseGithubUrl, server } = require('../server');

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
      res.on('end', () => resolve({ status: res.statusCode, body: data }));
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
  await t.test('sirve la interfaz', async () => {
    const r = await req('GET', '/', host);
    assert.equal(r.status, 200);
    assert.match(r.body, /<!doctype html>/i);
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
