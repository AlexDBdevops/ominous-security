'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const fx = require('./helpers/fixtures');
const netcache = require('../lib/netcache');

test('caché de consultas: repite la respuesta correcta y no guarda errores', async (t) => {
  const dir = fx.tmpDir('netcache');
  const real = global.fetch;
  let calls = 0;
  let status = 200;
  global.fetch = async () => { calls++; return new Response(JSON.stringify({ n: calls }), { status, headers: { 'content-type': 'application/json' } }); };
  t.after(() => { global.fetch = real; netcache.disable(); fx.rm(dir); });

  // Apagada por defecto: cada llamada va a la red
  await netcache.cachedFetch('https://api.osv.dev/v1/vulns/X');
  await netcache.cachedFetch('https://api.osv.dev/v1/vulns/X');
  assert.equal(calls, 2);

  netcache.enable({ dir });
  const a = await (await netcache.cachedFetch('https://api.osv.dev/v1/vulns/Y')).json();
  const b = await (await netcache.cachedFetch('https://api.osv.dev/v1/vulns/Y')).json();
  assert.deepEqual(a, b);
  assert.equal(calls, 3, 'la segunda vez sale de la caché');
  // Distinto cuerpo en un POST = distinta consulta
  await netcache.cachedFetch('https://api.osv.dev/v1/querybatch', { method: 'POST', body: '{"q":1}' });
  await netcache.cachedFetch('https://api.osv.dev/v1/querybatch', { method: 'POST', body: '{"q":2}' });
  assert.equal(calls, 5);
  // Un error no se guarda
  status = 503;
  await netcache.cachedFetch('https://api.osv.dev/v1/vulns/Z');
  status = 200;
  await netcache.cachedFetch('https://api.osv.dev/v1/vulns/Z');
  assert.equal(calls, 7);
  // Persiste en disco (otro proceso o tras reiniciar): se vacía la memoria y sigue sin preguntar
  assert.ok(fs.readdirSync(dir).length >= 3);
  netcache.disable();
  netcache.enable({ dir });
  await netcache.cachedFetch('https://api.osv.dev/v1/vulns/Y');
  assert.equal(calls, 7);
  // Caducada: vuelve a preguntar
  await netcache.cachedFetch('https://api.osv.dev/v1/vulns/Y', {}, 0);
  assert.equal(calls, 8);
});
