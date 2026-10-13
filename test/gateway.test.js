'use strict';
// Pasarela de red de Docker (lib/gateway.js): reenvía la entrada y solo deja salir HTTPS a
// direcciones públicas. Sin Internet: se comprueba lo que bloquea y que la entrada funciona.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const net = require('net');
const path = require('path');
const { spawn } = require('child_process');

const freePort = () => new Promise((r) => { const s = net.createServer().listen(0, '127.0.0.1', () => { const { port } = s.address(); s.close(() => r(port)); }); });
const connect = (port, target) => new Promise((r) => {
  const q = http.request({ host: '127.0.0.1', port, method: 'CONNECT', path: target });
  q.on('connect', (res, sock) => { sock.destroy(); r(res.statusCode); });
  q.on('error', (e) => r(e.code));
  q.end();
});

test('pasarela: entrada a la app y salida solo HTTPS a direcciones públicas', async (t) => {
  const app = http.createServer((req, res) => res.end(`app:${req.headers.host}`)).listen(0, '127.0.0.1');
  await new Promise((r) => app.on('listening', r));
  const [inPort, outPort] = [await freePort(), await freePort()];
  const gw = spawn(process.execPath, [path.join(__dirname, '..', 'lib', 'gateway.js')], {
    env: { ...process.env, GATEWAY_APP: `127.0.0.1:${app.address().port}`, GATEWAY_PORT: String(inPort), EGRESS_PORT: String(outPort) }, stdio: ['ignore', 'pipe', 'inherit'],
  });
  let out = '';
  gw.stdout.on('data', (d) => { out += d; });
  t.after(() => { gw.kill(); app.close(); });
  for (let i = 0; i < 50 && !/salida/.test(out); i++) await new Promise((r) => setTimeout(r, 100));

  const body = await new Promise((r, j) => http.get({ host: '127.0.0.1', port: inPort, headers: { host: 'localhost:8080' } }, (res) => { let b = ''; res.on('data', (d) => { b += d; }); res.on('end', () => r(b)); }).on('error', j));
  assert.equal(body, 'app:localhost:8080', 'la entrada llega a la app con su Host');

  assert.equal(await connect(outPort, '127.0.0.1:443'), 403, 'loopback');
  assert.equal(await connect(outPort, '10.0.0.1:443'), 403, 'red privada');
  assert.equal(await connect(outPort, '169.254.169.254:443'), 403, 'metadatos de la nube');
  assert.equal(await connect(outPort, 'localhost:443'), 403, 'nombre que resuelve a local');
  assert.equal(await connect(outPort, 'example.com:22'), 403, 'solo el puerto 443');
  assert.equal(await connect(outPort, 'a_b!:443'), 400, 'destino no válido');
  const plain = await new Promise((r) => http.get({ host: '127.0.0.1', port: outPort, path: 'http://example.com/' }, (res) => { res.resume(); r(res.statusCode); }).on('error', (e) => r(e.code)));
  assert.equal(plain, 405, 'HTTP sin cifrar no se reenvía');
  assert.match(out, /bloqueado: 127\.0\.0\.1:443/);
});
