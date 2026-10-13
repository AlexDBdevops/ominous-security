'use strict';
// Aislamiento del análisis: lo que devuelve el contenedor de análisis se comprueba antes de
// usarlo, el scanner solo clona github.com/<owner>/<repo>, y la app solo acepta conexiones de
// la pasarela (con la IP real por PROXY protocol) o locales.
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const net = require('net');
const { checkScan, validBranch } = require('../lib/scanclient');
const { refFrom } = require('../lib/scanner');
const { proxyServer } = require('../lib/proxyproto');

const ref = { owner: 'octo', repo: 'demo' };
const ok = () => ({
  ref: { owner: 'octo', repo: 'demo' }, commit: 'a'.repeat(40), branch: 'main',
  result: {
    vulnerabilities: [{ rule: 'js-eval', severity: 'high', title: 'eval', file: 'a.js', line: 3, fixable: false }],
    threats: [{ rule: 'curl-pipe', severity: 'critical', title: '<img src=x onerror=alert(1)>', file: 'b.sh', line: 1, extra: 'campo desconocido' }],
    coverage: [{ label: 'x', status: 'ok', detail: 'y' }], stats: { files: 2, bytes: 10 }, summary: { vulnStatus: 'red', threatStatus: 'red', overall: 'red' },
    aiContext: { findings: [], tree: ['a.js'], docs: [{ file: 'README.md', why: 'doc', text: 'hola' }], decoded: [], chars: 4 },
  },
});

test('aislamiento: la respuesta del scanner se comprueba entera', () => {
  const s = checkScan(ok(), ref);
  assert.equal(s.commit, 'a'.repeat(40));
  assert.equal(s.result.threats[0].extra, undefined, 'los campos desconocidos no pasan');
  assert.equal(s.result.threats[0].title, '<img src=x onerror=alert(1)>', 'el texto pasa como texto: la página lo pinta sin HTML');
  const bad = (mut) => { const x = ok(); mut(x); return () => checkScan(x, ref); };
  assert.throws(bad((x) => { x.commit = 'HEAD'; }), /commit/);
  assert.throws(bad((x) => { x.commit = `${'a'.repeat(40)}\n--upload-pack=id`; }), /commit/);
  assert.throws(bad((x) => { x.branch = '--upload-pack=touch /tmp/x'; }), /rama/);
  assert.throws(bad((x) => { x.branch = '../../etc'; }), /rama/);
  assert.throws(bad((x) => { x.ref.repo = 'otro'; }), /otro repositorio/);
  assert.throws(bad((x) => { x.result.threats = 'no'; }), /hallazgos/);
  const weird = ok(); weird.result.threats[0].severity = 'nada'; weird.result.summary.overall = 'azul';
  const w = checkScan(weird, ref);
  assert.equal(w.result.threats[0].severity, 'high', 'gravedad desconocida: se muestra, no se esconde');
  assert.equal(w.result.summary.overall, 'red');
  for (const b of ['main', 'release/1.2', 'v1.0.0', 'feature_x+y']) assert.ok(validBranch(b), b);
  for (const b of ['-x', 'a..b', '/a', 'a//b', 'x.lock', 'a b', 'a\nb', '']) assert.ok(!validBranch(b), JSON.stringify(b));
});

test('aislamiento: el scanner solo clona github.com/<owner>/<repo>', () => {
  assert.equal(refFrom({ ref: { owner: 'octo', repo: 'demo' } }).cloneUrl, 'https://github.com/octo/demo.git');
  for (const r of [{ owner: '../x', repo: 'y' }, { owner: 'x', repo: '..' }, { owner: '-x', repo: 'y' }, { owner: 'x', repo: 'y z' }, { owner: 'x@evil.example', repo: 'y' }, { owner: 'x', repo: 'y', cloneUrl: 'file:///etc' }]) {
    const out = (() => { try { return refFrom({ ref: r }); } catch { return null; } })();
    if (out) assert.equal(out.cloneUrl, `https://github.com/${r.owner}/${r.repo}.git`, 'cualquier cloneUrl que llegue se ignora');
    else assert.equal(out, null);
  }
  assert.throws(() => refFrom({ ref: { owner: '../x', repo: 'y' } }), /no válido/);
});

test('aislamiento: la app solo acepta la pasarela (con la IP real) o conexiones locales', async (t) => {
  const seen = [];
  const app = http.createServer((req, res) => { seen.push(req.socket.clientAddress); res.end('ok'); });
  // "localhost" es la pasarela de confianza en esta prueba
  const front = proxyServer(app, 'localhost').listen(0, '127.0.0.1');
  await new Promise((r) => front.once('listening', r));
  t.after(() => front.close());
  const port = front.address().port;
  const raw = (payload) => new Promise((resolve) => {
    const s = net.connect(port, '127.0.0.1', () => s.write(payload));
    let data = '';
    s.on('data', (d) => { data += d; });
    s.on('close', () => resolve(data));
    s.on('error', () => resolve(data));
    setTimeout(() => s.destroy(), 1500);
  });
  // Conexión local sin cabecera (el healthcheck): pasa
  assert.match(await raw('GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n'), /200 OK/);
  assert.equal(seen.pop(), '127.0.0.1');
});
