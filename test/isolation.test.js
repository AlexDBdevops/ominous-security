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

test('aislamiento: una cabecera PROXY que dice venir del scanner se rechaza', () => {
  const { clientFromLine } = require('../lib/proxyproto');
  const scanner = new Set(['172.20.0.5']);
  assert.equal(clientFromLine('PROXY TCP4 172.18.0.1 172.18.0.3 51000 8080', '172.18.0.3', scanner), '172.18.0.1', 'tu navegador, por el puerto publicado');
  assert.equal(clientFromLine('PROXY TCP4 172.20.0.5 172.20.0.2 51000 8080', '172.18.0.3', scanner), null, 'el scanner');
  assert.equal(clientFromLine('PROXY TCP6 ::ffff:172.20.0.5 ::1 51000 8080', '172.18.0.3', scanner), null, 'el scanner escrito como IPv6');
  assert.equal(clientFromLine('PROXY UNKNOWN', '172.18.0.3', scanner), '172.18.0.3');
  assert.equal(clientFromLine('PROXY TCP4 nada 1.2.3.4 1 2', '172.18.0.3', scanner), null, 'IP no válida');
  assert.equal(clientFromLine('GET / HTTP/1.1', '172.18.0.3', scanner), null, 'sin cabecera');
});

test('aislamiento: el scanner no comparte red con la pasarela de entrada', () => {
  // Lectura mínima de compose.yaml: las redes de cada servicio
  const yaml = require('fs').readFileSync(require('path').join(__dirname, '..', 'compose.yaml'), 'utf8');
  const nets = {};
  let svc = null;
  for (const line of yaml.split('\n')) {
    const s = line.match(/^ {2}([a-z-]+):\s*$/);
    if (s) svc = s[1];
    const n = line.match(/^ {4}networks:\s*\[([^\]]*)\]/);
    if (svc && n) nets[svc] = n[1].split(',').map((x) => x.trim());
  }
  assert.ok(nets.gateway && nets.scanner && nets.app && nets['salida-scanner'], JSON.stringify(nets));
  assert.deepEqual(nets.scanner.filter((x) => nets.gateway.includes(x)), [], 'scanner y pasarela de entrada sin red común');
  assert.ok(nets.scanner.some((x) => nets.app.includes(x)), 'la app llega al scanner');
  assert.ok(nets.scanner.some((x) => nets['salida-scanner'].includes(x)), 'el scanner tiene salida');
  assert.match(yaml, /salida-scanner:[\s\S]*?GATEWAY_PORT: "0"/, 'la salida del scanner no tiene entrada');
  assert.match(yaml, /OMINOUS_PROXY_DENY: scanner/);
});

test('aislamiento: los identificadores de OSV llegan a la app (la vigilancia los da por conocidos)', () => {
  const s = ok();
  s.result.vulnerabilities = [{ rule: 'dep-vuln', severity: 'high', title: 'werkzeug@0.14.1', file: 'requirements.txt', fixable: true, advisories: ['GHSA-xg9f-g7g7-2323', 'CVE-2023-25577', '-x', '../a', 'a b', 7] }];
  const r = checkScan(s, ref);
  assert.deepEqual(r.result.vulnerabilities[0].advisories, ['GHSA-xg9f-g7g7-2323', 'CVE-2023-25577']);
});
