'use strict';
// Paquete web (public/analyzer.js) con un GitHub simulado: mismo resultado que el
// analizador de Node sobre el mismo árbol, motivos claros de cada error y parche.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const fx = require('./helpers/fixtures');
const { analyzeTree } = require('../lib/analyzer');

const BUNDLE = fs.readFileSync(path.join(__dirname, '..', 'public', 'analyzer.js'), 'utf8');
const SHA = 'a'.repeat(40);

function listTree(root, rel = '') {
  const out = [];
  for (const e of fs.readdirSync(path.join(root, rel), { withFileTypes: true })) {
    const r = rel ? `${rel}/${e.name}` : e.name;
    if (e.name === '.git') continue;
    if (e.isDirectory()) { out.push(...listTree(root, r)); continue; }
    const abs = path.join(root, r);
    if (e.isSymbolicLink()) out.push({ path: r, mode: '120000', type: 'blob', size: fs.readlinkSync(abs).length, link: fs.readlinkSync(abs) });
    else out.push({ path: r, mode: '100644', type: 'blob', size: fs.statSync(abs).size });
  }
  return out;
}

// Simula api.github.com y raw.githubusercontent.com a partir de una carpeta.
function fakeGithub(root, { owner = 'acme', repo = 'tool', users = ['acme'], limit = false, calls = [] } = {}) {
  const tree = listTree(root);
  const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
  return async (url) => {
    calls.push(url);
    const u = new URL(url);
    if (u.hostname === 'api.osv.dev' || u.hostname === 'api.securityscorecards.dev') throw new TypeError('Failed to fetch');
    if (u.hostname === 'raw.githubusercontent.com') {
      const p = decodeURIComponent(u.pathname.split('/').slice(4).join('/'));
      const e = tree.find((x) => x.path === p);
      if (!e) return new Response('404', { status: 404 });
      return new Response(e.link != null ? e.link : fs.readFileSync(path.join(root, p)));
    }
    if (limit) return json(403, { message: 'API rate limit exceeded' }, { 'x-ratelimit-remaining': '0', 'x-ratelimit-reset': String(Math.floor(Date.now() / 1000) + 600) });
    const p = u.pathname;
    let m;
    if ((m = p.match(/^\/users\/([^/]+)$/))) return users.includes(m[1]) ? json(200, { login: m[1], created_at: '2015-01-01T00:00:00Z' }) : json(404, { message: 'Not Found' });
    const base = `/repos/${owner}/${repo}`;
    if (p === base) return json(200, { full_name: `${owner}/${repo}`, default_branch: 'main', stargazers_count: 50, forks_count: 1, created_at: '2019-01-01T00:00:00Z', pushed_at: '2026-01-01T00:00:00Z', license: { spdx_id: 'MIT' }, owner: { type: 'User' }, size: 10 });
    if (p === `${base}/commits/main`) return new Response(SHA);
    if (p.startsWith(`${base}/commits/`)) return json(422, { message: 'No commit found' });
    if (p === `${base}/git/trees/${SHA}`) return json(200, { sha: SHA, truncated: false, tree: tree.map(({ link, ...e }) => e) });
    if (p === `${base}/releases`) return json(200, []);
    return json(404, { message: 'Not Found' });
  };
}

function loadBundle(fetchImpl) {
  const ctx = { window: {}, fetch: fetchImpl, Response, URL, TextDecoder, TextEncoder, AbortSignal, AbortController, setTimeout, clearTimeout, console, Uint8Array, ArrayBuffer, crypto: globalThis.crypto, Date, Math, JSON, Promise };
  ctx.globalThis = ctx;
  vm.createContext(ctx);
  vm.runInContext(BUNDLE, ctx);
  return ctx.window.Ominous;
}

function call(om, msg) {
  return new Promise((resolve) => {
    const logs = [];
    om.handle(msg, (m) => { if (m.log) logs.push(m.log); else resolve({ ...m, logs }); });
  });
}

const key = (f) => `${f.kind}:${f.rule}:${f.file}:${f.line}:${f.severity}`;
const REPO_LEVEL = new Set(['new-repo', 'fake-stars', 'repo-moved', 'release-binaries']);

for (const name of ['trapRepo2', 'trapRepo3']) {
  test(`web: ${name} da los mismos hallazgos que en Node (payloads, imágenes, cifrado)`, async (t) => {
    const dir = fx[name]();
    t.after(() => fx.rm(dir));
    const r = await call(loadBundle(fakeGithub(dir)), { type: 'analyze', url: 'https://github.com/acme/tool' });
    assert.ifError(r.error && new Error(r.error.message));
    const node = await analyzeTree(fs.realpathSync(dir), null);
    const pick = (d) => [...d.vulnerabilities, ...d.threats].filter((f) => !REPO_LEVEL.has(f.rule)).map((f) => `${key(f)}:${f.decoded ? f.decoded.layers.join('>') : ''}`).sort();
    assert.ok(pick(node).length);
    assert.deepEqual(pick(r.result), pick(node));
  });
}

test('web: mismo análisis que el de Node sobre el mismo commit', async (t) => {
  const dir = fx.trapRepo();
  t.after(() => fx.rm(dir));
  const om = loadBundle(fakeGithub(dir));
  const r = await call(om, { type: 'analyze', url: 'https://github.com/acme/tool' });
  assert.ifError(r.error && new Error(r.error.message));
  const web = r.result;
  const node = await analyzeTree(fs.realpathSync(dir), null);
  const pick = (d) => [...d.vulnerabilities, ...d.threats].filter((f) => !REPO_LEVEL.has(f.rule)).map(key).sort();
  assert.deepEqual(pick(web), pick(node));
  assert.equal(web.repo.commit, SHA);
  assert.equal(web.summary.overall, node.summary.overall);
  assert.ok([...web.vulnerabilities, ...web.threats].every((f) => f.explain && f.explain.why), 'cada hallazgo lleva su ficha');
  assert.ok(web.coverage.some((c) => c.label === 'Historial de git' && c.status === 'skip'));
  assert.ok(web.coverage.some((c) => /OSV/.test(c.label) && c.status === 'skip'), 'sin OSV se marca como no revisado');
  assert.ok(web.aiPrompt.prompt.includes('<repo>'));
  assert.ok(r.logs.length > 2);
});

test('web: parche de los arreglos automáticos sin tocar el análisis en memoria', async (t) => {
  const dir = fx.trapRepo();
  t.after(() => fx.rm(dir));
  const om = loadBundle(fakeGithub(dir));
  const a = (await call(om, { type: 'analyze', url: 'github.com/acme/tool' })).result;
  const auto = a.vulnerabilities.filter((v) => v.fix && v.fix.auto && v.severity !== 'info');
  assert.ok(auto.length, 'el repo trampa tiene arreglos automáticos');
  const p1 = (await call(om, { type: 'patch', findings: auto })).result;
  const p2 = (await call(om, { type: 'patch', findings: auto })).result;
  assert.ok(p1.applied.length);
  assert.match(p1.diff, /^diff --git a\/\S+ b\/\S+\n--- a\/\S+\n\+\+\+ b\/\S+\n@@ -\d+,\d+ \+\d+,\d+ @@/);
  assert.equal(p1.diff, p2.diff, 'los ficheros vuelven a su estado original');
  // git apply lo acepta tal cual sobre el commit original
  const { execFileSync } = require('child_process');
  try { execFileSync('git', ['--version'], { stdio: 'pipe' }); } catch { return; }
  const pf = path.join(dir, '..', `${path.basename(dir)}.patch`);
  fs.writeFileSync(pf, p1.diff);
  t.after(() => fs.rmSync(pf, { force: true }));
  execFileSync('git', ['apply', '--check', pf], { cwd: dir, stdio: 'pipe' });
});

test('web: 404 explica si falta la cuenta o el repo', async (t) => {
  const dir = fx.cleanRepo();
  t.after(() => fx.rm(dir));
  const om = loadBundle(fakeGithub(dir));
  const noUser = (await call(om, { type: 'analyze', url: 'https://github.com/fantasma/x' })).error;
  assert.equal(noUser.status, 404);
  assert.match(noUser.message, /cuenta «fantasma» no existe/);
  assert.ok(noUser.reasons.some((x) => /suspendido/.test(x)));
  const noRepo = (await call(om, { type: 'analyze', url: 'https://github.com/acme/secreto' })).error;
  assert.equal(noRepo.status, 404);
  assert.match(noRepo.message, /ningún repositorio público/);
  assert.ok(noRepo.reasons.some((x) => /privado/.test(x)));
  assert.ok(noRepo.reasons.some((x) => /cambiado de nombre/.test(x)));
  const noBranch = (await call(om, { type: 'analyze', url: 'https://github.com/acme/tool/tree/nope' })).error;
  assert.match(noBranch.message, /rama «nope» no existe/);
});

test('web: límite de GitHub, sin conexión y URL no válida', async (t) => {
  const dir = fx.cleanRepo();
  t.after(() => fx.rm(dir));
  const limited = (await call(loadBundle(fakeGithub(dir, { limit: true })), { type: 'analyze', url: 'https://github.com/acme/tool' })).error;
  assert.equal(limited.status, 429);
  assert.ok(limited.reasons.some((x) => /60 consultas/.test(x)));
  const offline = (await call(loadBundle(async () => { throw new TypeError('Failed to fetch'); }), { type: 'analyze', url: 'https://github.com/acme/tool' })).error;
  assert.match(offline.message, /No se pudo conectar con GitHub/);
  assert.ok(offline.reasons.some((x) => /claude\.ai/.test(x)));
  const bad = (await call(loadBundle(fakeGithub(dir)), { type: 'analyze', url: 'https://evil.example/acme/tool' })).error;
  assert.equal(bad.status, 400);
});

test('web: solo pide a los servicios permitidos por la CSP, y descarga el commit analizado', async (t) => {
  const dir = fx.cleanRepo();
  t.after(() => fx.rm(dir));
  const calls = [];
  const r = await call(loadBundle(fakeGithub(dir, { calls })), { type: 'analyze', url: 'https://github.com/acme/tool' });
  assert.ok(r.result);
  const allowed = require('../lib/page').WEB_HOSTS.map((h) => new URL(h).hostname);
  for (const c of calls) assert.ok(allowed.includes(new URL(c).hostname), c);
  assert.ok(calls.filter((c) => c.includes('raw.githubusercontent.com')).every((c) => c.includes(`/${SHA}/`)));
});

test('web: el paquete está al día con lib/ y web/', () => {
  const { execFileSync } = require('child_process');
  let esbuild = true;
  try { require.resolve('esbuild'); } catch { esbuild = false; }
  if (!esbuild) return;
  execFileSync(process.execPath, [path.join(__dirname, '..', 'scripts', 'build-web.js'), '--check'], { stdio: 'pipe' });
});

test('web: el parche respeta ficheros sin salto de línea final', (t) => {
  const { execFileSync } = require('child_process');
  try { execFileSync('git', ['--version'], { stdio: 'pipe' }); } catch { return; }
  const { fileDiff } = require('../web/entry');
  const dir = fx.tmpDir('eol');
  t.after(() => fx.rm(dir));
  const before = 'uno\ndos\ntres\ncuatro';
  fs.writeFileSync(path.join(dir, 'f.txt'), before);
  fs.writeFileSync(path.join(dir, 'p.diff'), fileDiff('f.txt', before, 'uno\ndos\ntres\nCUATRO'));
  execFileSync('git', ['apply', 'p.diff'], { cwd: dir, stdio: 'pipe' });
  assert.equal(fs.readFileSync(path.join(dir, 'f.txt'), 'utf8'), 'uno\ndos\ntres\nCUATRO');
});

test('web: el token de GitHub solo va a api.github.com y se valida', async (t) => {
  const dir = fx.cleanRepo();
  t.after(() => fx.rm(dir));
  const seen = [];
  const inner = fakeGithub(dir);
  const om = loadBundle(async (url, opts) => { seen.push([new URL(url).hostname, (opts.headers || {}).authorization || null]); return inner(url, opts); });
  const tok = `github_pat_${'A'.repeat(60)}`;
  const r = await call(om, { type: 'analyze', url: 'https://github.com/acme/tool', token: tok });
  assert.ok(r.result);
  for (const [host, auth] of seen) assert.equal(auth, host === 'api.github.com' ? `Bearer ${tok}` : null, host);
  const bad = (await call(om, { type: 'analyze', url: 'https://github.com/acme/tool', token: 'hola' })).error;
  assert.equal(bad.status, 400);
  assert.ok(!JSON.stringify(bad).includes(tok));
  seen.length = 0;
  await call(om, { type: 'analyze', url: 'https://github.com/acme/tool' });
  assert.ok(seen.every(([, auth]) => auth === null), 'sin token en el análisis siguiente');
});

test('web: en la página (sin worker) el análisis lleva plazo y lo dice en la cobertura', async (t) => {
  const dir = fx.trapRepo2();
  t.after(() => fx.rm(dir));
  const om = loadBundle(fakeGithub(dir));
  const r = await call(om, { type: 'analyze', url: 'https://github.com/acme/tool', budgetMs: 5 * 60 * 1000, signal: new AbortController().signal });
  assert.ifError(r.error && new Error(r.error.message));
  assert.ok(r.result.coverage.some((c) => c.label === 'Corte por tiempo' && /5 minutos/.test(c.detail)));
  const ctl = new AbortController();
  ctl.abort();
  const gone = await call(om, { type: 'analyze', url: 'https://github.com/acme/tool', budgetMs: 5 * 60 * 1000, signal: ctl.signal });
  assert.match(gone.error.message, /cancelado/, 'al lanzar otro análisis el anterior se cancela');
});
