'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');

// Claude Code falso: responde a --version, auth status y -p, y deja constancia del entorno y la carpeta.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ominous-fakeclaude-'));
const bin = path.join(dir, 'claude');
const log = path.join(dir, 'log.json');
fs.writeFileSync(bin, `#!/usr/bin/env node
const fs = require('fs');
const a = process.argv.slice(2);
if (a[0] === '--version') { console.log('9.9.9 (Claude Code)'); process.exit(0); }
if (a[0] === 'auth') { console.log(JSON.stringify({ loggedIn: process.env.FAKE_LOGGED !== '0', authMethod: 'claude.ai' })); process.exit(process.env.FAKE_LOGGED === '0' ? 1 : 0); }
let input = '';
process.stdin.on('data', (c) => { input += c; });
process.stdin.on('end', () => {
  fs.writeFileSync(${JSON.stringify(log)}, JSON.stringify({ args: a, key: process.env.ANTHROPIC_API_KEY || null, token: process.env.OMINOUS_TOKEN || null, cwd: process.cwd(), files: fs.readdirSync(process.cwd()), input }));
  console.log(JSON.stringify({ type: 'result', is_error: false, result: '{}', modelUsage: { 'claude-sonnet-5-5': {} }, structured_output: { verdict: 'malicioso', summary: 'x', findings: [], falsePositives: [], limits: '' } }));
});
`, { mode: 0o755 });
process.env.OMINOUS_CLAUDE_BIN = bin;
process.env.ANTHROPIC_API_KEY = 'sk-ant-api03-ENVKEYxxxxxxxxxxxxxxxxxxxxxxxxx';
process.env.OMINOUS_TOKEN = 'secreto-que-no-debe-salir-de-la-app';
const conn = require('../lib/connection');
const ai = require('../lib/ai');
test.after(() => fs.rmSync(dir, { recursive: true, force: true }));

test('el estado nunca incluye la clave completa', () => {
  const s = JSON.stringify(conn.status());
  assert.ok(!s.includes('ENVKEYxxxxxxxxxxxxxxxxxxxxxxxxx'));
  assert.equal(conn.status().keySource, 'variable');
});

test('la clave escrita en la ventana solo se acepta por un canal seguro y con formato válido', async () => {
  await assert.rejects(conn.configure({ method: 'api', key: 'sk-ant-api03-' + 'a'.repeat(40) }, { secureChannel: false }), /HTTPS/);
  await assert.rejects(conn.configure({ method: 'api', key: 'hola' }, { secureChannel: true }), /sk-ant-/);
  await assert.rejects(conn.configure({ method: 'otro' }, { secureChannel: true }), /no válido/);
});

test('Claude Code: comprueba la sesión y se marca como conectado', async () => {
  const s = await conn.configure({ method: 'claude-code' }, { secureChannel: false });
  assert.equal(s.connected, true);
  assert.match(s.check.account, /uso de tu plan/);
  process.env.FAKE_LOGGED = '0';
  const s2 = await conn.verify();
  delete process.env.FAKE_LOGGED;
  assert.equal(s2.connected, false);
  assert.match(s2.check.detail, /sin sesión/);
});

test('Claude Code se ejecuta sin herramientas, sin claves y en una carpeta vacía; el repo va por stdin', async () => {
  await conn.configure({ method: 'claude-code' }, { secureChannel: false });
  const ctx = { docs: [{ file: 'a.js', why: 'x', text: 'codigo hostil' }], decoded: [], tree: ['a.js'], findings: [], chars: 13 };
  const r = await ai.aiReview({ repo: { owner: 'o', name: 'n', commit: 'c', meta: {} }, ctx });
  assert.equal(r.via, 'claude-code');
  assert.equal(r.verdict, 'malicioso');
  assert.equal(r.raises, true);
  const l = JSON.parse(fs.readFileSync(log, 'utf8'));
  assert.equal(l.key, null, 'sin ANTHROPIC_API_KEY: usa la cuenta, no la API');
  assert.equal(l.token, null, 'no hereda el token de la app');
  assert.deepEqual(l.files, [], 'carpeta vacía');
  assert.ok(!fs.existsSync(l.cwd), 'la carpeta se borra después');
  for (const f of ['--safe-mode', '--strict-mcp-config', '--no-session-persistence', '--json-schema']) assert.ok(l.args.includes(f), f);
  assert.equal(l.args[l.args.indexOf('--tools') + 1], '', 'sin herramientas');
  assert.equal(l.args[l.args.indexOf('--disallowedTools') + 1], 'mcp__*');
  assert.ok(l.input.includes('codigo hostil') && !l.args.some((x) => x.includes('codigo hostil')), 'el contenido del repo no va en los argumentos');
});

test('desconectar borra la clave y el estado', async () => {
  const s = await conn.configure({ method: 'none' }, { secureChannel: true });
  assert.equal(s.method, null);
  assert.equal(s.connected, false);
  assert.equal(conn._state.key, null);
});
