'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const { parseArgs, shouldFail, toCodeQuality, toSarif } = require('../bin/ominous-scan');
const fx = require('./helpers/fixtures');

const CLI = path.join(__dirname, '..', 'bin', 'ominous-scan.js');
const run = (args) => {
  try { return { code: 0, out: execFileSync(process.execPath, [CLI, ...args], { env: { ...process.env, OMINOUS_OFFLINE: '1' }, encoding: 'utf8' }) }; }
  catch (e) { return { code: e.status, out: e.stdout + e.stderr }; }
};

test('parseArgs', () => {
  const o = parseArgs(['.', '--exclude', 'a,b/', '--fail-on', 'yellow', '--codequality', 'cq.json']);
  assert.deepEqual(o.exclude, ['a', 'b/']);
  assert.equal(o.failOn, 'yellow');
  assert.throws(() => parseArgs(['.', '--fail-on', 'purple']));
  assert.throws(() => parseArgs(['.', '--nope']));
});

test('shouldFail', () => {
  assert.equal(shouldFail('red', 'red'), true);
  assert.equal(shouldFail('yellow', 'red'), false);
  assert.equal(shouldFail('yellow', 'yellow'), true);
  assert.equal(shouldFail('red', 'never'), false);
});

test('toCodeQuality genera el formato de GitLab', () => {
  const [i] = toCodeQuality({ vulnerabilities: [{ kind: 'vuln', rule: 'py-yaml', severity: 'high', title: 'X', file: 'a.py', line: 3 }], threats: [] });
  assert.equal(i.check_name, 'ominous/py-yaml');
  assert.equal(i.severity, 'critical');
  assert.deepEqual(i.location, { path: 'a.py', lines: { begin: 3 } });
  assert.match(i.fingerprint, /^[0-9a-f]{64}$/);
});

test('toSarif genera SARIF 2.1.0 para GitHub code scanning', () => {
  const s = toSarif({ vulnerabilities: [{ kind: 'vuln', rule: 'py-yaml', severity: 'high', title: 'X', description: 'd', file: 'a.py', line: 3, fix: { text: 'f' } }], threats: [{ kind: 'threat', rule: 'curl-pipe', severity: 'critical', title: 'Y', file: 'b.sh', line: 1 }] });
  assert.equal(s.version, '2.1.0');
  const run = s.runs[0];
  assert.deepEqual(run.tool.driver.rules.map((r) => r.id), ['py-yaml', 'curl-pipe']);
  assert.equal(run.results[1].level, 'error');
  assert.equal(run.tool.driver.rules[1].properties['security-severity'], '9.5');
  assert.equal(run.results[0].locations[0].physicalLocation.region.startLine, 3);
});

test('CLI: repo limpio sale con 0 y repo trampa con 1', (t) => {
  const clean = fx.cleanRepo();
  const trap = fx.trapRepo();
  t.after(() => { fx.rm(clean); fx.rm(trap); });
  assert.equal(run([clean]).code, 0);
  const cq = path.join(trap, '..', `cq-${process.pid}.json`);
  const r = run([trap, '--codequality', cq]);
  assert.equal(r.code, 1);
  assert.match(r.out, /Veredicto: red/);
  const report = JSON.parse(fs.readFileSync(cq, 'utf8'));
  fs.rmSync(cq);
  assert.ok(report.length > 10);
  assert.equal(run(['/no/existe']).code, 2);
});
