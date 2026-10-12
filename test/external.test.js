'use strict';
// Herramientas externas opcionales, con ejecutables falsos que imitan su salida JSON.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const fx = require('./helpers/fixtures');

function fakeBin(dir, name, js) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, `#!${process.execPath}\n'use strict';\n${js}\n`);
  fs.chmodSync(p, 0o755);
  return p;
}

test('herramientas externas: hallazgos con su explicación, sin duplicar secretos', async (t) => {
  const bins = fx.tmpDir('bins');
  const repo = fx.write(fx.tmpDir('ext'), { 'app/config.py': 'x = 1\n' });
  const tmp = fx.tmpDir('exttmp');
  t.after(() => { fx.rm(bins); fx.rm(repo); fx.rm(tmp); });
  const gitleaks = { File: 'app/config.py', StartLine: 3, RuleID: 'aws-access-token', Description: 'AWS Access Key', Commit: 'abcdef1234567890', Date: '2026-01-02T00:00:00Z', Match: 'REDACTED' };
  process.env.OMINOUS_GITLEAKS_BIN = fakeBin(bins, 'gitleaks', `
    const a = process.argv.slice(2);
    if (a[0] !== 'git') process.exit(2);
    require('fs').writeFileSync(a[a.indexOf('--report-path') + 1], JSON.stringify([${JSON.stringify(gitleaks)}]));`);
  const semgrep = { results: [{ check_id: 'python.lang.security.audit.eval-detected', path: path.join(repo, 'app/config.py'), start: { line: 1 }, extra: { message: 'Detected eval', severity: 'WARNING', lines: 'eval(x)', metadata: { cwe: ['CWE-95: Eval Injection'], references: ['https://example.org/eval'] } } }] };
  process.env.OMINOUS_SEMGREP_BIN = fakeBin(bins, 'semgrep', `process.stdout.write(${JSON.stringify(JSON.stringify(semgrep))});`);
  const trivy = { Results: [{ Target: 'app/config.py', Secrets: [{ RuleID: 'aws-access-key-id', Title: 'AWS Access Key ID', Severity: 'CRITICAL', StartLine: 3 }] }, { Target: 'Dockerfile', Misconfigurations: [{ ID: 'DS002', AVDID: 'AVD-DS-0002', Title: 'Image user should not be root', Message: 'Last USER is root', Severity: 'HIGH', Status: 'FAIL', Resolution: 'Add USER', PrimaryURL: 'https://avd.aquasec.com/misconfig/ds002', CauseMetadata: { StartLine: 1 } }] }] };
  process.env.OMINOUS_TRIVY_BIN = fakeBin(bins, 'trivy', `process.stdout.write(${JSON.stringify(JSON.stringify(trivy))});`);
  t.after(() => { delete process.env.OMINOUS_GITLEAKS_BIN; delete process.env.OMINOUS_SEMGREP_BIN; delete process.env.OMINOUS_TRIVY_BIN; });

  const { externalPass } = require('../lib/external');
  const extra = { vulns: [], threats: [], coverage: [] };
  await externalPass(repo, tmp, extra);
  const by = (rule) => extra.vulns.filter((v) => v.rule === rule);
  assert.equal(by('ext-gitleaks').length, 1);
  assert.match(by('ext-gitleaks')[0].description, /abcdef1234/);
  assert.equal(by('ext-semgrep')[0].file, 'app/config.py', 'ruta relativa al repo');
  assert.equal(by('ext-semgrep')[0].explain.cwe.id, 'CWE-95');
  assert.equal(by('ext-semgrep')[0].severity, 'medium');
  // El secreto de Trivy está en la misma línea que el de Gitleaks: no se repite
  assert.equal(by('ext-trivy').length, 1);
  assert.equal(by('ext-trivy')[0].fix.text, 'Add USER');
  assert.deepEqual(extra.coverage.map((c) => c.status), ['ok', 'ok', 'ok']);
});

test('herramientas externas: no instaladas o desactivadas no dejan rastro', async (t) => {
  const repo = fx.write(fx.tmpDir('ext2'), { 'a.txt': 'x' });
  t.after(() => fx.rm(repo));
  for (const id of ['GITLEAKS', 'SEMGREP', 'TRIVY']) process.env[`OMINOUS_${id}_BIN`] = path.join(repo, `no-existe-${id}`);
  t.after(() => { for (const id of ['GITLEAKS', 'SEMGREP', 'TRIVY']) delete process.env[`OMINOUS_${id}_BIN`]; });
  const { externalPass } = require('../lib/external');
  const extra = { vulns: [], threats: [], coverage: [] };
  await externalPass(repo, repo, extra);
  assert.deepEqual(extra, { vulns: [], threats: [], coverage: [] });
  process.env.OMINOUS_EXTERNAL = '0';
  t.after(() => { delete process.env.OMINOUS_EXTERNAL; });
  await externalPass(repo, repo, extra);
  assert.equal(extra.coverage.length, 0);
});
