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
  process.env.OMINOUS_SEMGREP_BIN = fakeBin(bins, 'semgrep', `
    const a = process.argv.slice(2).join(' ');
    if (!a.includes('--config p/owasp-top-ten --config /opt/semgrep-rules/python')) process.exit(7);
    process.stdout.write(${JSON.stringify(JSON.stringify(semgrep))});`);
  process.env.OMINOUS_SEMGREP_CONFIG = 'p/owasp-top-ten, /opt/semgrep-rules/python';
  t.after(() => { delete process.env.OMINOUS_SEMGREP_CONFIG; });
  const trivy = { Results: [{ Target: 'app/config.py', Secrets: [{ RuleID: 'aws-access-key-id', Title: 'AWS Access Key ID', Severity: 'CRITICAL', StartLine: 3 }] }, { Target: 'Dockerfile', Misconfigurations: [{ ID: 'DS002', AVDID: 'AVD-DS-0002', Title: 'Image user should not be root', Message: 'Last USER is root', Severity: 'HIGH', Status: 'FAIL', Resolution: 'Add USER', PrimaryURL: 'https://avd.aquasec.com/misconfig/ds002', CauseMetadata: { StartLine: 1 } }] }] };
  process.env.OMINOUS_TRIVY_BIN = fakeBin(bins, 'trivy', `process.stdout.write(${JSON.stringify(JSON.stringify(trivy))});`);
  process.env.OMINOUS_CODEQL_BIN = path.join(bins, 'no-existe-codeql');
  t.after(() => { for (const id of ['GITLEAKS', 'SEMGREP', 'TRIVY', 'CODEQL']) delete process.env[`OMINOUS_${id}_BIN`]; });

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
  for (const id of ['GITLEAKS', 'SEMGREP', 'TRIVY', 'CODEQL']) process.env[`OMINOUS_${id}_BIN`] = path.join(repo, `no-existe-${id}`);
  t.after(() => { for (const id of ['GITLEAKS', 'SEMGREP', 'TRIVY', 'CODEQL']) delete process.env[`OMINOUS_${id}_BIN`]; });
  const { externalPass } = require('../lib/external');
  const extra = { vulns: [], threats: [], coverage: [] };
  await externalPass(repo, repo, extra);
  assert.deepEqual(extra, { vulns: [], threats: [], coverage: [] });
  process.env.OMINOUS_EXTERNAL = '0';
  t.after(() => { delete process.env.OMINOUS_EXTERNAL; });
  await externalPass(repo, repo, extra);
  assert.equal(extra.coverage.length, 0);
});

test('CodeQL: recorrido del dato, solo seguridad y lenguajes sin compilar', async (t) => {
  const bins = fx.tmpDir('cqbins');
  const repo = fx.write(fx.tmpDir('cq'), { 'server.js': 'x\n', 'app.py': 'x\n', 'Main.java': 'class A {}\n', 'node_modules/x/i.rb': 'x\n' });
  const tmp = fx.tmpDir('cqtmp');
  t.after(() => { fx.rm(bins); fx.rm(repo); fx.rm(tmp); });
  const loc = (uri, line, text) => ({ location: { physicalLocation: { artifactLocation: { uri }, region: { startLine: line } }, message: { text } } });
  const sarif = { runs: [{ tool: { driver: { name: 'CodeQL', rules: [
    { id: 'js/command-line-injection', shortDescription: { text: 'Uncontrolled command line' }, fullDescription: { text: 'Externally controlled strings in a command line.' }, properties: { tags: ['security', 'external/cwe/cwe-078'], 'security-severity': '9.8' } },
    { id: 'js/unused-local-variable', shortDescription: { text: 'Unused variable' }, properties: { tags: ['maintainability'] } },
  ] } }, results: [
    { ruleId: 'js/command-line-injection', message: { text: 'This command line depends on a [user-provided value](1).' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'server.js' }, region: { startLine: 7 } } }],
      codeFlows: [{ threadFlows: [{ locations: [loc('server.js', 6, 'req.query.host'), loc('server.js', 6, 'host'), loc('server.js', 7, 'ControlFlowNode for build(host)')] }] }] },
    { ruleId: 'js/unused-local-variable', message: { text: 'Unused' }, locations: [{ physicalLocation: { artifactLocation: { uri: 'server.js' }, region: { startLine: 1 } } }] },
  ] }] };
  const calls = path.join(tmp, 'calls.txt');
  process.env.OMINOUS_CODEQL_BIN = fakeBin(bins, 'codeql', `
    const fs = require('fs');
    const a = process.argv.slice(2);
    fs.appendFileSync(${JSON.stringify(calls)}, a.join(' ') + '\\n');
    if (a[0] === 'resolve') { process.stdout.write(JSON.stringify({ javascript: ['/x'], java: ['/x'], ruby: ['/x'] })); process.exit(0); }
    if (a[1] === 'create') { fs.mkdirSync(a[2], { recursive: true }); process.exit(0); }
    if (a[1] === 'analyze') { fs.writeFileSync(a.find((x) => x.startsWith('--output=')).slice(9), JSON.stringify(${JSON.stringify(sarif)})); process.exit(0); }
    process.exit(3);`);
  for (const id of ['GITLEAKS', 'SEMGREP', 'TRIVY']) process.env[`OMINOUS_${id}_BIN`] = path.join(bins, `no-existe-${id}`);
  t.after(() => { for (const id of ['GITLEAKS', 'SEMGREP', 'TRIVY', 'CODEQL']) delete process.env[`OMINOUS_${id}_BIN`]; });

  const { externalPass } = require('../lib/external');
  const extra = { vulns: [], threats: [], coverage: [] };
  await externalPass(repo, tmp, extra);
  assert.equal(extra.vulns.length, 1, 'solo el hallazgo de seguridad');
  const f = extra.vulns[0];
  assert.equal(f.rule, 'ext-codeql');
  assert.equal(f.severity, 'critical');
  assert.equal(f.explain.cwe.id, 'CWE-78');
  assert.match(f.description, /user-provided value\. Recorrido de 3 pasos: entra en server\.js:6 y llega a server\.js:7/);
  assert.deepEqual(f.explain.flow.map((s) => s.text), ['req.query.host', 'host', 'build(host)']);
  const log = fs.readFileSync(calls, 'utf8');
  // Java está instalado pero no se analiza (habría que compilar); Python no está instalado;
  // Ruby solo aparece dentro de node_modules, que no cuenta
  assert.match(log, /--language=javascript/);
  assert.doesNotMatch(log, /--language=(java|python|ruby)\b/);
  assert.doesNotMatch(log, /build-mode|autobuild|--command/);
  assert.deepEqual(extra.coverage, [{ label: 'CodeQL (recorridos de datos)', status: 'ok', detail: '1 hallazgo · JavaScript/TypeScript' }]);
});

test('CodeQL: si un lenguaje falla, los demás siguen y la cobertura queda parcial', async (t) => {
  const bins = fx.tmpDir('cqbins2');
  const repo = fx.write(fx.tmpDir('cq2'), { 'a.js': 'x\n', 'b.py': 'x\n' });
  const tmp = fx.tmpDir('cqtmp2');
  t.after(() => { fx.rm(bins); fx.rm(repo); fx.rm(tmp); });
  process.env.OMINOUS_CODEQL_BIN = fakeBin(bins, 'codeql', `
    const fs = require('fs');
    const a = process.argv.slice(2);
    if (a[0] === 'resolve') { process.stdout.write(JSON.stringify({ javascript: ['/x'], python: ['/x'] })); process.exit(0); }
    if (a[1] === 'create' && a.includes('--language=python')) { process.stderr.write('A fatal error occurred: extractor\\n'); process.exit(1); }
    if (a[1] === 'create') { fs.mkdirSync(a[2], { recursive: true }); process.exit(0); }
    if (a[1] === 'analyze') { fs.writeFileSync(a.find((x) => x.startsWith('--output=')).slice(9), '{"runs":[]}'); process.exit(0); }`);
  for (const id of ['GITLEAKS', 'SEMGREP', 'TRIVY']) process.env[`OMINOUS_${id}_BIN`] = path.join(bins, `no-existe-${id}`);
  t.after(() => { for (const id of ['GITLEAKS', 'SEMGREP', 'TRIVY', 'CODEQL']) delete process.env[`OMINOUS_${id}_BIN`]; });
  const { externalPass } = require('../lib/external');
  const extra = { vulns: [], threats: [], coverage: [] };
  await externalPass(repo, tmp, extra);
  assert.equal(extra.coverage[0].status, 'partial');
  assert.match(extra.coverage[0].detail, /JavaScript\/TypeScript · sin revisar: Python: A fatal error occurred/);
  assert.deepEqual(fs.readdirSync(tmp).filter((n) => n.startsWith('codeql-') && !n.endsWith('.sarif')), [], 'las bases de datos se borran');
});
