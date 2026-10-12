#!/usr/bin/env node
'use strict';
// Escaneo por línea de comandos de una carpeta local (pensado para CI).
// Uso: node bin/ominous-scan.js <carpeta> [--exclude a,b/] [--fail-on red|yellow|never]
//                                         [--json informe.json] [--sarif ominous.sarif] [--codequality gl-code-quality-report.json]
// Código de salida: 0 si el veredicto no alcanza --fail-on, 1 si lo alcanza, 2 si hay un error.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { analyzeTree } = require('../lib/analyzer');

const USAGE = 'Uso: ominous-scan <carpeta> [--exclude a,b/] [--fail-on red|yellow|never] [--json fichero] [--sarif fichero] [--codequality fichero]';
// Severidades de Code Quality de GitLab: info, minor, major, critical, blocker
const CQ_SEVERITY = { info: 'info', low: 'minor', medium: 'major', high: 'critical', critical: 'blocker' };
// Niveles SARIF (GitHub code scanning) y puntuación security-severity (0-10)
const SARIF_LEVEL = { info: 'note', low: 'note', medium: 'warning', high: 'error', critical: 'error' };
const SARIF_SCORE = { info: '0.0', low: '3.0', medium: '5.5', high: '8.0', critical: '9.5' };

function parseArgs(argv) {
  const opts = { dir: null, exclude: [], failOn: 'red', json: null, sarif: null, codequality: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const val = () => { if (i + 1 >= argv.length) throw new Error(`Falta el valor de ${a}`); return argv[++i]; };
    if (a === '--exclude') opts.exclude.push(...val().split(',').map((s) => s.trim()).filter(Boolean));
    else if (a === '--fail-on') opts.failOn = val();
    else if (a === '--json') opts.json = val();
    else if (a === '--sarif') opts.sarif = val();
    else if (a === '--codequality') opts.codequality = val();
    else if (a === '-h' || a === '--help') opts.help = true;
    else if (a.startsWith('-')) throw new Error(`Opción desconocida: ${a}`);
    else if (!opts.dir) opts.dir = a;
    else throw new Error(`Argumento de más: ${a}`);
  }
  if (!['red', 'yellow', 'never'].includes(opts.failOn)) throw new Error('--fail-on debe ser red, yellow o never');
  return opts;
}

function toCodeQuality(result) {
  return [...result.vulnerabilities, ...result.threats].map((f) => ({
    description: `${f.kind === 'threat' ? 'Amenaza' : 'Vulnerabilidad'}: ${f.title}`,
    check_name: `ominous/${f.rule}`,
    fingerprint: crypto.createHash('sha256').update(`${f.rule}|${f.file || ''}|${f.line || 0}|${f.snippet || ''}`).digest('hex'),
    severity: CQ_SEVERITY[f.severity] || 'info',
    location: { path: f.file || '.', lines: { begin: f.line || 1 } },
  }));
}

function toSarif(result) {
  const findings = [...result.vulnerabilities, ...result.threats];
  const rules = new Map();
  for (const f of findings) {
    if (rules.has(f.rule)) continue;
    rules.set(f.rule, {
      id: f.rule,
      name: f.rule,
      shortDescription: { text: f.title },
      fullDescription: { text: f.description || f.title },
      help: { text: f.fix ? f.fix.text : (f.notFixableReason || f.description || f.title) },
      properties: { tags: ['security', f.kind === 'threat' ? 'malicious' : 'vulnerability'], 'security-severity': SARIF_SCORE[f.severity] || '0.0' },
    });
  }
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: 'Ominous Security', informationUri: 'https://github.com/AlexDBdevops/ominous-security', rules: [...rules.values()] } },
      results: findings.map((f) => ({
        ruleId: f.rule,
        level: SARIF_LEVEL[f.severity] || 'note',
        message: { text: `${f.title}${f.snippet ? `: ${f.snippet}` : ''}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file || '.' }, region: { startLine: f.line || 1 } } }],
        partialFingerprints: { ominous: crypto.createHash('sha256').update(`${f.rule}|${f.file || ''}|${f.snippet || ''}`).digest('hex') },
      })),
    }],
  };
}

function shouldFail(overall, failOn) {
  if (failOn === 'never') return false;
  if (failOn === 'yellow') return overall !== 'green';
  return overall === 'red';
}

async function main(argv = process.argv.slice(2)) {
  const opts = parseArgs(argv);
  if (opts.help || !opts.dir) { console.log(USAGE); return opts.help ? 0 : 2; }
  const root = path.resolve(opts.dir);
  if (!fs.statSync(root).isDirectory()) throw new Error(`${root} no es una carpeta`);

  const result = await analyzeTree(root, {}, () => {}, { exclude: opts.exclude });
  delete result.aiContext; // solo lo usa el servidor para la revisión con IA
  const { summary } = result;

  for (const f of [...result.threats, ...result.vulnerabilities]) {
    if (f.severity === 'info') continue;
    const where = f.file ? `${f.file}${f.line ? `:${f.line}` : ''}` : '';
    console.log(`[${f.severity.toUpperCase()}] ${f.kind === 'threat' ? 'amenaza' : 'vuln'} ${f.rule} ${where} ${f.title}`);
  }
  console.log(`\nVeredicto: ${summary.overall} (vulnerabilidades ${summary.vulnStatus}, amenazas ${summary.threatStatus}); ${result.stats.files} ficheros, ${result.vulnerabilities.length} vulnerabilidades, ${result.threats.length} amenazas`);

  if (opts.json) fs.writeFileSync(opts.json, JSON.stringify(result, null, 2));
  if (opts.sarif) fs.writeFileSync(opts.sarif, JSON.stringify(toSarif(result), null, 2));
  if (opts.codequality) fs.writeFileSync(opts.codequality, JSON.stringify(toCodeQuality(result), null, 2));
  return shouldFail(summary.overall, opts.failOn) ? 1 : 0;
}

if (require.main === module) {
  main().then((code) => process.exit(code)).catch((e) => { console.error(`Error: ${e.message}`); process.exit(2); });
}

module.exports = { main, parseArgs, toCodeQuality, toSarif, shouldFail };
