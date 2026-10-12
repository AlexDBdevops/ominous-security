'use strict';
// Escaneo del historial de git: secretos y código malicioso que se borraron
// pero siguen dentro del repositorio (cualquiera que lo clone los tiene).

const { spawn } = require('child_process');
const readline = require('readline');
const { vulnRules, threatRules } = require('./rules');

const SECRET_RULES = vulnRules.filter((r) => r.id.startsWith('secret-') && r.id !== 'secret-generic');
const BAD_RULES = threatRules.filter((r) => r.re && ['critical', 'high', 'medium'].includes(r.severity));
const MAX_BYTES = 80 * 1024 * 1024;

function scanHistory(gitArgs, dir, { commits = 300, env, timeoutMs = 120000 } = {}) {
  return new Promise((resolve) => {
    const findings = [];
    const seen = new Set();
    let bytes = 0, scanned = 0, truncated = false;
    let commit = null, file = null;
    const child = spawn('git', [...gitArgs, '-C', dir, 'log', '-p', '--no-color', '--no-ext-diff', '--no-merges', '-n', String(commits), '--format=@@OMINOUS %H%x09%an%x09%ad', '--date=short'], { env });
    const timer = setTimeout(() => { truncated = true; child.kill(); }, timeoutMs);
    const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });

    const add = (kind, rule, line) => {
      const key = `${rule.id}|${file}|${line.slice(0, 80)}`;
      if (seen.has(key) || findings.length >= 60) return;
      seen.add(key);
      const where = `Commit ${commit.sha.slice(0, 10)} (${commit.author}, ${commit.date})`;
      const s = line.slice(1).trim();
      const base = { kind, rule: `history-${rule.id}`, file, line: null, snippet: s.length > 200 ? `${s.slice(0, 200)}…` : s, history: { commit: commit.sha, author: commit.author, date: commit.date } };
      if (kind === 'vuln') {
        findings.push({ ...base, severity: rule.severity, title: `${rule.title} (en el historial de git)`, description: `${where} lo eliminó, pero sigue en el historial: cualquiera que clone el repo puede recuperarlo.`, fixable: false, notFixableReason: 'Hay que revocar la credencial y reescribir el historial (git filter-repo). Solo puede hacerlo el autor.' });
      } else {
        findings.push({ ...base, severity: rule.severity === 'critical' ? 'high' : rule.severity === 'high' ? 'medium' : 'low', title: `${rule.title} (borrado del código, sigue en el historial)`, description: `${where} lo eliminó. No está en la versión actual, pero indica que el autor llegó a publicar código malicioso o comprometido.` });
      }
    };

    rl.on('line', (line) => {
      bytes += line.length + 1;
      if (bytes > MAX_BYTES) { truncated = true; child.kill(); return; }
      if (line.startsWith('@@OMINOUS ')) {
        const [sha, author, date] = line.slice(10).split('\t');
        commit = { sha, author, date };
        scanned++;
        return;
      }
      if (line.startsWith('diff --git ')) { const m = line.match(/ b\/(.+)$/); file = m ? m[1] : null; return; }
      if (!commit || !file || line.length > 1000) return; // líneas cortas: el historial va en el hilo principal
      // Solo líneas eliminadas: lo que hay ahora ya lo analiza el escaneo normal.
      if (line[0] !== '-' || line.startsWith('---')) return;
      for (const r of SECRET_RULES) if (r.ext.test(file) && r.re.test(line) && !(r.skipIf && r.skipIf.test(line))) add('vuln', r, line);
      for (const r of BAD_RULES) if (r.ext.test(file) && r.re.test(line)) add('threat', r, line);
    });
    child.on('close', () => { clearTimeout(timer); resolve({ findings, scanned, truncated }); });
    child.on('error', () => { clearTimeout(timer); resolve({ findings, scanned, truncated: true, error: true }); });
  });
}

module.exports = { scanHistory };
