'use strict';
// Puntúa una tanda de análisis de repos reales contra las etiquetas de labels.json.
//   npm run gold -- <carpeta con los JSON de la tanda>
// Para cada etiqueta: "real" tiene que salir al menos con min (y como mucho max, si lo lleva);
// "ruido" no puede pasar de max. Al final lista las amenazas medias o más sin etiqueta: es lo
// siguiente que hay que revisar. Sale con código 1 si algo falla.
// Las muestras maliciosas están en test/helpers/malware.js y las comprueba npm test.
const fs = require('fs');
const path = require('path');

const RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
const NAMES = Object.keys(RANK);
const batch = process.argv[2];
if (!batch) { console.error('Uso: npm run gold -- <carpeta de la tanda>'); process.exit(2); }
const { labels } = JSON.parse(fs.readFileSync(path.join(__dirname, 'labels.json'), 'utf8'));
const ok = [];
const bad = [];
const unlabelled = [];

function check(name, findings, l) {
  const rule = new RegExp(`^(${l.rule})$`);
  const file = new RegExp(l.file);
  const hits = findings.filter((f) => (l.rule === '.' || rule.test(f.rule)) && file.test(f.file || ''));
  if (l.label === 'real') {
    const best = hits.reduce((m, f) => Math.max(m, RANK[f.severity]), -1);
    const pass = best >= RANK[l.min] && (!l.max || best <= RANK[l.max]);
    (pass ? ok : bad).push(`${pass ? 'bien ' : 'FALLA'} real  ${name} ${l.rule} ${l.file}: ${best < 0 ? 'no sale' : NAMES[best]} (mín. ${l.min}${l.max ? `, máx. ${l.max}` : ''})${pass ? '' : ` · ${l.why}`}`);
  } else {
    const over = hits.filter((f) => RANK[f.severity] > RANK[l.max]);
    (over.length ? bad : ok).push(`${over.length ? 'FALLA' : 'bien '} ruido ${name} ${l.rule} ${l.file}: ${over.length ? `${over.length} por encima de ${l.max}, p. ej. ${over[0].severity} ${over[0].file}:${over[0].line}` : `${hits.length} avisos, ninguno pasa de ${l.max}`}`);
  }
  return hits;
}

for (const f of fs.readdirSync(batch).filter((x) => x.endsWith('.json'))) {
  let r;
  try { r = JSON.parse(fs.readFileSync(path.join(batch, f), 'utf8')); } catch { continue; }
  if (r.error || !r.repo) continue;
  const name = `${r.repo.owner}/${r.repo.name}`;
  const seen = new Set();
  for (const l of labels.filter((x) => x.repo.toLowerCase() === name.toLowerCase())) {
    for (const h of check(name, l.kind === 'vuln' ? r.vulnerabilities : r.threats, l)) seen.add(h);
  }
  for (const t of r.threats) if (RANK[t.severity] >= 2 && !t.history && !seen.has(t)) unlabelled.push(`${name} ${t.severity} ${t.rule} ${t.file}${t.line ? `:${t.line}` : ''}`);
}
for (const x of [...bad, ...ok]) console.log(x);
console.log(`\n${ok.length} bien · ${bad.length} mal`);
if (unlabelled.length) console.log(`\nSin etiquetar (amenazas medias o más, ${unlabelled.length}):\n  ${unlabelled.join('\n  ')}`);
process.exitCode = bad.length ? 1 : 0;
