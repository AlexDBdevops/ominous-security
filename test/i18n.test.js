'use strict';
// Textos en inglés del botón de idioma (lib/i18n.js): cada regla y cada ficha tienen traducción,
// y las plantillas con valores variables y las frases encadenadas se traducen enteras.
const test = require('node:test');
const assert = require('node:assert/strict');
const { tr, has, PAIRS } = require('../lib/i18n');
const { vulnRules, threatRules } = require('../lib/rules');
const { FAMILIES } = require('../lib/explain');

test('i18n: toda regla y toda ficha tienen texto en inglés', () => {
  const missing = [];
  for (const r of [...vulnRules, ...threatRules]) {
    for (const s of [r.title, r.desc, r.fix && r.fix.text, r.notFixableReason]) if (s && !has(s)) missing.push(`${r.id}: ${s}`);
  }
  for (const f of FAMILIES) for (const s of [f.name, f.why, f.check]) if (s && !has(s)) missing.push(`ficha: ${s}`);
  assert.deepEqual(missing, [], 'añade la traducción en lib/i18n-en.json');
});

test('i18n: plantillas, plurales y frases encadenadas', () => {
  assert.equal(tr('1 dato de prueba en tests'), '1 test data item in tests');
  assert.equal(tr('3 datos de prueba en tests'), '3 test data items in tests');
  assert.equal(tr('Token de GitHub en el código (en el historial de git)'), 'GitHub token in the code (in the git history)', 'el valor variable también se traduce');
  assert.equal(tr('Revisado: está dentro de un comentario, así que no cambia lo que se ejecuta. Hay código desplazado 412 columnas a la derecha para que no se vea en el editor.'),
    'Reviewed: it is inside a comment, so it does not change what runs. There is code shifted 412 columns to the right so it cannot be seen in the editor.');
  assert.equal(tr('  Clonado en '), '  Cloned to ', 'conserva los espacios de alrededor');
  assert.equal(tr('Texto que no está en el diccionario.'), 'Texto que no está en el diccionario.', 'lo desconocido se queda igual');
  assert.equal(tr('src/a.js:3'), 'src/a.js:3');
});

test('i18n: el diccionario es coherente', () => {
  const seen = new Set();
  for (const [es, en] of PAIRS) {
    assert.ok(!seen.has(es), `duplicado: ${es}`);
    seen.add(es);
    const n = (es.match(/\{\d\}/g) || []).length;
    for (const m of en.matchAll(/\{(\d)/g)) assert.ok(+m[1] < n, `«${en}» usa {${m[1]}} y «${es}» solo tiene ${n} valores`);
  }
});
