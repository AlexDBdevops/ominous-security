'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { localSummary } = require('../lib/summary');

test('resumen local sin cambios', () => {
  assert.equal(localSummary([]), 'No se ha aplicado ningún cambio.');
});

test('resumen local explica cada arreglo y sus efectos', () => {
  const s = localSummary([{ rule: 'py-weakhash', file: 'app.py', line: 4, before: 'hashlib.md5(b"x")', after: 'hashlib.sha256(b"x")' }]);
  assert.match(s, /app\.py:4/);
  assert.match(s, /sha256/);
  assert.match(s, /hashes ya guardados/);
});
