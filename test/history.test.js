'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { scanHistory } = require('../lib/history');
const fx = require('./helpers/fixtures');

test('encuentra código malicioso borrado que sigue en el historial', async (t) => {
  const dir = fx.historyRepo();
  t.after(() => fx.rm(dir));
  const r = await scanHistory([], dir, { commits: 10, env: process.env });
  assert.equal(r.scanned, 2);
  assert.ok(r.findings.length > 0);
  assert.ok(r.findings.every((f) => f.file === 'src/x.sh'));
  assert.ok(r.findings.some((f) => /historial/.test(f.title)));
});
