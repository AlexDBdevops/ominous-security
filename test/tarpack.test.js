'use strict';
// El clon que la app manda a la página para escribirlo en la carpeta que eliges (lib/tarpack.js).
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { PassThrough } = require('stream');
const fx = require('./helpers/fixtures');
const { packTo, listTree } = require('../lib/tarpack');

// Lector mínimo, igual que el de la página (public/index.html, untarInto)
function untar(buf) {
  const out = new Map();
  let off = 0;
  let pax = null;
  const text = (b) => b.toString('utf8').replace(/\0.*$/s, '');
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    off += 512;
    if (h.every((x) => x === 0)) break;
    const size = parseInt(text(h.subarray(124, 136)).trim() || '0', 8);
    const type = String.fromCharCode(h[156] || 48);
    const name = pax || text(h.subarray(0, 100));
    pax = null;
    const data = buf.subarray(off, off + size);
    off += size + ((512 - (size % 512)) % 512);
    if (type === 'x') { const m = data.toString('utf8').match(/\d+ path=([^\n]*)\n/); pax = m ? m[1] : null; continue; }
    if (type === '0') out.set(name, Buffer.from(data));
    if (type === '5') out.set(name, 'dir');
  }
  return out;
}

test('tar del clon: rutas largas y con acentos, contenido exacto, sin seguir enlaces', async (t) => {
  const long = `${'carpeta-muy-larga/'.repeat(8)}fichero.txt`;
  const dir = fx.write(fx.tmpDir('tar'), {
    'README.md': '# hola\n',
    'src/año/ñandú.js': 'module.exports = 1;\n',
    [long]: 'x'.repeat(1000),
    '.git/HEAD': 'ref: refs/heads/main\n',
    'bin/data.bin': Buffer.from([0, 1, 2, 255]),
  });
  const outside = fx.write(fx.tmpDir('tar-fuera'), { 'secreto.txt': 'no debe salir' });
  try { fs.symlinkSync(path.join(outside, 'secreto.txt'), path.join(dir, 'enlace.txt')); } catch { /* sin permisos para enlaces (Windows) */ }
  t.after(() => { fx.rm(dir); fx.rm(outside); });

  const sink = new PassThrough();
  const chunks = [];
  sink.on('data', (c) => chunks.push(c));
  await packTo(dir, sink, listTree(dir));
  const files = untar(Buffer.concat(chunks));
  assert.equal(files.get('README.md').toString(), '# hola\n');
  assert.equal(files.get('src/año/ñandú.js').toString(), 'module.exports = 1;\n');
  assert.equal(files.get(long).length, 1000, 'ruta de más de 100 bytes (cabecera PAX)');
  assert.equal(files.get('.git/HEAD').toString(), 'ref: refs/heads/main\n', 'el .git va incluido: es un clon de verdad');
  assert.deepEqual([...files.get('bin/data.bin')], [0, 1, 2, 255]);
  assert.ok(![...files.keys()].some((k) => /enlace|secreto/.test(k)), 'los enlaces simbólicos no se siguen ni se incluyen');
});
