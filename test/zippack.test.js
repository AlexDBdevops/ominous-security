'use strict';
// El .zip del clon (lib/zippack.js): se comprueba con un lector independiente del escritor, que
// valida firmas, tamaños, CRC y el directorio central como haría cualquier descompresor.
const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('zlib');
const { zipChunks, crc32 } = require('../lib/zippack');

function unzip(buf) {
  const end = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(end >= 0, 'fin del directorio central');
  const count = buf.readUInt16LE(end + 10);
  let p = buf.readUInt32LE(end + 16);
  const out = new Map();
  for (let i = 0; i < count; i++) {
    assert.equal(buf.readUInt32LE(p), 0x02014b50, 'entrada del directorio central');
    const flags = buf.readUInt16LE(p + 8);
    const crc = buf.readUInt32LE(p + 16);
    const size = buf.readUInt32LE(p + 24);
    const n = buf.readUInt16LE(p + 28);
    const off = buf.readUInt32LE(p + 42);
    const name = buf.subarray(p + 46, p + 46 + n).toString(flags & 0x800 ? 'utf8' : 'latin1');
    assert.equal(buf.readUInt32LE(off), 0x04034b50, 'cabecera local');
    const ln = buf.readUInt16LE(off + 26);
    const data = buf.subarray(off + 30 + ln, off + 30 + ln + size);
    assert.equal(zlib.crc32 ? zlib.crc32(data) : crc32(data), crc, `CRC de ${name}`);
    out.set(name, Buffer.from(data));
    p += 46 + n + buf.readUInt16LE(p + 30) + buf.readUInt16LE(p + 32);
  }
  return out;
}

test('zip del clon: nombres con acentos, binarios y vacíos; CRC correcto', () => {
  const files = [
    { name: 'repo/README.md', data: Buffer.from('# hola\n') },
    { name: 'repo/src/año/ñandú.js', data: Buffer.from('module.exports = 1;\n') },
    { name: 'repo/.git/HEAD', data: Buffer.from('ref: refs/heads/main\n') },
    { name: 'repo/bin/data.bin', data: Buffer.from([0, 1, 2, 255]) },
    { name: 'repo/vacio.txt', data: Buffer.alloc(0) },
  ];
  const zip = Buffer.concat([...zipChunks(files)].map((c) => Buffer.from(c)));
  const got = unzip(zip);
  assert.equal(got.size, files.length);
  for (const f of files) assert.deepEqual(got.get(f.name), f.data, f.name);
  assert.equal(crc32(Buffer.from('123456789')), 0xcbf43926, 'CRC-32 de referencia');
});
