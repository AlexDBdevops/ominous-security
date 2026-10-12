'use strict';
// zlib síncrono para el navegador (fflate), con el mismo tope de salida que en Node
// para que un payload comprimido "bomba" no agote la memoria.
const { Buffer } = require('buffer');
const { Gunzip, Unzlib, Inflate } = require('fflate');

function run(Cls, buf, opts) {
  const max = (opts && opts.maxOutputLength) || 64 * 1024 * 1024;
  const chunks = [];
  let total = 0;
  let done = false;
  const s = new Cls((chunk, final) => {
    total += chunk.length;
    if (total > max) throw new Error('maxOutputLength superado');
    chunks.push(Buffer.from(chunk));
    if (final) done = true;
  });
  s.push(new Uint8Array(buf.buffer, buf.byteOffset, buf.length), true);
  if (!done) throw new Error('datos comprimidos incompletos');
  return Buffer.concat(chunks);
}

module.exports = {
  gunzipSync: (b, o) => run(Gunzip, b, o),
  inflateSync: (b, o) => run(Unzlib, b, o),
  inflateRawSync: (b, o) => run(Inflate, b, o),
};
