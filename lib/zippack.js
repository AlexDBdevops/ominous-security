'use strict';
// ZIP sin comprimir ("stored") y sin dependencias, para descargar el clon preparado en cualquier
// navegador y descomprimirlo donde quieras (Windows, macOS y Linux lo abren sin instalar nada).
// Funciona en Node y en el navegador: solo Uint8Array, DataView y TextEncoder.
// Límite: 4 GB en total y por fichero (sin ZIP64); el clon ya está acotado muy por debajo.

const TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; t[n] = c >>> 0; }
  return t;
})();
function crc32(data) {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i++) c = TABLE[(c ^ data[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// Fecha y hora en formato DOS (la de los ficheros del zip)
function dosTime(d) {
  return { time: (d.getHours() << 11) | (d.getMinutes() << 5) | Math.floor(d.getSeconds() / 2), date: ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate() };
}

// entries: iterable de { name, data } (puede ir generándolos a medida). Devuelve un generador de
// trozos Uint8Array que, juntos, son el zip.
function* zipChunks(entries, when = new Date()) {
  const enc = new TextEncoder();
  const { time, date } = dosTime(when);
  const central = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const n = enc.encode(name);
    const crc = crc32(data);
    if (data.length >= 0xffffffff || offset >= 0xffffffff) throw new Error('El clon es demasiado grande para un zip (4 GB).');
    const h = new Uint8Array(30 + n.length);
    const v = new DataView(h.buffer);
    v.setUint32(0, 0x04034b50, true); v.setUint16(4, 20, true); v.setUint16(6, 0x0800, true); // UTF-8
    v.setUint16(8, 0, true); v.setUint16(10, time, true); v.setUint16(12, date, true);
    v.setUint32(14, crc, true); v.setUint32(18, data.length, true); v.setUint32(22, data.length, true);
    v.setUint16(26, n.length, true); v.setUint16(28, 0, true);
    h.set(n, 30);
    central.push({ n, crc, size: data.length, offset });
    offset += h.length + data.length;
    yield h;
    if (data.length) yield data;
  }
  let size = 0;
  for (const c of central) {
    const h = new Uint8Array(46 + c.n.length);
    const v = new DataView(h.buffer);
    v.setUint32(0, 0x02014b50, true); v.setUint16(4, 20, true); v.setUint16(6, 20, true); v.setUint16(8, 0x0800, true);
    v.setUint16(10, 0, true); v.setUint16(12, time, true); v.setUint16(14, date, true);
    v.setUint32(16, c.crc, true); v.setUint32(20, c.size, true); v.setUint32(24, c.size, true);
    v.setUint16(28, c.n.length, true); v.setUint32(38, 0o100644 << 16, true); v.setUint32(42, c.offset, true);
    h.set(c.n, 46);
    size += h.length;
    yield h;
  }
  if (central.length > 0xffff) throw new Error('El clon tiene demasiados ficheros para un zip sin ZIP64.');
  const end = new Uint8Array(22);
  const v = new DataView(end.buffer);
  v.setUint32(0, 0x06054b50, true); v.setUint16(8, central.length, true); v.setUint16(10, central.length, true);
  v.setUint32(12, size, true); v.setUint32(16, offset, true);
  yield end;
}

module.exports = { zipChunks, crc32 };
