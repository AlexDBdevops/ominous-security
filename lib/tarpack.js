'use strict';
// Empaqueta una carpeta en formato tar (ustar, con cabeceras PAX para rutas largas) y lo
// escribe en un stream. Lo usa la app para mandar el clon preparado a la página, que lo
// guarda en la carpeta que elijas. Solo carpetas y ficheros normales: los enlaces simbólicos
// no se siguen ni se incluyen (el clon se prepara con core.symlinks=false, así que no hay).
const fs = require('fs');
const path = require('path');

function octal(n, len) { return `${n.toString(8).padStart(len - 1, '0')}\0`; }

function header(name, { size = 0, type = '0', mode = 0o644, mtime = 0 } = {}) {
  const b = Buffer.alloc(512);
  b.write(name.slice(0, 100), 0, 'utf8');
  b.write(octal(mode, 8), 100);
  b.write(octal(0, 8), 108);
  b.write(octal(0, 8), 116);
  b.write(octal(size, 12), 124);
  b.write(octal(Math.floor(mtime), 12), 136);
  b.write('        ', 148); // checksum: espacios mientras se calcula
  b.write(type, 156);
  b.write('ustar\0', 257);
  b.write('00', 263);
  let sum = 0;
  for (let i = 0; i < 512; i++) sum += b[i];
  b.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148);
  return b;
}

// Registro PAX "path=…" para nombres de más de 100 bytes o con caracteres fuera de ASCII
function pax(name) {
  const body = (() => {
    const rec = (len) => `${len} path=${name}\n`;
    let len = Buffer.byteLength(rec(0));
    while (Buffer.byteLength(rec(len)) !== len) len = Buffer.byteLength(rec(len));
    return Buffer.from(rec(len));
  })();
  return Buffer.concat([header('PaxHeader', { size: body.length, type: 'x' }), body, Buffer.alloc((512 - (body.length % 512)) % 512)]);
}

function entryHeader(rel, opts) {
  const needsPax = Buffer.byteLength(rel) > 100 || /[^\x20-\x7e]/.test(rel);
  return needsPax ? Buffer.concat([pax(rel), header(rel.slice(0, 99), opts)]) : header(rel, opts);
}

// Lista la carpeta sin seguir enlaces: [{ rel, dir, size }]
function listTree(root) {
  const out = [];
  const stack = [''];
  while (stack.length) {
    const rel = stack.pop();
    const entries = fs.readdirSync(path.join(root, rel), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (e.isDirectory()) { out.push({ rel: r, dir: true }); stack.push(r); } else if (e.isFile()) out.push({ rel: r, dir: false, size: fs.statSync(path.join(root, r)).size });
    }
  }
  return out;
}

// Escribe el tar de `root` en `out` (un stream con backpressure). Devuelve una promesa.
async function packTo(root, out, list = listTree(root)) {
  const write = (buf) => new Promise((resolve, reject) => {
    if (out.destroyed) return reject(new Error('conexión cerrada'));
    if (out.write(buf)) resolve(); else out.once('drain', resolve);
  });
  for (const e of list) {
    if (e.dir) { await write(entryHeader(`${e.rel}/`, { type: '5', mode: 0o755 })); continue; }
    await write(entryHeader(e.rel, { size: e.size }));
    let sent = 0;
    for await (const chunk of fs.createReadStream(path.join(root, e.rel))) {
      // Si el fichero creció mientras tanto, se recorta: el tamaño ya está en la cabecera
      const part = chunk.subarray(0, Math.max(0, e.size - sent));
      if (part.length) await write(part);
      sent += part.length;
    }
    if (sent < e.size) await write(Buffer.alloc(e.size - sent));
    const pad = (512 - (e.size % 512)) % 512;
    if (pad) await write(Buffer.alloc(pad));
  }
  await write(Buffer.alloc(1024));
}

module.exports = { packTo, listTree };
