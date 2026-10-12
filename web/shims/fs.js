'use strict';
// Sistema de ficheros en memoria para ejecutar el analizador en el navegador.
// Solo implementa lo que usa lib/: leer, listar, stat, enlaces simbólicos y escribir
// (para calcular el parche de los arreglos). Nada de esto toca el disco del usuario.
const { Buffer } = require('buffer');
const path = require('path');

const files = new Map(); // ruta absoluta -> { data: Uint8Array, size, link: string|null }
const dirs = new Map(); // ruta absoluta -> Set de nombres

function addDir(p) {
  while (p && !dirs.has(p)) {
    dirs.set(p, new Set());
    const parent = path.dirname(p);
    if (parent === p) break;
    dirs.get(parent) || addDir(parent);
    dirs.get(parent).add(path.basename(p));
    p = parent;
  }
}

function reset() { files.clear(); dirs.clear(); }
function putFile(p, data, size, link = null) {
  const parent = path.dirname(p);
  addDir(parent);
  dirs.get(parent).add(path.basename(p));
  files.set(p, { data: data || new Uint8Array(0), size: size != null ? size : (data ? data.length : 0), link });
}

const enoent = (p) => Object.assign(new Error(`ENOENT: ${p}`), { code: 'ENOENT' });
function resolveLink(p, depth = 0) {
  const f = files.get(p);
  if (!f || !f.link) return p;
  if (depth > 8) throw enoent(p);
  return resolveLink(path.resolve(path.dirname(p), f.link), depth + 1);
}
function stats(p, follow) {
  const real = follow ? resolveLink(p) : p;
  const f = files.get(real);
  if (f) return { size: f.size, isFile: () => !f.link, isDirectory: () => false, isSymbolicLink: () => !!f.link };
  if (dirs.has(real)) return { size: 0, isFile: () => false, isDirectory: () => true, isSymbolicLink: () => false };
  throw enoent(p);
}

function readdirSync(p, opts) {
  const d = dirs.get(p);
  if (!d) throw enoent(p);
  const names = [...d].sort();
  if (!opts || !opts.withFileTypes) return names;
  return names.map((name) => { const s = stats(path.join(p, name), false); return { name, isFile: s.isFile, isDirectory: s.isDirectory, isSymbolicLink: s.isSymbolicLink }; });
}
function readFileSync(p, enc) {
  const f = files.get(resolveLink(p));
  if (!f || f.link) throw enoent(p);
  const b = Buffer.from(f.data.buffer, f.data.byteOffset, f.data.length);
  return enc ? b.toString(enc === 'utf-8' ? 'utf8' : enc) : b;
}
function writeFileSync(p, data) {
  const f = files.get(p);
  const u8 = typeof data === 'string' ? new TextEncoder().encode(data) : new Uint8Array(data);
  putFile(p, u8, u8.length, f ? f.link : null);
}
const fds = new Map();
let nextFd = 3;
function openSync(p) { readFileSync(p); const fd = nextFd++; fds.set(fd, p); return fd; }
function readSync(fd, buf, off, len, pos) {
  const data = readFileSync(fds.get(fd));
  const n = Math.max(0, Math.min(len, data.length - (pos || 0)));
  data.copy(buf, off, pos || 0, (pos || 0) + n);
  return n;
}
function closeSync(fd) { fds.delete(fd); }
function readlinkSync(p) { const f = files.get(p); if (!f || !f.link) throw enoent(p); return f.link; }
function existsSync(p) { try { stats(p, true); return true; } catch { return false; } }
function realpathSync(p) { return resolveLink(p); }
realpathSync.native = realpathSync;

module.exports = {
  readdirSync, readFileSync, writeFileSync, openSync, readSync, closeSync, readlinkSync, existsSync, realpathSync,
  statSync: (p) => stats(p, true), lstatSync: (p) => stats(p, false),
  __vfs: { reset, putFile, files },
};
