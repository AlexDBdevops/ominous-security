'use strict';
// Lo mínimo de crypto que usa el decodificador (Fernet: HMAC-SHA256 + AES-128-CBC),
// con @noble, que es síncrono y no depende de Node.
const { Buffer } = require('buffer');
const { hmac } = require('@noble/hashes/hmac.js');
const { sha256 } = require('@noble/hashes/sha2.js');
const { cbc } = require('@noble/ciphers/aes.js');

const u8 = (b) => new Uint8Array(b.buffer, b.byteOffset, b.length);

function createHmac(alg, key) {
  if (alg !== 'sha256') throw new Error(`hmac ${alg} no soportado`);
  const parts = [];
  return { update(d) { parts.push(Buffer.from(d)); return this; }, digest() { return Buffer.from(hmac(sha256, u8(key), u8(Buffer.concat(parts)))); } };
}
function createHash(alg) {
  if (alg !== 'sha256') throw new Error(`hash ${alg} no soportado`);
  const parts = [];
  return { update(d) { parts.push(Buffer.from(d)); return this; }, digest(enc) { const out = Buffer.from(sha256(u8(Buffer.concat(parts)))); return enc ? out.toString(enc) : out; } };
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) throw new Error('longitudes distintas');
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}
function createDecipheriv(alg, key, iv) {
  if (alg !== 'aes-128-cbc') throw new Error(`${alg} no soportado`);
  const parts = [];
  return { update(d) { parts.push(Buffer.from(d)); return Buffer.alloc(0); }, final() { return Buffer.from(cbc(u8(key), u8(iv)).decrypt(u8(Buffer.concat(parts)))); } };
}
const randomUUID = () => globalThis.crypto.randomUUID();

module.exports = { createHmac, createHash, timingSafeEqual, createDecipheriv, randomUUID };
