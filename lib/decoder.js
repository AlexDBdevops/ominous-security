'use strict';
// Ingeniería inversa estática de payloads ocultos.
// Nunca ejecuta nada: solo decodifica capas (base64, hex, zlib/gzip, charcodes,
// escapes, cadenas invertidas, XOR de un byte, Fernet con clave embebida) y
// devuelve el texto final para volver a escanearlo.

const zlib = require('zlib');
const crypto = require('crypto');

const MAX_LAYERS = 6;
const MAX_OUT = 512 * 1024;

const CODE_HINTS = /\b(import|require|function|eval|exec|subprocess|socket|http|https|powershell|bash|curl|wget|fetch|child_process|os\.system|base64|decrypt|var |let |const |def |return|while|for)\b|\/bin\/|cmd\.exe|\.(sh|exe|ps1|py|js)\b/i;

function printableRatio(buf) {
  if (!buf.length) return 0;
  let ok = 0;
  const n = Math.min(buf.length, 4096);
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if ((c >= 32 && c < 127) || c === 9 || c === 10 || c === 13) ok++;
  }
  return ok / n;
}

function entropy(str) {
  if (!str.length) return 0;
  const freq = new Map();
  for (const ch of str) freq.set(ch, (freq.get(ch) || 0) + 1);
  let h = 0;
  for (const v of freq.values()) {
    const p = v / str.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksLikeText(buf) { return printableRatio(buf) > 0.92; }
// Al menos dos indicios distintos: una frase en inglés con "for" o "return" no es código.
function looksLikeCode(text) {
  const hits = new Set((text.slice(0, 20000).match(new RegExp(CODE_HINTS.source, 'gi')) || []).map((h) => h.toLowerCase().trim()));
  return hits.size >= 2;
}

function tryInflate(buf) {
  if (buf.length < 4) return null;
  const tries = [];
  if (buf[0] === 0x1f && buf[1] === 0x8b) tries.push(['gzip', () => zlib.gunzipSync(buf, { maxOutputLength: MAX_OUT })]);
  if (buf[0] === 0x78 && [0x01, 0x5e, 0x9c, 0xda].includes(buf[1])) tries.push(['zlib', () => zlib.inflateSync(buf, { maxOutputLength: MAX_OUT })]);
  if (buf[0] === 0x42 && buf[1] === 0x5a && buf[2] === 0x68) tries.push(['bzip2 (no soportado)', () => null]);
  for (const [name, fn] of tries) {
    try { const out = fn(); if (out) return { name, out }; } catch { /* no comprimido */ }
  }
  // zlib raw (deflate sin cabecera) es común en payloads de Python (zlib.decompress(..., -15))
  try { const out = zlib.inflateRawSync(buf, { maxOutputLength: MAX_OUT }); if (out.length > 16 && looksLikeText(out)) return { name: 'deflate-raw', out }; } catch { /* nada */ }
  return null;
}

function b64decode(s) {
  const clean = s.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (clean.length < 16 || !/^[A-Za-z0-9+/]+=*$/.test(clean)) return null;
  const buf = Buffer.from(clean, 'base64');
  return buf.length ? buf : null;
}

function hexdecode(s) {
  const clean = s.replace(/\\x|0x|[\s,]/gi, '');
  if (clean.length < 16 || clean.length % 2 || !/^[0-9a-f]+$/i.test(clean)) return null;
  return Buffer.from(clean, 'hex');
}

function xorBrute(buf) {
  if (buf.length < 12) return null;
  let best = null;
  for (let k = 1; k < 256; k++) {
    const out = Buffer.alloc(Math.min(buf.length, MAX_OUT));
    for (let i = 0; i < out.length; i++) out[i] = buf[i] ^ k;
    const ratio = printableRatio(out);
    if (ratio > 0.95) {
      const txt = out.toString('latin1');
      if (looksLikeCode(txt) && (!best || ratio > best.ratio)) best = { key: k, out, ratio };
    }
  }
  return best;
}

// Fernet (cryptography.fernet) = AES-128-CBC + HMAC-SHA256. Muy usado en paquetes maliciosos de PyPI
// con la clave escrita en el propio fichero: Fernet(b'clave').decrypt(b'gAAAA...').
function fernetDecrypt(keyB64, tokenB64) {
  try {
    const key = Buffer.from(keyB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    if (key.length !== 32) return null;
    const tok = Buffer.from(tokenB64.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
    if (tok.length < 57 || tok[0] !== 0x80) return null;
    const signing = key.subarray(0, 16), enc = key.subarray(16);
    const body = tok.subarray(0, tok.length - 32), mac = tok.subarray(tok.length - 32);
    const calc = crypto.createHmac('sha256', signing).update(body).digest();
    if (!crypto.timingSafeEqual(calc, mac)) return null;
    const iv = tok.subarray(9, 25), ct = tok.subarray(25, tok.length - 32);
    const d = crypto.createDecipheriv('aes-128-cbc', enc, iv);
    return Buffer.concat([d.update(ct), d.final()]);
  } catch { return null; }
}

// Decodifica capa a capa. Devuelve { layers: [...], text, final: 'text'|'binary'|'opaque' }
function peel(initialBuf, firstLayer) {
  const layers = [firstLayer];
  let buf = initialBuf;
  for (let depth = 0; depth < MAX_LAYERS; depth++) {
    const inflated = tryInflate(buf);
    if (inflated) { layers.push(inflated.name); buf = inflated.out; continue; }
    if (looksLikeText(buf)) {
      const txt = buf.toString('utf8').trim();
      // ¿El texto es a su vez otra capa codificada?
      const rev = txt.split('').reverse().join('');
      const b = /^[A-Za-z0-9+/_-]{24,}={0,2}$/.test(txt) ? b64decode(txt)
        : /^={0,2}[A-Za-z0-9+/_-]{24,}$/.test(txt) ? (layers.push('cadena invertida'), b64decode(rev)) : null;
      if (b) { layers.push('base64'); buf = b; continue; }
      const h = /^[0-9a-f\s]{32,}$/i.test(txt) ? hexdecode(txt) : null;
      if (h) { layers.push('hex'); buf = h; continue; }
      if (!looksLikeCode(txt)) {
        // XOR de un byte sobre ASCII suele seguir siendo imprimible: probamos igualmente
        const xx = xorBrute(buf);
        if (xx) { layers.push(`XOR clave 0x${xx.key.toString(16).padStart(2, '0')}`); buf = xx.out; continue; }
      }
      return { layers, text: txt.slice(0, MAX_OUT), final: 'text' };
    }
    const x = xorBrute(buf);
    if (x) { layers.push(`XOR clave 0x${x.key.toString(16).padStart(2, '0')}`); buf = x.out; continue; }
    break;
  }
  if (looksLikeText(buf)) return { layers, text: buf.toString('utf8'), final: 'text' };
  const magic = sniffBinary(buf);
  return { layers, text: null, final: magic ? 'binary' : 'opaque', binaryType: magic, entropy: entropy(buf.toString('latin1')) };
}

function sniffBinary(buf) {
  if (buf.length < 4) return null;
  if (buf[0] === 0x4d && buf[1] === 0x5a) return 'Ejecutable Windows (PE/MZ)';
  if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return 'Ejecutable Linux (ELF)';
  const m = buf.readUInt32BE(0);
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe].includes(m)) return 'Ejecutable macOS (Mach-O) o clase Java';
  if (buf[0] === 0x50 && buf[1] === 0x4b && buf[2] === 0x03 && buf[3] === 0x04) return 'Archivo ZIP/JAR';
  if ((buf[0] === 0x03 || buf[0] === 0x42 || buf[0] === 0x55 || buf[0] === 0x6f || buf[0] === 0xa7) && buf[2] === 0x0d && buf[3] === 0x0a) return 'Bytecode Python (.pyc)';
  if (buf[0] === 0xe3 || buf[0] === 0x63) return null; // podría ser marshal de Python, demasiado ambiguo
  return null;
}

// Busca blobs codificados dentro de un fichero de texto y los pela.
// Devuelve [{ line, kind, preview, layers, text, final, binaryType }]
function findHiddenPayloads(content, { isMinified = false } = {}) {
  const results = [];
  const seen = new Set();
  const lineOf = (idx) => content.slice(0, idx).split('\n').length;

  const push = (idx, raw, buf, layer) => {
    const key = raw.slice(0, 64);
    if (seen.has(key)) return;
    seen.add(key);
    const r = peel(buf, layer);
    if (r.final === 'text' && !looksLikeCode(r.text)) return; // datos inocuos (fixtures, licencias, traducciones...)
    if (r.final === 'opaque') return; // datos binarios sin contexto (geometrías, hashes, assets); los cifrados sospechosos se tratan aparte
    results.push({ line: lineOf(idx), raw: raw.slice(0, 120), ...r });
  };

  // base64 largo (evita data:image/font, hashes de integridad, etc.)
  const b64re = /(["'`])([A-Za-z0-9+/_-]{80,}={0,2})\1/g;
  let m;
  while ((m = b64re.exec(content)) && results.length < 40) {
    const before = content.slice(Math.max(0, m.index - 40), m.index);
    if (/data:(image|font|audio|video|application\/(font|x-font))|integrity|sha(256|384|512)-|sourceMappingURL/i.test(before)) continue;
    if (/^[0-9a-fA-F]+$/.test(m[2]) || m[2].startsWith('gAAAAA')) continue; // hex y tokens Fernet tienen su propio tratamiento
    const buf = b64decode(m[2]);
    if (buf && !looksLikeText(buf) && !tryInflate(buf) && !sniffBinary(buf) && entropy(m[2]) > 5.7 && !/decrypt|cipher|fernet|aes|xor/i.test(content.slice(Math.max(0, m.index - 400), m.index + m[0].length + 400))) {
      continue; // binario aleatorio sin contexto de descifrado: probablemente un asset/clave pública
    }
    if (buf) push(m.index, m[2], buf, 'base64');
    else {
      const rev = m[2].split('').reverse().join('');
      const rb = b64decode(rev);
      if (rb && looksLikeText(rb)) push(m.index, m[2], rb, 'cadena invertida + base64');
    }
  }

  // hex largo: "4d5a9000..." o "\x69\x6d\x70..."
  const hexre = /((?:\\x[0-9a-fA-F]{2}){24,}|["'][0-9a-fA-F]{64,}["'])/g;
  while ((m = hexre.exec(content)) && results.length < 40) {
    const raw = m[1].replace(/["']/g, '');
    if (/^[0-9a-f]{64}$/i.test(raw) || /^[0-9a-f]{40}$/i.test(raw)) continue; // hashes sha256/sha1
    const buf = hexdecode(raw);
    if (buf) push(m.index, raw, buf, 'hex');
  }

  // String.fromCharCode(105,109,...) y arrays numéricos largos ([105,109,112,...])
  const ccre = /(?:fromCharCode\s*\(|\[\s*)((?:\d{2,3}\s*,\s*){20,}\d{2,3})\s*[)\]]/g;
  while ((m = ccre.exec(content)) && results.length < 40) {
    const nums = m[1].split(',').map((n) => parseInt(n, 10));
    if (nums.some((n) => n > 255)) continue;
    const buf = Buffer.from(nums);
    if (looksLikeText(buf) || /fromCharCode/.test(m[0])) push(m.index, m[0].slice(0, 80), buf, 'códigos de carácter');
  }

  // Fernet: clave de 44 chars + token gAAAAA en el mismo fichero
  const keys = [...content.matchAll(/["']([A-Za-z0-9_-]{43}=)["']/g)].map((x) => x[1]);
  const tokens = [...content.matchAll(/(gAAAAA[A-Za-z0-9_=-]{60,})/g)];
  for (const t of tokens.slice(0, 10)) {
    let done = false;
    for (const k of keys) {
      const plain = fernetDecrypt(k, t[1]);
      if (plain) {
        const r = peel(plain, `Fernet (AES-128-CBC) descifrado con clave embebida ${k.slice(0, 8)}…`);
        results.push({ line: lineOf(t.index), raw: t[1].slice(0, 120), ...r });
        done = true;
        break;
      }
    }
    if (!done && /Fernet/.test(content) && /\b(exec|eval|loads|system|Popen)\s*\(/.test(content)) results.push({ line: lineOf(t.index), raw: t[1].slice(0, 120), layers: ['Token Fernet cifrado'], text: null, final: 'opaque', note: 'No se encontró la clave en el fichero: el contenido no puede descifrarse estáticamente.' });
  }

  // Blob opaco de alta entropía cerca de rutinas de descifrado (AES, RC4, XOR manual...)
  if (!isMinified) {
    const opaque = /(["'])([A-Za-z0-9+/=]{300,})\1/g;
    while ((m = opaque.exec(content)) && results.length < 40) {
      if (seen.has(m[2].slice(0, 64))) continue;
      const ctx = content.slice(Math.max(0, m.index - 600), m.index + m[0].length + 600);
      if (/createDecipher|AES\.new|Cipher\(|decrypt\(|CryptoJS|rc4|xor/i.test(ctx) && /eval|exec|Function\(|spawn|system|loads/i.test(ctx)) {
        seen.add(m[2].slice(0, 64));
        results.push({ line: lineOf(m.index), raw: m[2].slice(0, 120), layers: ['blob cifrado'], text: null, final: 'opaque', note: 'Datos cifrados que se descifran y ejecutan en tiempo de ejecución. La clave no es estática o el algoritmo no es reconocible.' });
      }
    }
  }

  return results;
}

module.exports = { findHiddenPayloads, entropy, sniffBinary, peel, fernetDecrypt, looksLikeCode };
