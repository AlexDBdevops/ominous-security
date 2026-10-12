'use strict';
// La interfaz y su CSP, compartidas por el servidor y por la demo estática.
// El script inline de la página se autoriza por su hash: cualquier script inyectado
// que no sea exactamente ese no se ejecuta.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PUBLIC = path.join(__dirname, '..', 'public');
const BODY = fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8');

function scriptHashes(html) {
  return [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
    .map((m) => `'sha256-${crypto.createHash('sha256').update(m[1], 'utf8').digest('base64')}'`);
}

const CSP = [
  "default-src 'none'", `script-src ${scriptHashes(BODY).join(' ')}`, "style-src 'unsafe-inline'",
  "font-src 'self'", "img-src 'self' data:", "connect-src 'self'",
  "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "object-src 'none'",
].join('; ');

const HTML = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>${BODY}</body></html>`;

module.exports = { PUBLIC, BODY, HTML, CSP, scriptHashes };
