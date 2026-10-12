'use strict';
// La interfaz y su CSP, compartidas por el servidor y por la versión web.
// El script inline de la página se autoriza por su hash: cualquier script inyectado
// que no sea exactamente ese no se ejecuta. El único script externo es analyzer.js,
// del mismo origen.
//
// Ediciones (misma página, distinta línea `const EDITION`):
// - local:  servidor local; la página solo habla con su propio servidor.
// - web:    GitHub Pages; analiza en el navegador y solo puede conectar con GitHub,
//           OSV.dev, OpenSSF Scorecard, deps.dev, EPSS (FIRST) y los registros de npm y PyPI
//           (solo lectura de datos públicos).
// - web-ai: como web, más la revisión con la cuenta de claude.ai (solo en artefactos).

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PUBLIC = path.join(__dirname, '..', 'public');
// El navegador convierte CRLF en LF dentro de <script> antes de calcular el hash. Si el repo se
// clona en Windows con core.autocrlf, el fichero llega con CRLF y la CSP bloquearía la página.
const lf = (s) => s.replace(/\r\n?/g, '\n');
const BODY = lf(fs.readFileSync(path.join(PUBLIC, 'index.html'), 'utf8'));
const MARK = "const EDITION = 'local';";
const EDITIONS = ['local', 'web', 'web-ai'];
const WEB_HOSTS = ['https://api.github.com', 'https://raw.githubusercontent.com', 'https://api.osv.dev', 'https://api.securityscorecards.dev', 'https://api.deps.dev', 'https://api.first.org', 'https://registry.npmjs.org', 'https://pypi.org', 'https://files.pythonhosted.org'];

function scriptHashes(html) {
  return [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)]
    .map((m) => `'sha256-${crypto.createHash('sha256').update(m[1], 'utf8').digest('base64')}'`);
}

function edition(name = 'local') {
  if (!EDITIONS.includes(name)) throw new Error(`Edición desconocida: ${name}`);
  if (!BODY.includes(MARK)) throw new Error('public/index.html no tiene la marca de edición');
  const body = BODY.replace(MARK, `const EDITION = '${name}';`);
  const web = name !== 'local';
  const csp = [
    "default-src 'none'", `script-src 'self' ${scriptHashes(body).join(' ')}`, ...(web ? ["worker-src 'self'"] : []),
    "style-src 'unsafe-inline'", "font-src 'self'", "img-src 'self' data:", `connect-src ${web ? WEB_HOSTS.join(' ') : "'self'"}`,
    "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'", "object-src 'none'",
  ].join('; ');
  const html = `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>${body}</body></html>`;
  return { name, body, html, csp };
}

const local = edition('local');

module.exports = { PUBLIC, BODY, lf, HTML: local.html, CSP: local.csp, scriptHashes, edition, EDITIONS, WEB_HOSTS };
