#!/usr/bin/env node
'use strict';
// Genera la versión web para Cloudflare Pages: la misma interfaz que sirve
// server.js en su edición "web" (analiza repos públicos en el navegador, sin IA),
// el analizador empaquetado, las fuentes y un _headers con las cabeceras de
// seguridad (la CSP lleva el hash del script y solo deja conectar con GitHub,
// OSV.dev y OpenSSF Scorecard).
// Uso: node scripts/build-site.js [carpeta] [edición]   (edición: web por defecto)
const fs = require('fs');
const path = require('path');
const page = require('../lib/page');

const out = path.resolve(process.argv[2] || 'dist');
const ed = page.edition(process.argv[3] || 'web');
// Solo se borra una carpeta vacía o una demo generada antes (tiene _headers).
if (fs.existsSync(out) && fs.readdirSync(out).length && !fs.existsSync(path.join(out, '_headers'))) {
  console.error(`${out} no está vacía y no parece una demo generada: no la borro.`);
  process.exit(1);
}
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(path.join(out, 'fonts'), { recursive: true });
fs.writeFileSync(path.join(out, 'index.html'), ed.html);
fs.copyFileSync(path.join(page.PUBLIC, 'analyzer.js'), path.join(out, 'analyzer.js'));
for (const f of fs.readdirSync(path.join(page.PUBLIC, 'fonts'))) {
  fs.copyFileSync(path.join(page.PUBLIC, 'fonts', f), path.join(out, 'fonts', f));
}
fs.writeFileSync(path.join(out, '_headers'), `/*
  X-Content-Type-Options: nosniff
  X-Frame-Options: DENY
  Referrer-Policy: no-referrer
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Cross-Origin-Opener-Policy: same-origin
  Cross-Origin-Resource-Policy: same-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), payment=(), interest-cohort=()
  Content-Security-Policy: ${ed.csp}; upgrade-insecure-requests
/fonts/*
  Cache-Control: public, max-age=604800, immutable
`);
console.log(`Edición ${ed.name} generada en ${out}`);
