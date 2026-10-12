#!/usr/bin/env node
'use strict';
// Genera la demo estática para GitHub Pages: la misma interfaz que sirve
// server.js, envuelta en un documento completo. Sin servidor detrás, la
// página detecta que /api/health no responde y entra en modo demo.
const fs = require('fs');
const path = require('path');

const out = process.argv[2] || 'site';
const body = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');
fs.mkdirSync(out, { recursive: true });
fs.writeFileSync(path.join(out, 'index.html'), `<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover"></head><body>${body}</body></html>`);
console.log(`Demo generada en ${path.join(out, 'index.html')}`);
