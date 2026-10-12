#!/usr/bin/env node
'use strict';
// Genera la versión web para GitHub Pages: la misma interfaz que sirve server.js en su
// edición "web" (analiza repos públicos en el navegador, sin IA), el analizador
// empaquetado y las fuentes.
// GitHub Pages no deja poner cabeceras, así que la CSP va en un <meta> al principio del
// <head> (con el hash de cada script y solo las conexiones de la edición web). Un <meta>
// no admite frame-ancestors: en su lugar la página se oculta si la cargan dentro de un
// marco de otro sitio (contra el clickjacking). HSTS ya lo pone github.io.
// Uso: node scripts/build-site.js [carpeta] [edición]   (edición: web por defecto)
const fs = require('fs');
const path = require('path');
const page = require('../lib/page');

const MARK = '.ominous-site';
const out = path.resolve(process.argv[2] || 'dist');
const ed = page.edition(process.argv[3] || 'web');

// Visible solo si no está en un marco; si lo está, intenta salir de él.
const BUSTER = "if(window.top===window.self){document.getElementById('antiframe').remove()}else{try{window.top.location=window.self.location.href}catch(e){}}";

function site(e) {
  const head = `<style id="antiframe">html{display:none!important}</style><script>${BUSTER}</script>`;
  const hashes = page.scriptHashes(head + e.body).join(' ');
  const csp = e.csp
    .replace(/script-src [^;]+/, `script-src 'self' ${hashes}`)
    .replace(/; frame-ancestors 'none'/, '');
  const meta = `<meta http-equiv="Content-Security-Policy" content="${csp}; upgrade-insecure-requests"><meta name="referrer" content="no-referrer">`;
  return { csp, html: e.html.replace('<meta charset="utf-8">', `<meta charset="utf-8">${meta}`).replace('</head>', `${head}</head>`) };
}

// Solo se borra una carpeta vacía o una demo generada antes (tiene la marca, que no se
// publica: upload-pages-artifact deja fuera los ficheros ocultos).
if (fs.existsSync(out) && fs.readdirSync(out).length && !fs.existsSync(path.join(out, MARK))) {
  console.error(`${out} no está vacía y no parece una demo generada: no la borro.`);
  process.exit(1);
}
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(path.join(out, 'fonts'), { recursive: true });
fs.writeFileSync(path.join(out, MARK), '');
fs.writeFileSync(path.join(out, 'index.html'), site(ed).html);
fs.copyFileSync(path.join(page.PUBLIC, 'analyzer.js'), path.join(out, 'analyzer.js'));
for (const f of fs.readdirSync(path.join(page.PUBLIC, 'fonts'))) {
  fs.copyFileSync(path.join(page.PUBLIC, 'fonts', f), path.join(out, 'fonts', f));
}
console.log(`Edición ${ed.name} generada en ${out}`);
