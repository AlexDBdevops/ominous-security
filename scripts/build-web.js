#!/usr/bin/env node
'use strict';
// Empaqueta lib/ para el navegador en public/analyzer.js (versión web en GitHub
// Pages y artefactos). Los módulos de Node que usa el analizador se sustituyen por
// equivalentes en web/shims: ficheros en memoria, zlib con fflate y crypto con @noble.
// El resultado se versiona; `npm run build:web -- --check` falla si no está al día.
const fs = require('fs');
const path = require('path');
const esbuild = require('esbuild');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'public', 'analyzer.js');
const shim = (n) => path.join(ROOT, 'web', 'shims', `${n}.js`);

async function build() {
  const r = await esbuild.build({
    entryPoints: [path.join(ROOT, 'web', 'entry.js')],
    bundle: true,
    write: false,
    format: 'iife',
    platform: 'browser',
    target: ['es2020'],
    minify: true,
    legalComments: 'eof',
    alias: { fs: shim('fs'), zlib: shim('zlib'), crypto: shim('crypto'), path: 'path-browserify', buffer: 'buffer' },
    inject: [shim('globals')],
    external: ['@anthropic-ai/sdk', 'os', 'child_process', 'worker_threads', 'readline', 'https', 'dns', 'net'],
    plugins: [{
      name: 'connection-stub',
      setup(b) { b.onResolve({ filter: /^\.\/connection$/ }, () => ({ path: shim('connection') })); },
    }],
    banner: { js: '\'use strict\';/* Ominous Security: analizador para el navegador. Generado por scripts/build-web.js, no editar. */' },
    logLevel: 'warning',
  });
  return r.outputFiles[0].text;
}

build().then((code) => {
  if (process.argv.includes('--check')) {
    const cur = fs.existsSync(OUT) ? fs.readFileSync(OUT, 'utf8') : '';
    if (cur !== code) { console.error('public/analyzer.js no está al día: ejecuta npm run build:web'); process.exit(1); }
    console.log('public/analyzer.js al día');
    return;
  }
  fs.writeFileSync(OUT, code);
  console.log(`public/analyzer.js (${Math.round(code.length / 1024)} KB)`);
}).catch((e) => { console.error(e.message); process.exit(1); });
