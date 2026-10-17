'use strict';
// Qué líneas son comentario, según el lenguaje del fichero. No vale una lista común de marcas:
// en JavaScript "#x = …" es un campo privado de clase y "* 2; …" la continuación de una
// multiplicación, y las dos líneas se ejecutan. En un lenguaje desconocido no se salta nada.
//
// JavaScript y TypeScript se leen con un analizador de verdad (@babel/parser, opcional): con
// expresiones regulares no se puede saber si "/*" abre un comentario o está dentro de una
// plantilla `…` o de una expresión regular como /[/*]/, y un atacante podría usar eso para
// que su código pareciera un comentario. Si el analizador no está o no entiende el fichero,
// se usa una lectura estricta que solo da por comentario lo que no puede ser otra cosa.
const HASH_COMMENT = /\.(sh|bash|zsh|ksh|fish|py|pyw|rb|pl|pm|r|ps1|psm1|ya?ml|toml|cfg|ini|conf|mk|mak|cmake|tf|nix|exs?|jl|coffee|dockerfile|bats|envrc|php)$|(^|\/)(Makefile|Dockerfile|Containerfile|Rakefile|Gemfile|Vagrantfile|Justfile|Brewfile|\.envrc|\.bashrc|\.zshrc|\.profile)$/i;
const SLASH_COMMENT = /\.(c|h|cc|cpp|cxx|hpp|cs|java|kt|kts|scala|go|rs|swift|m|mm|js|mjs|cjs|jsx|ts|mts|cts|tsx|vue|svelte|php|dart|groovy|gradle|zig|sol|jsonc|json5)$/i;
const MARKUP_COMMENT = /\.(html?|xml|svg|md|markdown|mdx|vue|svelte)$/i;
const JS_FILE = /\.(js|mjs|cjs|jsx|ts|mts|cts|tsx)$/i;
// Cierres de cadenas de varias líneas en otros lenguajes: `…` (Go), )" (C++ R"(…)"),
// "# (Rust r#"…"#) y """ (Java, Kotlin, Swift, Scala)
const RAW_CLOSE = /`|\)"|"#|"""/;
const MAX_PARSE = 1024 * 1024;

let babel;
function parser() {
  if (babel === undefined) {
    try { babel = require('@babel/parser'); } catch { babel = null; } // eslint-disable-line global-require
  }
  return babel;
}

// Con el analizador: una línea es comentario si todo lo que no es espacio cae dentro de comentarios.
function jsComments(rel, lines) {
  const p = parser();
  const src = lines.join('\n');
  if (!p || src.length > MAX_PARSE) return null;
  const ts = /\.(ts|mts|cts|tsx)$/i.test(rel);
  const plugins = ts ? (/x$/i.test(rel) ? ['typescript', 'jsx'] : ['typescript']) : ['jsx'];
  let ast;
  try {
    ast = p.parse(src, { sourceType: 'unambiguous', errorRecovery: true, allowReturnOutsideFunction: true, allowAwaitOutsideFunction: true, allowImportExportEverywhere: true, allowUndeclaredExports: true, plugins });
  } catch {
    if (ts) return null;
    try { ast = p.parse(src, { sourceType: 'unambiguous', errorRecovery: true, allowReturnOutsideFunction: true, plugins: [] }); } catch { return null; }
  }
  // Con errores graves el árbol puede no corresponder al código: mejor no saltar nada.
  if ((ast.errors || []).length > 20) return null;
  const covered = new Array(src.length + 1).fill(false);
  for (const c of ast.comments || []) for (let k = c.start; k < c.end; k++) covered[k] = true;
  const out = new Array(lines.length).fill(false);
  let pos = 0;
  for (let i = 0; i < lines.length; i++) {
    const l = lines[i];
    let any = false;
    let code = false;
    for (let k = 0; k < l.length; k++) {
      if (/\s/.test(l[k])) continue;
      any = true;
      if (!covered[pos + k]) { code = true; break; }
    }
    out[i] = any && !code;
    pos += l.length + 1;
  }
  return out;
}

function commentLines(rel, lines) {
  if (JS_FILE.test(rel)) {
    const exact = jsComments(rel, lines);
    if (exact) return exact;
  }
  const js = JS_FILE.test(rel) || /\.(vue|svelte|html?)$/i.test(rel); // también el JS dentro de <script>
  const hash = HASH_COMMENT.test(rel);
  const slash = SLASH_COMMENT.test(rel);
  const markup = MARKUP_COMMENT.test(rel);
  const out = new Array(lines.length).fill(false);
  let inBlock = false;
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trimStart();
    // Una cadena de varias líneas (plantilla `…` en JS, """ en Python, o una línea anterior
    // acabada en \) puede cerrarse en una línea que empieza por // o # y seguir con código:
    // esas líneas nunca cuentan como comentario.
    const continued = i > 0 && /\\\s*$/.test(lines[i - 1]);
    if (slash) {
      const risky = RAW_CLOSE.test(t);
      // En JavaScript sin analizador, nada de comentarios de bloque: una expresión regular
      // como /[/*]/ puede parecer que abre uno y esconder las líneas siguientes.
      if (!js && (inBlock || (t.startsWith('/*') && !risky && !continued))) {
        const end = t.indexOf('*/', inBlock ? 0 : 2);
        // Tras el cierre del bloque puede haber código en la misma línea: entonces no es comentario
        out[i] = !risky && (end < 0 || !t.slice(end + 2).trim() || t.slice(end + 2).trim().startsWith('//'));
        inBlock = end < 0;
        continue;
      }
      if (t.startsWith('//') && !risky && !continued) { out[i] = true; continue; }
    }
    if (hash && t.startsWith('#') && !(i === 0 && t.startsWith('#!')) && !continued && !/"""|'''/.test(t)) { out[i] = true; continue; }
    if (markup && t.startsWith('<!--') && t.includes('-->') && !t.slice(t.indexOf('-->') + 3).trim()) out[i] = true;
  }
  return out;
}

// Versión perezosa: el fichero solo se analiza si alguna regla encuentra algo en él.
function lazyCommentLines(rel, lines) {
  let map = null;
  return (i) => { if (!map) map = commentLines(rel, lines); return map[i]; };
}

module.exports = { commentLines, lazyCommentLines, hasParser: () => !!parser() };
