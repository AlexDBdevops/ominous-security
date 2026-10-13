'use strict';
// Qué líneas son comentario, según el lenguaje del fichero. No vale una lista común de marcas:
// en JavaScript "#x = …" es un campo privado de clase y "* 2; …" la continuación de una
// multiplicación, y las dos líneas se ejecutan. En un lenguaje desconocido no se salta nada.
const HASH_COMMENT = /\.(sh|bash|zsh|ksh|fish|py|pyw|rb|pl|pm|r|ps1|psm1|ya?ml|toml|cfg|ini|conf|mk|mak|cmake|tf|nix|exs?|jl|coffee|dockerfile|bats|envrc|php)$|(^|\/)(Makefile|Dockerfile|Containerfile|Rakefile|Gemfile|Vagrantfile|Justfile|Brewfile|\.envrc|\.bashrc|\.zshrc|\.profile)$/i;
const SLASH_COMMENT = /\.(c|h|cc|cpp|cxx|hpp|cs|java|kt|kts|scala|go|rs|swift|m|mm|js|mjs|cjs|jsx|ts|mts|cts|tsx|vue|svelte|php|dart|groovy|gradle|zig|sol|jsonc|json5)$/i;
const MARKUP_COMMENT = /\.(html?|xml|svg|md|markdown|mdx|vue|svelte)$/i;
function commentLines(rel, lines) {
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
      const tick = t.includes('`');
      if (inBlock || (t.startsWith('/*') && !tick && !continued)) {
        const end = t.indexOf('*/', inBlock ? 0 : 2);
        // Tras el cierre del bloque puede haber código en la misma línea: entonces no es comentario
        out[i] = !tick && (end < 0 || !t.slice(end + 2).trim() || t.slice(end + 2).trim().startsWith('//'));
        inBlock = end < 0;
        continue;
      }
      if (t.startsWith('//') && !tick && !continued) { out[i] = true; continue; }
    }
    if (hash && t.startsWith('#') && !(i === 0 && t.startsWith('#!')) && !continued && !/"""|'''/.test(t)) { out[i] = true; continue; }
    if (markup && t.startsWith('<!--') && t.includes('-->') && !t.slice(t.indexOf('-->') + 3).trim()) out[i] = true;
  }
  return out;
}

module.exports = { commentLines };
