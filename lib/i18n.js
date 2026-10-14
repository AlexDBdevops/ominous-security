'use strict';
// Textos en inglés para el botón de idioma de la página: avisos, fichas, notas de revisión,
// cobertura e interfaz. El análisis sigue escribiendo en español; la página traduce lo que pinta.
//
// lib/i18n-en.json: pares [español, inglés]. En el español, {0}, {1}… son valores variables (un
// número, un fichero, otro texto). En el inglés, {N} copia ese valor (traducido si es un texto
// conocido) y {N?a:b} pone «a» si el valor no está vacío y «b» si lo está (plurales: el código
// en español añade la «s» o la «n» en ese hueco).
const PAIRS = require('./i18n-en.json');

const exact = new Map();
const patterns = [];
const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
for (const [es, en] of PAIRS) {
  if (!/\{\d\}/.test(es)) { exact.set(es, en); continue; }
  const order = [];
  const src = es.split(/(\{\d\})/).map((p) => (/^\{\d\}$/.test(p) ? (order.push(+p[1]), '(.*?)') : esc(p))).join('');
  patterns.push({ re: new RegExp(`^${src}$`, 's'), order, en, fixed: es.replace(/\{\d\}/g, '').length });
}
// Los más concretos primero: «{0} días» no debe ganar a «Creado hace {0} días…»
patterns.sort((a, b) => b.fixed - a.fixed);

const cache = new Map();

function fill(en, caps, depth) {
  return en.replace(/\{(\d)(?:\?([^:}]*)(?::([^}]*))?)?\}/g, (m, n, yes, no) => {
    const v = caps[+n] == null ? '' : caps[+n];
    if (yes !== undefined) return v ? yes : (no || '');
    if (depth >= 3) return v;
    const [, lead, core, trail] = v.match(/^(\s*)([\s\S]*?)(\s*)$/);
    const t = label(core, depth + 1) ?? list(core, depth + 1);
    return t == null ? v : lead + t + trail;
  });
}

// Un valor con varios datos separados por « · » o «; » («182 KB · descripción», «pide sudo; borra
// carpetas»): cada uno por su lado.
function list(s, depth) {
  for (const sp of [' · ', '; ']) {
    if (!s.includes(sp)) continue;
    const raw = s.split(sp);
    const parts = raw.map((p) => label(p, depth));
    return parts.some((p) => p != null) ? raw.map((p, i) => parts[i] ?? p).join(sp) : null;
  }
  return null;
}

// Un texto entero, sin trocear. null si no se conoce.
function one(s, depth = 0) {
  if (exact.has(s)) return exact.get(s);
  for (const p of patterns) {
    const m = p.re.exec(s);
    if (!m) continue;
    // Un hueco no se traga otra frase: «Revisado: el paquete existe desde {0}.» no es el texto
    // entero cuando detrás va la descripción del aviso.
    if (m.slice(1).some((c) => /[.!?]\s+[¿¡"«(A-ZÁÉÍÓÚÑ]/.test(c))) continue;
    const caps = [];
    p.order.forEach((n, i) => { if (caps[n] === undefined) caps[n] = m[i + 1]; });
    return fill(p.en, caps, depth);
  }
  return null;
}

// Una etiqueta con dos puntos («Crítica:», «Antigüedad del repo:») o un trozo que empieza por
// un separador («· descripción»): se traduce sin ellos.
function label(s, depth = 0) {
  const r = one(s, depth);
  if (r != null) return r;
  const sep = s.match(/^([·,]\s*)([\s\S]+)$/);
  if (sep) { const t = label(sep[2], depth); return t == null ? null : sep[1] + t; }
  if (!/[:·.]$/.test(s)) return null;
  const t = one(s.slice(0, -1).trimEnd(), depth);
  return t == null ? null : t + s.slice(-1);
}

// Varias frases seguidas (la nota de la revisión delante de la descripción, la ficha del script
// remoto detrás): se traduce el trozo más largo que se conozca y se sigue con el resto.
function sentences(s) {
  let parts = s.split(/(?<=[.!?:…)])\s+(?=[¿¡"«(A-ZÁÉÍÓÚÑ])/);
  // Lo que va detrás puede empezar en minúscula (el mensaje de una herramienta externa)
  if (parts.length < 2) parts = s.split(/(?<=[.!?])\s+/);
  if (parts.length < 2) return null;
  const out = [];
  let hit = false;
  for (let i = 0; i < parts.length;) {
    let j = parts.length;
    for (; j > i; j--) {
      const r = label(parts.slice(i, j).join(' '));
      if (r != null) { out.push(r); hit = true; break; }
    }
    if (j > i) i = j; else out.push(parts[i++]);
  }
  return hit ? out.join(' ') : null;
}

// Traduce al inglés un texto de la página; lo que no conoce lo devuelve tal cual.
function tr(text) {
  if (typeof text !== 'string' || !/[A-Za-zÁÉÍÓÚáéíóúñÑ]/.test(text)) return text;
  if (cache.has(text)) return cache.get(text);
  let r;
  if (text.includes('\n')) r = text.split('\n').map(tr).join('\n');
  else {
    const [, lead, core, trail] = text.match(/^(\s*)([\s\S]*?)(\s*)$/);
    const t = label(core) ?? sentences(core) ?? list(core, 0);
    r = t == null ? text : lead + t + trail;
  }
  if (cache.size > 20000) cache.clear();
  cache.set(text, r);
  return r;
}

// ¿Hay traducción para este texto exacto? (algunos se quedan igual en inglés: «Reverse shell»)
const has = (s) => one(s) != null;

module.exports = { tr, has, PAIRS };
