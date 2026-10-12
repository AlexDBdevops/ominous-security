'use strict';
// Dependencias indirectas de npm cuando el repo no trae lockfile. Sin package-lock.json
// solo se conocen las dependencias directas (y con rangos como ^1.2.0), pero npm install
// instalaría también las de esas dependencias. deps.dev (Google) resuelve el árbol que
// saldría hoy: se elige la versión más alta que cumple cada rango y se pide su árbol.
// Solo se leen datos públicos; si deps.dev no responde, la cobertura lo dice.
const path = require('path');

const API = 'https://api.deps.dev/v3/systems/npm/packages/';
const MAX_DIRECT = 40;
const MAX_NODES = 2000;
const LOCKS = ['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml'];

// ---------- semver mínimo: lo justo para elegir la versión que instalaría npm ----------
function parse(v) {
  const m = String(v).trim().replace(/^[v=]+/, '').match(/^(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([\w.-]+))?(?:\+[\w.-]+)?$/);
  if (!m) return null;
  const n = (x) => (x == null || /^[xX*]$/.test(x) ? null : Number(x));
  return { major: n(m[1]), minor: n(m[2]), patch: n(m[3]), pre: m[4] || null };
}
const cmp = (a, b) => (a.major - b.major) || (a.minor - b.minor) || (a.patch - b.patch) || (a.pre === b.pre ? 0 : !a.pre ? 1 : !b.pre ? -1 : a.pre < b.pre ? -1 : 1);
const V = (major, minor = 0, patch = 0, pre = null) => ({ major, minor, patch, pre });

// Convierte un comparador (^1.2, ~1, 1.x, >=2 …) en límites [mínimo incluido, máximo excluido).
function bounds(c) {
  const m = c.match(/^(\^|~>?|>=|<=|>|<|=)?\s*(.*)$/);
  const op = m[1] || '';
  if (!m[2] || /^[xX*]$/.test(m[2])) return [V(0), null];
  const p = parse(m[2]);
  if (!p || p.major == null) return null;
  const { major, minor, patch } = p;
  const full = V(major, minor || 0, patch || 0, p.pre);
  if (op === '^') {
    if (major > 0 || minor == null) return [full, V(major + 1)];
    if (minor > 0 || patch == null) return [full, V(0, minor + 1)];
    return [full, V(0, 0, patch + 1)];
  }
  if (op.startsWith('~')) return [full, minor == null ? V(major + 1) : V(major, minor + 1)];
  const next = minor == null ? V(major + 1) : patch == null ? V(major, minor + 1) : V(major, minor, patch + 1);
  if (op === '>=') return [full, null];
  if (op === '>') return [next, null];
  if (op === '<') return [V(0), full];
  if (op === '<=') return [V(0), next];
  return [full, next]; // 1.2.3, 1.2, 1.x, =1.2.3
}

function satisfies(version, range) {
  const v = parse(version);
  if (!v || v.major == null || v.minor == null || v.patch == null) return false;
  return String(range).split('||').some((set) => {
    const s = set.trim().replace(/^(\S+)\s+-\s+(\S+)$/, '>=$1 <=$2').replace(/(\^|~>?|>=|<=|>|<|=)\s+/g, '$1');
    const parts = s.split(/\s+/).filter(Boolean);
    if (!parts.length) return !v.pre;
    let pre = false;
    for (const c of parts) {
      const b = bounds(c);
      if (!b) return false;
      if (cmp(v, b[0]) < 0 || (b[1] && cmp(v, b[1]) >= 0)) return false;
      if (v.pre && b[0].pre && b[0].major === v.major && b[0].minor === v.minor && b[0].patch === v.patch) pre = true;
    }
    return !v.pre || pre; // como npm: las prerelease solo si el rango las nombra
  });
}

function maxSatisfying(versions, range) {
  let best = null;
  for (const v of versions) if (satisfies(v, range) && (!best || cmp(parse(v), parse(best)) > 0)) best = v;
  return best;
}

// ---------- deps.dev ----------
async function getJson(url) {
  const r = await fetch(url, { signal: AbortSignal.timeout(15000) });
  if (r.status === 404) return null;
  if (!r.ok) throw new Error(`deps.dev ${r.status}`);
  return r.json();
}

async function pool(items, n, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]); }
  }));
  return out;
}

const RANGE = /^[\s\d.xX*^~<>=|-]+$/; // rangos de versión, no URLs, git, file: ni alias npm:

async function transitiveNpm(root, files, pkgs) {
  const fileSet = new Set(files);
  const unlocked = new Set(files.filter((f) => path.basename(f) === 'package.json' && !/node_modules\//.test(f) && !LOCKS.some((l) => fileSet.has(path.join(path.dirname(f), l).replace(/^\.\//, '')))));
  const direct = pkgs.filter((p) => p.ecosystem === 'npm' && p.direct && unlocked.has(p.file) && p.spec && RANGE.test(p.spec));
  if (!direct.length) return { pkgs: [], summary: null };
  if (process.env.OMINOUS_OFFLINE === '1') return { pkgs: [], summary: { status: 'skip', detail: 'modo sin conexión (OMINOUS_OFFLINE)' } };
  const todo = direct.slice(0, MAX_DIRECT);
  const out = [];
  const seen = new Set();
  let resolved = 0;
  let errors = 0;
  let lastError = null;
  await pool(todo, 8, async (d) => {
    try {
      const pkg = await getJson(API + encodeURIComponent(d.name));
      const version = pkg && maxSatisfying((pkg.versions || []).map((x) => x.versionKey && x.versionKey.version).filter(Boolean), d.spec);
      if (!version) return;
      const tree = await getJson(`${API}${encodeURIComponent(d.name)}/versions/${encodeURIComponent(version)}:dependencies`);
      resolved++;
      for (const n of (tree && tree.nodes) || []) {
        const k = n.versionKey || {};
        if (n.relation === 'SELF' || !k.name || !k.version || seen.has(`${k.name}@${k.version}`) || out.length >= MAX_NODES) continue;
        seen.add(`${k.name}@${k.version}`);
        out.push({ name: k.name, version: k.version, ecosystem: 'npm', file: d.file, direct: false, via: `${d.name}@${version}` });
      }
    } catch (e) { errors++; lastError = e.message; }
  });
  const partial = errors > 0 || direct.length > MAX_DIRECT || out.length >= MAX_NODES;
  return {
    pkgs: out,
    summary: {
      status: !resolved && errors ? 'skip' : partial ? 'partial' : 'ok',
      detail: !resolved && errors ? `no se pudo consultar deps.dev (${lastError})`
        : `${out.length} dependencias indirectas de ${resolved} directas sin lockfile${direct.length > MAX_DIRECT ? ` (máximo ${MAX_DIRECT})` : ''}${errors ? ` · ${errors} sin resolver` : ''}`,
    },
  };
}

module.exports = { transitiveNpm, maxSatisfying, satisfies };
