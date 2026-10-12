'use strict';
// Piezas comunes al servidor y a la versión web: URLs de GitHub, metadatos y avisos
// que no dependen del código del repo (renombrado, releases, Scorecard).

function parseGithubUrl(input) {
  const s = String(input || '').trim()
    .replace(/^git@github\.com:/i, 'https://github.com/')
    .replace(/^(?!https?:\/\/)(github\.com\/)/i, 'https://$1');
  let u;
  try { u = new URL(s); } catch { return null; }
  if (!/^(www\.)?github\.com$/i.test(u.hostname)) return null;
  const parts = u.pathname.split('/').filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, '');
  const ok = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/;
  if (!ok.test(owner) || !/^[A-Za-z0-9._-]{1,100}$/.test(repo) || repo === '.' || repo === '..') return null;
  let branch = null;
  if (parts[2] === 'tree' && parts[3]) {
    branch = decodeURIComponent(parts.slice(3).join('/'));
    if (!/^[\w./-]{1,200}$/.test(branch) || branch.includes('..') || branch.startsWith('-')) return null;
  }
  return { owner, repo, branch, cloneUrl: `https://github.com/${owner}/${repo}.git` };
}

// Metadatos de /repos/{owner}/{repo} en el formato que usa el analizador.
function repoMetaFrom(r, user, scorecard, releases) {
  return {
    full_name: r.full_name, description: r.description, stargazers_count: r.stargazers_count, forks_count: r.forks_count,
    created_at: r.created_at, pushed_at: r.pushed_at, archived: r.archived, fork: r.fork, parent: r.parent && r.parent.full_name,
    license: r.license && r.license.spdx_id !== 'NOASSERTION' ? r.license.spdx_id : null, default_branch: r.default_branch,
    owner_type: r.owner && r.owner.type, owner_created_at: user && user.created_at, size_kb: r.size, scorecard,
    releases: releases ? releases.map((rel) => ({ tag: rel.tag_name, assets: (rel.assets || []).map((a) => a.name) })) : null,
  };
}

// OpenSSF Scorecard: puntuación pública (0-10) de las prácticas de seguridad del repo.
function parseScorecard(j) {
  const weak = (j.checks || []).filter((c) => c.score >= 0 && c.score <= 3).map((c) => c.name);
  return { score: j.score, date: j.date, weak: weak.slice(0, 8) };
}

function movedPass(ref, meta, extra) {
  if (meta && meta.full_name && meta.full_name.toLowerCase() !== `${ref.owner}/${ref.repo}`.toLowerCase()) {
    extra.threats.push({ kind: 'threat', rule: 'repo-moved', severity: 'low', title: 'El repositorio ha cambiado de nombre o de dueño', description: `Pediste ${ref.owner}/${ref.repo} y GitHub redirige a ${meta.full_name}. Comprueba que es el proyecto que buscas: si el nombre antiguo queda libre, otra persona puede registrarlo y servir código distinto en la misma URL (repojacking).`, file: null, line: null });
  }
}

function scorecardCoverage(meta, extra) {
  extra.coverage.push({ label: 'OpenSSF Scorecard', status: meta && meta.scorecard ? 'ok' : 'skip', detail: meta && meta.scorecard ? `${meta.scorecard.score}/10 (${String(meta.scorecard.date).slice(0, 10)})` : 'el proyecto no tiene puntuación publicada o no se pudo consultar' });
}

// Releases: los binarios publicados no están en el código y no se pueden revisar.
function releasePass(meta, extra) {
  if (!meta || !meta.releases) { extra.coverage.push({ label: 'Releases de GitHub', status: 'skip', detail: 'no se pudo consultar la API de GitHub' }); return; }
  const bins = meta.releases.flatMap((r) => r.assets.filter((a) => /\.(exe|msi|dmg|pkg|appimage|deb|rpm|apk|zip|rar|7z|scr|bat)$/i.test(a)).map((a) => `${r.tag}/${a}`));
  if (bins.length) extra.threats.push({ kind: 'threat', rule: 'release-binaries', severity: 'low', title: 'Releases con ejecutables o comprimidos', description: `Publica ${bins.length} fichero${bins.length > 1 ? 's' : ''} binario${bins.length > 1 ? 's' : ''} en releases. No se generan desde este código de forma verificable y no se han analizado. Si vas a descargarlos, pásalos antes por un antivirus o VirusTotal.`, file: null, line: null, snippet: bins.slice(0, 5).join(', ') });
  extra.coverage.push({ label: 'Releases de GitHub', status: bins.length ? 'partial' : 'ok', detail: bins.length ? `${bins.length} binarios publicados sin analizar` : 'sin binarios publicados' });
}

module.exports = { parseGithubUrl, repoMetaFrom, parseScorecard, movedPass, scorecardCoverage, releasePass };
