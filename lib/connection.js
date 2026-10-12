'use strict';
// Conexión con Claude para la revisión con IA. Hay dos formas de conectarla:
// - "api": una clave de la API de Anthropic (de pago por uso, en console.anthropic.com).
//   Se toma de ANTHROPIC_API_KEY o se escribe en la ventana "Conectar Claude"; en ese
//   caso vive solo en la memoria del servidor: no se guarda en disco ni se devuelve nunca.
// - "claude-code": el Claude Code instalado en este equipo con tu sesión de Pro o Max.
//   Gasta el uso de tu plan, no dinero aparte. La app nunca lee tus credenciales: solo
//   ejecuta `claude -p` sin herramientas, sin MCP y sin personalizaciones, en una carpeta vacía.

const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');

const MODEL = process.env.OMINOUS_MODEL || 'claude-opus-5-5';
const CLAUDE_BIN = process.env.OMINOUS_CLAUDE_BIN || 'claude';
const CLAUDE_TIMEOUT = Number(process.env.OMINOUS_CLAUDE_TIMEOUT) || 600000;

let Anthropic = null;
try { const m = require('@anthropic-ai/sdk'); Anthropic = m.default || m; } catch { /* SDK opcional */ }

const state = {
  method: process.env.OMINOUS_AI_METHOD === 'claude-code' ? 'claude-code' : process.env.ANTHROPIC_API_KEY ? 'api' : null,
  key: null, // clave escrita en la ventana (si no, se usa ANTHROPIC_API_KEY)
  check: null, // { ok, at, detail, account }
};

function keySource() { return state.key ? 'ventana' : process.env.ANTHROPIC_API_KEY ? 'variable' : null; }
function mask(k) { return k ? `${k.slice(0, 7)}…${k.slice(-4)}` : null; }

// Lo que ve el navegador. Nunca incluye la clave.
function status() {
  return {
    method: state.method,
    sdk: !!Anthropic,
    keySource: keySource(),
    keyHint: mask(state.key || process.env.ANTHROPIC_API_KEY || ''),
    model: MODEL,
    check: state.check,
    connected: !!(state.check && state.check.ok && state.check.method === state.method),
  };
}

function apiClient() {
  if (!Anthropic) throw Object.assign(new Error('Falta el SDK de Anthropic: ejecuta npm install.'), { status: 501 });
  const key = state.key || process.env.ANTHROPIC_API_KEY;
  if (!key) throw Object.assign(new Error('No hay clave de la API. Escríbela en "Conectar Claude" o define ANTHROPIC_API_KEY.'), { status: 501 });
  return new Anthropic({ apiKey: key });
}

// Variables de entorno del proceso hijo: sin claves, para que Claude Code use tu sesión
// de Pro/Max (si ve una clave, la usaría y cobraría por uso).
function childEnv() {
  const env = { ...process.env };
  for (const k of ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'OMINOUS_TOKEN']) delete env[k];
  return env;
}

function run(args, { input, timeout = 20000, cwd } = {}) {
  return new Promise((resolve) => {
    const child = execFile(CLAUDE_BIN, args, { env: childEnv(), cwd: cwd || os.tmpdir(), timeout, maxBuffer: 20 * 1024 * 1024, windowsHide: true }, (err, stdout, stderr) => {
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : -1) : 0, missing: !!(err && err.code === 'ENOENT'), timedOut: !!(err && err.killed), stdout: String(stdout || ''), stderr: String(stderr || '') });
    });
    if (input != null) { child.stdin.on('error', () => {}); child.stdin.end(input); }
  });
}

async function verifyApi() {
  const client = apiClient();
  try {
    // Consultar el modelo no gasta tokens y confirma que la clave es válida.
    const m = await client.models.retrieve(MODEL);
    return { ok: true, detail: `Clave válida (${keySource() === 'ventana' ? 'escrita en la ventana' : 'ANTHROPIC_API_KEY'}). Modelo ${m.display_name || m.id}.`, account: 'API de Anthropic · pago por uso' };
  } catch (e) {
    if (Anthropic.AuthenticationError && e instanceof Anthropic.AuthenticationError) return { ok: false, detail: 'La clave no es válida o se ha revocado.' };
    if (Anthropic.PermissionDeniedError && e instanceof Anthropic.PermissionDeniedError) return { ok: false, detail: `La clave no tiene acceso a ${MODEL}.` };
    if (Anthropic.NotFoundError && e instanceof Anthropic.NotFoundError) return { ok: false, detail: `El modelo ${MODEL} no existe para esta clave. Revisa OMINOUS_MODEL.` };
    if (Anthropic.APIConnectionError && e instanceof Anthropic.APIConnectionError) return { ok: false, detail: 'No hay conexión con api.anthropic.com.' };
    return { ok: false, detail: `No se pudo comprobar la clave: ${String(e.message).slice(0, 200)}` };
  }
}

async function verifyClaudeCode() {
  const v = await run(['--version']);
  if (v.missing) return { ok: false, detail: 'No se encuentra Claude Code en este equipo. Instálalo (npm install -g @anthropic-ai/claude-code) y ejecuta `claude` una vez para iniciar sesión.' };
  const s = await run(['auth', 'status']);
  let j = null;
  try { j = JSON.parse(s.stdout); } catch { /* versión antigua */ }
  const version = v.stdout.trim().split(/\s/)[0] || '?';
  if (!j) return { ok: false, detail: `Claude Code ${version} no informa de su sesión. Actualízalo con \`claude update\`.` };
  if (!j.loggedIn) return { ok: false, detail: 'Claude Code está instalado pero sin sesión. Ejecuta `claude` en una terminal e inicia sesión con tu cuenta Pro o Max.' };
  const sub = j.authMethod === 'claude.ai' || j.authMethod === 'oauth_token';
  return {
    ok: true,
    detail: `Claude Code ${version} con sesión iniciada${sub ? '' : ` (${j.authMethod})`}.`,
    account: sub ? 'Cuenta de Claude · usa el uso de tu plan' : 'Claude Code con clave de API · pago por uso',
  };
}

async function verify() {
  const method = state.method;
  if (!method) { state.check = null; return status(); }
  const r = method === 'api' ? await verifyApi() : await verifyClaudeCode();
  state.check = { ...r, method, at: new Date().toISOString() };
  return status();
}

// Cambia la conexión. `secureChannel` indica si la clave puede viajar por esta conexión.
async function configure({ method, key }, { secureChannel }) {
  if (!['api', 'claude-code', 'none'].includes(method)) throw Object.assign(new Error('Método de conexión no válido.'), { status: 400 });
  if (method === 'none') { state.method = null; state.key = null; state.check = null; return status(); }
  if (method === 'api' && key != null && key !== '') {
    if (!secureChannel) throw Object.assign(new Error('Por seguridad, la clave solo se puede escribir desde este mismo equipo o a través de HTTPS. Usa ANTHROPIC_API_KEY.'), { status: 403 });
    const k = String(key).trim();
    if (!/^sk-ant-[A-Za-z0-9_-]{20,300}$/.test(k)) throw Object.assign(new Error('Eso no parece una clave de la API de Anthropic (empiezan por sk-ant-).'), { status: 400 });
    state.key = k;
  }
  state.method = method;
  return verify();
}

// Revisión con Claude Code: el texto del repo entra por stdin y la respuesta sale como JSON validado contra el esquema.
async function runClaudeCode({ system, prompt, schema, model }) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), 'ominous-claude-'));
  try {
    const args = [
      '-p', 'Analiza el contenido que llega por la entrada estándar siguiendo tus instrucciones y responde con el JSON pedido.',
      '--safe-mode', '--tools', '', '--disallowedTools', 'mcp__*', '--strict-mcp-config',
      '--permission-mode', 'dontAsk', '--no-session-persistence',
      '--system-prompt', system,
      '--output-format', 'json',
      ...(schema ? ['--json-schema', JSON.stringify(schema)] : []),
      ...(model ? ['--model', model] : []),
    ];
    const r = await run(args, { input: prompt, timeout: CLAUDE_TIMEOUT, cwd });
    if (r.missing) throw Object.assign(new Error('No se encuentra Claude Code en este equipo.'), { status: 501 });
    if (r.timedOut) throw Object.assign(new Error('Claude Code ha tardado demasiado en responder.'), { status: 504 });
    let j;
    try { j = JSON.parse(r.stdout); } catch { throw Object.assign(new Error(`Claude Code no ha devuelto JSON (código ${r.code}).`), { status: 502 }); }
    if (j.is_error || r.code !== 0) {
      const msg = String(j.result || j.subtype || 'error').slice(0, 300);
      const status = /rate|limit|usage/i.test(msg) ? 429 : /log ?in|auth/i.test(msg) ? 401 : 502;
      throw Object.assign(new Error(`Claude Code: ${msg}`), { status });
    }
    const model0 = Object.keys(j.modelUsage || {})[0] || model || 'Claude Code';
    return { structured: j.structured_output, text: String(j.result || ''), model: model0 };
  } finally {
    fs.rmSync(cwd, { recursive: true, force: true });
  }
}

const available = () => state.method === 'claude-code' || (!!Anthropic && !!(state.key || process.env.ANTHROPIC_API_KEY));

module.exports = { status, verify, configure, apiClient, runClaudeCode, available, method: () => state.method, MODEL, _state: state };
