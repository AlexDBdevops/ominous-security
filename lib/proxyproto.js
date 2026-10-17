'use strict';
// Entrada a la app detrás de la pasarela (Docker). La pasarela antepone a cada conexión una
// línea del PROXY protocol v1 con la IP real de quien se conecta. Aquí:
//  - solo se acepta esa línea si la conexión viene de la pasarela (su IP se resuelve por nombre);
//  - cualquier otra conexión que no sea local se cierra: el contenedor de análisis, que comparte
//    una red con la app (para que ella le pida los análisis), no puede hablarle;
//  - las conexiones locales (el healthcheck del propio contenedor) pasan sin cabecera;
//  - si la cabecera dice que quien se conecta es el contenedor de análisis (denyHost), se
//    cierra: aunque una red mal montada le diera camino hasta la pasarela, no llega a la app.
// La IP real queda en socket.clientAddress para el límite de peticiones por IP.
const net = require('net');
const dns = require('dns');

const LOOPBACK = (ip) => /^(127\.|::1$|::ffff:127\.)/.test(String(ip));
const plain = (ip) => String(ip || '').replace(/^::ffff:(?=\d+\.)/, '');

// IP real de quien se conecta según la línea PROXY, o null si la línea no vale o el origen
// está rechazado.
function clientFromLine(line, peer, denied = new Set()) {
  const m = String(line).match(/^PROXY (?:(TCP4|TCP6) (\S+) (\S+) (\d+) (\d+)|UNKNOWN.*)$/);
  if (!m || (m[1] && !net.isIP(m[2]))) return null;
  const ip = m[1] ? plain(m[2]) : peer;
  return denied.has(ip) ? null : ip;
}

// Direcciones de un nombre de Docker, resueltas como mucho cada 30 s. Si el nombre no
// resuelve, se conserva lo último que resolvió.
function resolver(host) {
  let set = new Set();
  let at = 0;
  return () => new Promise((resolve) => {
    if (!host || Date.now() - at < 30000) return resolve(set);
    dns.lookup(host, { all: true }, (err, list) => {
      if (!err) { set = new Set(list.map((x) => plain(x.address))); at = Date.now(); }
      resolve(set);
    });
  });
}

function proxyServer(httpServer, fromHost, denyHost = '') {
  const trusted = resolver(fromHost);
  const denied = resolver(denyHost);

  return net.createServer(async (socket) => {
    socket.on('error', () => socket.destroy());
    const peer = plain(socket.remoteAddress);
    if (LOOPBACK(peer)) { socket.clientAddress = peer; return httpServer.emit('connection', socket); }
    if (!(await trusted()).has(peer)) return socket.destroy();
    const deny = await denied();
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => socket.destroy(), 5000);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const end = buf.indexOf('\r\n');
      if (end < 0) { if (buf.length > 107) socket.destroy(); return; }
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.pause();
      const ip = clientFromLine(buf.slice(0, end).toString('latin1'), peer, deny);
      if (!ip) return socket.destroy();
      socket.clientAddress = ip;
      const rest = buf.slice(end + 2);
      if (rest.length) socket.unshift(rest);
      httpServer.emit('connection', socket);
      socket.resume();
    };
    socket.on('data', onData);
  });
}

module.exports = { proxyServer, clientFromLine };
