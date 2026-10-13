'use strict';
// Entrada a la app detrás de la pasarela (Docker). La pasarela antepone a cada conexión una
// línea del PROXY protocol v1 con la IP real de quien se conecta. Aquí:
//  - solo se acepta esa línea si la conexión viene de la pasarela (su IP se resuelve por nombre);
//  - cualquier otra conexión que no sea local se cierra: el contenedor de análisis, que comparte
//    la red interna, no puede hablar con la app;
//  - las conexiones locales (el healthcheck del propio contenedor) pasan sin cabecera.
// La IP real queda en socket.clientAddress para el límite de peticiones por IP.
const net = require('net');
const dns = require('dns');

const LOOPBACK = (ip) => /^(127\.|::1$|::ffff:127\.)/.test(String(ip));
const plain = (ip) => String(ip || '').replace(/^::ffff:(?=\d+\.)/, '');

function proxyServer(httpServer, fromHost) {
  let trusted = new Set();
  let resolvedAt = 0;
  const refresh = () => new Promise((resolve) => {
    if (Date.now() - resolvedAt < 30000) return resolve();
    dns.lookup(fromHost, { all: true }, (err, list) => {
      if (!err) { trusted = new Set(list.map((x) => plain(x.address))); resolvedAt = Date.now(); }
      resolve();
    });
  });

  return net.createServer(async (socket) => {
    socket.on('error', () => socket.destroy());
    const peer = plain(socket.remoteAddress);
    if (LOOPBACK(peer)) { socket.clientAddress = peer; return httpServer.emit('connection', socket); }
    await refresh();
    if (!trusted.has(peer)) return socket.destroy();
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => socket.destroy(), 5000);
    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const end = buf.indexOf('\r\n');
      if (end < 0) { if (buf.length > 107) socket.destroy(); return; }
      clearTimeout(timer);
      socket.removeListener('data', onData);
      socket.pause();
      const m = buf.slice(0, end).toString('latin1').match(/^PROXY (?:(TCP4|TCP6) (\S+) (\S+) (\d+) (\d+)|UNKNOWN.*)$/);
      if (!m || (m[1] && !net.isIP(m[2]))) return socket.destroy();
      socket.clientAddress = m[1] ? plain(m[2]) : peer;
      const rest = buf.slice(end + 2);
      if (rest.length) socket.unshift(rest);
      httpServer.emit('connection', socket);
      socket.resume();
    };
    socket.on('data', onData);
  });
}

module.exports = { proxyServer };
