'use strict';
// Pasarela de red del despliegue con Docker (servicio "gateway" de compose.yaml).
// La app corre en una red interna de Docker sin salida a ninguna parte; este proceso, en su
// propio contenedor, es la única conexión entre esa red y el exterior:
//
//  - Entrada (GATEWAY_PORT, 8080): lo que abres en el navegador se reenvía tal cual a la app.
//    Con GATEWAY_PORT=0 no hay entrada: es la pasarela de salida del contenedor de análisis,
//    que así no tiene ningún camino hasta la app.
//  - Salida (EGRESS_PORT, 3128): proxy HTTPS para la app y sus herramientas (git, Semgrep,
//    Trivy, las consultas a OSV, GitHub…). Solo deja pasar CONNECT al puerto 443 de
//    direcciones públicas: nada de tu equipo, tu red local ni el servicio de metadatos de la
//    nube, aunque un dominio resuelva a ellas. La IP se comprueba al conectar.
//
// Así, aunque algo dentro de la app intentara llegar a tu red (un fallo, una herramienta,
// un fichero preparado), la red de Docker no tiene camino.
const http = require('http');
const net = require('net');
const dns = require('dns');
const { privateAddress } = require('./remote');

const APP = process.env.GATEWAY_APP || 'app:8080';
const IN_PORT = process.env.GATEWAY_PORT === undefined ? 8080 : Number(process.env.GATEWAY_PORT);
const OUT_PORT = Number(process.env.EGRESS_PORT) || 3128;
const IDLE = 5 * 60 * 1000;
const MAX = 256;
let open = 0;
// Sin caracteres de control: un salto de línea en lo registrado no puede inventar otra línea
const log = (m) => console.log(`${new Date().toISOString()} ${String(m).replace(/[\u0000-\u001f\u007f]/g, ' ')}`);

function pipe(a, b) {
  a.setTimeout(IDLE, () => a.destroy());
  b.setTimeout(IDLE, () => b.destroy());
  a.on('error', () => b.destroy());
  b.on('error', () => a.destroy());
  a.on('close', () => b.destroy());
  b.on('close', () => a.destroy());
  a.pipe(b);
  b.pipe(a);
}

// ---------- Entrada: navegador → app ----------
const [appHost, appPort] = APP.split(':');
if (IN_PORT) net.createServer((client) => {
  if (open >= MAX) return client.destroy();
  open++;
  client.on('close', () => { open--; });
  const upstream = net.connect(Number(appPort), appHost);
  // PROXY protocol v1: la app sabe la IP real de quien se conecta (para su límite de peticiones
  // por IP) y que la conexión viene de aquí (solo acepta esta cabecera desde la pasarela).
  if (process.env.GATEWAY_PROXY_PROTOCOL === '1') upstream.write(proxyHeader(client));
  pipe(client, upstream);
}).listen(IN_PORT, '0.0.0.0', () => log(`entrada :${IN_PORT} → ${APP}`));
else log('sin entrada (solo salida)');

function proxyHeader(s) {
  const src = String(s.remoteAddress || '').replace(/^::ffff:(?=\d+\.)/, '');
  const dst = String(s.localAddress || '').replace(/^::ffff:(?=\d+\.)/, '');
  const fam = net.isIPv4(src) && net.isIPv4(dst) ? 'TCP4' : net.isIPv6(src) && net.isIPv6(dst) ? 'TCP6' : null;
  return fam ? `PROXY ${fam} ${src} ${dst} ${s.remotePort} ${s.localPort}\r\n` : 'PROXY UNKNOWN\r\n';
}

// ---------- Salida: app → Internet (solo HTTPS a direcciones públicas) ----------
const proxy = http.createServer((req, res) => {
  // Sin CONNECT no hay cifrado extremo a extremo: no se reenvía HTTP plano.
  res.writeHead(405, { 'content-type': 'text/plain' });
  res.end('La pasarela solo deja salir HTTPS (CONNECT).\n');
  log(`bloqueado: ${req.method} ${String(req.url).slice(0, 120)} (HTTP sin cifrar)`);
});
proxy.on('connect', (req, client, head) => {
  const deny = (status, why) => {
    client.end(`HTTP/1.1 ${status}\r\nContent-Length: 0\r\n\r\n`);
    log(`bloqueado: ${String(req.url).slice(0, 120)} (${why})`);
  };
  if (open >= MAX) return deny('503 Service Unavailable', 'demasiadas conexiones');
  const m = /^([a-z0-9.-]{1,253}|\[[0-9a-f:.]{2,45}\]):(\d{1,5})$/i.exec(String(req.url));
  if (!m) return deny('400 Bad Request', 'destino no válido');
  if (m[2] !== '443') return deny('403 Forbidden', `puerto ${m[2]}: solo 443`);
  const host = m[1].replace(/^\[|\]$/g, '');
  dns.lookup(host, { all: true }, (err, list) => {
    if (err || !list.length) return deny('502 Bad Gateway', err ? err.code : 'sin dirección');
    // Si alguna dirección es local, se rechaza entero: no se elige "la buena" de un dominio trucado.
    if (list.some((a) => privateAddress(a.address))) return deny('403 Forbidden', `${host} resuelve a una dirección local o privada`);
    open++;
    const upstream = net.connect(443, list[0].address, () => {
      client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head && head.length) upstream.write(head);
      pipe(client, upstream);
    });
    upstream.on('close', () => { open--; });
    upstream.on('error', () => client.destroy());
  });
});
proxy.listen(OUT_PORT, '0.0.0.0', () => log(`salida :${OUT_PORT} (solo HTTPS a direcciones públicas)`));

process.on('SIGTERM', () => process.exit(0));
