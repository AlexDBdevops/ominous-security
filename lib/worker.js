'use strict';
// Ejecuta el análisis en un hilo aparte para poder cortarlo si un fichero
// diseñado para bloquear analizadores (ReDoS) lo deja colgado.
const { parentPort, workerData } = require('worker_threads');
const { analyzeTree } = require('./analyzer');

analyzeTree(workerData.root, workerData.meta, (m) => parentPort.postMessage({ log: m }), workerData.extra)
  .then((result) => parentPort.postMessage({ result }))
  .catch((e) => parentPort.postMessage({ error: e.message }));
