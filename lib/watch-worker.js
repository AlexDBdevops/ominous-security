'use strict';
// Comprobación de la vigilancia en un hilo aparte (ver checkInWorker en lib/watch.js):
// entrega cada repo en cuanto lo termina para que, si se corta por tiempo, no se pierda.
const { parentPort, workerData } = require('worker_threads');
const { checkRepoSafe } = require('./watch');

(async () => {
  const log = (m) => parentPort.postMessage({ log: m });
  for (const r of workerData.repos) parentPort.postMessage({ result: await checkRepoSafe(workerData.base, r, log) });
  parentPort.postMessage({ done: true });
})();
