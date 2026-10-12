'use strict';
// Globales de Node que espera lib/ (inyectados por esbuild en el paquete web).
export { Buffer } from 'buffer';
export const process = { env: {}, platform: 'browser', cwd: () => '/' };
