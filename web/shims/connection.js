'use strict';
// En el navegador no hay conexión de servidor con Claude: la revisión con IA, cuando
// existe, se hace desde la página (artefacto de claude.ai).
module.exports = { available: () => false, method: () => null, status: () => ({ method: null, connected: false }) };
