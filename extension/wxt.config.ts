import { defineConfig } from 'wxt';

import { HOST_PERMISSIONS, PERMISSIONS } from './permissions.mjs';

/**
 * The extension's manifest, built from the permission list that carries a written reason for every
 * entry (`permissions.mjs`, checked by a test).
 *
 * There is deliberately nothing else here. No background network access, no remote code, no analytics:
 * the extension reads the page you asked it to seal, writes the receipt locally, and keeps the signing
 * key in the browser's own storage.
 */
export default defineConfig({
  manifest: {
    name: 'Vidimus',
    description: 'Save what the page said: seal the page you are reading into a signed receipt.',
    version: '0.1.0',
    permissions: [...PERMISSIONS],
    host_permissions: [...HOST_PERMISSIONS],
  },
});
