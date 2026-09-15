/**
 * The permissions this extension asks for, and the reason for each one.
 *
 * A permission list is a claim about what a program does, and this project's position is that a claim
 * nobody writes down is a claim nobody checks. So every entry here needs a reason, `wxt.config.ts`
 * builds the manifest from this file, and a test fails if a permission appears without one
 * (`reference/test/extension.test.mjs`).
 *
 * The reasons are the whole point: somebody installing this can read why it wants to see requests, and
 * somebody reviewing a pull request that adds a permission has to add a sentence saying why.
 *
 * @module permissions
 */

/** Why each permission is needed. Anything not in this list cannot be asked for. */
export const REASONS = {
  storage: 'to keep the sealing key and the receipts this browser has made. Nothing is synced',
  scripting: 'to read the rendered document of the page you asked to capture',
  webRequest: 'to observe the status line and response headers of that page, so the claim can record them',
  '<all_urls>': 'the pages you capture can be anywhere, and a host permission is per-site',
};

/** The API permissions. Reaching the page needs the host permission below as well. */
export const PERMISSIONS = ['storage', 'scripting', 'webRequest'];

/**
 * Host permissions.
 *
 * `<all_urls>` is the widest thing here and it is worth being honest about the alternatives: without it
 * the extension cannot see a response status, so the claim would carry no `status` and no
 * `content_type` (both optional in the format). That is a smaller ask and a poorer receipt, and it is
 * the trade to revisit first if this ever feels like too much.
 */
export const HOST_PERMISSIONS = ['<all_urls>'];
