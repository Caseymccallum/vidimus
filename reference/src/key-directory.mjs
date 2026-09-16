/**
 * Key directories: who a key belongs to.
 *
 * A receipt's `signature.signer` field is a **claim**, not a fact. The key id is derived and checkable, so
 * a verifier can say *this key signed this claim* with certainty - but nothing in the format says whose key
 * it is. That is not an oversight: a name inside a signature is worth exactly as much as the claim it
 * appears in, and the format cannot do better on its own (D-007).
 *
 * What closes the gap is a document the verifier's *caller* chose to trust:
 *
 * ```json
 * {
 *   "kind": "receipt-key-directory",
 *   "spec_version": "0.1.0",
 *   "keys": [
 *     {
 *       "key_id": "…64 hex…",
 *       "public_key": "…base64url raw ed25519…",
 *       "name": "Example Org",
 *       "note": "records desk",
 *       "valid_from": "2026-01-01T00:00:00Z",
 *       "valid_until": "2027-01-01T00:00:00Z"
 *     }
 *   ]
 * }
 * ```
 *
 * **It is trusted because it was chosen, not because it is signed.** A signed directory would only move
 * the question one step back - who signed the signature on it? - and a directory fetched over the network
 * is a directory an attacker can replace. Saying that plainly is more useful than a bootstrap chain nobody
 * can check by hand.
 *
 * Two rules make a directory trustworthy as *data*: an entry's `key_id` must be the digest of its own
 * `public_key` (so a directory cannot contradict itself about which key an id names), and no two entries
 * may share a key id (a directory that says two things about one key is not a directory). Both are refused
 * by name rather than resolved.
 *
 * @module key-directory
 */

import { toHex } from './encode.mjs';
import { sha256 } from './sha256.mjs';

/** Thrown when a directory cannot be read as one. */
export class KeyDirectoryError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'KeyDirectoryError';
  }
}

/** The `kind` a directory must declare, so a different JSON file cannot be mistaken for one. */
export const KEY_DIRECTORY_KIND = 'receipt-key-directory';

/** A base64url raw Ed25519 public key is 32 bytes, which is 43 characters without padding. */
const RAW_KEY = /^[A-Za-z0-9_-]{43}$/;

/** A whole-second UTC instant, the only timestamp shape this format admits. */
const UTC_SECOND = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;

/**
 * @param {unknown} value
 * @returns {value is Record<string, any>}
 */
function isObject(value) {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * @param {string} base64url A raw public key, as the claim carries it.
 * @returns {string} The key id it derives: lowercase hex SHA-256.
 */
export function keyIdOf(base64url) {
  const binary = atob(base64url.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return toHex(sha256(bytes));
}

/**
 * @typedef {object} KeyEntry
 * @property {string} key_id
 * @property {string} public_key
 * @property {string | null} name
 * @property {string | null} email
 * @property {string | null} note
 * @property {string | null} valid_from
 * @property {string | null} valid_until
 */

/**
 * Read a key directory, refusing anything it cannot be sure of.
 *
 * @param {unknown} value Parsed JSON, or anything else.
 * @returns {{ keys: Map<string, KeyEntry>, name: string | null, problems: string[] }}
 * @throws {KeyDirectoryError} When the document is not a directory at all.
 */
export function readKeyDirectory(value) {
  if (!isObject(value)) {
    throw new KeyDirectoryError('a key directory must be a JSON object');
  }
  if (value.kind !== KEY_DIRECTORY_KIND) {
    throw new KeyDirectoryError(`a key directory must declare kind "${KEY_DIRECTORY_KIND}"`);
  }
  if (typeof value.spec_version !== 'string' || !/^\d+\.\d+\.\d+$/.test(value.spec_version)) {
    throw new KeyDirectoryError('a key directory must declare a semantic spec_version');
  }
  if (!Array.isArray(value.keys)) {
    throw new KeyDirectoryError('a key directory must have a "keys" array');
  }

  /** @type {Map<string, KeyEntry>} */
  const keys = new Map();
  const problems = [];

  for (const [index, candidate] of value.keys.entries()) {
    const where = `keys[${index}]`;
    if (!isObject(candidate)) {
      problems.push(`${where} is not an object`);
      continue;
    }
    if (typeof candidate.public_key !== 'string' || !RAW_KEY.test(candidate.public_key)) {
      problems.push(`${where}.public_key must be a raw Ed25519 public key in base64url`);
      continue;
    }
    if (typeof candidate.key_id !== 'string') {
      problems.push(`${where}.key_id is missing`);
      continue;
    }

    const derived = keyIdOf(candidate.public_key);
    if (candidate.key_id !== derived) {
      // The same rule as everywhere else in this project: a key id is derived, never asserted.
      problems.push(
        `${where} says key_id ${candidate.key_id} and its public_key derives ${derived}: `
        + 'a directory cannot disagree with itself about which key an id names',
      );
      continue;
    }
    if (keys.has(derived)) {
      problems.push(
        `${where} repeats key id ${derived}: a directory that says two things about one key is not one`,
      );
      continue;
    }
    for (const field of ['valid_from', 'valid_until']) {
      if (candidate[field] !== undefined && !UTC_SECOND.test(candidate[field])) {
        problems.push(`${where}.${field} must be a UTC timestamp to the second, or absent`);
      }
    }

    keys.set(derived, {
      key_id: derived,
      public_key: candidate.public_key,
      name: typeof candidate.name === 'string' ? candidate.name : null,
      email: typeof candidate.email === 'string' ? candidate.email : null,
      note: typeof candidate.note === 'string' ? candidate.note : null,
      valid_from: typeof candidate.valid_from === 'string' ? candidate.valid_from : null,
      valid_until: typeof candidate.valid_until === 'string' ? candidate.valid_until : null,
    });
  }

  return {
    keys,
    name: typeof value.name === 'string' ? value.name : null,
    problems,
  };
}

/**
 * What a directory says about a key, or nothing when it has never heard of it.
 *
 * "Not in the directory" is not an accusation, and this function does not phrase it as one: a receipt from
 * a stranger is an ordinary thing, and a verifier that treated every unknown key as suspect would be
 * useless for the receipts people are most likely to receive.
 *
 * @param {{ keys: Map<string, KeyEntry> } | null} directory
 * @param {string | null} keyId
 * @returns {KeyEntry | null}
 */
export function lookUpKey(directory, keyId) {
  if (directory === null || typeof keyId !== 'string') return null;
  return directory.keys.get(keyId) ?? null;
}

/**
 * Whether a claim's own timestamp falls inside an entry's stated validity window.
 *
 * The timestamp compared against is the **claimed** capture time, which nothing has verified - so this is
 * reported as a fact about the two values and never as a verdict. An anchor that establishes when a claim
 * existed would make the comparison mean more; until then, saying which two values were compared is the
 * honest version of it (section 6.7 of the specification).
 *
 * @param {KeyEntry} entry
 * @param {string | null} claimedAt
 * @returns {'inside' | 'outside' | 'not_stated' | 'no_time'}
 */
export function validityAt(entry, claimedAt) {
  if (entry.valid_from === null && entry.valid_until === null) return 'not_stated';
  if (typeof claimedAt !== 'string' || !UTC_SECOND.test(claimedAt)) return 'no_time';
  if (entry.valid_from !== null && claimedAt < entry.valid_from) return 'outside';
  if (entry.valid_until !== null && claimedAt > entry.valid_until) return 'outside';
  return 'inside';
}
