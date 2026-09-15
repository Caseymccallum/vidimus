/**
 * Canonical JSON for signed material in the Receipt format - `canonical-json-v1`.
 *
 * The contract is in `docs/RECEIPT-SPEC.md` section 4. This file is its normative
 * implementation, and it is deliberately *not* RFC 8785 (JCS) at large: it is the
 * subset of JCS that a signed receipt is allowed to contain, enforced rather than
 * assumed.
 *
 * Why a subset: the one thing that breaks cross-language canonicalisation is the
 * number. `1e21`, `-0`, `0.1`, and every shortest-round-trip float rule are where two
 * correct-looking implementations produce two different byte strings, and a byte
 * string that differs is a signature that fails for a reason nobody can debug. So
 * signed material in a receipt may contain **integers only**, in the range every
 * consumer can hold exactly, and a floating point value anywhere in the signed subtree
 * is a verification failure with a name.
 *
 * Everything here is pure: no crypto, no I/O, no clock, no globals. Hashing lives in
 * `digest.mjs`, which is why this file can be tested against the spec's vectors in a
 * browser, a worker or a CI job with no build step.
 *
 * @module canonical
 */

/** Thrown for anything that is not representable in `canonical-json-v1`. */
export class CanonicalJsonError extends Error {
  /**
   * @param {string} message
   * @param {string} path JSON-pointer-ish path to the offending value.
   */
  constructor(message, path = '') {
    super(path ? `${message} (at ${path})` : message);
    this.name = 'CanonicalJsonError';
    this.path = path;
  }
}

/**
 * Largest integer that survives every hop in a receipt (JSON -> JS number -> JSON):
 * 2^53 - 1. Anything larger is rejected rather than silently rounded.
 */
export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

/** Deepest object nesting permitted, so a hostile manifest cannot blow the stack. */
export const MAX_DEPTH = 64;

/**
 * @param {unknown} value
 * @returns {value is Record<string, unknown>}
 */
function isPlainObject(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Reject strings whose code units cannot be encoded as UTF-8. A lone surrogate
 * round-trips differently depending on who is doing the escaping, so it is refused at
 * the door instead of producing a hash nobody else can reproduce.
 *
 * @param {string} value
 * @param {string} path
 */
export function assertEncodable(value, path) {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) {
        throw new CanonicalJsonError('unpaired high surrogate in string', `${path}[${i}]`);
      }
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new CanonicalJsonError('unpaired low surrogate in string', `${path}[${i}]`);
    }
  }
}

/**
 * Canonicalise a value to the `canonical-json-v1` byte string.
 *
 * Rules, in the order a reader will want them:
 *  1. Object keys are sorted by UTF-16 code unit (which is what `Array#sort` does, and
 *     what RFC 8785 specifies).
 *  2. No whitespace anywhere.
 *  3. Strings escape only `"`, `\` and C0 controls, using the short forms for
 *     `\b \t \n \f \r` - exactly what `JSON.stringify` emits - and non-ASCII is left
 *     as-is, to be encoded as UTF-8 by the caller.
 *  4. Numbers must be integers, `-0` is forbidden, and the safe-integer range is
 *     enforced. A non-integer is a hard error, by name.
 *  5. Parentheses, not rules: an object is already parsed, so duplicate keys cannot be
 *     seen here. That gap is closed by `assertCanonicalBytes`, which compares against
 *     the bytes the verifier was handed rather than trusting a re-serialisation.
 *  6. Depth is capped at `MAX_DEPTH`.
 *
 * @param {unknown} value
 * @param {{ path?: string, depth?: number }} [options]
 * @returns {string}
 * @throws {CanonicalJsonError}
 */
export function canonicalise(value, options = {}) {
  return write(value, options.path ?? '', options.depth ?? 0);
}

/**
 * @param {unknown} value
 * @param {string} path
 * @param {number} depth
 * @returns {string}
 */
function write(value, path, depth) {
  if (depth > MAX_DEPTH) {
    throw new CanonicalJsonError(`nesting deeper than ${MAX_DEPTH} levels`, path);
  }

  if (value === null) return 'null';

  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';

    case 'string':
      assertEncodable(value, path);
      return JSON.stringify(value);

    case 'number': {
      if (!Number.isFinite(value)) {
        throw new CanonicalJsonError('non-finite number is not representable', path);
      }
      if (!Number.isInteger(value)) {
        throw new CanonicalJsonError(
          'non-integer number: canonical-json-v1 admits integers only',
          path,
        );
      }
      if (Object.is(value, -0)) {
        throw new CanonicalJsonError('-0 is not representable', path);
      }
      if (Math.abs(value) > MAX_SAFE_INTEGER) {
        throw new CanonicalJsonError('integer outside the safe range', path);
      }
      return JSON.stringify(value);
    }

    case 'object': {
      if (Array.isArray(value)) {
        const parts = value.map((item, index) => write(item, `${path}[${index}]`, depth + 1));
        return `[${parts.join(',')}]`;
      }
      if (!isPlainObject(value)) {
        throw new CanonicalJsonError('only plain objects and arrays are representable', path);
      }
      const keys = Object.keys(value).sort();
      const parts = keys.map((key) => {
        assertEncodable(key, path);
        return `${JSON.stringify(key)}:${write(value[key], `${path}.${key}`, depth + 1)}`;
      });
      return `{${parts.join(',')}}`;
    }

    case 'undefined':
      throw new CanonicalJsonError('undefined is not representable', path);
    case 'bigint':
      throw new CanonicalJsonError('bigint is not representable', path);
    case 'function':
      throw new CanonicalJsonError('function is not representable', path);
    case 'symbol':
      throw new CanonicalJsonError('symbol is not representable', path);
    default:
      throw new CanonicalJsonError(`cannot canonicalise a ${typeof value}`, path);
  }
}

/**
 * The canonical form must be a fixed point: canonicalising the canonical form yields
 * itself. If that ever fails, the encoder is not deterministic and every signature
 * over it is a coin flip.
 *
 * @param {unknown} value
 * @returns {boolean}
 */
export function isCanonicalFixedPoint(value) {
  try {
    const once = canonicalise(value);
    return canonicalise(JSON.parse(once)) === once;
  } catch {
    return false;
  }
}

/**
 * Close the duplicate-key gap that parsing opens.
 *
 * `JSON.parse` silently keeps the last of two identical keys, so a manifest that says
 * `"url":"a","url":"b"` parses to one value while two readers of the raw bytes can
 * disagree about which one was signed. A verifier therefore does not only canonicalise
 * the parsed object - it re-canonicalises and compares against the exact bytes it was
 * handed. If the document was not already in canonical form, the signature covers
 * something other than what was delivered, and that is a failure rather than a
 * normalisation.
 *
 * @param {Uint8Array} bytes The exact bytes of the signed document.
 * @param {string} expected The canonical form of the parsed document.
 * @returns {{ ok: true } | { ok: false, reason: string }}
 */
export function assertCanonicalBytes(bytes, expected) {
  // The BOM has to be caught on the *bytes*. `TextDecoder` removes a leading U+FEFF as
  // part of decoding (that is what the default `ignoreBOM: false` means), so a check on the
  // decoded string would never see it - which is exactly the kind of silently-dead
  // guardrail this project is supposed to be able to notice.
  if (bytes.length >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    return { ok: false, reason: 'document starts with a byte order mark' };
  }

  let actual;
  try {
    actual = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { ok: false, reason: 'document is not valid UTF-8' };
  }
  if (actual.charCodeAt(0) === 0xfeff) {
    return { ok: false, reason: 'document starts with a byte order mark' };
  }
  if (actual !== expected) {
    return {
      ok: false,
      reason: 'document bytes are not in canonical form: it was re-serialised before delivery',
    };
  }
  return { ok: true };
}
