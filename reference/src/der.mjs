/**
 * ASN.1 DER: just enough to read a timestamp token, and just enough to mint one for the tests.
 *
 * An RFC 3161 token is a CMS `SignedData` carrying a `TSTInfo`, and both are DER. Reading them means
 * reading ASN.1, which is the piece of this project most likely to be a source of quiet bugs - so the
 * reader here is deliberately strict and small, and every limit it has is a refusal with a reason rather
 * than a guess:
 *
 * - **definite lengths only.** The indefinite form is legal BER and illegal DER, and a token that uses it
 *   was not produced by a conforming TSA.
 * - **low tag numbers only.** Multi-byte tags exist and appear in no part of a timestamp token.
 * - **a depth and an element budget.** A token arrives inside a receipt, and a receipt is untrusted input:
 *   a nesting bomb must run out of budget rather than out of stack.
 * - **every length is checked against the bytes that are actually there**, so a truncated token is refused
 *   at the element that overruns rather than producing a plausible partial structure.
 *
 * The *writer* half exists because the conformance vectors need a token, and a fixture has to be a
 * deterministic function of committed bytes: RSA PKCS#1 v1.5 signing is deterministic, so a token minted
 * from fixed values is byte-identical on every run and every machine (D-014).
 *
 * Pure and browser-safe: no `Buffer`, no Node built-ins. The verifier calls the reader; the fixture builder
 * calls the writer, on a command line where `node:crypto` supplies the signing.
 *
 * @module der
 */

import { latin1 } from './encode.mjs';

/** Thrown for anything this reader will not guess at. */
export class DerError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'DerError';
  }
}

/** How deep a structure may nest before this reader calls it a bomb. A timestamp token is about 8 deep. */
const MAX_DEPTH = 24;

/** How many elements a single token may contain. A certificate plus attributes is a few hundred. */
const MAX_ELEMENTS = 4096;

/**
 * @typedef {object} DerElement
 * @property {number} tag The first byte of the element, class and constructed bit included: `0x30` is a
 *   `SEQUENCE`, `0x02` an `INTEGER`, `0xA0` a constructed `[0]`. **Not** the low five bits - a `0x30` read
 *   that way is `0x10`, and that mistake is what this reader's tests were built to catch once it was made.
 * @property {boolean} constructed
 * @property {number} start Offset of this element's first byte in the buffer it came from.
 * @property {number} end Offset one past its last byte.
 * @property {Uint8Array} whole The element, tag and length included. Needed to re-encode a `SET OF`.
 * @property {Uint8Array} value The contents, without the tag and length.
 * @property {DerElement[]} children Parsed contents; empty for a primitive.
 */

/**
 * Parse one element and everything under it.
 *
 * @param {Uint8Array} bytes
 * @param {number} [offset] Where the element starts.
 * @returns {{ element: DerElement, end: number }} The element, and where it ended.
 * @throws {DerError}
 */
function parseAt(bytes, offset = 0) {
  let budget = MAX_ELEMENTS;

  /**
   * @param {number} start
   * @param {number} depth
   * @returns {DerElement}
   */
  const parse = (start, depth) => {
    if (depth > MAX_DEPTH) {
      throw new DerError(`this structure nests deeper than ${MAX_DEPTH} levels, which no token does`);
    }
    budget -= 1;
    if (budget < 0) {
      throw new DerError(`this structure holds more than ${MAX_ELEMENTS} elements, which no token does`);
    }
    if (start >= bytes.length) throw new DerError('a structure ended before its contents did');

    const octet = bytes[start];
    const constructed = (octet & 0x20) !== 0;
    if ((octet & 0x1f) === 0x1f) {
      throw new DerError('multi-byte tag numbers do not appear in a timestamp token, and are not read here');
    }

    let cursor = start + 1;
    if (cursor >= bytes.length) throw new DerError('an element declares no length');
    const first = bytes[cursor];
    cursor += 1;

    let length;
    if (first === 0x80) {
      throw new DerError('the indefinite length form is BER, not DER, and is refused here');
    }
    if (first < 0x80) {
      length = first;
    } else {
      const count = first & 0x7f;
      if (count > 4) throw new DerError('a length of more than four bytes is not a timestamp token');
      if (cursor + count > bytes.length) throw new DerError('a length runs past the end of the token');
      length = 0;
      for (let index = 0; index < count; index += 1) {
        length = length * 256 + bytes[cursor + index];
      }
      cursor += count;
    }

    const end = cursor + length;
    if (end > bytes.length) {
      throw new DerError(
        `an element declares ${length} bytes and only ${bytes.length - cursor} remain: the token is truncated`,
      );
    }

    /** @type {DerElement} */
    const element = {
      tag: octet,
      constructed,
      start,
      end,
      whole: bytes.subarray(start, end),
      value: bytes.subarray(cursor, end),
      children: [],
    };

    if (constructed) {
      let childCursor = cursor;
      const children = [];
      while (childCursor < end) {
        const child = parse(childCursor, depth + 1);
        if (child.end <= childCursor) throw new DerError('an element did not advance the reader');
        children.push(child);
        childCursor = child.end;
      }
      if (childCursor !== end) {
        throw new DerError('the contents of a constructed element do not add up to its length');
      }
      element.children = children;
    }

    return element;
  };

  const element = parse(offset, 0);
  return { element, end: element.end };
}

/**
 * @param {Uint8Array[]} parts
 * @returns {Uint8Array}
 */
export function concat(parts) {
  let total = 0;
  for (const part of parts) total += part.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/**
 * A DER length, in the shortest form that holds it.
 *
 * @param {number} length
 * @returns {Uint8Array}
 */
export function encodeLength(length) {
  if (!Number.isInteger(length) || length < 0) {
    throw new DerError(`a length must be a whole number of bytes, and ${length} is not`);
  }
  if (length < 0x80) return new Uint8Array([length]);
  const bytes = [];
  let remaining = length;
  while (remaining > 0) {
    bytes.unshift(remaining & 0xff);
    remaining = Math.floor(remaining / 256);
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

/**
 * One element: a tag byte, a length, and the contents.
 *
 * @param {number} tagOctet
 * @param {Uint8Array[]} parts
 * @returns {Uint8Array}
 */
export function element(tagOctet, parts) {
  const contents = concat(parts);
  return concat([new Uint8Array([tagOctet]), encodeLength(contents.length), contents]);
}

/** @param {Uint8Array[]} parts */
export const sequence = (...parts) => element(0x30, parts);
/** @param {Uint8Array[]} parts */
export const setOf = (...parts) => element(0x31, parts);
/** A `NULL`, which is what an absent parameter list looks like. */
export const nullValue = () => element(0x05, []);

/**
 * An `INTEGER`, minimally encoded, with a leading zero when the high bit would make it negative.
 *
 * @param {number | Uint8Array} value
 * @returns {Uint8Array}
 */
export function integer(value) {
  let bytes;
  if (value instanceof Uint8Array) {
    bytes = value.slice();
  } else {
    if (!Number.isInteger(value) || value < 0) throw new DerError('an INTEGER here must be non-negative');
    if (value === 0) return element(0x02, [new Uint8Array([0])]);
    const built = [];
    let remaining = value;
    while (remaining > 0) {
      built.unshift(remaining & 0xff);
      remaining = Math.floor(remaining / 256);
    }
    bytes = new Uint8Array(built);
  }
  while (bytes.length > 1 && bytes[0] === 0 && (bytes[1] & 0x80) === 0) {
    bytes = bytes.subarray(1);
  }
  return element(0x02, [(bytes[0] & 0x80) !== 0 ? concat([new Uint8Array([0]), bytes]) : bytes]);
}

/** @param {Uint8Array} bytes */
export const octetString = (bytes) => element(0x04, [bytes]);

/** A `BIT STRING` with no unused bits, which is what a public key is. @param {Uint8Array} bytes */
export const bitString = (bytes) => element(0x03, [concat([new Uint8Array([0]), bytes])]);

/** @param {string} oid Dotted decimal. @returns {Uint8Array} */
export function objectIdentifier(oid) {
  const arcs = oid.split('.').map((part) => Number.parseInt(part, 10));
  if (arcs.length < 2 || arcs.some((arc) => !Number.isInteger(arc) || arc < 0)) {
    throw new DerError(`"${oid}" is not a dotted-decimal object identifier`);
  }
  const bytes = [arcs[0] * 40 + arcs[1]];
  for (const arc of arcs.slice(2)) {
    const stack = [];
    let remaining = arc;
    do {
      stack.unshift(remaining & 0x7f);
      remaining = Math.floor(remaining / 128);
    } while (remaining > 0);
    for (let index = 0; index < stack.length - 1; index += 1) stack[index] |= 0x80;
    bytes.push(...stack);
  }
  return element(0x06, [new Uint8Array(bytes)]);
}

/**
 * A `GeneralizedTime` in Zulu, from a whole-second UTC instant.
 *
 * Seconds are always written: DER requires the seconds field, and a token whose time this reader had to
 * complete from memory would be one it half-understood.
 *
 * @param {string} utcSecond `2026-01-01T00:00:00Z`
 * @returns {Uint8Array}
 */
export function generalizedTime(utcSecond) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(utcSecond);
  if (match === null) throw new DerError(`"${utcSecond}" is not a whole-second UTC instant`);
  const digits = `${match[1]}${match[2]}${match[3]}${match[4]}${match[5]}${match[6]}Z`;
  return element(0x18, [latin1(digits)]);
}

/**
 * A `UTCTime` in Zulu. RFC 5280 requires this two-digit form for dates through 2049, and every
 * certificate in the world follows it, so a fixture that wants to look like a certificate uses it.
 *
 * @param {string} utcSecond
 * @returns {Uint8Array}
 */
export function utcTime(utcSecond) {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/.exec(utcSecond);
  if (match === null) throw new DerError(`"${utcSecond}" is not a whole-second UTC instant`);
  const year = Number.parseInt(match[1], 10);
  if (year < 1950 || year > 2049) {
    throw new DerError('UTCTime cannot express a year before 1950 or after 2049');
  }
  const digits = `${String(year % 100).padStart(2, '0')}${match[2]}${match[3]}`
    + `${match[4]}${match[5]}${match[6]}Z`;
  return element(0x17, [latin1(digits)]);
}

/**
 * A context-specific element. `[0] EXPLICIT` in CMS is a wrapper; `[0] IMPLICIT` is a retagged value.
 *
 * @param {number} number
 * @param {boolean} constructed
 * @param {Uint8Array[]} parts
 * @returns {Uint8Array}
 */
export function context(number, constructed, ...parts) {
  if (number > 30) throw new DerError('context tag numbers above 30 would need a multi-byte tag');
  return element((0x80 | (constructed ? 0x20 : 0x00)) | number, parts);
}

/** @param {boolean} value */
export const boolean = (value) => element(0x01, [new Uint8Array([value ? 0xff : 0x00])]);

/**
 * Parse exactly one element, and refuse trailing bytes.
 *
 * The trailing-byte refusal is not pedantry: a CMS structure that ends before the bytes do is either a
 * concatenation this reader does not understand or a token somebody appended to, and both deserve a reason
 * rather than a partial parse.
 *
 * @param {Uint8Array} bytes
 * @returns {DerElement}
 * @throws {DerError}
 */
export function readDer(bytes) {
  const { element, end } = parseAt(bytes, 0);
  if (end !== bytes.length) {
    throw new DerError(`${bytes.length - end} bytes follow the structure, which a token does not have`);
  }
  return element;
}

/**
 * The bytes of an `INTEGER`, whatever it holds.
 *
 * @param {DerElement} node
 * @returns {Uint8Array}
 * @throws {DerError}
 */
export function integerBytes(node) {
  if (node.tag !== 0x02 || node.constructed) {
    throw new DerError(`expected an INTEGER and found tag 0x${node.tag.toString(16)}`);
  }
  return node.value;
}

/**
 * An `INTEGER` as a number. Refused beyond `2^53`, where a JavaScript number stops being exact - and a
 * serial number compared inexactly is a serial number compared wrongly.
 *
 * @param {DerElement} node
 * @returns {number}
 * @throws {DerError}
 */
export function integerValue(node) {
  const bytes = integerBytes(node);
  let value = 0;
  for (const byte of bytes) {
    value = value * 256 + byte;
    if (!Number.isSafeInteger(value)) {
      throw new DerError('this INTEGER is larger than a JavaScript number can hold exactly');
    }
  }
  return value;
}

/**
 * The dotted-decimal form of an `OBJECT IDENTIFIER`, which is how this code compares algorithms.
 *
 * @param {DerElement} node
 * @returns {string}
 * @throws {DerError}
 */
export function oidValue(node) {
  if (node.tag !== 0x06 || node.constructed) {
    throw new DerError(`expected an OBJECT IDENTIFIER and found tag 0x${node.tag.toString(16)}`);
  }
  const bytes = node.value;
  if (bytes.length === 0) throw new DerError('an object identifier with no bytes names nothing');
  const arcs = [Math.floor(bytes[0] / 40), bytes[0] % 40];
  let value = 0;
  for (let index = 1; index < bytes.length; index += 1) {
    value = value * 128 + (bytes[index] & 0x7f);
    if ((bytes[index] & 0x80) === 0) {
      arcs.push(value);
      value = 0;
    }
  }
  if (value !== 0) throw new DerError('an object identifier ends in the middle of an arc');
  return arcs.join('.');
}

/**
 * A time value as a whole-second UTC instant, whichever of the two forms it uses.
 *
 * `UTCTime` has two-digit years, resolved by the RFC 5280 rule for the century - the rule every
 * certificate in the world was issued under.
 *
 * @param {DerElement} node
 * @returns {string}
 * @throws {DerError}
 */
export function timeValue(node) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(node.value);
  if (node.tag === 0x18) {
    const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (match === null) throw new DerError(`"${text}" is not a Zulu GeneralizedTime this reader accepts`);
    return `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}Z`;
  }
  if (node.tag === 0x17) {
    const match = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(text);
    if (match === null) throw new DerError(`"${text}" is not a Zulu UTCTime this reader accepts`);
    const year = Number.parseInt(match[1], 10);
    return `${(year >= 50 ? 1900 : 2000) + year}-${match[2]}-${match[3]}`
      + `T${match[4]}:${match[5]}:${match[6]}Z`;
  }
  throw new DerError(`expected a time and found tag 0x${node.tag.toString(16)}`);
}
