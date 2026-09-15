/**
 * A gzip stream this project writes itself, so that a fixture's digest is the same on
 * every machine.
 *
 * `zlib.gzipSync` is deterministic per platform but not *across* them: the header
 * carries an operating-system byte and the deflate stream itself may differ between zlib
 * versions and builds. A conformance fixture whose bytes depend on who ran the generator
 * is not a fixture - it is a coincidence that happens to hold on the author's laptop, and
 * it fails for the next person with a different Node in a way that looks like a spec bug.
 *
 * So the fixture's WARC is compressed with **stored** deflate blocks: a legal gzip stream
 * that simply wraps the bytes. Ten bytes of header with the mtime zeroed and the OS byte
 * set to "unknown", then 5 bytes per 64 KiB block, then the CRC-32 and length. No
 * entropy coding, no version dependence, and the output is byte-identical everywhere -
 * which is what lets `spec/vectors/*.json` record real digests instead of a recipe.
 *
 * This says nothing about what a *capture tool* should emit: a real WACZ compresses
 * properly, and the verifier never decompresses it. The fixture is the thing that has to
 * be stable, and it is the one thing we control (D-010).
 *
 * @module gzip
 */

import { crc32 } from './zip-common.mjs';

/** Largest payload in a stored deflate block, per RFC 1951. */
const MAX_STORED_BLOCK = 0xffff;

/** gzip header: magic, deflate, no flags, mtime 0, no extra flags, OS "unknown" (255). */
const GZIP_HEADER = new Uint8Array([0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff]);

/**
 * Wrap bytes in a stored-block deflate stream.
 * @param {Uint8Array} bytes
 * @returns {Uint8Array}
 */
function storedDeflate(bytes) {
  const blockCount = Math.max(1, Math.ceil(bytes.length / MAX_STORED_BLOCK));
  const output = new Uint8Array(blockCount * 5 + bytes.length);
  let cursor = 0;
  let offset = 0;

  for (let block = 0; block < blockCount; block += 1) {
    const length = Math.min(MAX_STORED_BLOCK, bytes.length - offset);
    const isLast = block === blockCount - 1;
    output[cursor] = isLast ? 0x01 : 0x00; // BFINAL, BTYPE=00 (stored)
    output[cursor + 1] = length & 0xff;
    output[cursor + 2] = (length >>> 8) & 0xff;
    output[cursor + 3] = ~length & 0xff;
    output[cursor + 4] = (~length >>> 8) & 0xff;
    output.set(bytes.subarray(offset, offset + length), cursor + 5);
    cursor += 5 + length;
    offset += length;
  }

  return output;
}

/**
 * @param {Uint8Array} bytes
 * @returns {Uint8Array} A gzip stream that decompresses to `bytes`.
 */
export function storeGzip(bytes) {
  const body = storedDeflate(bytes);
  const output = new Uint8Array(GZIP_HEADER.length + body.length + 8);
  output.set(GZIP_HEADER, 0);
  output.set(body, GZIP_HEADER.length);

  const trailer = GZIP_HEADER.length + body.length;
  const checksum = crc32(bytes);
  const view = new DataView(output.buffer);
  view.setUint32(trailer, checksum, true);
  view.setUint32(trailer + 4, bytes.length >>> 0, true);

  return output;
}
