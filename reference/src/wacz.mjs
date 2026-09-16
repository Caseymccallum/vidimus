/**
 * Finding the WARC inside a WACZ.
 *
 * A WACZ is a ZIP whose `datapackage.json` says which files it holds and what they hash to. Two callers
 * need exactly one of those files - the record layer of this project - and they reach it differently: the
 * command line reads a ZIP with Node's `zlib`, a browser reads it with `DecompressionStream`. So the
 * *lookup* lives here, pure, and the container reader is passed in.
 *
 * Nothing here interprets WACZ beyond that lookup: it does not validate the profile, the index, or the
 * page list. What it does do is refuse by name, because a producer that cannot find the record it is
 * about to build a claim over must stop rather than guess (D-016).
 *
 * @module wacz
 */

/** Thrown when a capture does not hold a WARC this project can read. */
export class WaczError extends Error {
  /** @param {string} message */
  constructor(message) {
    super(message);
    this.name = 'WaczError';
  }
}

/** A WACZ advertises its records in `datapackage.json`; the WARC is the one this project reads. */
const WARC_RESOURCE = /\.warc(\.gz)?$/i;

/**
 * @typedef {object} WarcEntry
 * @property {string} path
 * @property {string | null} advertised The digest the capture advertises for it, when it advertises one.
 * @property {Uint8Array} bytes
 */

/**
 * Find the WARC among an already-read archive's entries.
 *
 * @param {{ entries: Map<string, Uint8Array> }} archive
 * @returns {WarcEntry}
 * @throws {WaczError}
 */
export function warcEntryOf(archive) {
  const advertised = archive.entries.get('datapackage.json');
  if (advertised === undefined) {
    throw new WaczError('the capture has no datapackage.json, so it advertises no WARC to read');
  }

  let dataPackage;
  try {
    dataPackage = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(advertised));
  } catch (error) {
    throw new WaczError(`the capture's datapackage.json is not valid JSON: ${error.message}`);
  }

  const resources = Array.isArray(dataPackage?.resources) ? dataPackage.resources : [];
  const resource = resources.find(
    (candidate) => typeof candidate?.path === 'string' && WARC_RESOURCE.test(candidate.path),
  );
  if (resource === undefined) {
    const paths = resources.map((candidate) => candidate?.path ?? '(no path)');
    throw new WaczError(
      `the capture advertises no WARC record to read: ${paths.length > 0 ? paths.join(', ') : 'nothing'}`,
    );
  }

  const bytes = archive.entries.get(resource.path);
  if (bytes === undefined) {
    throw new WaczError(`the capture advertises "${resource.path}" and does not contain it`);
  }

  return {
    path: resource.path,
    advertised: typeof resource.hash === 'string' ? resource.hash : null,
    bytes,
  };
}

/**
 * Find the WARC in a capture's bytes, reading the container with the caller's reader.
 *
 * @param {Uint8Array} waczBytes
 * @param {{ readContainer: (bytes: Uint8Array) => any }} runtime
 * @returns {Promise<WarcEntry>}
 * @throws {WaczError}
 */
export async function findWarcEntry(waczBytes, runtime) {
  let archive;
  try {
    archive = await runtime.readContainer(waczBytes);
  } catch (error) {
    throw new WaczError(`the capture is not a readable WACZ: ${error.message}`);
  }
  return warcEntryOf(archive);
}
