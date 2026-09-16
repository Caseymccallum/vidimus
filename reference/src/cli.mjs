#!/usr/bin/env node
/**
 * `vidimus` - seal a capture into a receipt, and verify a receipt.
 *
 *   vidimus verify  <file.receipt> [--json] [--trusted-key <hex>]... [--previous <hex>]
 *   vidimus inspect <file.receipt>
 *   vidimus seal    <capture.wacz> [--url <url>] [--captured-at <ts>] [--document <file>]
 *                                  [--key <key.json> | --unsigned] [--chain <n> --prev <hash>]
 *                                  [--out <file.receipt>] [--force] [--json]
 *   vidimus keygen  [--out <key.json>] [--signer <name>] [--force]
 *
 * The CLI is deliberately thin: it reads bytes from a file, hands them to `verify.mjs` or
 * `seal.mjs`, and prints what came back. All the judgement lives in those modules, so there is no
 * second place for a claim about a verdict to be formed - and no place for the CLI to be more
 * reassuring than the checks it ran.
 *
 * `seal` **verifies what it just wrote** before it reports success (D-017). A producer that hands
 * over a receipt it has not checked is a producer whose first bug is discovered by a stranger
 * holding the receipt, which is the worst possible place to discover it.
 *
 * `check` is the only command that makes a network request, and it is a separate command for exactly
 * that reason: `verify` must stay something a person can run on a receipt with no network at all, and
 * "is the page still the same?" must be impossible to do by accident. `check` fetches the page a receipt
 * cites, seals a second receipt for what it says now, and prints the comparison. It never changes a
 * verdict, and it never writes `verified` (D-005).
 *
 * Exit codes (three, not two, because they mean different things to a script):
 *   0  verified: integrity and attribution both hold
 *   1  nothing failed, and nothing was proven either
 *   2  something failed, the seal was refused, or the file could not be read at all
 *
 * `check` returns the verdict's code, so a script sees whether the *receipt* is sound; add
 * `--require-same-words` to make the *comparison* decide instead: `0` the words are unchanged, `1` they
 * are not, `2` they could not be compared.
 *
 * @module cli
 */

import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { exitCode, verifyReceipt } from './verify-node.mjs';
import { SealError, sealFromCapture } from './seal.mjs';
import { sha256, fromBase64Url, toBase64Url } from './digest.mjs';
import { generateSeed, keyId, privateKeyFromSeed, rawPublicKey } from './signature.mjs';
import { buildCapture } from './capture.mjs';
import { compareCurrency } from './currency.mjs';
import { textDigest } from './text.mjs';
import { KEY_DIRECTORY_KIND, readKeyDirectory } from './key-directory.mjs';

/** Every command, printed when the arguments do not make sense. */
const USAGE = [
  'usage: vidimus verify  <file.receipt> [--json] [--trusted-key <hex>]... [--key-directory <file>]',
  '                                      [--previous <hex>]',
  '       vidimus inspect <file.receipt>',
  '       vidimus check   <file.receipt> [--json] [--key <key.json>] [--key-directory <file>]',
  '                       [--out <file.receipt>] [--force] [--timeout <seconds>] [--require-same-words]',
  '       vidimus seal    <capture.wacz> [--url <url>] [--captured-at <ts>] [--document <file>]',
  '                       [--profile <name>] [--key <key.json> | --unsigned]',
  '                       [--chain <n> --prev <hash>] [--out <file.receipt>] [--force] [--json]',
  '       vidimus keygen  [--out <key.json>] [--signer <name>] [--force]',
  '       vidimus keys    <directory.json>',
];

/**
 * The value that follows a flag.
 * @param {string[]} rest
 * @param {number} index
 * @param {string} name
 * @returns {string | null} Null, after saying why, when there is no value.
 */
function nextValue(rest, index, name) {
  const value = rest[index + 1];
  if (value === undefined || value.startsWith('--')) {
    console.error(`${name} needs a value`);
    return null;
  }
  return value;
}

/** `--captured-at` becomes `capturedAt`, so the flags and the options cannot drift apart. */
function flagName(argument) {
  return argument.slice(2).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}

/**
 * Split argv into a command and its arguments, refusing anything it does not recognise.
 *
 * Each command parses its own flags, so an option belonging to `seal` cannot be quietly accepted and
 * ignored by `verify`. That is how a person comes to believe they passed a key when they did not.
 *
 * @param {string[]} argv
 * @returns {Record<string, any> | null}
 */
function parseArguments(argv) {
  const [command, ...rest] = argv;
  if (command === 'verify' || command === 'inspect') return parseVerifyLike(command, rest);
  if (command === 'seal') return parseSeal(rest);
  if (command === 'keygen') return parseKeygen(rest);
  if (command === 'check') return parseCheck(rest);
  if (command === 'keys') return parseKeys(rest);
  return null;
}

/**
 * `check` parses its own flags, like every other command here, so an option belonging to `seal` cannot
 * be accepted and quietly ignored by it.
 *
 * @param {string[]} rest
 * @returns {Record<string, any> | null}
 */
function parseCheck(rest) {
  /** @type {Record<string, any>} */
  const parsed = { command: 'check', json: false, force: false, requireSameWords: false };
  let file = null;

  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === '--json') {
      parsed.json = true;
    } else if (argument === '--force') {
      parsed.force = true;
    } else if (argument === '--require-same-words') {
      parsed.requireSameWords = true;
    } else if (argument === '--key-directory') {
      const value = nextValue(rest, index, '--key-directory');
      if (value === null) return null;
      try {
        parsed.keyDirectory = readDirectoryFile(value);
      } catch (error) {
        console.error(`${value}: could not be read as a key directory: ${error.message}`);
        return null;
      }
      index += 1;
    } else if (argument === '--key' || argument === '--out') {
      const value = nextValue(rest, index, argument);
      if (value === null) return null;
      parsed[flagName(argument)] = value;
      index += 1;
    } else if (argument === '--timeout') {
      const value = nextValue(rest, index, '--timeout');
      if (value === null) return null;
      if (!/^\d+$/.test(value) || Number(value) < 1) {
        console.error('--timeout needs a whole number of seconds');
        return null;
      }
      parsed.timeout = Number(value);
      index += 1;
    } else if (argument.startsWith('--')) {
      console.error(`unknown option: ${argument}`);
      return null;
    } else if (file === null) {
      file = argument;
    } else {
      console.error(`unexpected argument: ${argument}`);
      return null;
    }
  }

  if (file === null) {
    console.error('check needs the receipt to compare with the page');
    return null;
  }
  parsed.file = file;
  return parsed;
}

/**
 * @param {string} command
 * @param {string[]} rest
 * @returns {Record<string, any> | null}
 */
function parseVerifyLike(command, rest) {
  /** @type {Record<string, any>} */
  const options = {};
  let file = null;
  let json = false;

  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === '--json') {
      json = true;
    } else if (argument === '--trusted-key') {
      const value = nextValue(rest, index, '--trusted-key');
      if (value === null) return null;
      options.trustedKeys = [...(options.trustedKeys ?? []), value];
      index += 1;
    } else if (argument === '--previous') {
      const value = nextValue(rest, index, '--previous');
      if (value === null) return null;
      options.previousClaimHash = value;
      index += 1;
    } else if (argument === '--key-directory') {
      const value = nextValue(rest, index, '--key-directory');
      if (value === null) return null;
      try {
        options.keyDirectory = readDirectoryFile(value);
      } catch (error) {
        console.error(`${value}: could not be read as a key directory: ${error.message}`);
        return null;
      }
      index += 1;
    } else if (argument.startsWith('--')) {
      console.error(`unknown option: ${argument}`);
      return null;
    } else {
      file = argument;
    }
  }

  return file === null ? null : { command, file, json, options };
}

/**
 * `seal` insists on being told whether to sign, and it is deliberate. A receipt with no signature is
 * a perfectly good receipt - it says "nobody signs for this" - but it should be a decision, not the
 * result of forgetting a flag.
 *
 * @param {string[]} rest
 * @returns {Record<string, any> | null}
 */
function parseSeal(rest) {
  /** @type {Record<string, any>} */
  const parsed = { command: 'seal', json: false, force: false, unsigned: false };
  let capture = null;

  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === '--json') {
      parsed.json = true;
    } else if (argument === '--force') {
      parsed.force = true;
    } else if (argument === '--unsigned') {
      parsed.unsigned = true;
    } else if (['--url', '--captured-at', '--document', '--key', '--out', '--prev', '--profile'].includes(argument)) {
      const value = nextValue(rest, index, argument);
      if (value === null) return null;
      parsed[flagName(argument)] = value;
      index += 1;
    } else if (argument === '--chain') {
      const value = nextValue(rest, index, '--chain');
      if (value === null) return null;
      if (!/^\d+$/.test(value) || Number(value) < 1) {
        console.error('--chain needs a sequence of 1 or more');
        return null;
      }
      parsed.chain = Number(value);
      index += 1;
    } else if (argument.startsWith('--')) {
      console.error(`unknown option: ${argument}`);
      return null;
    } else if (capture === null) {
      capture = argument;
    } else {
      console.error(`unexpected argument: ${argument}`);
      return null;
    }
  }

  if (capture === null) {
    console.error('seal needs the capture to seal');
    return null;
  }
  parsed.capture = capture;

  if (parsed.unsigned && parsed.key !== undefined) {
    console.error('--key and --unsigned are mutually exclusive: choose whether this claim is signed');
    return null;
  }
  if (!parsed.unsigned && parsed.key === undefined) {
    console.error('seal needs --key <key.json> to sign the claim, or --unsigned to say');
    console.error('deliberately that nobody signs it');
    return null;
  }
  if (parsed.prev !== undefined && parsed.chain === undefined) {
    console.error('--prev only means something with --chain: a chain link names its position');
    return null;
  }
  return parsed;
}

/**
 * @param {string[]} rest
 * @returns {Record<string, any> | null}
 */
function parseKeygen(rest) {
  /** @type {Record<string, any>} */
  const parsed = { command: 'keygen', force: false };
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index];
    if (argument === '--force') {
      parsed.force = true;
    } else if (argument === '--out' || argument === '--signer') {
      const value = nextValue(rest, index, argument);
      if (value === null) return null;
      parsed[flagName(argument)] = value;
      index += 1;
    } else {
      console.error(`unknown option: ${argument}`);
      return null;
    }
  }
  return parsed;
}

/** @param {string} file @returns {Uint8Array} */
function read(file) {
  return new Uint8Array(readFileSync(file));
}

/**
 * Read a key directory file.
 *
 * Parsed here and *interpreted by the verifier*: this command finds the file and turns it into JSON, and
 * `key-directory.mjs` owns what a directory is. A path that cannot be read stops the command with a
 * message about the file, rather than becoming a caveat inside a verdict nobody reads (section 6.7).
 *
 * @param {string} file
 * @returns {unknown}
 */
function readDirectoryFile(file) {
  return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(file)));
}

/**
 * `keys` takes one argument and no flags: it is a way of looking at a file, not a way of changing anything.
 *
 * @param {string[]} rest
 * @returns {Record<string, any> | null}
 */
function parseKeys(rest) {
  if (rest.length !== 1 || rest[0].startsWith('--')) {
    console.error('keys needs the directory file, and nothing else');
    return null;
  }
  return { command: 'keys', file: rest[0] };
}

/** @param {string} file @param {Record<string, any>} options @param {boolean} json */
async function verify(file, options, json) {
  let verdict;
  try {
    verdict = await verifyReceipt(read(file), options);
  } catch (error) {
    console.error(`${file}: could not be read: ${error.message}`);
    return 2;
  }

  if (json) {
    console.log(JSON.stringify(verdict, null, 2));
    return exitCode(verdict);
  }

  for (const line of verdict.summary) console.log(line);
  console.log('');
  for (const check of verdict.checks) {
    if (check.status === 'pass') continue;
    console.log(`  ${check.status.padEnd(14)} ${check.id}${check.reason ? ` - ${check.reason}` : ''}`);
  }
  for (const caveat of verdict.caveats) console.log(`  caveat         ${caveat}`);
  if (!verdict.verified) {
    console.log('');
    console.log('This is not a verified receipt. Read the lines above before using it as evidence.');
  }
  return exitCode(verdict);
}

/** @param {string} file */
async function inspect(file) {
  const verdict = await verifyReceipt(read(file));
  const printable = {
    verifier: verdict.verifier,
    receipt: verdict.receipt,
    verified: verdict.verified,
    levels: verdict.levels,
    attribution: verdict.attribution,
    time: verdict.time,
    caveats: verdict.caveats,
    summary: verdict.summary,
  };
  console.log(JSON.stringify(printable, null, 2));
  return 0;
}

/** The algorithm a key file declares: one algorithm, named, so nothing has to guess. */
const KEY_ALG = 'ed25519';

/**
 * Read a key file.
 *
 * The key id is checked against the seed rather than trusted, exactly as it is in a receipt: it is a
 * derived value, and a file whose id does not match its own seed is a file that has been edited.
 *
 * @param {string} file
 * @returns {{ privateKey: import('node:crypto').KeyObject, signer: string | null, keyId: string } | null}
 */
function readKeyFile(file) {
  let contents;
  try {
    contents = new TextDecoder('utf-8', { fatal: true }).decode(readFileSync(file));
  } catch (error) {
    console.error(`${file}: could not be read: ${error.message}`);
    return null;
  }

  let key;
  try {
    key = JSON.parse(contents);
  } catch (error) {
    console.error(`${file}: is not valid JSON: ${error.message}`);
    return null;
  }

  if (key?.alg !== KEY_ALG) {
    console.error(`${file}: alg must be "${KEY_ALG}"`);
    return null;
  }
  if (typeof key.seed !== 'string') {
    console.error(`${file}: has no seed to sign with`);
    return null;
  }

  let privateKey;
  try {
    privateKey = privateKeyFromSeed(fromBase64Url(key.seed));
  } catch (error) {
    console.error(`${file}: ${error.message}`);
    return null;
  }

  const derived = keyId(rawPublicKey(privateKey));
  if (typeof key.key_id === 'string' && key.key_id !== derived) {
    console.error(`${file}: says key_id ${key.key_id} and its seed derives ${derived}.`);
    console.error('A key id is derived, never asserted, so this file has been edited: nothing was sealed.');
    return null;
  }

  return { privateKey, signer: typeof key.signer === 'string' ? key.signer : null, keyId: derived };
}

/**
 * @param {{ out?: string, signer?: string, force: boolean }} options
 * @returns {number}
 */
function keygen(options) {
  const out = options.out ?? 'vidimus-key.json';
  if (existsSync(out) && options.force !== true) {
    console.error(`${out} already exists. A key file is the one thing here that cannot be regenerated:`);
    console.error('replace it, and every receipt signed with the old key keeps verifying while none of');
    console.error('them looks like yours again. Pass --force only if you are certain.');
    return 2;
  }

  const seed = generateSeed();
  const file = {
    alg: KEY_ALG,
    seed: toBase64Url(seed),
    key_id: keyId(rawPublicKey(privateKeyFromSeed(seed))),
    ...(typeof options.signer === 'string' && options.signer !== '' ? { signer: options.signer } : {}),
    created_at: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
  };
  writeFileSync(out, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });

  console.log(`wrote ${out}`);
  console.log(`  key id  ${file.key_id}`);
  console.log(`  signer  ${file.signer ?? '(none: receipts will carry a key id and no name)'}`);
  console.log('');
  console.log('This file signs claims. Keep it out of anything you publish:');
  console.log('  the capture digest proves what a page said; this key proves who recorded it.');
  return 0;
}

/**
 * Seal a capture, then verify what was written (D-017).
 *
 * If the receipt this program has just produced does not verify, the file is removed and the failure
 * is reported. Handing over an unchecked receipt would make the first person to notice the bug
 * somebody who had already trusted it.
 *
 * @param {Record<string, any>} options
 * @returns {number}
 */
async function sealCapture(options) {
  let capture;
  try {
    capture = read(options.capture);
  } catch (error) {
    console.error(`${options.capture}: could not be read: ${error.message}`);
    return 2;
  }

  const out = options.out ?? `${options.capture.replace(/\.wacz$/i, '')}.receipt`;
  if (existsSync(out) && options.force !== true) {
    console.error(`${out} already exists. Pass --force to replace it, or --out to write elsewhere.`);
    return 2;
  }

  let key = null;
  if (options.key !== undefined) {
    key = readKeyFile(options.key);
    if (key === null) return 2;
  }

  let document = null;
  if (options.document !== undefined) {
    try {
      document = read(options.document);
    } catch (error) {
      console.error(`${options.document}: could not be read: ${error.message}`);
      return 2;
    }
  }

  const anchor = options.chain === undefined
    ? { type: 'none' }
    : (options.chain === 1
      ? { type: 'chain', sequence: 1 }
      : { type: 'chain', sequence: options.chain, prev_claim_hash: options.prev });

  let sealed;
  try {
    sealed = sealFromCapture({
      capture,
      url: options.url ?? null,
      document,
      capturedAt: options.capturedAt ?? null,
      // Declared only when the caller says so: this command seals captures other tools made, and it has
      // no way to know what is inside one (section 4.4 of the specification).
      captureProfile: options.profile ?? null,
      anchor,
      key,
    });
  } catch (error) {
    console.error(`not sealed: ${error.message}`);
    return 2;
  }

  for (const warning of sealed.warnings) console.error(`warning: ${warning}`);
  writeFileSync(out, sealed.bytes);

  console.log(`sealed ${options.capture} into ${out}`);
  console.log(`  claim hash  ${sealed.claimHash}`);
  console.log(`  subject     ${sealed.manifest.subject.url}`);
  console.log(`  captured    ${sealed.manifest.capture.captured_at}`);
  console.log(`  signature   ${sealed.manifest.signature === null
    ? 'none: this receipt says nobody signs for it'
    : `ed25519, key ${sealed.manifest.signature.key_id.slice(0, 16)}`}`);
  console.log('');
  console.log('checking what was just written:');

  const status = await verify(out, {}, options.json === true);
  if (status === 0) return 0;

  unlinkSync(out);
  console.error('');
  console.error(`${out} did not verify, so it has been removed. That is a bug in this program rather`);
  console.error('than anything you did, and it would be worth reporting with the output above.');
  return 2;
}

/** The current instant, UTC to the second: the only timestamp shape a claim admits. */
function utcSecond() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

/**
 * Fetch a page, once, as the receipt's subject rather than as a browser would.
 *
 * No cookies and no credentials: what this fetches is a *second look* at a public page, and a comparison
 * that depended on the fetcher's session would be a comparison of two different things.
 *
 * @param {string} url
 * @param {number} seconds
 * @returns {Promise<{ url: string, status: number, statusText: string, contentType: string | null,
 *   headers: Array<[string, string]>, body: Uint8Array }>}
 */
async function fetchPage(url, seconds) {
  const response = await fetch(url, {
    redirect: 'follow',
    headers: { 'user-agent': 'vidimus (receipt currency check)' },
    signal: AbortSignal.timeout(Math.round(seconds * 1000)),
  });
  return {
    url: response.url === '' ? url : response.url,
    status: response.status,
    statusText: response.statusText,
    contentType: response.headers.get('content-type'),
    headers: [...response.headers.entries()],
    body: new Uint8Array(await response.arrayBuffer()),
  };
}

/**
 * Compare a receipt with the page as it is now.
 *
 * The order matters: the receipt is verified *first*, and a receipt that does not hold up at its own
 * integrity level stops the command. Comparing a page with a claim whose bytes do not match its own
 * digest would be comparing with a sentence somebody typed.
 *
 * The second look is sealed into a real receipt, by the same producer as any other, so the comparison is
 * between two claims rather than between a claim and a loose fetch. That is what makes `words_unchanged`
 * mean something: both fingerprints were computed by the same rules over the same kind of input
 * (section 4.5).
 *
 * @param {Record<string, any>} options
 * @returns {Promise<number>}
 */
async function checkAgainstPage(options) {
  let verdict;
  try {
    verdict = await verifyReceipt(
      read(options.file),
      options.keyDirectory === undefined ? {} : { keyDirectory: options.keyDirectory },
    );
  } catch (error) {
    console.error(`${options.file}: could not be read: ${error.message}`);
    return 2;
  }

  if (verdict.levels.L0.status !== 'pass') {
    console.error(`${options.file} does not hold up at its own integrity level, so there is nothing to`);
    console.error('compare with a page:');
    for (const line of verdict.summary) console.error(`  ${line}`);
    return 2;
  }

  const claimed = {
    url: verdict.subject.url,
    capturedAt: verdict.subject.captured_at,
    status: verdict.subject.status,
    document: { sha256: verdict.subject.document_sha256 },
    textSha256: verdict.subject.text_sha256,
  };
  if (claimed.url === null) {
    console.error(`${options.file}: the claim names no URL, so there is nothing to fetch`);
    return 2;
  }

  let key = null;
  if (options.key !== undefined) {
    key = readKeyFile(options.key);
    if (key === null) return 2;
  }

  let now = null;
  let fresh = null;
  let why = null;
  let charset = null;
  try {
    const page = await fetchPage(claimed.url, options.timeout ?? 20);
    const capturedAt = utcSecond();
    charset = page.contentType;
    const capture = buildCapture({
      url: claimed.url,
      finalUrl: page.url,
      status: page.status,
      statusText: page.statusText,
      headers: page.headers,
      html: new TextDecoder('utf-8').decode(page.body),
      capturedAt,
    });
    fresh = sealFromCapture({ capture: capture.wacz, url: claimed.url, capturedAt, key });
    now = {
      url: page.url,
      capturedAt,
      status: page.status,
      // Taken from the fresh *claim*, not from the fetch, so both sides of the comparison were derived the
      // same way, from a capture this project wrote (section 4.5).
      documentSha256: fresh.manifest.subject.document.sha256,
      documentBytes: fresh.manifest.subject.document.bytes,
      textSha256: fresh.manifest.subject.text?.sha256 ?? null,
    };
  } catch (error) {
    why = `the page could not be fetched: ${error.message}`;
  }

  const report = compareCurrency(claimed, now, why);
  if (typeof charset === 'string' && !/charset=utf-?8(;|$)/i.test(charset)) {
    // Worth saying out loud: the comparison decoded the page as UTF-8, and a page that says otherwise may
    // have been decoded wrongly - which would look exactly like a change in the words.
    report.caveats.push(
      `the page declares ${charset}, and this comparison decodes as UTF-8, so a difference in the words `
      + 'could be a difference in decoding',
    );
  }
  const changed = (field) => report.differences.includes(field);
  const words = report.outcome === 'not_compared'
    ? 'not compared'
    : (claimed.textSha256 === null
      ? 'no fingerprint to compare'
      : (changed('text_sha256') ? 'changed' : 'unchanged'));

  if (options.json) {
    console.log(JSON.stringify({ receipt: verdict, currency: report }, null, 2));
  } else {
    console.log(`${options.file} · claim ${verdict.receipt.claim_hash ?? 'not computed'}`);
    console.log(`claim says  ${claimed.url} · ${claimed.capturedAt ?? 'no time stated'}`);
    console.log('');
    if (now === null) {
      console.log(`fetching ${claimed.url}: ${why}`);
    } else {
      console.log(`fetched     ${now.status} at ${now.capturedAt} (a request made because you asked)`);
      console.log(`  bytes     ${changed('document_sha256') ? 'changed' : 'unchanged'}`);
      console.log(`  words     ${words}`);
      console.log(`  outcome   ${report.meaning}`);
    }
    for (const caveat of report.caveats) console.log(`  caveat    ${caveat}`);
  }

  if (options.out !== undefined && fresh !== null) {
    if (existsSync(options.out) && options.force !== true) {
      console.error(`${options.out} already exists. Pass --force to replace it, or --out to write elsewhere.`);
      return 2;
    }
    writeFileSync(options.out, fresh.bytes);
    if (!options.json) {
      console.log('');
      console.log(`wrote ${options.out}: a receipt for what the page says now`
        + `${key === null ? ', unsigned' : ''}`);
    }
  }

  if (options.requireSameWords === true) {
    if (now === null) return 2;
    if (claimed.textSha256 === null) {
      console.error('the receipt declares no text fingerprint, so there are no words to require');
      return 2;
    }
    return claimed.textSha256 === now.textSha256 ? 0 : 1;
  }
  return exitCode(verdict);
}

/**
 * Read a key directory, and say what is in it.
 *
 * A directory is a statement about who holds which key, and the person who has to trust it is the person
 * who keeps it. So this prints what it found and refuses what it cannot use, rather than waiting for a
 * receipt to fail against it.
 *
 * @param {string} file
 * @returns {number}
 */
function listKeys(file) {
  let directory;
  try {
    directory = readKeyDirectory(readDirectoryFile(file));
  } catch (error) {
    console.error(`${file}: ${error.message}`);
    return 2;
  }

  console.log(`${file}${directory.name === null ? '' : ` · ${directory.name}`}`);
  console.log(`${directory.keys.size} key${directory.keys.size === 1 ? '' : 's'}`);

  for (const entry of directory.keys.values()) {
    const window = entry.valid_from === null && entry.valid_until === null
      ? 'no validity window stated'
      : `valid ${entry.valid_from ?? 'from the beginning'} to ${entry.valid_until ?? 'until further notice'}`;
    console.log('');
    console.log(`  ${entry.key_id}`);
    console.log(`    ${entry.name ?? '(no name given)'}`
      + `${entry.email === null ? '' : ` <${entry.email}>`}`);
    if (entry.note !== null) console.log(`    ${entry.note}`);
    console.log(`    ${window}`);
  }

  if (directory.problems.length > 0) {
    console.log('');
    console.error(`${directory.problems.length} ${directory.problems.length === 1 ? 'entry' : 'entries'} will not be used:`);
    for (const problem of directory.problems) console.error(`  ${problem}`);
    return 2;
  }
  return 0;
}

const parsed = parseArguments(process.argv.slice(2));
if (parsed === null) {
  for (const line of USAGE) console.error(line);
  process.exitCode = 2;
} else if (parsed.command === 'inspect') {
  process.exitCode = await inspect(parsed.file);
} else if (parsed.command === 'seal') {
  process.exitCode = await sealCapture(parsed);
} else if (parsed.command === 'check') {
  process.exitCode = await checkAgainstPage(parsed);
} else if (parsed.command === 'keys') {
  process.exitCode = listKeys(parsed.file);
} else if (parsed.command === 'keygen') {
  process.exitCode = keygen(parsed);
} else {
  process.exitCode = await verify(parsed.file, parsed.options, parsed.json);
}

