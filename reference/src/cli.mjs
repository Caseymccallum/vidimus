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
 * Exit codes (three, not two, because they mean different things to a script):
 *   0  verified: integrity and attribution both hold
 *   1  nothing failed, and nothing was proven either
 *   2  something failed, the seal was refused, or the file could not be read at all
 *
 * @module cli
 */

import { existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { exitCode, verifyReceipt } from './verify.mjs';
import { SealError, sealFromCapture } from './seal.mjs';
import { fromBase64Url, toBase64Url } from './digest.mjs';
import { generateSeed, keyId, privateKeyFromSeed, rawPublicKey } from './signature.mjs';

/** Every command, printed when the arguments do not make sense. */
const USAGE = [
  'usage: vidimus verify  <file.receipt> [--json] [--trusted-key <hex>]... [--previous <hex>]',
  '       vidimus inspect <file.receipt>',
  '       vidimus seal    <capture.wacz> [--url <url>] [--captured-at <ts>] [--document <file>]',
  '                       [--key <key.json> | --unsigned] [--chain <n> --prev <hash>]',
  '                       [--out <file.receipt>] [--force] [--json]',
  '       vidimus keygen  [--out <key.json>] [--signer <name>] [--force]',
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
  return null;
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
    } else if (['--url', '--captured-at', '--document', '--key', '--out', '--prev'].includes(argument)) {
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

/** @param {string} file @param {Record<string, any>} options @param {boolean} json */
function verify(file, options, json) {
  let verdict;
  try {
    verdict = verifyReceipt(read(file), options);
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
function inspect(file) {
  const verdict = verifyReceipt(read(file));
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
function sealCapture(options) {
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

  const status = verify(out, {}, options.json === true);
  if (status === 0) return 0;

  unlinkSync(out);
  console.error('');
  console.error(`${out} did not verify, so it has been removed. That is a bug in this program rather`);
  console.error('than anything you did, and it would be worth reporting with the output above.');
  return 2;
}

const parsed = parseArguments(process.argv.slice(2));
if (parsed === null) {
  for (const line of USAGE) console.error(line);
  process.exitCode = 2;
} else if (parsed.command === 'inspect') {
  process.exitCode = inspect(parsed.file);
} else if (parsed.command === 'seal') {
  process.exitCode = sealCapture(parsed);
} else if (parsed.command === 'keygen') {
  process.exitCode = keygen(parsed);
} else {
  process.exitCode = verify(parsed.file, parsed.options, parsed.json);
}

