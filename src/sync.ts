// @incy/link-encoder/sync — synchronous, pure-JS entry point.
//
// Same wire format and function names as the Node and Web entries,
// but AES-256-GCM and SHA-256 run on @noble/ciphers + @noble/hashes
// (audited, MIT, zero native deps) instead of node:crypto or
// globalThis.crypto.subtle. That makes every function SYNCHRONOUS and
// available in any JS runtime — including browsers.
//
// Why this exists: some hosts substitute a link inside a synchronous
// codepath where an `await` is impossible. The concrete case is the
// Remnawave subscription page's Template Variables (INCY_CRYPT1_LINK):
// variable substitution there is synchronous, and on iOS/Safari a
// navigation to a custom scheme (`incy://…`) must happen inside the
// user-activation tick — awaiting `crypto.subtle` first loses that
// "fresh tap" and the link silently fails to open. A synchronous
// encoder lets the crypt1 link drop into one string, exactly like the
// jsencrypt-based Happ encoder it sits next to.
//
//   import { encryptLink } from '@incy/link-encoder/sync';
//   const link = encryptLink('https://sub.example.com/token');  // no await
//
// The security notes from index.ts apply unchanged: this is
// obfuscation, not secrecy. The key is already public — it ships in
// this package and inside every INCY client.

import { gcm } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import {
  EXPECTED_KEY_FINGERPRINT,
  assembleLink,
  buildPlaintext,
  bytesToHex,
  concatBytes,
  fingerprintMismatchError,
  keySeed,
  parseLink,
  parsePlaintext,
  type DecryptedLink,
  type EncryptOptions,
} from './core.js';

export type { DecryptedLink, EncryptOptions, SchemeInfo } from './core.js';
export { VERSION, SCHEME_VERSION, KEY_FINGERPRINT, SCHEMES } from './core.js';

const IV_LEN = 12;

let keyCache: Uint8Array | undefined;

function deriveKey(): Uint8Array {
  if (keyCache) return keyCache;
  const k = sha256(keySeed());
  const fp = bytesToHex(sha256(k));
  if (fp !== EXPECTED_KEY_FINGERPRINT) {
    throw fingerprintMismatchError(fp);
  }
  keyCache = k;
  return k;
}

function seal(plaintext: Uint8Array, iv: Uint8Array): string {
  // noble's gcm().encrypt() returns ciphertext || tag — exactly the
  // wire layout after the IV, matching the Node and Web entries.
  const ctAndTag = gcm(deriveKey(), iv).encrypt(plaintext);
  return assembleLink(concatBytes(iv, ctAndTag));
}

// --- Public API ----------------------------------------------------

/**
 * Encrypt a subscription URL into an `incy://crypt1/<payload>` deep
 * link string. Synchronous — identical output to the Node and Web
 * entries' `encryptLink`.
 *
 * Throws if the URL is empty.
 */
export function encryptLink(url: string, opts: EncryptOptions = {}): string {
  const plaintext = buildPlaintext(url, opts);
  return seal(plaintext, randomBytes(IV_LEN));
}

/** Optional explicit IV — for deterministic tests. */
export interface EncryptDeterministicOptions extends EncryptOptions {
  iv: Uint8Array;
}

/**
 * Same as `encryptLink` but takes a caller-provided IV. Useful for
 * test vectors / reproducibility. **Do not** reuse an IV across
 * different plaintexts in production — that breaks AES-GCM
 * confidentiality.
 */
export function encryptLinkDeterministic(
  url: string,
  opts: EncryptDeterministicOptions
): string {
  if (opts.iv.length !== IV_LEN) {
    throw new TypeError('encryptLinkDeterministic: iv must be 12 bytes');
  }
  return seal(buildPlaintext(url, opts), opts.iv);
}

/**
 * Decrypt a `incy://crypt1/<payload>` deep link back to its
 * subscription URL + optional name. Throws on malformed input or
 * authentication failure (wrong key, tampered ciphertext).
 */
export function decryptLink(link: string): DecryptedLink {
  const { iv, ct, tag } = parseLink(link);
  let plaintext: Uint8Array;
  try {
    plaintext = gcm(deriveKey(), iv).decrypt(concatBytes(ct, tag));
  } catch {
    throw new Error('decryptLink: authentication failed');
  }
  return parsePlaintext(plaintext);
}
