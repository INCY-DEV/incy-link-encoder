// @incy/link-encoder/web — Web Crypto entry point.
//
// Same wire format and function names as the Node entry, but built
// on `globalThis.crypto.subtle`, so it runs where `node:crypto` does
// not: browsers, web workers, service workers, Cloudflare Workers /
// edge runtimes, Deno — and modern Node too. Web Crypto is
// Promise-based, so every function here returns a Promise; that is
// the only interface difference from the Node entry.
//
// The security notes from index.ts apply unchanged: this is
// obfuscation, not secrecy. The key is already public — it ships in
// this package and inside every INCY client. Running the encoder in
// a browser reveals nothing that isn't already published.
//
//   import { encryptLink } from '@incy/link-encoder/web';
//   const link = await encryptLink('https://sub.example.com/token');

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
const TAG_LEN_BITS = 128;

// TS ≥5.7 types WebCrypto inputs as views over a plain ArrayBuffer.
// Everything we pass is exactly that (core never uses
// SharedArrayBuffer); this cast just tells the compiler so.
function bs(u: Uint8Array): Uint8Array<ArrayBuffer> {
  return u as Uint8Array<ArrayBuffer>;
}

function subtle(): SubtleCrypto {
  const s = globalThis.crypto?.subtle;
  if (!s) {
    throw new Error(
      'incy-link-encoder/web: WebCrypto (globalThis.crypto.subtle) is not available in this runtime. ' +
        'In Node, use the main entry (`@incy/link-encoder`) instead; in browsers, make sure the page ' +
        'is served over HTTPS or localhost (crypto.subtle is restricted to secure contexts).'
    );
  }
  return s;
}

let keyCache: Promise<CryptoKey> | undefined;

function deriveKey(): Promise<CryptoKey> {
  if (keyCache) return keyCache;
  const derived = (async () => {
    const s = subtle();
    const raw = new Uint8Array(await s.digest('SHA-256', bs(keySeed())));
    const fp = bytesToHex(new Uint8Array(await s.digest('SHA-256', raw)));
    if (fp !== EXPECTED_KEY_FINGERPRINT) {
      throw fingerprintMismatchError(fp);
    }
    return s.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  })();
  // Don't cache a rejected derivation — let a later call retry.
  keyCache = derived;
  derived.catch(() => {
    keyCache = undefined;
  });
  return derived;
}

async function seal(plaintext: Uint8Array, iv: Uint8Array): Promise<string> {
  const key = await deriveKey();
  // WebCrypto AES-GCM returns ciphertext || tag, which is exactly the
  // wire layout after the IV — no splitting needed.
  const ctAndTag = new Uint8Array(
    await subtle().encrypt({ name: 'AES-GCM', iv: bs(iv), tagLength: TAG_LEN_BITS }, key, bs(plaintext))
  );
  return assembleLink(concatBytes(iv, ctAndTag));
}

// --- Public API ----------------------------------------------------

/**
 * Encrypt a subscription URL into an `incy://crypt1/<payload>` deep
 * link string. Identical output format to the Node entry's
 * `encryptLink` — only the interface is async.
 *
 * Rejects if the URL is empty.
 */
export async function encryptLink(url: string, opts: EncryptOptions = {}): Promise<string> {
  const plaintext = buildPlaintext(url, opts);
  const iv = new Uint8Array(IV_LEN);
  globalThis.crypto.getRandomValues(iv);
  return seal(plaintext, iv);
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
export async function encryptLinkDeterministic(
  url: string,
  opts: EncryptDeterministicOptions
): Promise<string> {
  if (opts.iv.length !== IV_LEN) {
    throw new TypeError('encryptLinkDeterministic: iv must be 12 bytes');
  }
  const plaintext = buildPlaintext(url, opts);
  return seal(plaintext, opts.iv);
}

/**
 * Decrypt a `incy://crypt1/<payload>` deep link back to its
 * subscription URL + optional name. Rejects on malformed input or
 * authentication failure (wrong key, tampered ciphertext).
 */
export async function decryptLink(link: string): Promise<DecryptedLink> {
  const { iv, ct, tag } = parseLink(link);
  const key = await deriveKey();

  let plaintext: Uint8Array;
  try {
    plaintext = new Uint8Array(
      await subtle().decrypt(
        { name: 'AES-GCM', iv: bs(iv), tagLength: TAG_LEN_BITS },
        key,
        bs(concatBytes(ct, tag))
      )
    );
  } catch {
    throw new Error('decryptLink: authentication failed');
  }

  return parsePlaintext(plaintext);
}
