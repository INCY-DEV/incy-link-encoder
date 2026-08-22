// @incy/link-encoder — Node entry point.
//
// Encode subscription URLs into `incy://crypt1/<payload>` deep links
// that the INCY iOS/Android/Desktop clients know how to decode.
//
// ⚠️  THIS IS OBFUSCATION, NOT SECURITY.
//
// The AES-256-GCM key K1 is derived from constants and binary asset
// bytes embedded in this package — anyone reading the source can
// reconstruct it. The same K1 already lives inside every shipped INCY
// client app (iOS IPA, Android APK, Desktop installer), where it is
// also extractable by a reverse engineer. Publishing this package
// reveals nothing new; it just acknowledges the offline-decryption
// limitation honestly.
//
// What we DO defend against:
//   ✅  Telegram chat moderation bots scanning for VPN-URL patterns
//   ✅  Russian regulator (RKN) automated scanners
//   ✅  Casual users accidentally pasting plaintext URLs in screenshots
//   ✅  `grep` over chat dumps / supply-chain string scanners
//
// What we DON'T defend against:
//   ❌  A determined reverse engineer with Frida — the key materialises
//       in memory at the moment `AES.GCM.seal()` runs, regardless of
//       how it was derived. Same applies on the client side.
//
// If the key is ever burnt publicly, the INCY clients ship a new
// release adding `crypt2/` (different salt parts + different keymat
// asset bytes). Existing `crypt1/` links in chat histories keep
// working forever — clients never remove the old scheme from their
// decoder table.
//
// This entry is synchronous and uses `node:crypto`. For browsers,
// workers, and edge runtimes use `@incy/link-encoder/web` — same
// wire format, same function names, Promise-based (see web.ts).

import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import {
  EXPECTED_KEY_FINGERPRINT,
  assembleLink,
  buildPlaintext,
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

let keyCache: Buffer | undefined;

function deriveKey(): Buffer {
  if (keyCache) return keyCache;
  const k = createHash('sha256').update(keySeed()).digest();
  const fp = createHash('sha256').update(k).digest('hex');
  if (fp !== EXPECTED_KEY_FINGERPRINT) {
    throw fingerprintMismatchError(fp);
  }
  keyCache = k;
  return k;
}

// --- Public API ----------------------------------------------------

/**
 * Encrypt a subscription URL into an `incy://crypt1/<payload>` deep
 * link string. The URL must be an http(s) subscription endpoint —
 * v2ray/vless/trojan share links are not yet supported in v1.
 *
 * Throws if the URL is empty.
 */
export function encryptLink(url: string, opts: EncryptOptions = {}): string {
  const plaintext = buildPlaintext(url, opts);
  const key = deriveKey();

  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return assembleLink(concatBytes(iv, ct, tag));
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
  if (opts.iv.length !== 12) {
    throw new TypeError('encryptLinkDeterministic: iv must be 12 bytes');
  }
  const plaintext = buildPlaintext(url, opts);
  const key = deriveKey();

  const cipher = createCipheriv('aes-256-gcm', key, opts.iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  return assembleLink(concatBytes(opts.iv, ct, tag));
}

/**
 * Decrypt a `incy://crypt1/<payload>` deep link back to its
 * subscription URL + optional name. Throws on malformed input or
 * authentication failure (wrong key, tampered ciphertext).
 *
 * Used mainly for verification / testing — production decryption
 * happens inside the INCY client apps.
 */
export function decryptLink(link: string): DecryptedLink {
  const { iv, ct, tag } = parseLink(link);

  const key = deriveKey();
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ct), decipher.final()]);
  } catch {
    throw new Error('decryptLink: authentication failed');
  }

  return parsePlaintext(plaintext);
}
