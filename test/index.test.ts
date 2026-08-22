import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  encryptLink,
  encryptLinkDeterministic,
  decryptLink,
  KEY_FINGERPRINT,
  SCHEME_VERSION,
  SCHEMES,
} from '../src/index.ts';

test('key fingerprint matches cross-platform constant', () => {
  // If this fails, the keymat assets in this package have drifted
  // from what iOS/Android/Desktop ship. Re-sync before publishing.
  assert.equal(
    KEY_FINGERPRINT,
    'b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c'
  );
});

test('SCHEME_VERSION is crypt1', () => {
  assert.equal(SCHEME_VERSION, 'crypt1');
});

test('encrypt + decrypt round-trip', () => {
  const url = 'https://sub.example.com/test-token';
  const link = encryptLink(url);
  assert.ok(link.startsWith('incy://crypt1/'));
  const decoded = decryptLink(link);
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, undefined);
});

test('encrypt with name + decrypt preserves name', () => {
  const url = 'https://sub.example.com/abc';
  const name = 'MyProvider VPN';
  const link = encryptLink(url, { name });
  const decoded = decryptLink(link);
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, name);
});

test('deterministic vector matches cross-platform reference', () => {
  // This vector was computed in JS and confirmed to decode identically
  // on iOS (CryptoKit), Android (javax.crypto), and Desktop
  // (javax.crypto). If this test fails, the package is no longer
  // wire-compatible with the shipped client apps. Plaintext is an
  // example URL — NOT a real provider endpoint — and is reused
  // verbatim in the iOS/Android/Desktop interop tests so all four
  // sides pin against the same wire bytes.
  const iv = Buffer.from('000102030405060708090a0b', 'hex');
  const url = 'https://sub.example.com/test-vector';
  const expected =
    'incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGKSLXP6o8NdSXQVSSALNbbUyIr__tWGFUexdIfKvvmDnuDGbmBvuppfNef6aKNZUwOm4c-Sg';
  const link = encryptLinkDeterministic(url, { iv });
  assert.equal(link, expected);
});

test('encrypt produces unique ciphertext per call (random IV)', () => {
  const url = 'https://test.example/abc';
  const a = encryptLink(url);
  const b = encryptLink(url);
  // Same plaintext, different random IV → different wire bytes.
  // This is the property that defeats "is this the same subscription
  // URL?" pattern matching by RKN/Telegram bots.
  assert.notEqual(a, b);
  assert.equal(decryptLink(a).url, url);
  assert.equal(decryptLink(b).url, url);
});

test('decryptLink rejects tampered payload', () => {
  const url = 'https://test.example/x';
  const link = encryptLink(url);
  // Flip a character in the middle of the base64url payload.
  const tampered =
    link.slice(0, -10) + (link[link.length - 10] === 'A' ? 'B' : 'A') + link.slice(-9);
  assert.throws(() => decryptLink(tampered));
});

test('decryptLink rejects non-crypt1 prefix', () => {
  assert.throws(() => decryptLink('https://incy.cc/foo'));
  assert.throws(() => decryptLink('incy://add/https%3A%2F%2Ffoo.bar'));
  assert.throws(() => decryptLink(''));
});

test('encryptLink rejects empty input', () => {
  assert.throws(() => encryptLink(''));
  // @ts-expect-error type check
  assert.throws(() => encryptLink(undefined));
});

test('encryptLinkDeterministic rejects wrong IV length', () => {
  assert.throws(() =>
    encryptLinkDeterministic('https://test/x', {
      iv: Buffer.alloc(11),
    })
  );
});

test('name is truncated to 128 chars', () => {
  const long = 'X'.repeat(500);
  const link = encryptLink('https://test/x', { name: long });
  const decoded = decryptLink(link);
  assert.equal(decoded.name?.length, 128);
});

test('SCHEMES registry describes crypt1', () => {
  assert.deepEqual(Object.keys(SCHEMES), ['crypt1']);
  assert.equal(SCHEMES.crypt1.host, 'crypt1');
  assert.equal(SCHEMES.crypt1.prefix, 'incy://crypt1/');
  assert.equal(SCHEMES.crypt1.keyFingerprint, KEY_FINGERPRINT);
  // Frozen so callers can't mutate the shared registry.
  assert.ok(Object.isFrozen(SCHEMES));
  assert.ok(Object.isFrozen(SCHEMES.crypt1));
});

// --- CLI smoke tests. Run against the TS source via tsx (the same
// runner as `npm test`), so no build step is required.

const CLI = fileURLToPath(new URL('../src/cli.ts', import.meta.url));

function runCli(args: string[], input?: string): string {
  return execFileSync('node', ['--import', 'tsx', CLI, ...args], {
    input,
    encoding: 'utf8',
  }).trim();
}

test('cli: encrypt then decode round-trips via stdout', () => {
  const url = 'https://sub.example.com/cli-token';
  const link = runCli(['--url', url]);
  assert.ok(link.startsWith('incy://crypt1/'));
  assert.equal(runCli(['--decode', link]), url);
});

test('cli: positional URL and --json shorthand', () => {
  const url = 'https://sub.example.com/cli-json';
  const out = JSON.parse(runCli(['--json', url]));
  assert.ok(out.link.startsWith('incy://crypt1/'));
  const decoded = JSON.parse(runCli(['--json', '--decode', out.link]));
  assert.equal(decoded.url, url);
});

test('cli: reads URL from stdin', () => {
  const url = 'https://sub.example.com/cli-stdin';
  const link = runCli([], url + '\n');
  assert.equal(runCli(['--decode', link]), url);
});
