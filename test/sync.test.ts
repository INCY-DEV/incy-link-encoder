// Tests for the synchronous pure-JS entry (`@incy/link-encoder/sync`),
// built on @noble/ciphers. Mirrors the Node/Web suites plus interop
// checks proving all three entries are wire-identical.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  encryptLink,
  encryptLinkDeterministic,
  decryptLink,
  KEY_FINGERPRINT,
  SCHEME_VERSION,
  SCHEMES,
} from '../src/sync.ts';
import * as nodeEntry from '../src/index.ts';
import * as webEntry from '../src/web.ts';

test('sync: key fingerprint matches cross-platform constant', () => {
  assert.equal(
    KEY_FINGERPRINT,
    'b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c'
  );
  assert.equal(SCHEME_VERSION, 'crypt1');
});

test('sync: encrypt + decrypt round-trip', () => {
  const url = 'https://sub.example.com/test-token';
  const link = encryptLink(url);
  assert.ok(link.startsWith('incy://crypt1/'));
  const decoded = decryptLink(link);
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, undefined);
});

test('sync: encrypt with name + decrypt preserves name', () => {
  const url = 'https://sub.example.com/abc';
  const name = 'MyProvider VPN';
  const decoded = decryptLink(encryptLink(url, { name }));
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, name);
});

test('sync: deterministic vector matches cross-platform reference', () => {
  const iv = Buffer.from('000102030405060708090a0b', 'hex');
  const url = 'https://sub.example.com/test-vector';
  const expected =
    'incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGKSLXP6o8NdSXQVSSALNbbUyIr__tWGFUexdIfKvvmDnuDGbmBvuppfNef6aKNZUwOm4c-Sg';
  const link = encryptLinkDeterministic(url, { iv });
  assert.equal(link, expected);
});

test('sync: is genuinely synchronous (returns a string, not a Promise)', () => {
  const link = encryptLink('https://test.example/sync');
  assert.equal(typeof link, 'string');
  assert.ok(!(link instanceof Promise));
});

test('sync: encrypt produces unique ciphertext per call (random IV)', () => {
  const url = 'https://test.example/abc';
  const a = encryptLink(url);
  const b = encryptLink(url);
  assert.notEqual(a, b);
  assert.equal(decryptLink(a).url, url);
  assert.equal(decryptLink(b).url, url);
});

test('sync: decryptLink rejects tampered payload', () => {
  const link = encryptLink('https://test.example/x');
  const tampered =
    link.slice(0, -10) + (link[link.length - 10] === 'A' ? 'B' : 'A') + link.slice(-9);
  assert.throws(() => decryptLink(tampered));
});

test('sync: decryptLink rejects non-crypt1 prefix', () => {
  assert.throws(() => decryptLink('https://incy.cc/foo'));
  assert.throws(() => decryptLink('incy://add/https%3A%2F%2Ffoo.bar'));
  assert.throws(() => decryptLink(''));
});

test('sync: encryptLink rejects empty input', () => {
  assert.throws(() => encryptLink(''));
  // @ts-expect-error type check
  assert.throws(() => encryptLink(undefined));
});

test('sync: encryptLinkDeterministic rejects wrong IV length', () => {
  assert.throws(() => encryptLinkDeterministic('https://test/x', { iv: Buffer.alloc(11) }));
});

test('sync: name is truncated to 128 chars', () => {
  const decoded = decryptLink(encryptLink('https://test/x', { name: 'X'.repeat(500) }));
  assert.equal(decoded.name?.length, 128);
});

test('sync: SCHEMES registry describes crypt1', () => {
  assert.deepEqual(Object.keys(SCHEMES), ['crypt1']);
  assert.equal(SCHEMES.crypt1.prefix, 'incy://crypt1/');
});

// --- Interop across all three entries -----------------------------

test('interop: sync and node deterministic output is byte-identical', () => {
  const iv = Buffer.from('0b0a09080706050403020100', 'hex');
  const url = 'https://sub.example.com/interop-sync-node';
  const name = 'Interop';
  assert.equal(
    encryptLinkDeterministic(url, { iv, name }),
    nodeEntry.encryptLinkDeterministic(url, { iv, name })
  );
});

test('interop: sync and web deterministic output is byte-identical', async () => {
  const iv = new Uint8Array([1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144]);
  const url = 'https://sub.example.com/interop-sync-web';
  const fromSync = encryptLinkDeterministic(url, { iv });
  const fromWeb = await webEntry.encryptLinkDeterministic(url, { iv });
  assert.equal(fromSync, fromWeb);
});

test('interop: node encrypts → sync decrypts', () => {
  const url = 'https://sub.example.com/node-to-sync';
  const decoded = decryptLink(nodeEntry.encryptLink(url, { name: 'N2S' }));
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, 'N2S');
});

test('interop: sync encrypts → node decrypts', () => {
  const url = 'https://sub.example.com/sync-to-node';
  const decoded = nodeEntry.decryptLink(encryptLink(url, { name: 'S2N' }));
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, 'S2N');
});

test('interop: sync encrypts → web decrypts', async () => {
  const url = 'https://sub.example.com/sync-to-web';
  const decoded = await webEntry.decryptLink(encryptLink(url, { name: 'S2W' }));
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, 'S2W');
});
