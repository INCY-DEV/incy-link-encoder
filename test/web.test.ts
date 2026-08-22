// Tests for the Web Crypto entry (`@incy/link-encoder/web`). Node
// ships the same `globalThis.crypto.subtle` implementation browsers
// use, so the whole suite runs under `node --test` — plus interop
// checks proving the two entries are wire-identical.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  encryptLink,
  encryptLinkDeterministic,
  decryptLink,
  KEY_FINGERPRINT,
  SCHEME_VERSION,
} from '../src/web.ts';
import * as nodeEntry from '../src/index.ts';

test('web: key fingerprint matches cross-platform constant', () => {
  assert.equal(
    KEY_FINGERPRINT,
    'b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c'
  );
  assert.equal(SCHEME_VERSION, 'crypt1');
});

test('web: encrypt + decrypt round-trip', async () => {
  const url = 'https://sub.example.com/test-token';
  const link = await encryptLink(url);
  assert.ok(link.startsWith('incy://crypt1/'));
  const decoded = await decryptLink(link);
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, undefined);
});

test('web: encrypt with name + decrypt preserves name', async () => {
  const url = 'https://sub.example.com/abc';
  const name = 'MyProvider VPN';
  const link = await encryptLink(url, { name });
  const decoded = await decryptLink(link);
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, name);
});

test('web: deterministic vector matches cross-platform reference', async () => {
  // Same pinned vector as the Node suite — iOS/Android/Desktop
  // interop tests pin against the identical wire bytes.
  const iv = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0x0a, 0x0b]);
  const url = 'https://sub.example.com/test-vector';
  const expected =
    'incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGKSLXP6o8NdSXQVSSALNbbUyIr__tWGFUexdIfKvvmDnuDGbmBvuppfNef6aKNZUwOm4c-Sg';
  const link = await encryptLinkDeterministic(url, { iv });
  assert.equal(link, expected);
});

test('web: encrypt produces unique ciphertext per call (random IV)', async () => {
  const url = 'https://test.example/abc';
  const a = await encryptLink(url);
  const b = await encryptLink(url);
  assert.notEqual(a, b);
  assert.equal((await decryptLink(a)).url, url);
  assert.equal((await decryptLink(b)).url, url);
});

test('web: decryptLink rejects tampered payload', async () => {
  const url = 'https://test.example/x';
  const link = await encryptLink(url);
  const tampered =
    link.slice(0, -10) + (link[link.length - 10] === 'A' ? 'B' : 'A') + link.slice(-9);
  await assert.rejects(() => decryptLink(tampered));
});

test('web: decryptLink rejects non-crypt1 prefix', async () => {
  await assert.rejects(() => decryptLink('https://incy.cc/foo'));
  await assert.rejects(() => decryptLink('incy://add/https%3A%2F%2Ffoo.bar'));
  await assert.rejects(() => decryptLink(''));
});

test('web: encryptLink rejects empty input', async () => {
  await assert.rejects(() => encryptLink(''));
  // @ts-expect-error type check
  await assert.rejects(() => encryptLink(undefined));
});

test('web: encryptLinkDeterministic rejects wrong IV length', async () => {
  await assert.rejects(() =>
    encryptLinkDeterministic('https://test/x', { iv: new Uint8Array(11) })
  );
});

test('web: name is truncated to 128 chars', async () => {
  const long = 'X'.repeat(500);
  const link = await encryptLink('https://test/x', { name: long });
  const decoded = await decryptLink(link);
  assert.equal(decoded.name?.length, 128);
});

// --- Interop between the two entries -------------------------------

test('interop: web and node deterministic output is byte-identical', async () => {
  const iv = new Uint8Array([9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 0xff, 0xee]);
  const url = 'https://sub.example.com/interop';
  const name = 'Interop Check';
  const fromWeb = await encryptLinkDeterministic(url, { iv, name });
  const fromNode = nodeEntry.encryptLinkDeterministic(url, { iv, name });
  assert.equal(fromWeb, fromNode);
});

test('interop: node encrypts → web decrypts', async () => {
  const url = 'https://sub.example.com/node-to-web';
  const link = nodeEntry.encryptLink(url, { name: 'N2W' });
  const decoded = await decryptLink(link);
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, 'N2W');
});

test('interop: web encrypts → node decrypts', async () => {
  const url = 'https://sub.example.com/web-to-node';
  const link = await encryptLink(url, { name: 'W2N' });
  const decoded = nodeEntry.decryptLink(link);
  assert.equal(decoded.url, url);
  assert.equal(decoded.name, 'W2N');
});
