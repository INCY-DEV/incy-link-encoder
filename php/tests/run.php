<?php

declare(strict_types=1);

// Dependency-free test runner for the PHP port (no PHPUnit needed):
//   php tests/run.php
// Mirrors test/index.test.ts, including the pinned cross-platform
// vector that guards wire compatibility.

require __DIR__ . '/../src/Keymat.php';
require __DIR__ . '/../src/LinkEncoder.php';

use Incy\LinkEncoder\LinkEncoder;

const PINNED_VECTOR = 'incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGKSLXP6o8NdSXQVSSALNbbUyIr__tWGFUexdIfKvvmDnuDGbmBvuppfNef6aKNZUwOm4c-Sg';

$failures = 0;

function check(string $label, callable $fn): void
{
    global $failures;
    try {
        $fn();
        echo "  ok  {$label}\n";
    } catch (\Throwable $e) {
        $failures++;
        echo "FAIL  {$label}: {$e->getMessage()}\n";
    }
}

function assertSame($expected, $actual, string $what = 'value'): void
{
    if ($expected !== $actual) {
        throw new \RuntimeException(
            "{$what}: expected " . var_export($expected, true) . ', got ' . var_export($actual, true)
        );
    }
}

function assertThrows(callable $fn, string $what): void
{
    try {
        $fn();
    } catch (\Throwable $e) {
        return;
    }
    throw new \RuntimeException("{$what}: expected an exception, none thrown");
}

check('key fingerprint matches cross-platform constant', function () {
    assertSame(
        'b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c',
        LinkEncoder::KEY_FINGERPRINT
    );
    assertSame('crypt1', LinkEncoder::SCHEME_VERSION);
});

check('encrypt + decrypt round-trip', function () {
    $url = 'https://sub.example.com/test-token';
    $link = LinkEncoder::encryptLink($url);
    if (!str_starts_with($link, 'incy://crypt1/')) {
        throw new \RuntimeException("bad prefix: {$link}");
    }
    $decoded = LinkEncoder::decryptLink($link);
    assertSame($url, $decoded['url'], 'url');
    assertSame(null, $decoded['name'], 'name');
});

check('encrypt with name + decrypt preserves name', function () {
    $decoded = LinkEncoder::decryptLink(
        LinkEncoder::encryptLink('https://sub.example.com/abc', 'MyProvider VPN')
    );
    assertSame('https://sub.example.com/abc', $decoded['url'], 'url');
    assertSame('MyProvider VPN', $decoded['name'], 'name');
});

check('deterministic vector matches cross-platform reference', function () {
    $iv = hex2bin('000102030405060708090a0b');
    $link = LinkEncoder::encryptLinkDeterministic('https://sub.example.com/test-vector', $iv);
    assertSame(PINNED_VECTOR, $link, 'pinned vector');
});

check('encrypt produces unique ciphertext per call (random IV)', function () {
    $url = 'https://test.example/abc';
    $a = LinkEncoder::encryptLink($url);
    $b = LinkEncoder::encryptLink($url);
    if ($a === $b) {
        throw new \RuntimeException('two encryptions produced identical wire bytes');
    }
    assertSame($url, LinkEncoder::decryptLink($a)['url'], 'url a');
    assertSame($url, LinkEncoder::decryptLink($b)['url'], 'url b');
});

check('decryptLink rejects tampered payload', function () {
    $link = LinkEncoder::encryptLink('https://test.example/x');
    $i = strlen($link) - 10;
    $link[$i] = $link[$i] === 'A' ? 'B' : 'A';
    assertThrows(fn () => LinkEncoder::decryptLink($link), 'tampered payload');
});

check('decryptLink rejects non-crypt1 prefix', function () {
    assertThrows(fn () => LinkEncoder::decryptLink('https://incy.cc/foo'), 'https prefix');
    assertThrows(fn () => LinkEncoder::decryptLink('incy://add/https%3A%2F%2Ffoo.bar'), 'incy://add');
    assertThrows(fn () => LinkEncoder::decryptLink(''), 'empty link');
});

check('encryptLink rejects empty input', function () {
    assertThrows(fn () => LinkEncoder::encryptLink(''), 'empty url');
});

check('encryptLinkDeterministic rejects wrong IV length', function () {
    assertThrows(
        fn () => LinkEncoder::encryptLinkDeterministic('https://test/x', str_repeat("\0", 11)),
        '11-byte IV'
    );
});

check('name is truncated to 128 chars', function () {
    $decoded = LinkEncoder::decryptLink(
        LinkEncoder::encryptLink('https://test/x', str_repeat('X', 500))
    );
    assertSame(128, strlen($decoded['name']), 'name length');
});

check('query-param URL survives JSON escaping', function () {
    $url = 'https://sub.example.com/get?token=abc&format=v2ray';
    $decoded = LinkEncoder::decryptLink(LinkEncoder::encryptLink($url));
    assertSame($url, $decoded['url'], 'url');
});

echo $failures === 0 ? "\nAll tests passed\n" : "\n{$failures} test(s) FAILED\n";
exit($failures === 0 ? 0 : 1);
