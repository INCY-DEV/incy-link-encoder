<?php

declare(strict_types=1);

namespace Incy\LinkEncoder;

/**
 * PHP port of @incy/link-encoder.
 *
 * Encodes subscription URLs into incy://crypt1/<payload> deep links
 * that the INCY iOS/Android/Desktop clients know how to decode.
 *
 * THIS IS OBFUSCATION, NOT SECURITY. The AES-256-GCM key is derived
 * from constants and asset bytes embedded in this package — anyone
 * reading the source can reconstruct it. See the README of the JS
 * package for the full threat model.
 *
 * Wire format (identical across JS/Python/PHP/Go and the client apps):
 *
 *     incy://crypt1/base64url( iv[12] || ciphertext || tag[16] )
 *
 * where the plaintext is compact JSON with sorted keys, e.g.
 * {"n":"Name","url":"https://...","v":1}.
 */
final class LinkEncoder
{
    public const VERSION = '1.3.0';
    public const SCHEME_VERSION = 'crypt1';
    public const KEY_FINGERPRINT =
        'b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c';

    // Salt parts — concatenated in order and fed into the SHA-256
    // KDF. Split into four constants for the same greppability
    // reasons as in the JS package and the client apps.
    private const SALT_P1 = 'incy';
    private const SALT_P2 = 'deep';
    private const SALT_P3 = 'crypt1';
    private const SALT_P4 = 'v2026.06';

    private const KEYMAT_A_OFFSET = 1024;
    private const KEYMAT_B_OFFSET = 2048;
    private const KEYMAT_LEN = 32;

    private const LINK_PREFIX = 'incy://crypt1/';

    private const IV_LEN = 12;
    private const TAG_LEN = 16;

    private static ?string $keyCache = null;

    /**
     * Registry of every deep-link scheme this build understands (today
     * only `crypt1`). A future key rotation adds `crypt2` here while
     * keeping `crypt1` so old links never stop decoding. Mirrors
     * SCHEMES in the JS package.
     *
     * @return array<string, array{host: string, prefix: string, keyFingerprint: string}>
     */
    public static function schemes(): array
    {
        return [
            'crypt1' => [
                'host' => 'crypt1',
                'prefix' => self::LINK_PREFIX,
                'keyFingerprint' => self::KEY_FINGERPRINT,
            ],
        ];
    }

    private static function deriveKey(): string
    {
        if (self::$keyCache !== null) {
            return self::$keyCache;
        }
        $a = base64_decode(Keymat::KEYMAT_A_B64, true);
        $b = base64_decode(Keymat::KEYMAT_B_B64, true);
        if ($a === false || $b === false
            || strlen($a) < self::KEYMAT_A_OFFSET + self::KEYMAT_LEN
            || strlen($b) < self::KEYMAT_B_OFFSET + self::KEYMAT_LEN) {
            throw new \RuntimeException('incy-link-encoder: keymat assets are smaller than expected');
        }
        $seed = self::SALT_P1 . self::SALT_P2 . self::SALT_P3 . self::SALT_P4
            . substr($a, self::KEYMAT_A_OFFSET, self::KEYMAT_LEN)
            . substr($b, self::KEYMAT_B_OFFSET, self::KEYMAT_LEN);
        $key = hash('sha256', $seed, true);
        $fp = hash('sha256', $key);
        if ($fp !== self::KEY_FINGERPRINT) {
            throw new \RuntimeException(
                'incy-link-encoder: derived K1 fingerprint mismatch (expected '
                . self::KEY_FINGERPRINT . ", got {$fp}) — keymat assets are out of sync "
                . 'with the published clients. Reinstall the package or report a bug.'
            );
        }
        return self::$keyCache = $key;
    }

    private static function b64urlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private static function b64urlDecode(string $s): string
    {
        $padded = strtr($s, '-_', '+/');
        $rem = strlen($padded) % 4;
        if ($rem !== 0) {
            $padded .= str_repeat('=', 4 - $rem);
        }
        $out = base64_decode($padded, true);
        if ($out === false) {
            throw new \InvalidArgumentException('decryptLink: bad base64url payload');
        }
        return $out;
    }

    private static function buildPlaintext(string $url, ?string $name): string
    {
        if ($url === '') {
            throw new \InvalidArgumentException('encryptLink: url must be a non-empty string');
        }
        $payload = ['url' => $url, 'v' => 1];
        if ($name !== null && $name !== '') {
            $payload['n'] = mb_substr($name, 0, 128, 'UTF-8');
        }
        // Compact JSON with sorted keys — byte-for-byte identical to
        // JSON.stringify over sorted keys in the JS package.
        // JSON_UNESCAPED_SLASHES / _UNICODE match JS escaping ("/"
        // and non-ASCII stay literal).
        ksort($payload, SORT_STRING);
        $json = json_encode($payload, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            throw new \RuntimeException('encryptLink: payload is not valid UTF-8');
        }
        return $json;
    }

    private static function seal(string $plaintext, string $iv): string
    {
        $tag = '';
        $ct = openssl_encrypt(
            $plaintext,
            'aes-256-gcm',
            self::deriveKey(),
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::TAG_LEN
        );
        if ($ct === false) {
            throw new \RuntimeException('encryptLink: openssl_encrypt failed');
        }
        return self::LINK_PREFIX . self::b64urlEncode($iv . $ct . $tag);
    }

    /**
     * Encrypt a subscription URL into an incy://crypt1/<payload>
     * deep-link string. $name is an optional human-readable
     * subscription name shown in the receiving app's import sheet
     * (truncated to 128 chars).
     */
    public static function encryptLink(string $url, ?string $name = null): string
    {
        return self::seal(self::buildPlaintext($url, $name), random_bytes(self::IV_LEN));
    }

    /**
     * Same as encryptLink() with a caller-provided IV. For test
     * vectors only — never reuse an IV across different plaintexts in
     * production; that breaks AES-GCM confidentiality.
     */
    public static function encryptLinkDeterministic(string $url, string $iv, ?string $name = null): string
    {
        if (strlen($iv) !== self::IV_LEN) {
            throw new \InvalidArgumentException('encryptLinkDeterministic: iv must be 12 bytes');
        }
        return self::seal(self::buildPlaintext($url, $name), $iv);
    }

    /**
     * Decrypt an incy://crypt1/<payload> link back to
     * ['url' => string, 'name' => ?string]. Throws on malformed input
     * or authentication failure (wrong key, tampered ciphertext).
     *
     * @return array{url: string, name: ?string}
     */
    public static function decryptLink(string $link): array
    {
        if (!str_starts_with($link, self::LINK_PREFIX)) {
            throw new \InvalidArgumentException('decryptLink: expected ' . self::LINK_PREFIX . ' prefix');
        }
        $payload = rtrim(substr($link, strlen(self::LINK_PREFIX)), '/');
        if ($payload === '') {
            throw new \InvalidArgumentException('decryptLink: empty payload');
        }
        $wire = self::b64urlDecode($payload);
        if (strlen($wire) < self::IV_LEN + self::TAG_LEN + 1) {
            throw new \InvalidArgumentException('decryptLink: payload too short');
        }
        $iv = substr($wire, 0, self::IV_LEN);
        $tag = substr($wire, -self::TAG_LEN);
        $ct = substr($wire, self::IV_LEN, strlen($wire) - self::IV_LEN - self::TAG_LEN);

        $plaintext = openssl_decrypt($ct, 'aes-256-gcm', self::deriveKey(), OPENSSL_RAW_DATA, $iv, $tag);
        if ($plaintext === false) {
            throw new \RuntimeException('decryptLink: authentication failed');
        }

        $parsed = json_decode($plaintext, true);
        if (!is_array($parsed)) {
            throw new \RuntimeException('decryptLink: malformed plaintext');
        }
        $url = $parsed['url'] ?? null;
        if (!is_string($url) || $url === '') {
            throw new \RuntimeException('decryptLink: missing url field');
        }
        $name = $parsed['n'] ?? null;
        return [
            'url' => $url,
            'name' => (is_string($name) && $name !== '') ? $name : null,
        ];
    }
}
