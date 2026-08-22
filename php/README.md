# incy/link-encoder (PHP)

PHP port of [`@incy/link-encoder`](https://github.com/INCY-DEV/incy-link-encoder) —
encode VPN subscription URLs into `incy://crypt1/<payload>` deep links
that the INCY iOS, Android, and Desktop clients decode automatically.

Wire-compatible with the JS/Python/Go ports and the client apps; a
pinned test vector guards against drift.

> **This is obfuscation, not security.** The AES-256-GCM key is derived
> from constants and asset bytes embedded in this package. See the
> [main README](../README.md) for the full threat model.

## Install

```bash
composer require incy/link-encoder
```

Requires PHP ≥ 8.1 with `openssl`, `mbstring`, and `json` extensions.

## Usage

```php
use Incy\LinkEncoder\LinkEncoder;

$link = LinkEncoder::encryptLink('https://sub.your-provider.example/abc123token', 'My Provider VPN');
// → incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGK…

$decoded = LinkEncoder::decryptLink($link);
echo $decoded['url'], ' ', $decoded['name'];
```

## API

```php
LinkEncoder::encryptLink(string $url, ?string $name = null): string
LinkEncoder::decryptLink(string $link): array   // ['url' => string, 'name' => ?string]
LinkEncoder::encryptLinkDeterministic(string $url, string $iv, ?string $name = null): string  // tests only

LinkEncoder::VERSION
LinkEncoder::SCHEME_VERSION   // "crypt1"
LinkEncoder::KEY_FINGERPRINT  // SHA-256 of K1
```

## Tests

```bash
php tests/run.php
```
