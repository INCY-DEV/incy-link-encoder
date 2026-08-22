# @incy/link-encoder

Encode VPN subscription URLs into `incy://crypt1/<payload>` deep links
that the [INCY](https://incy.cc) iOS, Android, and Desktop clients
decode automatically.

```
https://sub.your-provider.example/abc123token
                ⬇
incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGK…
```

Open the resulting link on a device with INCY installed → the
subscription imports without the user copy-pasting anything.

## Install

```bash
npm install @incy/link-encoder
```

## Usage

```js
import { encryptLink, decryptLink } from '@incy/link-encoder';

const link = encryptLink('https://sub.your-provider.example/abc123token', {
  name: 'My Provider VPN',
});

console.log(link);
// → incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGK…

// Decryption mainly for testing — the INCY apps do this end-side.
const decoded = decryptLink(link);
console.log(decoded.url, decoded.name);
```

`encryptLink(url, opts?)` accepts:

| Field    | Type      | Notes                                              |
|----------|-----------|----------------------------------------------------|
| `url`    | `string`  | The http(s) subscription URL. Required.            |
| `opts.name` | `string?` | Display name shown in the receiver's import sheet. |

## Browser / edge usage (Web Crypto)

The main entry is synchronous and uses `node:crypto`. For frontends —
subscription pages, user dashboards, anything bundled for the
browser — import the **`/web` entry** instead. Same wire format, same
function names, built on `globalThis.crypto.subtle`, so it runs in
browsers, web workers, Cloudflare Workers / edge runtimes, Deno, and
modern Node. Web Crypto is Promise-based, so every function returns a
Promise — that is the only interface difference:

```js
import { encryptLink, decryptLink } from '@incy/link-encoder/web';

const link = await encryptLink('https://sub.your-provider.example/abc123token', {
  name: 'My Provider VPN',
});
const decoded = await decryptLink(link);
```

Notes:

- Output is byte-for-byte identical to the Node entry (the test suite
  cross-checks both against the same pinned vector).
- `crypto.subtle` only exists in [secure contexts](https://developer.mozilla.org/en-US/docs/Web/Security/Secure_Contexts) —
  serve the page over HTTPS or localhost.
- Using this in a frontend reveals no secrets that aren't already
  public: the key ships in this package and in every INCY client (see
  "What this is NOT" below).

## Other languages

Wire-compatible ports live in this repo, all pinned against the same
cross-platform test vector:

| Language | Package                                    | Directory            |
|----------|--------------------------------------------|----------------------|
| Python   | `incy-link-encoder` (PyPI)                 | [`python/`](python/) |
| PHP      | `incy/link-encoder` (Composer)             | [`php/`](php/)       |
| Go       | `github.com/INCY-DEV/incy-link-encoder/go` | [`go/`](go/)         |

The embedded key material for every port is generated from
`assets/*.bin` by `npm run gen-keymat`; CI fails if any port's keymat
drifts from the canonical bytes.

## CLI

The package ships a small CLI — no install needed with `npx`:

```bash
# Encrypt
npx @incy/link-encoder --url https://sub.example.org/token --name "My VPN"
# → incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGK…

# Decrypt (auto-detected from the incy:// prefix)
npx @incy/link-encoder --decode incy://crypt1/AAEC…

# Pipe a URL in, get a link out
echo "https://sub.example.org/token" | npx @incy/link-encoder

# JSON output for scripting
npx @incy/link-encoder --json --url https://sub.example.org/token
```

Run `npx @incy/link-encoder --help` for all flags.

## Framework examples

**React** (browser — the `/web` entry):

```jsx
import { useState } from 'react';
import { encryptLink } from '@incy/link-encoder/web';

function EncodeButton({ url, name }) {
  const [link, setLink] = useState('');
  return (
    <button onClick={async () => setLink(await encryptLink(url, { name }))}>
      {link || 'Encode subscription link'}
    </button>
  );
}
```

**Express / NestJS** (server — the Node entry, synchronous):

```ts
import { encryptLink } from '@incy/link-encoder';

// Express route
app.post('/encode', (req, res) => {
  res.json({ link: encryptLink(req.body.url, { name: req.body.name }) });
});

// NestJS service
@Injectable()
export class SubscriptionService {
  toDeepLink(url: string, name?: string): string {
    return encryptLink(url, name ? { name } : {});
  }
}
```

## What this is

A small, dependency-free encoder for embedding subscription URLs in
chat messages and websites without exposing the raw URL to scanners,
moderation bots, or screenshots.

## What this is NOT

**This is not encryption-for-secrecy.** The AES-256-GCM key is derived
from constants and binary assets shipped inside this package — anyone
reading the source can reconstruct it.

The exact same key already lives inside every INCY client (iOS, Android,
Desktop). Anyone with a copy of those apps could already extract it
using standard mobile reverse-engineering tools. Publishing this
package reveals nothing new — it just makes the limitation explicit.

### Threat model

|                                              | Defended |
|----------------------------------------------|:--------:|
| Telegram chat moderation bots                |    ✅    |
| Russian regulator (RKN) automated scanners   |    ✅    |
| Casual screenshots and clipboard mishaps     |    ✅    |
| `grep` over chat dumps                       |    ✅    |
| Determined reverse engineer with Frida       |    ❌    |

If the key is ever published publicly (e.g. extracted and shared on
Twitter), a future INCY release will introduce `crypt2/` with a fresh
key. Existing `crypt1/` links in chat histories will keep working
forever — the clients never remove old schemes.

## API

```ts
// '@incy/link-encoder' — Node, synchronous
encryptLink(url: string, opts?: { name?: string }): string
decryptLink(link: string): { url: string; name?: string }

// '@incy/link-encoder/web' — browsers/workers/edge, Promise-based
encryptLink(url: string, opts?: { name?: string }): Promise<string>
decryptLink(link: string): Promise<{ url: string; name?: string }>

// For deterministic tests only — never reuse an IV with different
// plaintexts in production code.
encryptLinkDeterministic(url: string, opts: { iv: Uint8Array; name?: string }): string

// Runtime info
VERSION: string         // package version
SCHEME_VERSION: string  // current deep-link scheme, e.g. "crypt1"
KEY_FINGERPRINT: string // SHA-256 of K1 — for sanity checks

// Registry of every scheme this build understands (today: crypt1).
// A future key rotation adds crypt2 here without breaking callers.
SCHEMES: Record<string, { host: string; prefix: string; keyFingerprint: string }>
```

## Cross-platform compatibility

A link generated by this package decodes bit-for-bit identically on
iOS (CryptoKit), Android (`javax.crypto`), and Desktop (Compose
Multiplatform JVM, also `javax.crypto`). A test vector pinned in the
test suite guards against drift between updates.

## License

MIT
