# incy-link-encoder (Python)

Python port of [`@incy/link-encoder`](https://github.com/INCY-DEV/incy-link-encoder) —
encode VPN subscription URLs into `incy://crypt1/<payload>` deep links
that the INCY iOS, Android, and Desktop clients decode automatically.

Wire-compatible with the JS/PHP/Go ports and the client apps; a pinned
test vector guards against drift.

> **This is obfuscation, not security.** The AES-256-GCM key is derived
> from constants and asset bytes embedded in this package. See the
> [main README](../README.md) for the full threat model.

## Install

```bash
pip install incy-link-encoder
```

Requires Python ≥ 3.9 and [`cryptography`](https://pypi.org/project/cryptography/).

## Usage

```python
from incy_link_encoder import encrypt_link, decrypt_link

link = encrypt_link("https://sub.your-provider.example/abc123token", name="My Provider VPN")
print(link)
# → incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGK…

decoded = decrypt_link(link)
print(decoded.url, decoded.name)
```

## API

```python
encrypt_link(url: str, name: str | None = None) -> str
decrypt_link(link: str) -> DecryptedLink          # .url, .name
encrypt_link_deterministic(url: str, iv: bytes, name: str | None = None) -> str  # tests only

VERSION: str
SCHEME_VERSION: str   # "crypt1"
KEY_FINGERPRINT: str  # SHA-256 of K1
SCHEMES: dict[str, SchemeInfo]  # registry of known schemes (today: crypt1)
```

## Tests

```bash
python -m unittest discover -s tests -v
```
