"""incy-link-encoder — Python port of @incy/link-encoder.

Encode subscription URLs into ``incy://crypt1/<payload>`` deep links
that the INCY iOS/Android/Desktop clients know how to decode.

THIS IS OBFUSCATION, NOT SECURITY. The AES-256-GCM key is derived
from constants and asset bytes embedded in this package — anyone
reading the source can reconstruct it. See the README of the JS
package for the full threat model.

Wire format (identical across JS/Python/PHP/Go and the client apps):

    incy://crypt1/base64url( iv[12] || ciphertext || tag[16] )

where the plaintext is compact JSON with sorted keys, e.g.
``{"n":"Name","url":"https://...","v":1}``.
"""

from __future__ import annotations

import hashlib
import json
import os
from base64 import b64decode, urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._keymat import KEYMAT_A_B64, KEYMAT_B_B64

__all__ = [
    "DecryptedLink",
    "KEY_FINGERPRINT",
    "SCHEMES",
    "SCHEME_VERSION",
    "SchemeInfo",
    "VERSION",
    "decrypt_link",
    "encrypt_link",
    "encrypt_link_deterministic",
]

# Salt parts — concatenated in order and fed into the SHA-256 KDF.
# Split into four constants for the same greppability reasons as in
# the JS package and the client apps.
_SALT_P1 = "incy"
_SALT_P2 = "deep"
_SALT_P3 = "crypt1"
_SALT_P4 = "v2026.06"

_KEYMAT_A_OFFSET = 1024
_KEYMAT_B_OFFSET = 2048
_KEYMAT_LEN = 32

_EXPECTED_KEY_FINGERPRINT = (
    "b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c"
)

_SCHEME = "incy"
_HOST = "crypt1"
_LINK_PREFIX = f"{_SCHEME}://{_HOST}/"

_IV_LEN = 12
_TAG_LEN = 16

VERSION = "1.3.0"
SCHEME_VERSION = "crypt1"
KEY_FINGERPRINT = _EXPECTED_KEY_FINGERPRINT


@dataclass(frozen=True)
class SchemeInfo:
    """One deep-link scheme's identifying constants."""

    host: str
    prefix: str
    key_fingerprint: str


# Registry of every deep-link scheme this build understands (today only
# ``crypt1``). A future key rotation adds ``crypt2`` here while keeping
# ``crypt1`` so old links never stop decoding. Mirrors ``SCHEMES`` in
# the JS package.
SCHEMES: dict[str, SchemeInfo] = {
    "crypt1": SchemeInfo(
        host=_HOST,
        prefix=_LINK_PREFIX,
        key_fingerprint=_EXPECTED_KEY_FINGERPRINT,
    ),
}

_key_cache: bytes | None = None


def _derive_key() -> bytes:
    global _key_cache
    if _key_cache is not None:
        return _key_cache
    a = b64decode(KEYMAT_A_B64)
    b = b64decode(KEYMAT_B_B64)
    if len(a) < _KEYMAT_A_OFFSET + _KEYMAT_LEN or len(b) < _KEYMAT_B_OFFSET + _KEYMAT_LEN:
        raise ValueError("incy-link-encoder: keymat assets are smaller than expected")
    seed = (
        _SALT_P1.encode() + _SALT_P2.encode() + _SALT_P3.encode() + _SALT_P4.encode()
        + a[_KEYMAT_A_OFFSET : _KEYMAT_A_OFFSET + _KEYMAT_LEN]
        + b[_KEYMAT_B_OFFSET : _KEYMAT_B_OFFSET + _KEYMAT_LEN]
    )
    key = hashlib.sha256(seed).digest()
    fp = hashlib.sha256(key).hexdigest()
    if fp != _EXPECTED_KEY_FINGERPRINT:
        raise ValueError(
            "incy-link-encoder: derived K1 fingerprint mismatch "
            f"(expected {_EXPECTED_KEY_FINGERPRINT}, got {fp}) — keymat assets are out "
            "of sync with the published clients. Reinstall the package or report a bug."
        )
    _key_cache = key
    return key


def _b64url_encode(data: bytes) -> str:
    return urlsafe_b64encode(data).decode().rstrip("=")


def _b64url_decode(s: str) -> bytes:
    pad = "" if len(s) % 4 == 0 else "=" * (4 - len(s) % 4)
    return urlsafe_b64decode(s + pad)


def _build_plaintext(url: str, name: str | None) -> bytes:
    if not url or not isinstance(url, str):
        raise TypeError("encrypt_link: url must be a non-empty string")
    payload: dict[str, object] = {"url": url, "v": 1}
    if name:
        payload["n"] = name[:128]
    # Compact JSON with sorted keys — byte-for-byte identical to
    # JSON.stringify over sorted keys in the JS package and to the
    # sorted-keys serializers in the client apps.
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


@dataclass(frozen=True)
class DecryptedLink:
    """Result of decrypting an ``incy://crypt1/...`` link."""

    url: str
    name: str | None = None


def encrypt_link(url: str, name: str | None = None) -> str:
    """Encrypt a subscription URL into an ``incy://crypt1/<payload>`` link.

    ``name`` is an optional human-readable subscription name shown in
    the receiving app's import sheet (truncated to 128 chars).
    """
    plaintext = _build_plaintext(url, name)
    key = _derive_key()
    iv = os.urandom(_IV_LEN)
    out = AESGCM(key).encrypt(iv, plaintext, None)  # returns ct || tag
    return _LINK_PREFIX + _b64url_encode(iv + out)


def encrypt_link_deterministic(url: str, iv: bytes, name: str | None = None) -> str:
    """Same as :func:`encrypt_link` with a caller-provided IV.

    For test vectors only — never reuse an IV across different
    plaintexts in production; that breaks AES-GCM confidentiality.
    """
    if len(iv) != _IV_LEN:
        raise ValueError("encrypt_link_deterministic: iv must be 12 bytes")
    plaintext = _build_plaintext(url, name)
    key = _derive_key()
    out = AESGCM(key).encrypt(iv, plaintext, None)
    return _LINK_PREFIX + _b64url_encode(iv + out)


def decrypt_link(link: str) -> DecryptedLink:
    """Decrypt an ``incy://crypt1/<payload>`` link.

    Raises ``ValueError`` on malformed input or authentication failure
    (wrong key, tampered ciphertext).
    """
    if not link or not isinstance(link, str):
        raise TypeError("decrypt_link: link must be a non-empty string")
    if not link.startswith(_LINK_PREFIX):
        raise ValueError(f"decrypt_link: expected {_LINK_PREFIX} prefix")
    payload = link[len(_LINK_PREFIX):].rstrip("/")
    if not payload:
        raise ValueError("decrypt_link: empty payload")
    wire = _b64url_decode(payload)
    if len(wire) < _IV_LEN + _TAG_LEN + 1:
        raise ValueError("decrypt_link: payload too short")
    iv, ct_and_tag = wire[:_IV_LEN], wire[_IV_LEN:]

    key = _derive_key()
    try:
        plaintext = AESGCM(key).decrypt(iv, ct_and_tag, None)
    except InvalidTag:
        raise ValueError("decrypt_link: authentication failed") from None

    try:
        parsed = json.loads(plaintext.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        raise ValueError("decrypt_link: malformed plaintext") from None
    url = parsed.get("url") if isinstance(parsed, dict) else None
    if not isinstance(url, str) or not url:
        raise ValueError("decrypt_link: missing url field")
    name = parsed.get("n")
    return DecryptedLink(url=url, name=name if isinstance(name, str) and name else None)
