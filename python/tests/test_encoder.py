"""Tests for the Python port. Mirrors test/index.test.ts, including
the pinned cross-platform test vector that guards wire compatibility
with the JS package and the iOS/Android/Desktop clients."""

import unittest

from incy_link_encoder import (
    KEY_FINGERPRINT,
    SCHEMES,
    SCHEME_VERSION,
    VERSION,
    decrypt_link,
    encrypt_link,
    encrypt_link_deterministic,
)

PINNED_FINGERPRINT = "b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c"
PINNED_VECTOR = (
    "incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGKSLXP6o8NdSXQVSSALNbbUyIr"
    "__tWGFUexdIfKvvmDnuDGbmBvuppfNef6aKNZUwOm4c-Sg"
)


class LinkEncoderTest(unittest.TestCase):
    def test_key_fingerprint_matches_cross_platform_constant(self):
        self.assertEqual(KEY_FINGERPRINT, PINNED_FINGERPRINT)
        self.assertEqual(SCHEME_VERSION, "crypt1")

    def test_round_trip(self):
        url = "https://sub.example.com/test-token"
        link = encrypt_link(url)
        self.assertTrue(link.startswith("incy://crypt1/"))
        decoded = decrypt_link(link)
        self.assertEqual(decoded.url, url)
        self.assertIsNone(decoded.name)

    def test_round_trip_with_name(self):
        url = "https://sub.example.com/abc"
        name = "MyProvider VPN"
        decoded = decrypt_link(encrypt_link(url, name=name))
        self.assertEqual(decoded.url, url)
        self.assertEqual(decoded.name, name)

    def test_deterministic_vector_matches_cross_platform_reference(self):
        iv = bytes.fromhex("000102030405060708090a0b")
        link = encrypt_link_deterministic("https://sub.example.com/test-vector", iv)
        self.assertEqual(link, PINNED_VECTOR)

    def test_unique_ciphertext_per_call(self):
        url = "https://test.example/abc"
        a, b = encrypt_link(url), encrypt_link(url)
        self.assertNotEqual(a, b)
        self.assertEqual(decrypt_link(a).url, url)
        self.assertEqual(decrypt_link(b).url, url)

    def test_rejects_tampered_payload(self):
        link = encrypt_link("https://test.example/x")
        flip = "B" if link[-10] == "A" else "A"
        tampered = link[:-10] + flip + link[-9:]
        with self.assertRaises(ValueError):
            decrypt_link(tampered)

    def test_rejects_non_crypt1_prefix(self):
        for bad in ("https://incy.cc/foo", "incy://add/https%3A%2F%2Ffoo.bar"):
            with self.assertRaises(ValueError):
                decrypt_link(bad)
        with self.assertRaises(TypeError):
            decrypt_link("")

    def test_rejects_empty_input(self):
        with self.assertRaises(TypeError):
            encrypt_link("")
        with self.assertRaises(TypeError):
            encrypt_link(None)  # type: ignore[arg-type]

    def test_rejects_wrong_iv_length(self):
        with self.assertRaises(ValueError):
            encrypt_link_deterministic("https://test/x", b"\x00" * 11)

    def test_name_truncated_to_128_chars(self):
        decoded = decrypt_link(encrypt_link("https://test/x", name="X" * 500))
        assert decoded.name is not None
        self.assertEqual(len(decoded.name), 128)

    def test_schemes_registry_describes_crypt1(self):
        self.assertEqual(list(SCHEMES.keys()), ["crypt1"])
        self.assertEqual(SCHEMES["crypt1"].host, "crypt1")
        self.assertEqual(SCHEMES["crypt1"].prefix, "incy://crypt1/")
        self.assertEqual(SCHEMES["crypt1"].key_fingerprint, KEY_FINGERPRINT)

    def test_version_is_current(self):
        self.assertEqual(VERSION, "1.3.0")


if __name__ == "__main__":
    unittest.main()
