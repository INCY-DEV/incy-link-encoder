package incylink

import (
	"encoding/hex"
	"strings"
	"testing"
)

const pinnedVector = "incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGKSLXP6o8NdSXQVSSALNbbUyIr__tWGFUexdIfKvvmDnuDGbmBvuppfNef6aKNZUwOm4c-Sg"

func TestKeyFingerprintMatchesCrossPlatformConstant(t *testing.T) {
	if KeyFingerprint != "b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c" {
		t.Fatalf("fingerprint drifted: %s", KeyFingerprint)
	}
	if SchemeVersion != "crypt1" {
		t.Fatalf("scheme version drifted: %s", SchemeVersion)
	}
}

func TestRoundTrip(t *testing.T) {
	url := "https://sub.example.com/test-token"
	link, err := EncryptLink(url, "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(link, "incy://crypt1/") {
		t.Fatalf("bad prefix: %s", link)
	}
	dec, err := DecryptLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if dec.URL != url || dec.Name != "" {
		t.Fatalf("round-trip mismatch: %+v", dec)
	}
}

func TestRoundTripWithName(t *testing.T) {
	url, name := "https://sub.example.com/abc", "MyProvider VPN"
	link, err := EncryptLink(url, name)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if dec.URL != url || dec.Name != name {
		t.Fatalf("round-trip mismatch: %+v", dec)
	}
}

func TestDeterministicVectorMatchesCrossPlatformReference(t *testing.T) {
	iv, _ := hex.DecodeString("000102030405060708090a0b")
	link, err := EncryptLinkDeterministic("https://sub.example.com/test-vector", "", iv)
	if err != nil {
		t.Fatal(err)
	}
	if link != pinnedVector {
		t.Fatalf("wire drift:\n got %s\nwant %s", link, pinnedVector)
	}
}

func TestUniqueCiphertextPerCall(t *testing.T) {
	url := "https://test.example/abc"
	a, _ := EncryptLink(url, "")
	b, _ := EncryptLink(url, "")
	if a == b {
		t.Fatal("two encryptions produced identical wire bytes")
	}
}

func TestRejectsTamperedPayload(t *testing.T) {
	link, _ := EncryptLink("https://test.example/x", "")
	i := len(link) - 10
	flip := byte('A')
	if link[i] == 'A' {
		flip = 'B'
	}
	tampered := link[:i] + string(flip) + link[i+1:]
	if _, err := DecryptLink(tampered); err == nil {
		t.Fatal("tampered payload accepted")
	}
}

func TestRejectsNonCrypt1Prefix(t *testing.T) {
	for _, bad := range []string{"https://incy.cc/foo", "incy://add/https%3A%2F%2Ffoo.bar", ""} {
		if _, err := DecryptLink(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestRejectsEmptyURL(t *testing.T) {
	if _, err := EncryptLink("", ""); err == nil {
		t.Fatal("empty url accepted")
	}
}

func TestRejectsWrongIVLength(t *testing.T) {
	if _, err := EncryptLinkDeterministic("https://test/x", "", make([]byte, 11)); err == nil {
		t.Fatal("11-byte IV accepted")
	}
}

func TestNameTruncatedTo128Chars(t *testing.T) {
	link, _ := EncryptLink("https://test/x", strings.Repeat("X", 500))
	dec, err := DecryptLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Name) != 128 {
		t.Fatalf("name length = %d, want 128", len(dec.Name))
	}
}

// URLs with query params exercise SetEscapeHTML(false) — Go must not
// emit & where JS writes a literal &.
func TestQueryParamURLRoundTrip(t *testing.T) {
	url := "https://sub.example.com/get?token=abc&format=v2ray"
	link, err := EncryptLink(url, "")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptLink(link)
	if err != nil {
		t.Fatal(err)
	}
	if dec.URL != url {
		t.Fatalf("url mangled: %s", dec.URL)
	}
}
