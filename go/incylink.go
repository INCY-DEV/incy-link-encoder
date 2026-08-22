// Package incylink is the Go port of @incy/link-encoder.
//
// It encodes subscription URLs into incy://crypt1/<payload> deep
// links that the INCY iOS/Android/Desktop clients know how to decode.
//
// THIS IS OBFUSCATION, NOT SECURITY. The AES-256-GCM key is derived
// from constants and asset bytes embedded in this package — anyone
// reading the source can reconstruct it. See the README of the JS
// package for the full threat model.
//
// Wire format (identical across JS/Python/PHP/Go and the client apps):
//
//	incy://crypt1/base64url( iv[12] || ciphertext || tag[16] )
//
// where the plaintext is compact JSON with sorted keys, e.g.
// {"n":"Name","url":"https://...","v":1}.
package incylink

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Salt parts — concatenated in order and fed into the SHA-256 KDF.
// Split into four constants for the same greppability reasons as in
// the JS package and the client apps.
const (
	saltP1 = "incy"
	saltP2 = "deep"
	saltP3 = "crypt1"
	saltP4 = "v2026.06"
)

const (
	keymatAOffset = 1024
	keymatBOffset = 2048
	keymatLen     = 32
)

const expectedKeyFingerprint = "b6bf708471cc90043232967660aade86a50b4e57929db2e53c5fa34db624c08c"

const (
	scheme     = "incy"
	host       = "crypt1"
	linkPrefix = scheme + "://" + host + "/"
)

const (
	ivLen  = 12
	tagLen = 16
)

// Runtime info — mirrors VERSION / SCHEME_VERSION / KEY_FINGERPRINT
// in the JS package.
const (
	Version        = "1.2.0"
	SchemeVersion  = "crypt1"
	KeyFingerprint = expectedKeyFingerprint
)

// DecryptedLink is the result of decrypting an incy://crypt1/... link.
type DecryptedLink struct {
	// URL is the embedded subscription URL.
	URL string
	// Name is the optional human-readable name supplied at encrypt
	// time ("" if absent).
	Name string
}

var deriveKey = sync.OnceValues(func() ([]byte, error) {
	a, err := base64.StdEncoding.DecodeString(keymatAB64)
	if err != nil {
		return nil, fmt.Errorf("incy-link-encoder: bad keymat A: %w", err)
	}
	b, err := base64.StdEncoding.DecodeString(keymatBB64)
	if err != nil {
		return nil, fmt.Errorf("incy-link-encoder: bad keymat B: %w", err)
	}
	if len(a) < keymatAOffset+keymatLen || len(b) < keymatBOffset+keymatLen {
		return nil, errors.New("incy-link-encoder: keymat assets are smaller than expected")
	}
	var seed bytes.Buffer
	seed.WriteString(saltP1)
	seed.WriteString(saltP2)
	seed.WriteString(saltP3)
	seed.WriteString(saltP4)
	seed.Write(a[keymatAOffset : keymatAOffset+keymatLen])
	seed.Write(b[keymatBOffset : keymatBOffset+keymatLen])
	key := sha256.Sum256(seed.Bytes())
	fp := sha256.Sum256(key[:])
	if got := hex.EncodeToString(fp[:]); got != expectedKeyFingerprint {
		return nil, fmt.Errorf(
			"incy-link-encoder: derived K1 fingerprint mismatch (expected %s, got %s) — "+
				"keymat assets are out of sync with the published clients",
			expectedKeyFingerprint, got)
	}
	return key[:], nil
})

func newGCM() (cipher.AEAD, error) {
	key, err := deriveKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// buildPlaintext serializes the payload as compact JSON with sorted
// keys — byte-for-byte identical to JSON.stringify over sorted keys
// in the JS package. encoding/json sorts map keys and, with
// SetEscapeHTML(false), matches JS escaping for URLs containing
// &, <, > (JS does not HTML-escape).
func buildPlaintext(url, name string) ([]byte, error) {
	if url == "" {
		return nil, errors.New("EncryptLink: url must be a non-empty string")
	}
	payload := map[string]any{"url": url, "v": 1}
	if name != "" {
		if r := []rune(name); len(r) > 128 {
			name = string(r[:128])
		}
		payload["n"] = name
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

func b64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func b64urlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func seal(plaintext, iv []byte) (string, error) {
	gcm, err := newGCM()
	if err != nil {
		return "", err
	}
	wire := make([]byte, 0, ivLen+len(plaintext)+tagLen)
	wire = append(wire, iv...)
	wire = gcm.Seal(wire, iv, plaintext, nil) // appends ct || tag after the IV
	return linkPrefix + b64urlEncode(wire), nil
}

// EncryptLink encrypts a subscription URL into an
// incy://crypt1/<payload> deep-link string. name is an optional
// human-readable subscription name shown in the receiving app's
// import sheet ("" for none; truncated to 128 chars).
func EncryptLink(url, name string) (string, error) {
	plaintext, err := buildPlaintext(url, name)
	if err != nil {
		return "", err
	}
	iv := make([]byte, ivLen)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	return seal(plaintext, iv)
}

// EncryptLinkDeterministic is EncryptLink with a caller-provided IV.
// For test vectors only — never reuse an IV across different
// plaintexts in production; that breaks AES-GCM confidentiality.
func EncryptLinkDeterministic(url, name string, iv []byte) (string, error) {
	if len(iv) != ivLen {
		return "", errors.New("EncryptLinkDeterministic: iv must be 12 bytes")
	}
	plaintext, err := buildPlaintext(url, name)
	if err != nil {
		return "", err
	}
	return seal(plaintext, iv)
}

// DecryptLink decrypts an incy://crypt1/<payload> link back to its
// subscription URL and optional name. It returns an error on
// malformed input or authentication failure (wrong key, tampered
// ciphertext).
func DecryptLink(link string) (DecryptedLink, error) {
	var zero DecryptedLink
	if len(link) <= len(linkPrefix) || link[:len(linkPrefix)] != linkPrefix {
		return zero, fmt.Errorf("DecryptLink: expected %s prefix", linkPrefix)
	}
	payload := bytes.TrimRight([]byte(link[len(linkPrefix):]), "/")
	if len(payload) == 0 {
		return zero, errors.New("DecryptLink: empty payload")
	}
	wire, err := b64urlDecode(string(payload))
	if err != nil {
		return zero, fmt.Errorf("DecryptLink: bad base64url payload: %w", err)
	}
	if len(wire) < ivLen+tagLen+1 {
		return zero, errors.New("DecryptLink: payload too short")
	}

	gcm, err := newGCM()
	if err != nil {
		return zero, err
	}
	plaintext, err := gcm.Open(nil, wire[:ivLen], wire[ivLen:], nil)
	if err != nil {
		return zero, errors.New("DecryptLink: authentication failed")
	}

	var parsed struct {
		URL  string `json:"url"`
		Name string `json:"n"`
	}
	if err := json.Unmarshal(plaintext, &parsed); err != nil {
		return zero, errors.New("DecryptLink: malformed plaintext")
	}
	if parsed.URL == "" {
		return zero, errors.New("DecryptLink: missing url field")
	}
	return DecryptedLink{URL: parsed.URL, Name: parsed.Name}, nil
}
