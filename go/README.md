# incylink (Go)

Go port of [`@incy/link-encoder`](https://github.com/INCY-DEV/incy-link-encoder) —
encode VPN subscription URLs into `incy://crypt1/<payload>` deep links
that the INCY iOS, Android, and Desktop clients decode automatically.

Wire-compatible with the JS/Python/PHP ports and the client apps; a
pinned test vector guards against drift. Standard library only — no
dependencies.

> **This is obfuscation, not security.** The AES-256-GCM key is derived
> from constants and asset bytes embedded in this package. See the
> [main README](../README.md) for the full threat model.

## Install

```bash
go get github.com/INCY-DEV/incy-link-encoder/go
```

## Usage

```go
import incylink "github.com/INCY-DEV/incy-link-encoder/go"

link, err := incylink.EncryptLink("https://sub.your-provider.example/abc123token", "My Provider VPN")
// → incy://crypt1/AAECAwQFBgcICQoLNyIQL3rDwRZqnyoD8pGK…

decoded, err := incylink.DecryptLink(link)
fmt.Println(decoded.URL, decoded.Name)
```

## API

```go
func EncryptLink(url, name string) (string, error)                       // name "" for none
func DecryptLink(link string) (DecryptedLink, error)                     // .URL, .Name
func EncryptLinkDeterministic(url, name string, iv []byte) (string, error)  // tests only

const Version, SchemeVersion, KeyFingerprint
```

## Tests

```bash
go test ./...
```
