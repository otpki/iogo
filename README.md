# IoGo (yoh-goh)

![IoGo Mascot](misc/gopher.png "Our mascot")

IOGO is OTPKI's fork of Go's `crypto/x509` library, with additional
post-quantum signature schemes, elliptic curves, hash algorithms, and X.509
functionality. Cryptographic implementations are provided in part by
[OTPKI's CIRCL fork](https://github.com/otpki/circl).

The `main` branch is a standalone Go module. It works with the standard Go
toolchain; installing a custom Go compiler is not required.

## Requirements and installation

Use Go 1.27 or newer:

```sh
go get github.com/otpki/iogo@main
```

Applications should pin a reviewed version or commit in `go.mod`.
Import the fork explicitly, for example:

```go
import "github.com/otpki/iogo/crypto/x509"
```

This import does not replace the standard library's `crypto/x509` or change
the certificate handling used by `crypto/tls`.

| Package | Purpose |
| --- | --- |
| `crypto/x509` | Certificate, CSR, CRL, and key parsing, generation, and verification |
| `crypto` | Additional hash identifiers and interfaces |
| `crypto/circl/...` | CIRCL signature scheme and curve adapters |
| `crypto/rsa` | RSA-PSS helpers |
| `crypto/signer` | Signer adapters |

## Development

```sh
git clone https://github.com/otpki/iogo.git
cd iogo
git switch main
go test -short -timeout 5m ./...
go vet ./...
```

With [Just](https://github.com/casey/just) installed, use `just test-ci`,
`just test`, and `just lint`. CI runs short tests and vet on Linux, macOS,
and Windows. See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution workflow
and [SECURITY.md](SECURITY.md) for private vulnerability reporting.

The library retains the relevant upstream Go history beneath the IOGO changes.
See [UPSTREAM.md](UPSTREAM.md) for provenance and the Go update procedure.

## License and attribution

This library derives from [the Go project](https://go.googlesource.com/go).
The Go Authors' BSD-style [LICENSE](LICENSE), copyright notices, and
[PATENTS](PATENTS) grant are retained. This fork is maintained by OTPKI and is
not an official Go release. See [NOTICE](NOTICE) for provenance and
third-party attribution.
