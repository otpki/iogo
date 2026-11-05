# Contributing

Pull requests to `otpki/iogo` target `main`, the standalone library branch.
Discuss substantial cryptographic or public API changes in an issue before
starting. Keep changes focused and include a summary and test plan in the PR.

Use Go 1.27 or newer. Before submitting, run:

```sh
go vet ./...
go test -short -timeout 5m ./...
go test -timeout 5m ./...
```

The Just equivalents are `just lint`, `just test-ci`, and `just test`.
Format changed Go files with `gofmt`. Add tests for changed behavior;
cryptographic changes should include relevant specifications and test vectors.
Describe public API, certificate encoding, and compatibility changes in the PR.
Use synthetic keys and certificates in reproductions and test fixtures.

CI runs short tests and vet on Linux, macOS, and Windows. The module and its
dependencies build without private GitHub credentials or a custom Go toolchain.

## Upstream and licensing

Keep Go's copyright headers and BSD-style license notices when modifying or
copying Go source. Preserve `LICENSE`, `PATENTS`, and applicable third-party
notices. Contributions follow the repository's existing BSD-style license
unless a file specifies otherwise.

For changes that also belong in Go, follow
[Go's contribution guidelines](https://go.dev/doc/contribute) and prepare a
separate upstream change. Fork-specific APIs and CIRCL integration stay here.

Report suspected vulnerabilities privately as described in
[SECURITY.md](SECURITY.md), not through public issues or PRs.
