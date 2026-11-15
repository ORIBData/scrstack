# Pinned SAST toolchain

This separate module locks gosec 2.30.0 and govulncheck 1.9.0 and their
dependency graphs for the `scrs-sast` image (`deploy/Dockerfile.sast`). The
root application does not import them.

Do not run `go mod tidy` here: the module has no packages of its own, so tidy
would drop the command dependencies. Upgrade with
`go get github.com/securego/gosec/v2/cmd/gosec@<version> golang.org/x/vuln/cmd/govulncheck@<version>`.
