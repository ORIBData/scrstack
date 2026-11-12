# Pinned scanner toolchain

This separate module locks OSV-Scanner 2.7.1 and its dependency graph for the
single SCRS image. The root application does not import the scanner's libraries.
`make scanner-test` builds this graph and exercises actual offline matching.
The Dockerfile builds this same command for the requested Linux architecture.

Do not run `go mod tidy` here without preserving the command dependency: this
module has no local Go packages. Update dependencies deliberately, rebuild both
platforms, run scanner fixtures and vulnerability checks, and inspect the image
SBOM. Dependency overrides for x/net, x/crypto and compress follow the reviewed
runtime versions rather than the older upstream scanner defaults.
