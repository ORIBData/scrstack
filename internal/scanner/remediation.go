package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Remediate operates only on a disposable copy. The sandbox has no shell,
// package manager or provider credentials and its network is proxy-allowlisted.
func (e Engine) Remediate(ctx context.Context, archive []byte, manifest, strategy string) (json.RawMessage, error) {
	if !e.RemediationEnabled || e.RemediationProxy == "" {
		return nil, errors.New("remediation sandbox disabled")
	}
	if strategy != "in-place" || !filepath.IsLocal(manifest) || strings.Contains(manifest, "\\") || filepath.Base(manifest) != "package-lock.json" {
		return nil, errors.New("unsupported remediation manifest or strategy")
	}
	database, err := pinnedFeed(e.Database)
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp(e.WorkRoot, "scrs-plan-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(directory)
	checkout := filepath.Join(directory, "checkout")
	if err := os.Mkdir(checkout, 0700); err != nil {
		return nil, err
	}
	if err := Extract(archive, checkout); err != nil {
		return nil, err
	}
	target := filepath.Join(checkout, filepath.FromSlash(manifest))
	info, err := os.Stat(target)
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("remediation lockfile unavailable")
	}
	command := exec.CommandContext(ctx, e.Binary, "fix", "--strategy=in-place", "--format=json", "--no-introduce", "--offline-vulnerabilities", "--lockfile", target)
	command.Dir = directory
	command.Env = []string{"HOME=" + directory, "TMPDIR=" + directory, "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=" + database, "HTTPS_PROXY=" + e.RemediationProxy, "HTTP_PROXY=" + e.RemediationProxy, "npm_config_ignore_scripts=true", "NO_COLOR=1"}
	stdout := &cappedBuffer{limit: 8 << 20}
	stderr := &cappedBuffer{limit: 1 << 20}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return nil, errors.New("guided remediation failed")
	}
	if !json.Valid(stdout.Bytes()) {
		return nil, errors.New("invalid remediation output")
	}
	return json.RawMessage(strings.ReplaceAll(stdout.String(), checkout+string(os.PathSeparator), "")), nil
}
