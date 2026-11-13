package scanner

import (
	"bufio"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

//go:embed rules/scrs.yar
var rules []byte

// RulesVersion identifies the embedded ruleset in stage details and audit.
var RulesVersion = func() string { sum := sha256.Sum256(rules); return hex.EncodeToString(sum[:])[:12] }()

// InstallRules writes the embedded ruleset into ClamAV's database directory
// atomically. clamd loads *.yar files from there and its SelfCheck reload
// picks up changes; the scanner's canary then confirms the rules are live.
func InstallRules(directory string) error {
	info, err := os.Stat(directory)
	if err != nil || !info.IsDir() {
		return errors.New("ClamAV database directory unavailable")
	}
	temporary, err := os.CreateTemp(directory, ".scrs-yara-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(rules); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0644); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), filepath.Join(directory, "scrs.yar"))
}

// ReloadClamd asks clamd to reload its databases so new rules apply now
// rather than at the next SelfCheck interval.
func ReloadClamd(ctx context.Context, address string) error {
	conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err := io.WriteString(conn, "zRELOAD\x00"); err != nil {
		return err
	}
	reply, err := bufio.NewReader(io.LimitReader(conn, 256)).ReadString(0)
	if err != nil || !strings.HasPrefix(reply, "RELOADING") {
		return errors.New("clamd did not accept reload")
	}
	return nil
}
