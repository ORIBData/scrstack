package scanner

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func archiveFor(t *testing.T, name string, kind byte, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	g := gzip.NewWriter(&b)
	tarWriter := tar.NewWriter(g)
	size := int64(len(body))
	if kind != tar.TypeReg {
		size = 0
	}
	if err := tarWriter.WriteHeader(&tar.Header{Name: name, Typeflag: kind, Size: size, Mode: 0600, Linkname: "/etc/passwd"}); err != nil {
		t.Fatal(err)
	}
	if size > 0 {
		_, _ = tarWriter.Write([]byte(body))
	}
	_ = tarWriter.Close()
	_ = g.Close()
	return b.Bytes()
}
func TestArchiveRejectsTraversalLinksAndDuplicates(t *testing.T) {
	for _, c := range []struct {
		name string
		kind byte
	}{{"root/../../escape", tar.TypeReg}, {"/absolute", tar.TypeReg}, {"root/link", tar.TypeSymlink}, {"root/hardlink", tar.TypeLink}, {"root/fifo", tar.TypeFifo}} {
		if err := Extract(archiveFor(t, c.name, c.kind, "data"), t.TempDir()); err == nil {
			t.Fatalf("accepted unsafe %s", c.name)
		}
	}
}
func TestOfflineOSVDetectsSyntheticVulnerability(t *testing.T) {
	binary := os.Getenv("SCRS_TEST_OSV_BINARY")
	if binary == "" {
		t.Skip("requires pinned OSV-Scanner binary")
	}
	db := t.TempDir()
	directory := filepath.Join(db, "osv-scalibr", "npm")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(filepath.Join(directory, "all.zip"))
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(file)
	entry, err := z.Create("GHSA-xxxx-yyyy-zzzz.json")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = entry.Write([]byte(`{"id":"GHSA-xxxx-yyyy-zzzz","modified":"2026-11-01T00:00:00Z","published":"2026-11-01T00:00:00Z","summary":"Synthetic critical advisory","database_specific":{"severity":"CRITICAL"},"affected":[{"package":{"name":"bad-package","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"1.0.1"}]}]}]}`))
	_ = z.Close()
	_ = file.Close()
	manifest, _ := json.Marshal(FeedManifest{FetchedAt: time.Now(), Ecosystems: []string{"npm"}})
	if err := os.WriteFile(filepath.Join(db, "manifest.json"), manifest, 0644); err != nil {
		t.Fatal(err)
	}
	lock := `{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0"},"node_modules/bad-package":{"version":"1.0.0","resolved":"https://registry.npmjs.org/bad-package/-/bad-package-1.0.0.tgz"}}}`
	engine := Engine{Binary: binary, WorkRoot: t.TempDir(), Database: db}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var input bytes.Buffer
	gz := gzip.NewWriter(&input)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"root/package-lock.json": lock, "root/osv-scanner.toml": "[[IgnoredVulns]]\nid = \"GHSA-xxxx-yyyy-zzzz\"\n", "root/.gitignore": "package-lock.json\n"} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Size: int64(len(body)), Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	result, err := engine.Run(ctx, input.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Severity != "critical" || !json.Valid(result.SBOM) {
		t.Fatalf("unexpected result: components=%d findings=%v", len(result.Components), result.Findings)
	}
	var sbom struct {
		Format  string `json:"bomFormat"`
		Version string `json:"specVersion"`
	}
	if json.Unmarshal(result.SBOM, &sbom) != nil || sbom.Format != "CycloneDX" || sbom.Version != "1.6" {
		t.Fatal("invalid CycloneDX output")
	}
}

func TestScannerAuthenticationAndProxyDeny(t *testing.T) {
	token := strings.Repeat("x", 40)
	h := (Engine{}).Handler(token)
	r := httptest.NewRequest("POST", "/scan", strings.NewReader("untrusted"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("unauthorized scan: %d", w.Code)
	}
	for _, target := range []string{"evil.example:443", "127.0.0.1:443", "api.deps.dev:80", "api.deps.dev.evil.example:443"} {
		r := httptest.NewRequest("CONNECT", "http://"+target, nil)
		r.Host = target
		w := httptest.NewRecorder()
		EgressProxy().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("accepted destination %s", target)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "::ffff:192.168.1.1"} {
		if publicAddress(netip.MustParseAddr(ip)) {
			t.Fatalf("accepted nonpublic %s", ip)
		}
	}
}
func TestFeedFreshness(t *testing.T) {
	for _, fetched := range []time.Time{time.Now().Add(-25 * time.Hour), time.Now().Add(time.Hour)} {
		root := t.TempDir()
		data, _ := json.Marshal(FeedManifest{FetchedAt: fetched, Ecosystems: []string{"npm"}})
		if err := os.WriteFile(filepath.Join(root, "manifest.json"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := pinnedFeed(root); err == nil {
			t.Fatal("invalid feed freshness accepted")
		}
	}
}
func TestScannerProgressPathsAreNotProblems(t *testing.T) {
	benign := "Scanning dir /work/scrs-scan-1/checkout\nScanned /work/scrs-scan-1/checkout/packages/error-pages/package-lock.json file and found 12 packages\nScanned /work/x/warnings/go.mod file and found 1 package\n"
	if reportsProblem(benign) {
		t.Fatal("repository path text treated as scanner problem")
	}
	for _, bad := range []string{benign + "Error during extraction of yarn.lock\n", "Warning: lockfile could not be parsed\n"} {
		if !reportsProblem(bad) {
			t.Fatalf("scanner problem ignored: %q", bad)
		}
	}
}

// SCRS_TEST_OSV_FEED_ZIP points at a downloaded ecosystem all.zip, e.g. npm's,
// which outgrew the original 200k-entry cap.
func TestRealFeedArchiveValidates(t *testing.T) {
	archive := os.Getenv("SCRS_TEST_OSV_FEED_ZIP")
	if archive == "" {
		t.Skip("set SCRS_TEST_OSV_FEED_ZIP to a downloaded OSV all.zip")
	}
	if err := validateFeed(archive); err != nil {
		t.Fatal(err)
	}
}
