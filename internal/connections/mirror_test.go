package connections

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/cgi"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// Mirror against a real smart-HTTP server (git http-backend): every branch
// and tag must restore from the bundle, and pull refs must not be included.
func TestMirrorBundleRestores(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("requires git")
	}
	root := t.TempDir()
	work := filepath.Join(root, "work")
	_ = os.MkdirAll(work, 0700)
	git(t, work, "init", "-q", "-b", "main")
	_ = os.WriteFile(filepath.Join(work, "a.txt"), []byte("one"), 0600)
	git(t, work, "add", ".")
	git(t, work, "commit", "-qm", "one")
	git(t, work, "tag", "-a", "v1.0", "-m", "release")
	git(t, work, "checkout", "-qb", "feature")
	_ = os.WriteFile(filepath.Join(work, "b.txt"), []byte("two"), 0600)
	git(t, work, "add", ".")
	git(t, work, "commit", "-qm", "two")
	feature := git(t, work, "rev-parse", "HEAD")
	git(t, work, "update-ref", "refs/pull/1/head", feature)
	served := filepath.Join(root, "org", "repo.git")
	git(t, root, "clone", "-q", "--mirror", work, served)
	gitPath, _ := exec.LookPath("git")
	server := httptest.NewServer(&cgi.Handler{Path: gitPath, Args: []string{"http-backend"}, Env: []string{"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1"}})
	defer server.Close()

	a := NativeAdapters{Client: server.Client(), GitHubGit: server.URL}
	c := Connection{Provider: "github", Enabled: true, Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: Scope{Include: []string{"org/*"}}}
	secret := json.RawMessage(`{"token":"synthetic"}`)
	if _, err := a.Mirror(context.Background(), c, secret, "other/repo", 1<<30, &bytes.Buffer{}); err == nil {
		t.Fatal("out-of-scope repository mirrored")
	}
	if _, err := a.Mirror(context.Background(), c, secret, "org/repo", 64, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "SCRS_MIRROR_MAX_BYTES") {
		t.Fatal("size limit not enforced", err)
	}
	var bundle bytes.Buffer
	info, err := a.Mirror(context.Background(), c, secret, "org/repo", 1<<30, &bundle)
	if err != nil {
		t.Fatal(err)
	}
	if info.Refs != 3 || info.Head == "" || bytes.Contains(bundle.Bytes(), []byte("refs/pull/")) {
		t.Fatalf("unexpected refs: %+v", info)
	}
	path := filepath.Join(root, "repo.bundle")
	_ = os.WriteFile(path, bundle.Bytes(), 0600)
	restored := filepath.Join(root, "restored")
	git(t, root, "clone", "-q", path, restored)
	git(t, restored, "bundle", "verify", path)
	if got := git(t, restored, "rev-parse", "origin/feature"); got != feature {
		t.Fatal("feature branch not restored", got)
	}
	if git(t, restored, "tag") != "v1.0" {
		t.Fatal("tag not restored")
	}
	// A corrupted pack must be rejected, not stored.
	if err := copyPack(&bytes.Buffer{}, bytes.NewReader(append([]byte("PACK"), bytes.Repeat([]byte{1}, 40)...)), 1<<20); err == nil {
		t.Fatal("corrupt pack accepted")
	}
}
