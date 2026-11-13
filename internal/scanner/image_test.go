package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// Live M6 path: SCRS_TEST_REGISTRY (a plain-HTTP registry holding
// library/alpine:3.19.1), SCRS_TEST_ALPINE_FEED (OSV Alpine all.zip) and the
// pinned scanner. scripts/test_images.sh provides all three.
func TestLiveImageArchiveAndScan(t *testing.T) {
	registry, feed, binary := os.Getenv("SCRS_TEST_REGISTRY"), os.Getenv("SCRS_TEST_ALPINE_FEED"), os.Getenv("SCRS_TEST_OSV_BINARY")
	if registry == "" || feed == "" || binary == "" {
		t.Skip("requires a local registry, the Alpine OSV feed and the pinned scanner")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if source := os.Getenv("SCRS_TEST_IMAGE_TAR"); source != "" {
		image, err := tarball.ImageFromPath(source, nil)
		if err != nil {
			t.Fatal(err)
		}
		ref, err := name.ParseReference(registry+"/library/alpine:3.19.1", name.Insecure)
		if err != nil {
			t.Fatal(err)
		}
		if err := remote.Write(ref, image, remote.WithContext(ctx)); err != nil {
			t.Fatal("push to test registry failed", err)
		}
	}
	adapters := connections.NewNativeAdapters()
	adapters.RegistryHost = registry
	c := connections.Connection{Provider: "dockerhub", Enabled: true, Config: json.RawMessage(`{"namespace":"library","identifier":"x"}`), Scope: connections.Scope{Include: []string{registry + "/library/*"}}}
	secret := json.RawMessage(`{"token":"unused"}`)
	locator := registry + "/library/alpine"
	if _, err := adapters.ImageArchive(ctx, c, secret, registry+"/other/image", "3.19.1", "", "linux/amd64", 1<<30, &bytes.Buffer{}); err == nil {
		t.Fatal("out-of-scope image pulled")
	}
	if _, err := adapters.ImageArchive(ctx, c, secret, locator, "3.19.1", "", "linux/amd64", 1024, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "SCRS_MAX_IMAGE_BYTES") {
		t.Fatal("size cap not enforced before download", err)
	}
	var archive bytes.Buffer
	digest, err := adapters.ImageArchive(ctx, c, secret, locator, "3.19.1", "", "linux/amd64", 64<<20, &archive)
	if err != nil || !strings.HasPrefix(digest, "sha256:") || archive.Len() < 1<<20 {
		t.Fatal("image not streamed", err, digest, archive.Len())
	}
	byDigest, err := adapters.ImageArchive(ctx, c, secret, locator, "", digest, "linux/amd64", 64<<20, &bytes.Buffer{})
	if err != nil || byDigest != digest {
		t.Fatal("digest pull not stable", err, byDigest)
	}
	db := t.TempDir()
	if err := os.MkdirAll(filepath.Join(db, "osv-scalibr", "Alpine"), 0755); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(feed)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(db, "osv-scalibr", "Alpine", "all.zip"), data, 0644)
	manifest, _ := json.Marshal(FeedManifest{FetchedAt: time.Now(), Ecosystems: []string{"Alpine"}})
	_ = os.WriteFile(filepath.Join(db, "manifest.json"), manifest, 0644)
	work := t.TempDir()
	path := filepath.Join(work, "image.tar")
	if err := os.WriteFile(path, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := Engine{Binary: binary, WorkRoot: work, Database: db}.RunImage(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	stages := map[string]string{}
	for _, s := range out.Stages {
		stages[s.Name] = s.Status
	}
	if stages["inventory"] != "ok" || stages["malware"] != "skipped" || len(out.Components) < 10 || len(out.Findings) == 0 || !json.Valid(out.SBOM) {
		t.Fatal("image inventory incomplete", stages, len(out.Components), len(out.Findings))
	}
	for _, c := range out.Components {
		if strings.HasPrefix(c.Path, "/") || strings.Contains(c.Path, "..") || !strings.HasPrefix(c.PURL, "pkg:apk/") {
			t.Fatal("unexpected image component", c)
		}
	}
	if bytes.Contains(out.SBOM, []byte(path)) {
		t.Fatal("SBOM leaked scanner work path")
	}
	t.Logf("image %s: %d packages, %d findings", digest, len(out.Components), len(out.Findings))
}
