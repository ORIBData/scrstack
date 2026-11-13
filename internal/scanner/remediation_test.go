package scanner

import (
	"archive/tar"
	"archive/zip"
	"context"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpstreamRemediationEmptyPlan(t *testing.T) { testRemediationFixture(t, false) }
func TestUpstreamRemediationVulnerablePackage(t *testing.T) {
	if os.Getenv("SCRS_TEST_LIVE_REMEDIATION") != "1" {
		t.Skip("requires public deps.dev access")
	}
	testRemediationFixture(t, true)
}
func testRemediationFixture(t *testing.T, vulnerable bool) {
	binary := os.Getenv("SCRS_TEST_OSV_BINARY")
	if binary == "" {
		t.Skip("requires pinned scanner")
	}
	db := t.TempDir()
	directory := filepath.Join(db, "osv-scalibr", "npm")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(directory, "all.zip"))
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	entry, err := z.Create("SYNTHETIC-1.json")
	if err != nil {
		t.Fatal(err)
	}
	advisory := `{"id":"SYNTHETIC-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"unrelated","ecosystem":"npm"},"versions":["1.0.0"]}]}`
	if vulnerable {
		advisory = `{"id":"SYNTHETIC-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.21"}]}]}]}`
	}
	_, _ = entry.Write([]byte(advisory))
	_ = z.Close()
	_ = f.Close()
	manifest, _ := json.Marshal(FeedManifest{FetchedAt: time.Now(), Ecosystems: []string{"npm"}})
	if err := os.WriteFile(filepath.Join(db, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(EgressProxy())
	defer proxy.Close()
	engine := Engine{Binary: binary, WorkRoot: t.TempDir(), Database: db, RemediationEnabled: true, RemediationProxy: proxy.URL}
	lock := `{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0"}}}`
	if vulnerable {
		lock = `{"name":"fixture","version":"1.0.0","lockfileVersion":3,"packages":{"":{"name":"fixture","version":"1.0.0","dependencies":{"lodash":"^4.17.20"}},"node_modules/lodash":{"version":"4.17.20","resolved":"https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz"}}}`
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	plan, err := engine.Remediate(ctx, archiveFor(t, "root/package-lock.json", tar.TypeReg, lock), "package-lock.json", "in-place")
	if err != nil {
		t.Fatal(err)
	}
	if vulnerable && (!strings.Contains(string(plan), "versionTo") || !strings.Contains(string(plan), "SYNTHETIC-1")) {
		t.Fatalf("expected upstream patch: %s", plan)
	}
	if !json.Valid(plan) {
		t.Fatal("invalid upstream plan")
	}
}

// Live: Maven override plan through the egress proxy (deps.dev, Maven Central).
func TestUpstreamRemediationMaven(t *testing.T) {
	if os.Getenv("SCRS_TEST_LIVE_REMEDIATION") != "1" {
		t.Skip("requires public deps.dev and Maven Central access")
	}
	binary := os.Getenv("SCRS_TEST_OSV_BINARY")
	if binary == "" {
		t.Skip("requires pinned scanner")
	}
	db := t.TempDir()
	directory := filepath.Join(db, "osv-scalibr", "Maven")
	if err := os.MkdirAll(directory, 0755); err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(directory, "all.zip"))
	if err != nil {
		t.Fatal(err)
	}
	z := zip.NewWriter(f)
	entry, _ := z.Create("SYNTHETIC-MVN-1.json")
	_, _ = entry.Write([]byte(`{"id":"SYNTHETIC-MVN-1","modified":"2026-11-01T00:00:00Z","affected":[{"package":{"name":"org.apache.logging.log4j:log4j-core","ecosystem":"Maven"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.17.1"}]}]}]}`))
	_ = z.Close()
	_ = f.Close()
	manifest, _ := json.Marshal(FeedManifest{FetchedAt: time.Now(), Ecosystems: []string{"Maven"}})
	if err := os.WriteFile(filepath.Join(db, "manifest.json"), manifest, 0600); err != nil {
		t.Fatal(err)
	}
	proxy := httptest.NewServer(EgressProxy())
	defer proxy.Close()
	engine := Engine{Binary: binary, WorkRoot: t.TempDir(), Database: db, RemediationEnabled: true, RemediationProxy: proxy.URL}
	pom := `<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion><groupId>com.example</groupId><artifactId>fixture</artifactId><version>1.0.0</version><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>`
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if _, err := engine.Remediate(ctx, archiveFor(t, "root/pom.xml", tar.TypeReg, pom), "pom.xml", "in-place"); err == nil {
		t.Fatal("unsupported Maven strategy accepted")
	}
	plan, err := engine.Remediate(ctx, archiveFor(t, "root/pom.xml", tar.TypeReg, pom), "pom.xml", "override")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(plan) || !strings.Contains(string(plan), "SYNTHETIC-MVN-1") || !strings.Contains(string(plan), "log4j-core") {
		t.Fatalf("expected Maven override plan: %s", plan)
	}
}
