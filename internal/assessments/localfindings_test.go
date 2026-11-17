package assessments_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/semver"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A local advisory opens register entries for the components it names, at
// creation from the stored inventories and at every later scan, closes them
// when the component is fixed or the advisory withdrawn, and a malicious one
// fails the gate.
func TestPostgresLocalAdvisoriesOpenRegisterEntries(t *testing.T) {
	url := os.Getenv("SCRS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: url, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	providers, err := connections.Open(ctx, url, schema, base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	defer providers.Close()
	c := connections.Connection{Name: "github", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := providers.Put(ctx, c, json.RawMessage(`{"token":"synthetic"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := providers.Discover(ctx, c.Name, inventory{}); err != nil {
		t.Fatal(err)
	}
	s, err := assessments.Open(ctx, url, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	npm := func(name, version string) assessments.Component {
		return assessments.Component{Name: name, Version: version, Ecosystem: "npm", PURL: "pkg:npm/" + name + "@" + version, Path: "package-lock.json"}
	}
	pypi := assessments.Component{Name: "Some_Lib", Version: "1.0", Ecosystem: "PyPI", PURL: "pkg:pypi/some-lib@1.0", Path: "requirements.txt"}
	run := 0
	scan := func(components ...assessments.Component) assessments.Assessment {
		t.Helper()
		run++
		request := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}
		if _, _, err := s.Enqueue(ctx, request, uuid.New(), "tester", "local-"+string(rune('a'+run))); err != nil {
			t.Fatal(err)
		}
		a, err := s.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		stages := []assessments.Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}, {Name: "inventory", Status: "ok"}, {Name: "sbom", Status: "ok"}, {Name: "match_vuln", Status: "ok"}, {Name: "match_malicious", Status: "ok"}}
		if err := s.Complete(ctx, a, assessments.Result{Commit: strings.Repeat(string(rune('a'+run)), 40), Stages: stages, Components: components}); err != nil {
			t.Fatal(err)
		}
		done, err := s.Get(ctx, a.ID)
		if err != nil {
			t.Fatal(err)
		}
		return done
	}
	// entries maps advisory id to "type:severity:status" for entries of local advisories.
	entries := func() map[string]string {
		t.Helper()
		items, err := s.FindingsFiltered(ctx, assessments.RegisterFilter{}, uuid.Nil)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]string{}
		for _, f := range items {
			if strings.HasPrefix(f.AdvisoryID, "x_SCRS-") {
				out[f.AdvisoryID+"/"+f.Component.Name] = f.Type + ":" + f.Severity + ":" + f.Status
			}
		}
		return out
	}
	opened := func(record json.RawMessage) (string, int) {
		var doc struct {
			ID     string `json:"id"`
			Opened int    `json:"register_entries_opened"`
		}
		if err := json.Unmarshal(record, &doc); err != nil {
			t.Fatal(err)
		}
		return doc.ID, doc.Opened
	}
	local := func(summary string, malicious bool, rating string, affected ...assessments.LocalAffected) assessments.LocalAdvisoryInput {
		return assessments.LocalAdvisoryInput{Summary: summary, Affected: affected, Malicious: malicious, Rating: rating}
	}

	first := scan(npm("left", "1.1.0"), npm("right", "2.5.0"), npm("steady", "3.0.0"), pypi)
	if first.Verdict == "fail" {
		t.Fatalf("nothing is wrong yet: %s", first.Verdict)
	}

	// Inputs: ranges only where versions order semantically, valid and bounded; ratings known.
	for name, bad := range map[string]assessments.LocalAdvisoryInput{
		"pypi range":    local("pypi range", false, "", assessments.LocalAffected{Package: assessments.LocalPackage{Ecosystem: "PyPI", Name: "x"}, Ranges: []semver.Range{{Introduced: "1.0", Fixed: "2.0"}}}),
		"inverted":      local("inverted", false, "", assessments.LocalAffected{Package: assessments.LocalPackage{Ecosystem: "npm", Name: "x"}, Ranges: []semver.Range{{Introduced: "2.0.0", Fixed: "1.0.0"}}}),
		"both ends":     local("both ends", false, "", assessments.LocalAffected{Package: assessments.LocalPackage{Ecosystem: "npm", Name: "x"}, Ranges: []semver.Range{{Introduced: "1.0.0", Fixed: "2.0.0", LastAffected: "1.5.0"}}}),
		"all and range": local("all and range", false, "", assessments.LocalAffected{Package: assessments.LocalPackage{Ecosystem: "npm", Name: "x"}, AllVersions: true, Ranges: []semver.Range{{Fixed: "2.0.0"}}}),
		"bad rating":    local("bad rating", false, "urgent", assessments.LocalAffected{Package: assessments.LocalPackage{Ecosystem: "npm", Name: "x"}, AllVersions: true}),
	} {
		if _, err := s.CreateLocalAdvisory(ctx, bad, "tester"); !errors.Is(err, assessments.ErrInput) {
			t.Fatalf("%s should be refused: %v", name, err)
		}
	}

	// A range opens an entry for the stored inventory at once; the fixed version is not touched.
	rangeRecord, err := s.CreateLocalAdvisory(ctx, local("left below 1.2.0 leaks tokens", false, "critical", assessments.LocalAffected{Package: assessments.LocalPackage{Ecosystem: "npm", Name: "left"}, Ranges: []semver.Range{{Introduced: "1.0.0", Fixed: "1.2.0"}}}), "tester")
	if err != nil {
		t.Fatal(err)
	}
	rangeID, n := opened(rangeRecord)
	if n != 1 {
		t.Fatalf("entries opened: %d", n)
	}
	// An all-versions malicious advisory, and a PyPI one matched through name folding and explicit versions.
	maliciousRecord, err := s.CreateLocalAdvisory(ctx, local("right is a backdoor", true, "", assessments.LocalAffected{Package: assessments.LocalPackage{Ecosystem: "npm", Name: "RIGHT"}, AllVersions: true}), "tester")
	if err != nil {
		t.Fatal(err)
	}
	maliciousID, n := opened(maliciousRecord)
	if n != 1 {
		t.Fatalf("malicious entries opened: %d", n)
	}
	pyRecord, err := s.CreateLocalAdvisory(ctx, local("some-lib 1.0 is yanked", false, "medium", assessments.LocalAffected{Package: assessments.LocalPackage{Ecosystem: "PyPI", Name: "some-lib"}, Versions: []string{"1.0"}}), "tester")
	if err != nil {
		t.Fatal(err)
	}
	pyID, n := opened(pyRecord)
	if n != 1 {
		t.Fatalf("pypi entries opened: %d", n)
	}
	got := entries()
	want := map[string]string{
		rangeID + "/left":      "vulnerability:critical:open",
		maliciousID + "/right": "malicious_dependency:critical:open",
		pyID + "/Some_Lib":     "vulnerability:medium:open",
	}
	if len(got) != len(want) {
		t.Fatalf("entries %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("entry %s = %q, want %q (all: %v)", k, got[k], v, got)
		}
	}
	affected, err := s.AffectedBy(ctx, rangeID)
	if err != nil || len(affected) != 1 || affected[0].Component.Name != "left" {
		t.Fatalf("affected by the range: %+v %v", affected, err)
	}

	// The next scan raises them as part of the assessment, and the malicious one fails the gate.
	second := scan(npm("left", "1.1.0"), npm("right", "2.5.0"), pypi)
	if second.Verdict != "fail" {
		t.Fatalf("a malicious local advisory must fail the gate: %s", second.Verdict)
	}
	found, err := s.Findings(ctx, second.ID, uuid.Nil, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, f := range found {
		seen[f.AdvisoryID] = true
	}
	if !seen[rangeID] || !seen[maliciousID] || !seen[pyID] {
		t.Fatalf("the scan lacks local entries: %v", seen)
	}

	// Upgrading past the range closes that entry; versions outside it never matched.
	third := scan(npm("left", "1.2.0"), npm("right", "2.5.0"), pypi)
	if third.Verdict != "fail" {
		t.Fatalf("right is still malicious: %s", third.Verdict)
	}
	if got := entries(); got[rangeID+"/left"] != "vulnerability:critical:fixed" || got[maliciousID+"/right"] != "malicious_dependency:critical:open" {
		t.Fatalf("after the upgrade: %v", got)
	}

	// Withdrawing closes the entries and reports how many; later scans stay quiet.
	withdrawn, err := s.WithdrawLocalAdvisory(ctx, maliciousID, "found to be a false alarm", "tester")
	if err != nil {
		t.Fatal(err)
	}
	var closed struct {
		Closed int `json:"register_entries_closed"`
	}
	if err := json.Unmarshal(withdrawn, &closed); err != nil || closed.Closed != 1 {
		t.Fatalf("withdrawn: %s %v", withdrawn, err)
	}
	if got := entries(); got[maliciousID+"/right"] != "malicious_dependency:critical:fixed" {
		t.Fatalf("after withdrawing: %v", got)
	}
	if fourth := scan(npm("left", "1.2.0"), npm("right", "2.5.0")); fourth.Verdict == "fail" {
		t.Fatalf("a withdrawn advisory must not fail the gate: %s", fourth.Verdict)
	}
	var history string
	if err := pool.QueryRow(ctx, "SELECT string_agg(e.action,',' ORDER BY e.id) FROM "+schema+".finding_events e JOIN "+schema+".findings f ON f.id=e.finding_id WHERE f.advisory_id=$1", maliciousID).Scan(&history); err != nil || !strings.Contains(history, "detected") || !strings.Contains(history, "advisory_withdrawn") {
		t.Fatalf("history: %q %v", history, err)
	}
}
