package assessments_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/advisory"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresSBOMDiffAndRevisions(t *testing.T) {
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
	actor := uuid.New()
	request := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/repo", Ref: "main"}}
	component := func(name, version, license string) assessments.Component {
		out := assessments.Component{Name: name, Version: version, Ecosystem: "npm", PURL: "pkg:npm/" + name + "@" + version, Path: "package-lock.json"}
		if license != "" {
			out.License = &assessments.ComponentLicense{Expression: license, Source: "declared"}
		}
		return out
	}
	complete := func(key string, commit string, components ...assessments.Component) uuid.UUID {
		t.Helper()
		if _, _, err := s.Enqueue(ctx, request, actor, "automation", key); err != nil {
			t.Fatal(err)
		}
		a, err := s.Claim(ctx)
		if err != nil {
			t.Fatal(err)
		}
		sha := strings.Repeat(commit[:1], 64)
		result := assessments.Result{Commit: commit, SBOMKey: "sbom/" + sha + ".cdx.json", SBOMSHA256: sha, Complete: true, Components: components}
		if err := s.Complete(ctx, a, result); err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	first := complete("one", strings.Repeat("a", 40), component("left", "1.0.0", "MIT"), component("same", "2.0.0", "MIT"), component("gone", "1.0.0", ""), component("relicensed", "1.0.0", "MIT"))
	second := complete("two", strings.Repeat("b", 40), component("left", "1.1.0", "MIT"), component("same", "2.0.0", "MIT"), component("new", "0.1.0", "Apache-2.0"), component("relicensed", "1.0.0", "GPL-3.0-only"))
	var asset uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT asset_id FROM `+schema+`.assessments WHERE id=$1`, first).Scan(&asset); err != nil {
		t.Fatal(err)
	}

	diff, err := s.DiffSBOM(ctx, asset, strings.Repeat("a", 40), second.String(), 500)
	if err != nil {
		t.Fatal(err)
	}
	if diff.From.AssessmentID != first || diff.To.AssessmentID != second || diff.From.Components != 4 || diff.To.Components != 4 {
		t.Fatalf("sides %+v %+v", diff.From, diff.To)
	}
	if len(diff.Added) != 1 || diff.Added[0].Name != "new" || len(diff.Removed) != 1 || diff.Removed[0].Name != "gone" {
		t.Fatalf("added or removed %+v %+v", diff.Added, diff.Removed)
	}
	if len(diff.Changed) != 1 || diff.Changed[0].Name != "left" || diff.Changed[0].FromVersion[0] != "1.0.0" || diff.Changed[0].ToVersion[0] != "1.1.0" {
		t.Fatalf("changed %+v", diff.Changed)
	}
	if len(diff.LicenseChanged) != 1 || diff.LicenseChanged[0].Name != "relicensed" || diff.LicenseChanged[0].FromLicense != "MIT" || diff.LicenseChanged[0].ToLicense != "GPL-3.0-only" {
		t.Fatalf("licence %+v", diff.LicenseChanged)
	}
	if diff.Unchanged != 1 || diff.Truncated || diff.Totals["added"] != 1 {
		t.Fatalf("totals %+v", diff)
	}
	// Reversing swaps added and removed.
	back, err := s.DiffSBOM(ctx, asset, second.String(), first.String(), 1)
	if err != nil || len(back.Added) != 1 || back.Added[0].Name != "gone" || back.Totals["changed"] != 1 {
		t.Fatalf("reverse %+v %v", back, err)
	}
	if _, err := s.DiffSBOM(ctx, asset, "main", second.String(), 10); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("a branch name is not a revision:", err)
	}
	if _, err := s.DiffSBOM(ctx, asset, strings.Repeat("c", 40), second.String(), 10); !errors.Is(err, assessments.ErrNotFound) {
		t.Fatal("unknown commit:", err)
	}
	if _, err := s.DiffSBOM(ctx, uuid.New(), first.String(), second.String(), 10); !errors.Is(err, assessments.ErrNotFound) {
		t.Fatal("an assessment of another asset must not resolve:", err)
	}
	if _, err := s.DiffSBOM(ctx, asset, first.String(), second.String(), 0); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("limit:", err)
	}

	revisions, err := s.Revisions(ctx, asset, "main", nil, 10)
	if err != nil || len(revisions) != 2 || revisions[0].Commit != strings.Repeat("b", 40) || revisions[0].AssessmentID != second || !revisions[0].HasSBOM || revisions[0].Assessments != 1 {
		t.Fatalf("revisions %+v %v", revisions, err)
	}
	older := revisions[0].CreatedAt
	page, err := s.Revisions(ctx, asset, "", &older, 10)
	if err != nil || len(page) != 1 || page[0].Commit != strings.Repeat("a", 40) {
		t.Fatalf("page %+v %v", page, err)
	}
	if other, err := s.Revisions(ctx, asset, "release", nil, 10); err != nil || len(other) != 0 {
		t.Fatalf("other ref %+v %v", other, err)
	}

	// Local advisories (OSV-008).
	year := time.Now().UTC().Year()
	local := func(summary string, affected ...assessments.LocalAffected) assessments.LocalAdvisoryInput {
		return assessments.LocalAdvisoryInput{Summary: summary, Details: "Internal report " + summary, Aliases: []string{"INC-1"}, Affected: affected, References: []advisory.Reference{{Type: "REPORT", URL: "https://example.com/incident"}}}
	}
	pkg := func(name string) assessments.LocalPackage {
		return assessments.LocalPackage{Ecosystem: "npm", Name: name}
	}
	for _, bad := range []assessments.LocalAdvisoryInput{
		local("no packages"),
		local("both", assessments.LocalAffected{Package: pkg("left"), Versions: []string{"1.0.0"}, AllVersions: true}),
		local("neither", assessments.LocalAffected{Package: pkg("left")}),
		local("x", assessments.LocalAffected{Package: pkg("left"), AllVersions: true}),
		{Summary: "bad link", Affected: []assessments.LocalAffected{{Package: pkg("left"), AllVersions: true}}, References: []advisory.Reference{{Type: "REPORT", URL: "javascript:alert(1)"}}},
		{Summary: "bad severity", Affected: []assessments.LocalAffected{{Package: pkg("left"), AllVersions: true}}, Severity: []advisory.Severity{{Type: "HIGH", Score: "9"}}},
	} {
		if _, err := s.CreateLocalAdvisory(ctx, bad, "tester"); !errors.Is(err, assessments.ErrInput) {
			t.Fatalf("%q should be refused: %v", bad.Summary, err)
		}
	}
	record, err := s.CreateLocalAdvisory(ctx, local("left 1.1.0 is compromised", assessments.LocalAffected{Package: pkg("left"), Versions: []string{"1.1.0"}}), "tester")
	if err != nil {
		t.Fatal(err)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(record, &created); err != nil || created.ID != fmt.Sprintf("x_SCRS-%d-0001", year) {
		t.Fatal(string(record), err)
	}
	// Concurrent creates never share a number.
	ids := make(chan string, 6)
	for i := 0; i < 6; i++ {
		go func(i int) {
			rec, err := s.CreateLocalAdvisory(ctx, local(fmt.Sprintf("concurrent %d", i), assessments.LocalAffected{Package: pkg("other"), AllVersions: true}), "tester")
			if err != nil {
				ids <- "error: " + err.Error()
				return
			}
			var c struct {
				ID string `json:"id"`
			}
			_ = json.Unmarshal(rec, &c)
			ids <- c.ID
		}(i)
	}
	seen := map[string]bool{}
	for i := 0; i < 6; i++ {
		id := <-ids
		if strings.HasPrefix(id, "error") || seen[id] {
			t.Fatal("duplicate or failed id", id)
		}
		seen[id] = true
	}
	hits, err := s.AffectedBy(ctx, created.ID)
	if err != nil || len(hits) != 1 || hits[0].Component.Version != "1.1.0" || hits[0].AssessmentID != second.String() || hits[0].Locator != "org/repo" {
		t.Fatalf("affected %+v %v", hits, err)
	}
	stale, err := s.CreateLocalAdvisory(ctx, local("left 1.0.0 old", assessments.LocalAffected{Package: pkg("left"), Versions: []string{"1.0.0"}}), "tester")
	if err != nil {
		t.Fatal(err)
	}
	var staleID struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(stale, &staleID)
	if hits, err := s.AffectedBy(ctx, staleID.ID); err != nil || len(hits) != 0 {
		t.Fatalf("only the newest assessment counts: %+v %v", hits, err)
	}
	found, err := s.SearchAdvisories(ctx, assessments.AdvisoryFilter{Query: "COMPROMISED", Limit: 10})
	if err != nil || len(found) != 1 || found[0].ID != created.ID || found[0].Origin != "local" || found[0].Aliases[0] != "INC-1" {
		t.Fatalf("search %+v %v", found, err)
	}
	if byPackage, err := s.SearchAdvisories(ctx, assessments.AdvisoryFilter{Ecosystem: "NPM", Package: "LEFT", Limit: 50}); err != nil || len(byPackage) != 2 {
		t.Fatalf("package filter %+v %v", byPackage, err)
	}
	if byAlias, err := s.SearchAdvisories(ctx, assessments.AdvisoryFilter{Alias: "INC-1", Limit: 50}); err != nil || len(byAlias) != 8 {
		t.Fatalf("alias filter %d %v", len(byAlias), err)
	}
	if literal, err := s.SearchAdvisories(ctx, assessments.AdvisoryFilter{Query: "100%_", Limit: 10}); err != nil || len(literal) != 0 {
		t.Fatalf("wildcards must be literal: %+v %v", literal, err)
	}
	firstPage, err := s.SearchAdvisories(ctx, assessments.AdvisoryFilter{Limit: 3})
	if err != nil || len(firstPage) != 4 {
		t.Fatalf("a page reads one extra row: %d %v", len(firstPage), err)
	}
	after, err := s.SearchAdvisories(ctx, assessments.AdvisoryFilter{Limit: 3, AfterID: firstPage[2].ID, AfterOrig: firstPage[2].Origin})
	if err != nil || len(after) == 0 || after[0].ID != firstPage[3].ID {
		t.Fatalf("cursor %+v %v", after, err)
	}
	if _, err := s.WithdrawLocalAdvisory(ctx, created.ID, "short", "tester"); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("a reason is required:", err)
	}
	if _, err := s.WithdrawLocalAdvisory(ctx, "CVE-2024-0001", "not a local advisory", "tester"); !errors.Is(err, assessments.ErrNotFound) {
		t.Fatal("only local advisories can be withdrawn:", err)
	}
	if _, err := s.WithdrawLocalAdvisory(ctx, created.ID, "false alarm, version was clean", "tester"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.WithdrawLocalAdvisory(ctx, created.ID, "false alarm, version was clean", "tester"); !errors.Is(err, assessments.ErrConflict) {
		t.Fatal("second withdrawal:", err)
	}
	if _, err := s.AffectedBy(ctx, created.ID); !errors.Is(err, assessments.ErrNotFound) {
		t.Fatal("a withdrawn advisory affects nothing:", err)
	}
	no := false
	if live, err := s.SearchAdvisories(ctx, assessments.AdvisoryFilter{Query: "compromised", Withdrawn: &no, Limit: 10}); err != nil || len(live) != 0 {
		t.Fatalf("withdrawn filter %+v %v", live, err)
	}
	view, err := s.Advisory(ctx, created.ID, "")
	if err != nil || len(view.Records) != 1 {
		t.Fatalf("lookup %+v %v", view, err)
	}
}
