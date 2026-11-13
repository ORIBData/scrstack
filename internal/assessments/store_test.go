package assessments_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type inventory struct{}

func (inventory) List(context.Context, connections.Connection, json.RawMessage) ([]connections.Resource, error) {
	return []connections.Resource{{Type: "github_repo", Locator: "org/repo"}}, nil
}
func TestPostgresDurableAssessmentAndFencing(t *testing.T) {
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
	var wg sync.WaitGroup
	ids := make(chan uuid.UUID, 8)
	failures := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, _, err := s.Enqueue(ctx, request, actor, "automation", "same-key")
			ids <- a.ID
			failures <- err
		}()
	}
	wg.Wait()
	close(ids)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	id := <-ids
	for next := range ids {
		if id != next {
			t.Fatal("idempotency created duplicates")
		}
	}
	changed := request
	changed.Target.Ref = "other"
	if _, _, err := s.Enqueue(ctx, changed, actor, "automation", "same-key"); !errors.Is(err, assessments.ErrConflict) {
		t.Fatal("idempotency conflict accepted", err)
	}
	second, _, err := s.Enqueue(ctx, request, actor, "automation", "second")
	if err != nil {
		t.Fatal(err)
	}
	running, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx); !errors.Is(err, assessments.ErrNotFound) {
		t.Fatal("simultaneous asset claims allowed", err)
	}
	// Simulate a worker crash, reclaim, and reject its stale completion token.
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".assessments SET lease_until=now()-interval '1 second' WHERE id=$1", running.ID); err != nil {
		t.Fatal(err)
	}
	_, _ = s.Claim(ctx)
	if err := s.BindRevision(ctx, running, strings.Repeat("a", 40), false); !errors.Is(err, assessments.ErrLease) {
		t.Fatal("expired worker accepted", err)
	}
	// Cancel both outstanding jobs; a cancelled attempt cannot publish findings.
	for _, aid := range []uuid.UUID{id, second.ID} {
		_ = s.Cancel(ctx, aid, actor)
	}
	if _, _, err := s.Enqueue(ctx, request, actor, "automation", "complete"); err != nil {
		t.Fatal(err)
	}
	a, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	result := assessments.Result{Commit: strings.Repeat("b", 40), SBOMKey: "sbom/" + strings.Repeat("c", 64) + ".cdx.json", SBOMSHA256: strings.Repeat("c", 64), Complete: true, Components: []assessments.Component{{Name: "pkg", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/pkg@1.0.0", Path: "package-lock.json"}}, Findings: []assessments.Finding{{Type: "vulnerability", AdvisoryID: "TEST-001", Title: "Synthetic", Severity: "critical", Score: 60, Component: assessments.Component{PURL: "pkg:npm/pkg@1.0.0"}, Evidence: json.RawMessage(`{}`), Guidance: json.RawMessage(`{}`)}}}
	result.Findings = append(result.Findings, result.Findings[0]) // duplicate adapter output must not inflate counts
	if err := s.Complete(ctx, a, result); err != nil {
		t.Fatal(err)
	}
	saved, err := s.Get(ctx, a.ID)
	if err != nil || saved.Status != "succeeded" || saved.Verdict != "fail" || saved.Counts["total"] != 1 {
		t.Fatal("critical detection in partial scan not gated as fail", err, saved.Verdict)
	}
	findings, err := s.Findings(ctx, a.ID, uuid.Nil, uuid.Nil)
	if err != nil || len(findings) != 1 {
		t.Fatal("finding absent", err)
	}
	past := time.Now().Add(-time.Hour)
	if err := s.Transition(ctx, findings[0].ID, actor, "accepted", "valid reason", &past); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("expired waiver accepted", err)
	}
	future := time.Now().Add(time.Hour)
	if err := s.Transition(ctx, findings[0].ID, actor, "accepted", "reviewed exception", &future); err != nil {
		t.Fatal(err)
	}

	// Later triage must never rewrite a historical assessment snapshot.
	historical, err := s.Findings(ctx, a.ID, uuid.Nil, uuid.Nil)
	if err != nil || historical[0].Status != "open" || historical[0].FirstSeen.IsZero() {
		t.Fatal("historical findings mutated", err)
	}
	plan, _, err := s.EnqueuePlan(ctx, a.ID, a.AssetID, actor, "automation", "plan", "package-lock.json", "in-place")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.EnqueuePlan(ctx, a.ID, uuid.New(), actor, "automation", "wrongasset", "package-lock.json", "in-place"); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("cross asset plan accepted", err)
	}
	if _, _, err := s.EnqueuePlan(ctx, a.ID, a.AssetID, actor, "automation", "traversal", "../package-lock.json", "in-place"); !errors.Is(err, assessments.ErrInput) {
		t.Fatal("traversal plan accepted", err)
	}
	runningPlan, err := s.Claim(ctx)
	if err != nil || runningPlan.ID != plan.ID {
		t.Fatal("plan not claimable", err)
	}
	digest := strings.Repeat("d", 64)
	key := "remediation/" + digest + ".json"
	if err := s.CompletePlan(ctx, runningPlan, key, digest); err != nil {
		t.Fatal(err)
	}
	if stored, err := s.PlanKey(ctx, plan.ID); err != nil || stored != key {
		t.Fatal("plan artifact missing", err)
	}
	if err := s.CompletePlan(ctx, runningPlan, key, digest); !errors.Is(err, assessments.ErrLease) {
		t.Fatal("stale plan accepted", err)
	}
	// Indicator imports preserve version history; duplicate versions cannot deactivate the current bundle.
	bundle := `{"version":"test-v1","indicators":[{"id":"ioc-1","type":"domain","value":"bad.example","valid_until":"2099-01-01T00:00:00Z"}]}`
	if _, err := s.ImportIndicators(ctx, actor, []byte(bundle)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ImportIndicators(ctx, actor, []byte(bundle)); !errors.Is(err, assessments.ErrConflict) {
		t.Fatal("indicator version mutated", err)
	}
	if raw, err := s.ActiveIndicators(ctx); err != nil || !strings.Contains(string(raw), "test-v1") {
		t.Fatal("active bundle lost", err)
	}
	// Completion durably schedules automatic remediation; repeated dispatch creates one child.
	autoRequest := request
	autoRequest.AutoRemediation = true
	if _, _, err := s.Enqueue(ctx, autoRequest, actor, "automation", "automatic"); err != nil {
		t.Fatal(err)
	}
	auto, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Complete(ctx, auto, result); err != nil {
		t.Fatal(err)
	}
	dispatchErrors := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); dispatchErrors <- s.DispatchAutomaticPlan(ctx) }()
	}
	wg.Wait()
	close(dispatchErrors)
	for err := range dispatchErrors {
		if err != nil {
			t.Fatal(err)
		}
	}
	plans, err := s.AutomaticPlans(ctx, auto.ID)
	if err != nil || len(plans) != 1 {
		t.Fatal("automatic plan missing", err)
	}
	child, err := s.Claim(ctx)
	if err != nil || child.Request.Remediation == nil || child.Request.Remediation.Parent != auto.ID {
		t.Fatal("automatic child missing", err)
	}
	if err := s.Cancel(ctx, child.ID, actor); err != nil {
		t.Fatal(err)
	}
	// An incomplete follow-up with no detections must not erase prior findings.
	if _, _, err := s.Enqueue(ctx, request, actor, "automation", "followup"); err != nil {
		t.Fatal(err)
	}
	followup, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	partial := result
	partial.Findings = nil
	if err := s.Complete(ctx, followup, partial); err != nil {
		t.Fatal(err)
	}
	current, err := s.Findings(ctx, uuid.Nil, a.AssetID, uuid.Nil)
	if err != nil || len(current) != 1 || current[0].Status != "accepted" {
		t.Fatal("incomplete scan erased finding", err)
	}

	policy, err := s.Retention(ctx)
	if err != nil || policy.InboundEventDays != 0 {
		t.Fatal("unsafe retention default", err)
	}
	policy, err = s.SetRetention(ctx, actor, policy.Revision, assessments.Retention{InboundEventDays: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetRetention(ctx, actor, policy.Revision-1, assessments.Retention{InboundEventDays: 2}); !errors.Is(err, assessments.ErrConflict) {
		t.Fatal("stale retention write accepted", err)
	}
	pending, _, err := s.Enqueue(ctx, request, actor, "automation", "retention-protected")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "UPDATE "+schema+".inbound_events SET created_at=now()-interval '2 days'"); err != nil {
		t.Fatal(err)
	}
	preview, err := s.PreviewRetention(ctx, 1)
	if err != nil || preview["rows"] == 0 {
		t.Fatal("retention preview empty", err)
	}
	purged, err := s.PurgeEvents(ctx, actor, policy.Revision)
	if err != nil || purged != preview["rows"] {
		t.Fatal("purge differs from preview", err)
	}
	var protected int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+schema+".inbound_events WHERE assessment_id=$1", pending.ID).Scan(&protected); err != nil || protected != 1 {
		t.Fatal("pending event lost", err)
	}
	if records, err := s.Findings(ctx, uuid.Nil, a.AssetID, uuid.Nil); err != nil || len(records) != 1 {
		t.Fatal("retention erased findings", err)
	}
	if err := s.Complete(ctx, a, result); !errors.Is(err, assessments.ErrLease) {
		t.Fatal("completed job accepted duplicate result", err)
	}

	// Webhook pushes name commit and ref. A full-coverage SCA scan of the ref's
	// head closes vulnerability entries it no longer sees; waived entries do not gate.
	allStages := []assessments.Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}, {Name: "inventory", Status: "ok"}, {Name: "sbom", Status: "ok"}, {Name: "match_vuln", Status: "ok"}, {Name: "match_malicious", Status: "ok"}, {Name: "malware", Status: "ok"}, {Name: "ioc", Status: "ok"}, {Name: "integrity", Status: "partial"}}
	waivedRun, err := s.Claim(ctx) // the queued retention-protected job
	if err != nil || waivedRun.ID != pending.ID {
		t.Fatal("pending job not claimable", err)
	}
	withHigh := result
	withHigh.Stages = allStages
	withHigh.Findings = append([]assessments.Finding{}, result.Findings[0])
	withHigh.Findings = append(withHigh.Findings, assessments.Finding{Type: "vulnerability", AdvisoryID: "TEST-002", Title: "Synthetic high", Severity: "high", Score: 45, Component: assessments.Component{PURL: "pkg:npm/pkg@1.0.0"}, Evidence: json.RawMessage(`{}`), Guidance: json.RawMessage(`{}`)})
	if err := s.Complete(ctx, waivedRun, withHigh); err != nil {
		t.Fatal(err)
	}
	if saved, err := s.Get(ctx, waivedRun.ID); err != nil || saved.Verdict != "incomplete" || saved.Counts["waived"] != 1 {
		t.Fatal("waived critical still gated or partial integrity hidden", err, saved.Verdict, saved.Counts)
	}
	pushed := request
	pushed.Target.Commit = strings.Repeat("b", 40)
	if _, _, err := s.Enqueue(ctx, pushed, actor, "automation", "webhook-style"); err != nil {
		t.Fatal(err)
	}
	pushRun, err := s.Claim(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clean := result
	clean.Stages = allStages
	clean.Findings = nil
	if err := s.Complete(ctx, pushRun, clean); err != nil {
		t.Fatal(err)
	}
	register, err := s.Findings(ctx, uuid.Nil, a.AssetID, uuid.Nil)
	if err != nil {
		t.Fatal(err)
	}
	statuses := map[string]string{}
	for _, f := range register {
		statuses[f.AdvisoryID] = f.Status
	}
	if statuses["TEST-002"] != "fixed" || statuses["TEST-001"] != "accepted" {
		t.Fatal("webhook-style complete scan did not close fixed entry or altered waiver", statuses)
	}
}
