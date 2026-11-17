package httpapi

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// The incident sweep: what an actor touched, found read-only, with where to
// restore from and fresh scans of the revisions touched.
func TestPostgresIncidentSweep(t *testing.T) {
	h := newHarness(t)
	gh := connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}}
	if _, err := h.store.Put(h.ctx, gh, json.RawMessage(`{"token":"t"}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Discover(h.ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/api"}}); err != nil {
		t.Fatal(err)
	}
	complete := func(actor, commit string, findings ...assessments.Finding) uuid.UUID {
		t.Helper()
		request := assessments.Request{Target: assessments.Target{Type: "git", Repository: "org/api", Ref: "main", Commit: commit}}
		request.Trigger.Actor = actor
		if _, _, err := h.jobs.Enqueue(h.ctx, request, uuid.New(), "tester", "sweep-"+commit); err != nil {
			t.Fatal(err)
		}
		a, err := h.jobs.Claim(h.ctx)
		if err != nil {
			t.Fatal(err)
		}
		stages := []assessments.Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}}
		if err := h.jobs.Complete(h.ctx, a, assessments.Result{Commit: commit, Stages: stages, Findings: findings}); err != nil {
			t.Fatal(err)
		}
		return a.ID
	}
	good := strings.Repeat("a", 40)
	bad := strings.Repeat("b", 40)
	goodID := complete("Alice", good)
	if _, err := h.pool.Exec(h.ctx, "UPDATE "+h.schema+".assessments SET verdict='pass' WHERE id=$1", goodID); err != nil {
		t.Fatal(err)
	}
	workflow := assessments.Finding{Type: "integrity", AdvisoryID: "SCRS-WORKFLOW-CHANGE", Title: "Workflow file changed", Severity: "high", Score: 60, Component: assessments.Component{Path: ".github/workflows/ci.yml"}, Evidence: json.RawMessage(`{}`), Guidance: json.RawMessage(`{}`)}
	badID := complete("Mallory", bad, workflow)
	asset, err := h.store.Asset(h.ctx, func() uuid.UUID {
		var id uuid.UUID
		if err := h.pool.QueryRow(h.ctx, "SELECT asset_id FROM "+h.schema+".assessments WHERE id=$1", badID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}())
	if err != nil {
		t.Fatal(err)
	}
	// Webhook evidence: a force push, a pushed branch and a pull request, all by mallory.
	push := `{"ref":"refs/heads/evil","repository":{"full_name":"org/api"},"pusher":{"name":"mallory"},"forced":true}`
	if _, err := h.jobs.RecordIntegrity(h.ctx, "d-push", uuid.New(), []byte(push), "direct", "push", []assessments.IntegrityEvent{{Kind: "force_push", Severity: "high", Title: "Force push", Repository: "org/api", Ref: "refs/heads/evil", Actor: "Mallory"}}); err != nil {
		t.Fatal(err)
	}
	pr := `{"action":"opened","pull_request":{"number":7,"title":"bump deps","head":{"ref":"evil","sha":"` + bad + `"},"base":{"ref":"main"}},"repository":{"full_name":"org/api"},"sender":{"login":"mallory"}}`
	if _, err := h.jobs.RecordIntegrity(h.ctx, "d-pr", uuid.New(), []byte(pr), "direct", "pull_request", []assessments.IntegrityEvent{{Kind: "pr_title_pattern", Severity: "medium", Title: "PR", Repository: "org/api", Actor: "mallory"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.pool.Exec(h.ctx, "INSERT INTO "+h.schema+".asset_mirrors(id,asset_id,status,head,size_bytes,requested_by) VALUES($1,$2,'succeeded',$3,2048,'tester')", uuid.New(), asset.ID, good); err != nil {
		t.Fatal(err)
	}

	read, write := h.issue("viewer", "read"), h.issue("engineer", "write")
	since := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	create := func(token, body string) *struct {
		code int
		body []byte
	} {
		w := h.call("POST", "/incidents", token, []byte(body), "application/json")
		return &struct {
			code int
			body []byte
		}{w.Code, w.Body.Bytes()}
	}
	if r := create(write, `{"actors":["mallory"],"since":"`+since+`"}`); r.code != 403 {
		t.Fatalf("write scope created an incident: %d", r.code)
	}
	for name, body := range map[string]string{
		"no actors":        `{"actors":[],"since":"` + since + `"}`,
		"too many actors":  `{"actors":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u"],"since":"` + since + `"}`,
		"no since":         `{"actors":["mallory"]}`,
		"since after":      `{"actors":["mallory"],"since":"` + since + `","until":"2020-01-01T00:00:00Z"}`,
		"window too long":  `{"actors":["mallory"],"since":"2024-01-01T00:00:00Z","until":"2026-01-01T00:00:00Z"}`,
		"too many rescans": `{"actors":["mallory"],"since":"` + since + `","max_reassess":500}`,
		"unknown field":    `{"actors":["mallory"],"since":"` + since + `","contain":true}`,
		"long title":       `{"actors":["mallory"],"since":"` + since + `","title":"` + strings.Repeat("x", 201) + `"}`,
	} {
		if r := create(h.admin, body); r.code != 400 {
			t.Fatalf("%s: status %d", name, r.code)
		}
	}

	r := create(h.admin, `{"title":"token theft","actors":["MALLORY","mallory"],"since":"`+since+`"}`)
	if r.code != 201 {
		t.Fatalf("create: %d %s", r.code, r.body)
	}
	var incident assessments.Incident
	if err := json.Unmarshal(r.body, &incident); err != nil {
		t.Fatal(err)
	}
	if len(incident.Actors) != 1 || incident.Actors[0] != "mallory" || incident.Title != "token theft" || incident.CreatedBy == "" {
		t.Fatalf("incident header: %+v", incident)
	}
	report := incident.Report
	if len(report.Touched) != 1 || report.Touched[0].Commit != bad || report.Touched[0].Locator != "org/api" || report.Touched[0].Actor != "mallory" {
		t.Fatalf("touched (alice's scan must not appear): %+v", report.Touched)
	}
	if len(report.Signals) != 2 {
		t.Fatalf("signals: %+v", report.Signals)
	}
	if len(report.Branches) != 1 || report.Branches[0].Ref != "refs/heads/evil" || report.Branches[0].Actor != "mallory" {
		t.Fatalf("branches: %+v", report.Branches)
	}
	if len(report.PullRequests) != 1 || report.PullRequests[0].Number != 7 || report.PullRequests[0].Title != "bump deps" || report.PullRequests[0].Ref != "evil" {
		t.Fatalf("pull requests: %+v", report.PullRequests)
	}
	if len(report.Changes) != 1 || report.Changes[0].AdvisoryID != "SCRS-WORKFLOW-CHANGE" || report.Changes[0].Path != ".github/workflows/ci.yml" {
		t.Fatalf("changes: %+v", report.Changes)
	}
	if len(report.Recovery) != 1 || report.Recovery[0].LastKnownGood == nil || report.Recovery[0].LastKnownGood.Commit != good || len(report.Recovery[0].Mirrors) != 1 || report.Recovery[0].Mirrors[0].Head != good {
		t.Fatalf("recovery: %+v", report.Recovery)
	}
	if len(incident.Reassessments) != 1 || incident.Reassessments[0].Commit != bad || incident.Reassessments[0].Status != "queued" || incident.ReassessCounts["queued"] != 1 || len(report.Truncated) != 0 {
		t.Fatalf("reassessments: %+v %v", incident.Reassessments, report.Truncated)
	}
	queued, err := h.jobs.Get(h.ctx, incident.Reassessments[0].AssessmentID)
	if err != nil || queued.Request.Target.Commit != bad || queued.Request.Trigger.Origin != "incident" || queued.Request.Trigger.Context["incident"] != incident.ID.String() {
		t.Fatalf("queued scan: %+v %v", queued.Request, err)
	}

	// Reading it back shows the live state, and the list leaves reports out.
	var read1 assessments.Incident
	if err := json.Unmarshal(h.expect(h.call("GET", "/incidents/"+incident.ID.String(), read, nil, ""), 200).Body.Bytes(), &read1); err != nil || len(read1.Report.Touched) != 1 {
		t.Fatalf("get: %+v %v", read1, err)
	}
	if _, err := h.pool.Exec(h.ctx, "UPDATE "+h.schema+".assessments SET status='succeeded',verdict='fail' WHERE id=$1", incident.Reassessments[0].AssessmentID); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(h.expect(h.call("GET", "/incidents/"+incident.ID.String(), read, nil, ""), 200).Body.Bytes(), &read1); err != nil || read1.Reassessments[0].Status != "succeeded" || read1.Reassessments[0].Verdict != "fail" || read1.ReassessCounts["succeeded"] != 1 {
		t.Fatalf("live reassessment state: %+v %v", read1.Reassessments, err)
	}
	var page struct {
		Items      []assessments.Incident `json:"items"`
		NextCursor string                 `json:"next_cursor"`
	}
	if err := json.Unmarshal(h.expect(h.call("GET", "/incidents", read, nil, ""), 200).Body.Bytes(), &page); err != nil || len(page.Items) != 1 || len(page.Items[0].Report.Touched) != 0 {
		t.Fatalf("list: %+v %v", page, err)
	}
	h.expect(h.call("GET", "/incidents/"+uuid.NewString(), read, nil, ""), 404)
	h.expect(h.call("GET", "/incidents/nope", read, nil, ""), 404)
	h.expect(h.call("GET", "/incidents?limit=0", read, nil, ""), 400)
	h.expect(h.call("GET", "/incidents?cursor=!!", read, nil, ""), 400)

	// Without re-assessment nothing is queued; an actor who touched nothing yields an empty report.
	if r := create(h.admin, `{"actors":["mallory"],"since":"`+since+`","reassess":false}`); r.code != 201 {
		t.Fatalf("no reassess: %d", r.code)
	} else {
		var second assessments.Incident
		if err := json.Unmarshal(r.body, &second); err != nil || len(second.Reassessments) != 0 || len(second.Report.Touched) != 1 {
			t.Fatalf("no reassess: %+v %v", second, err)
		}
	}
	if r := create(h.admin, `{"actors":["nobody"],"since":"`+since+`"}`); r.code != 201 || !strings.Contains(string(r.body), `"touched":[]`) {
		t.Fatalf("an actor who touched nothing: %d %s", r.code, r.body)
	}
	if audit := h.expect(h.call("GET", "/audit", h.admin, nil, ""), 200).Body.String(); !strings.Contains(audit, "incident.created") {
		t.Fatal("incident creation is not in the audit log")
	}
}
