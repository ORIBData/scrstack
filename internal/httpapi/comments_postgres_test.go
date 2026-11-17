package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/google/uuid"
)

// Assignment and comments on register entries: scopes, validation, history,
// filters, export and clean-up when the entries are removed.
func TestPostgresFindingCommentsAndAssignment(t *testing.T) {
	h := newHarness(t)
	asset, assessment := h.upload("commented", "a")
	one := h.finding(asset, assessment, "CVE-2021-0001", "high")
	two := h.finding(asset, assessment, "CVE-2021-0002", "low")
	three := h.finding(asset, assessment, "CVE-2021-0003", "low")
	read, write := h.issue("viewer", "read"), h.issue("engineer", "write")
	path := func(id uuid.UUID, rest string) string { return "/register/" + id.String() + rest }

	// Assignment: write scope, free text, case-insensitive filter, cleared with an empty value.
	h.expect(h.call("PUT", path(one, "/assignee"), read, []byte(`{"assignee":"alex@example.com"}`), "application/json"), 403)
	h.expect(h.call("PUT", path(one, "/assignee"), write, []byte(`{"assignee":"Alex@Example.com","on_behalf_of":"Alex"}`), "application/json"), 204)
	h.expect(h.call("PUT", path(two, "/assignee"), write, []byte(`{"assignee":"platform-team"}`), "application/json"), 204)
	h.expect(h.call("PUT", path(one, "/assignee"), write, []byte(`{"assignee":"`+strings.Repeat("x", 101)+`"}`), "application/json"), 400)
	h.expect(h.call("PUT", path(one, "/assignee"), write, []byte(`{"assignee":"a\u0007b"}`), "application/json"), 400)
	h.expect(h.call("PUT", path(one, "/assignee"), write, []byte(`{}`), "application/json"), 204) // an empty assignee clears it
	h.expect(h.call("PUT", path(one, "/assignee"), write, []byte(`{"assignee":"Alex@Example.com"}`), "application/json"), 204)
	h.expect(h.call("PUT", path(uuid.New(), "/assignee"), write, []byte(`{"assignee":"x"}`), "application/json"), 404)
	h.expect(h.call("PUT", path(one, "/assignee"), write, []byte(`{"assignee":"x","nope":1}`), "application/json"), 400)

	type listing struct {
		Items []struct {
			ID           uuid.UUID `json:"id"`
			Assignee     string    `json:"assignee"`
			CommentCount int       `json:"comment_count"`
		} `json:"items"`
	}
	list := func(query string) listing {
		var l listing
		if err := json.Unmarshal(h.expect(h.call("GET", "/register"+query, read, nil, ""), 200).Body.Bytes(), &l); err != nil {
			t.Fatal(err)
		}
		return l
	}
	if l := list("?assignee=alex@example.com"); len(l.Items) != 1 || l.Items[0].ID != one || l.Items[0].Assignee != "Alex@Example.com" {
		t.Fatalf("assignee filter: %+v", l)
	}
	if l := list("?unassigned=true"); len(l.Items) != 1 || l.Items[0].ID != three {
		t.Fatalf("unassigned filter: %+v", l)
	}
	if l := list("?assignee=nobody"); len(l.Items) != 0 {
		t.Fatalf("assignee nobody: %+v", l)
	}
	h.expect(h.call("GET", "/register?unassigned=maybe", read, nil, ""), 400)
	// The same filters narrow the aggregates.
	var summary assessments.RegisterSummary
	if err := json.Unmarshal(h.expect(h.call("GET", "/register/summary?assignee=platform-team", read, nil, ""), 200).Body.Bytes(), &summary); err != nil || summary.Total != 1 {
		t.Fatalf("summary by assignee: %+v %v", summary, err)
	}
	if csv := h.expect(h.call("GET", "/register/export?format=csv&assignee=platform-team", read, nil, ""), 200).Body.String(); !strings.Contains(csv, ",assignee\n") || !strings.Contains(csv, "platform-team") {
		t.Fatalf("csv export: %s", csv)
	}

	// Comments: write adds, read lists, admin deletes.
	h.expect(h.call("POST", path(one, "/comments"), read, []byte(`{"body":"hello"}`), "application/json"), 403)
	var first, second assessments.Comment
	if err := json.Unmarshal(h.expect(h.call("POST", path(one, "/comments"), write, []byte(`{"body":"  Waiting on the vendor patch  ","on_behalf_of":"Alex"}`), "application/json"), 201).Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	if first.Author != "engineer" || first.OnBehalfOf != "Alex" || first.Body != "Waiting on the vendor patch" || first.FindingID != one {
		t.Fatalf("comment: %+v", first)
	}
	if err := json.Unmarshal(h.expect(h.call("POST", path(one, "/comments"), h.admin, []byte(`{"body":"Second"}`), "application/json"), 201).Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	h.expect(h.call("POST", path(one, "/comments"), write, []byte(`{"body":"   "}`), "application/json"), 400)
	h.expect(h.call("POST", path(one, "/comments"), write, []byte(`{"body":"`+strings.Repeat("x", 4001)+`"}`), "application/json"), 400)
	h.expect(h.call("POST", path(uuid.New(), "/comments"), write, []byte(`{"body":"x"}`), "application/json"), 404)
	var comments struct {
		Items      []assessments.Comment `json:"items"`
		NextCursor string                `json:"next_cursor"`
	}
	if err := json.Unmarshal(h.expect(h.call("GET", path(one, "/comments"), read, nil, ""), 200).Body.Bytes(), &comments); err != nil || len(comments.Items) != 2 || comments.Items[0].ID != first.ID || comments.Items[1].ID != second.ID || comments.NextCursor != "" {
		t.Fatalf("comments: %+v %v", comments, err)
	}
	if err := json.Unmarshal(h.expect(h.call("GET", path(one, "/comments?cursor="+first.ID.String()), read, nil, ""), 200).Body.Bytes(), &comments); err != nil || len(comments.Items) != 1 || comments.Items[0].ID != second.ID {
		t.Fatalf("comments after cursor: %+v %v", comments, err)
	}
	h.expect(h.call("GET", path(one, "/comments?cursor=nope"), read, nil, ""), 400)
	h.expect(h.call("GET", path(uuid.New(), "/comments"), read, nil, ""), 404)
	if l := list("?assignee=alex@example.com"); l.Items[0].CommentCount != 2 {
		t.Fatalf("comment count: %+v", l)
	}

	// Deleting needs admin, leaves a trace without the text, and is scoped to the entry.
	h.expect(h.call("DELETE", path(one, "/comments/"+first.ID.String()), write, nil, ""), 403)
	h.expect(h.call("DELETE", path(two, "/comments/"+first.ID.String()), h.admin, nil, ""), 404)
	h.expect(h.call("DELETE", path(one, "/comments/not-a-uuid"), h.admin, nil, ""), 404)
	h.expect(h.call("DELETE", path(one, "/comments/"+first.ID.String()), h.admin, nil, ""), 204)
	h.expect(h.call("DELETE", path(one, "/comments/"+first.ID.String()), h.admin, nil, ""), 404)
	history := h.expect(h.call("GET", path(one, "/events"), read, nil, ""), 200).Body.String()
	for _, action := range []string{`"assigned"`, `"comment.added"`, `"comment.deleted"`} {
		if !strings.Contains(history, action) {
			t.Fatalf("history lacks %s: %s", action, history)
		}
	}
	if strings.Contains(history, "vendor patch") {
		t.Fatalf("history must not repeat comment text: %s", history)
	}
	h.expect(h.call("PATCH", path(one, "/comments"), write, nil, ""), 405)

	// Removing entries removes their comments too, by retention and by a maintenance reset.
	h.expect(h.call("POST", path(two, "/comments"), write, []byte(`{"body":"closing"}`), "application/json"), 201)
	if _, err := h.pool.Exec(h.ctx, "UPDATE "+h.schema+".findings SET status='fixed',last_seen=now()-interval '10 days' WHERE id=$1", two); err != nil {
		t.Fatal(err)
	}
	policy, err := h.jobs.Retention(h.ctx)
	if err != nil {
		t.Fatal(err)
	}
	days := 1
	if _, err := h.jobs.SetRetentionClasses(h.ctx, uuid.Nil, policy.Revision, map[string]*int{"closed_findings": &days}); err != nil {
		t.Fatal(err)
	}
	policy, _ = h.jobs.Retention(h.ctx)
	if purged, err := h.jobs.PurgeRetention(h.ctx, uuid.Nil, policy.Revision); err != nil || purged["closed_findings"] != 1 {
		t.Fatalf("retention purge: %v %v", purged, err)
	}
	if removed, err := h.jobs.Reset(h.ctx, "asset_findings", asset, uuid.Nil); err != nil || removed["findings"] != 2 {
		t.Fatalf("reset: %v %v", removed, err)
	}
	var left int
	if err := h.pool.QueryRow(h.ctx, "SELECT count(*) FROM "+h.schema+".finding_comments").Scan(&left); err != nil || left != 0 {
		t.Fatalf("comments left after removal: %d %v", left, err)
	}
}
