package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/assessments"
)

func TestPostgresDependencyPolicyAPI(t *testing.T) {
	h := newHarness(t)
	read, write := h.issue("viewer", "read"), h.issue("engineer", "write")
	var policy assessments.DependencyPolicy
	w := h.expect(h.call("GET", "/policies/dependencies", read, nil, ""), 200)
	if err := json.Unmarshal(w.Body.Bytes(), &policy); err != nil || policy.MinReleaseAgeDays != 0 || policy.Typosquat || policy.Revision != 1 || w.Header().Get("ETag") != `"1"` {
		t.Fatalf("default: %+v etag=%q %v", policy, w.Header().Get("ETag"), err)
	}
	// Only an admin changes it, with the revision it read.
	send := func(token, ifMatch, body string) int {
		r := httptest.NewRequest("PUT", BasePath+"/policies/dependencies", strings.NewReader(body))
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer "+token)
		r.Header.Set("Content-Type", "application/json")
		if ifMatch != "" {
			r.Header.Set("If-Match", ifMatch)
		}
		w := httptest.NewRecorder()
		h.handler.ServeHTTP(w, r)
		return w.Code
	}
	if code := send(write, `"1"`, `{"min_release_age_days":7,"typosquat":true}`); code != 403 {
		t.Fatalf("write scope changed the policy: %d", code)
	}
	if code := send(h.admin, "", `{"min_release_age_days":7,"typosquat":true}`); code != 428 {
		t.Fatalf("missing If-Match: %d", code)
	}
	if code := send(h.admin, `"9"`, `{"min_release_age_days":7,"typosquat":true}`); code != 409 {
		t.Fatalf("stale If-Match: %d", code)
	}
	if code := send(h.admin, `"1"`, `{"min_release_age_days":400,"typosquat":true}`); code != 400 {
		t.Fatalf("out of range: %d", code)
	}
	if code := send(h.admin, `"1"`, `{"min_release_age_days":7,"typosquat":true,"extra":1}`); code != 400 {
		t.Fatalf("unknown field: %d", code)
	}
	if code := send(h.admin, `"1"`, `{"min_release_age_days":7,"typosquat":true}`); code != 200 {
		t.Fatalf("admin update: %d", code)
	}
	w = h.expect(h.call("GET", "/policies/dependencies", write, nil, ""), 200)
	if err := json.Unmarshal(w.Body.Bytes(), &policy); err != nil || policy.MinReleaseAgeDays != 7 || !policy.Typosquat || policy.Revision != 2 || w.Header().Get("ETag") != `"2"` {
		t.Fatalf("after update: %+v etag=%q %v", policy, w.Header().Get("ETag"), err)
	}
	if audit := h.expect(h.call("GET", "/audit", h.admin, nil, ""), 200).Body.String(); !strings.Contains(audit, "dependency_policy.updated") {
		t.Fatal("the change is not in the audit log")
	}
	h.expect(h.call("DELETE", "/policies/dependencies", h.admin, nil, ""), 405)
}
