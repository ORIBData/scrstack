package assessments

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
)

// validate checks a value against the subset of JSON Schema the event
// schemas use: type, required, properties, items, const and enum.
func validate(schema map[string]any, value any, path string) error {
	if c, ok := schema["const"]; ok && fmt.Sprint(c) != fmt.Sprint(value) {
		return fmt.Errorf("%s: want %v", path, c)
	}
	if enum, ok := schema["enum"].([]any); ok {
		found := false
		for _, e := range enum {
			found = found || e == value
		}
		if !found {
			return fmt.Errorf("%s: %v not in enum", path, value)
		}
	}
	if t, ok := schema["type"]; ok {
		types := []any{t}
		if list, ok := t.([]any); ok {
			types = list
		}
		matched := false
		for _, want := range types {
			switch want {
			case "object":
				_, matched = value.(map[string]any)
			case "array":
				_, matched = value.([]any)
			case "string":
				_, matched = value.(string)
			case "integer", "number":
				_, matched = value.(float64)
			case "boolean":
				_, matched = value.(bool)
			case "null":
				matched = value == nil
			}
			if matched {
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s: %T is not %v", path, value, t)
		}
	}
	if obj, ok := value.(map[string]any); ok {
		for _, r := range asList(schema["required"]) {
			if _, ok := obj[r.(string)]; !ok {
				return fmt.Errorf("%s: missing %s", path, r)
			}
		}
		props, _ := schema["properties"].(map[string]any)
		for k, v := range obj {
			sub, ok := props[k].(map[string]any)
			if !ok {
				if schema["additionalProperties"] == false {
					return fmt.Errorf("%s: unexpected %s", path, k)
				}
				continue
			}
			if err := validate(sub, v, path+"/"+k); err != nil {
				return err
			}
		}
	}
	if list, ok := value.([]any); ok {
		if items, ok := schema["items"].(map[string]any); ok {
			for i, v := range list {
				if err := validate(items, v, fmt.Sprintf("%s/%d", path, i)); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func asList(v any) []any {
	list, _ := v.([]any)
	return list
}

// Every event type has a schema, and the payloads SCRS builds conform.
func TestEventPayloadsMatchSchemas(t *testing.T) {
	now := time.Now().UTC()
	a := Assessment{ID: uuid.New(), AssetID: uuid.New(), ConnectionID: uuid.New(), Status: "succeeded", Verdict: "pass", Counts: map[string]int{"total": 1}, CreatedAt: now, CompletedAt: &now, Commit: "abc"}
	a.Request.Target = Target{Type: "git", Repository: "org/api", Ref: "main"}
	f := Finding{ID: uuid.New(), Type: "malicious_dependency", Severity: "critical", Score: 100, AdvisoryID: "MAL-1", Title: "evil", Change: "new"}
	brief := findingBrief(f)
	rescored := findingBrief(f)
	rescored["previous_severity"], rescored["previous_score"] = "high", 45
	base := map[string]any{"assessment_id": a.ID, "asset_id": a.AssetID, "repository": "org/api", "ref": "main", "commit": "abc", "total": 1, "truncated": false}
	with := func(extra map[string]any) map[string]any {
		out := map[string]any{}
		for k, v := range base {
			out[k] = v
		}
		for k, v := range extra {
			out[k] = v
		}
		return out
	}
	run := QARun{ID: uuid.New(), AssetID: a.AssetID, Kind: "functional", Status: "passed", Trigger: "assessment", CreatedAt: now}
	samples := map[string]any{
		"assessment.completed":           Summary(a),
		"assessment.failed":              Summary(a),
		"finding.created":                with(map[string]any{"findings": []any{brief}}),
		"finding.rescored":               with(map[string]any{"findings": []any{rescored}}),
		"malicious_dependency.reported":  with(map[string]any{"findings": []any{brief}}),
		"finding.status_changed":         map[string]any{"finding_id": f.ID, "asset_id": a.AssetID, "previous_status": "open", "status": "triaged", "waiver_until": nil, "actor_id": uuid.New(), "link": "x"},
		"integrity.alert":                map[string]any{"source": "event", "kind": "force_push", "severity": "high", "title": "t", "repository": "org/api", "ref": "main"},
		"feed.stale":                     map[string]any{"feed": "osv", "detail": "stale"},
		"connection.degraded":            map[string]any{"connection_id": uuid.New(), "name": "gh", "provider": "github", "check": "test"},
		"maintenance.completed":          map[string]any{"trigger": "scheduled", "report": MaintenanceReport{}},
		"qa.completed":                   QASummary(run),
		"qa.failed":                      QASummary(run),
		"dependency_track.upload_failed": map[string]any{"upload_id": uuid.New(), "assessment_id": uuid.New(), "project": "org/app", "version": "main", "stage": "upload", "error": "dependency-track rejected the request: HTTP 403"},
		"system.degraded":                map[string]any{"status": "down", "previous_status": "ok", "since": now, "components": []any{map[string]any{"name": "redis", "status": "down", "detail": "unavailable"}}},
		"system.recovered":               map[string]any{"status": "ok", "previous_status": "down", "since": now, "duration_seconds": 90},
		"ping":                           map[string]any{},
	}
	for event := range notify.Events {
		raw, ok := notify.EventSchema(event, notify.SchemaVersion)
		if !ok {
			t.Errorf("%s has no schema", event)
			continue
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatal(event, err)
		}
		sample, ok := samples[event]
		if !ok {
			t.Errorf("%s has no sample payload", event)
			continue
		}
		envelope, _ := json.Marshal(map[string]any{"event": map[string]any{"id": uuid.New(), "type": event, "version": notify.SchemaVersion, "time": now}, "data": sample})
		var decoded any
		_ = json.Unmarshal(envelope, &decoded)
		if err := validate(schema, decoded, ""); err != nil {
			t.Errorf("%s: %v", event, err)
		}
	}
	// The validator rejects a payload that breaks the schema.
	raw, _ := notify.EventSchema("finding.rescored", notify.SchemaVersion)
	var schema map[string]any
	_ = json.Unmarshal(raw, &schema)
	bad := map[string]any{"event": map[string]any{"id": "x", "type": "finding.rescored", "version": 1.0, "time": "t"}, "data": map[string]any{"findings": []any{map[string]any{"id": "x", "severity": "high"}}}}
	if validate(schema, bad, "") == nil {
		t.Fatal("missing previous_severity accepted")
	}
	if _, ok := notify.EventSchema("assessment.completed", 99); ok {
		t.Fatal("unknown version served")
	}
}
