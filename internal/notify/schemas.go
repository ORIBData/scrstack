package notify

import (
	"encoding/json"
	"fmt"
	"sort"
)

// Event JSON Schemas (OUT-008): one per event type and SchemaVersion,
// served at /schemas/events/{type}/{version}. Data objects allow further
// properties, so additive changes keep version 1; a breaking change raises
// SchemaVersion and keeps the old schemas published.

func object(required []string, properties map[string]any) map[string]any {
	return map[string]any{"type": "object", "required": required, "properties": properties, "additionalProperties": true}
}

func str() map[string]any     { return map[string]any{"type": "string"} }
func integer() map[string]any { return map[string]any{"type": "integer"} }
func enum(values ...string) map[string]any {
	return map[string]any{"type": "string", "enum": values}
}
func boolean() map[string]any { return map[string]any{"type": "boolean"} }
func array(items map[string]any) map[string]any {
	return map[string]any{"type": "array", "items": items}
}
func nullable(t string) map[string]any { return map[string]any{"type": []string{t, "null"}} }

var findingBriefSchema = object([]string{"id", "type", "severity", "advisory_id", "title"}, map[string]any{
	"id": str(), "type": str(), "severity": str(), "score": integer(), "advisory_id": str(), "title": str(), "change": str(), "component": map[string]any{"type": "object"}, "link": str(), "introduced_by": map[string]any{"type": "object"},
})

var assessmentData = object([]string{"assessment", "links"}, map[string]any{
	"assessment": object([]string{"id", "status", "verdict", "asset_id", "connection_id", "repository"}, map[string]any{
		"id": str(), "kind": str(), "status": str(), "verdict": str(), "counts": map[string]any{"type": "object"}, "asset_id": str(), "connection_id": str(),
		"repository": str(), "ref": str(), "commit": str(), "ref_moved": boolean(), "requested_by": str(), "request_id": str(), "error": str(),
		"created_at": str(), "completed_at": nullable("string"),
	}),
	"links": map[string]any{"type": "object"},
	// full and agent profiles add the assessment context document.
	"schema_version": integer(), "profile": str(), "findings": array(map[string]any{"type": "object"}), "untrusted_paths": array(str()),
})

var findingSet = func(extra map[string]any) map[string]any {
	props := map[string]any{"assessment_id": str(), "asset_id": str(), "repository": str(), "ref": str(), "commit": str(), "total": integer(), "truncated": boolean(), "findings": array(findingBriefSchema)}
	for k, v := range extra {
		props[k] = v
	}
	return object([]string{"findings"}, props)
}

var qaData = object([]string{"qa_run", "links"}, map[string]any{
	"qa_run": object([]string{"id", "kind", "status", "asset_id"}, map[string]any{
		"id": str(), "kind": str(), "status": str(), "trigger": str(), "asset_id": str(), "assessment_id": nullable("string"), "ref": str(), "commit": str(),
		"summary": map[string]any{"type": "object"}, "coverage": map[string]any{}, "perf": map[string]any{}, "error": str(),
	}),
	"links": map[string]any{"type": "object"},
})

var eventData = map[string]map[string]any{
	"assessment.completed": assessmentData,
	"assessment.failed":    assessmentData,
	"finding.created":      findingSet(map[string]any{"qa_run_id": str()}),
	"finding.rescored": findingSet(map[string]any{"findings": array(object([]string{"id", "severity", "previous_severity"}, map[string]any{
		"id": str(), "severity": str(), "score": integer(), "previous_severity": str(), "previous_score": integer(),
	}))}),
	"malicious_dependency.reported": findingSet(nil),
	"finding.status_changed": object([]string{"finding_id", "status"}, map[string]any{
		"finding_id": str(), "asset_id": str(), "previous_status": str(), "status": str(), "waiver_until": nullable("string"), "actor_id": str(), "link": str(),
	}),
	"integrity.alert": object([]string{"repository"}, map[string]any{
		"source": str(), "kind": str(), "severity": str(), "title": str(), "repository": str(), "ref": str(), "asset_id": str(), "finding_id": str(), "findings": array(findingBriefSchema), "link": str(),
	}),
	"feed.stale": object([]string{"feed", "detail"}, map[string]any{"feed": str(), "source": str(), "source_id": str(), "failures": integer(), "detail": str()}),
	"connection.degraded": object([]string{"connection_id", "name", "provider", "check"}, map[string]any{
		"connection_id": str(), "name": str(), "provider": str(), "check": str(), "state": str(), "problems": array(str()), "link": str(),
	}),
	"maintenance.completed": object([]string{"trigger", "report"}, map[string]any{"trigger": str(), "report": map[string]any{"type": "object"}}),
	"dependency_track.upload_failed": object([]string{"upload_id", "project", "version", "stage", "error"}, map[string]any{
		"upload_id": str(), "assessment_id": str(), "asset_id": str(), "project": str(), "version": str(), "stage": enum("upload", "processing"), "error": str(),
	}),
	"system.degraded": object([]string{"status", "previous_status", "components", "since"}, map[string]any{
		"status": enum("degraded", "down"), "previous_status": enum("ok", "degraded", "down"), "since": map[string]any{"type": "string", "format": "date-time"},
		"components": array(object([]string{"name", "status"}, map[string]any{"name": str(), "status": enum("degraded", "down"), "detail": str()})),
	}),
	"system.recovered": object([]string{"status", "previous_status", "since", "duration_seconds"}, map[string]any{
		"status": enum("ok"), "previous_status": enum("degraded", "down"), "since": map[string]any{"type": "string", "format": "date-time"}, "duration_seconds": integer(),
	}),
	"qa.completed": qaData,
	"qa.failed":    qaData,
	"ping":         object(nil, map[string]any{}),
}

// EventSchema returns the JSON Schema of an event type at a version.
func EventSchema(eventType string, version int) (json.RawMessage, bool) {
	data, ok := eventData[eventType]
	if !ok || version != SchemaVersion {
		return nil, false
	}
	schema := map[string]any{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"$id":     Link(fmt.Sprintf("/schemas/events/%s/%d", eventType, version)),
		"title":   "SCRS " + eventType + " event, version " + fmt.Sprint(version),
		"type":    "object", "required": []string{"event", "data"}, "additionalProperties": false,
		"properties": map[string]any{
			"event": object([]string{"id", "type", "version", "time"}, map[string]any{
				"id": map[string]any{"type": "string", "format": "uuid"}, "type": map[string]any{"const": eventType}, "version": map[string]any{"const": version},
				"time": map[string]any{"type": "string", "format": "date-time"}, "profile": map[string]any{"enum": []string{"summary", "full", "agent"}},
			}),
			"data": data,
		},
	}
	out, _ := json.MarshalIndent(schema, "", " ")
	return out, true
}

// EventTypes lists the event types with schemas, sorted.
func EventTypes() []string {
	out := make([]string, 0, len(eventData))
	for t := range eventData {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}
