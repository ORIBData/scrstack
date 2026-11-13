package assessments

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
)

// VEX exports an OpenVEX 0.2.0 document for an assessment's vulnerability and
// malicious-package findings, with status from register triage (M7). Triage
// reasons are operator statements; package data comes from the snapshot.
func (s *Store) VEX(ctx context.Context, id uuid.UUID) (json.RawMessage, error) {
	a, err := s.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `SELECT af.snapshot,COALESCE(CASE WHEN f.status='accepted' AND f.waiver_until<=clock_timestamp() THEN 'open' ELSE f.status END,'open'),f.waiver_until,COALESCE((SELECT e.details->>'reason' FROM `+s.schema+`.finding_events e WHERE e.finding_id=af.finding_id AND e.action='status_changed' ORDER BY e.id DESC LIMIT 1),'') FROM `+s.schema+`.assessment_findings af LEFT JOIN `+s.schema+`.findings f ON f.id=af.finding_id WHERE af.assessment_id=$1 AND af.snapshot->>'type' IN ('vulnerability','malicious_dependency') ORDER BY af.snapshot->>'advisory_id',af.finding_id`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	statements := []map[string]any{}
	for rows.Next() {
		var raw []byte
		var status, reason string
		var until *time.Time
		if err := rows.Scan(&raw, &status, &until, &reason); err != nil {
			return nil, err
		}
		var f Finding
		if err := json.Unmarshal(raw, &f); err != nil {
			return nil, err
		}
		var guidance struct {
			Fixed   []string `json:"fixed_versions"`
			Aliases []string `json:"aliases"`
		}
		_ = json.Unmarshal(f.Guidance, &guidance)
		if guidance.Aliases == nil {
			guidance.Aliases = []string{}
		}
		statement := map[string]any{
			"vulnerability": map[string]any{"name": f.AdvisoryID, "aliases": guidance.Aliases},
			"products":      []map[string]any{{"@id": f.Component.PURL}},
		}
		reason = clean(reason, 512)
		switch status {
		case "false_positive":
			statement["status"] = "not_affected"
			statement["impact_statement"] = "Marked false positive in the SCRS risk register: " + reason
		case "fixed":
			statement["status"] = "fixed"
		case "accepted":
			statement["status"] = "affected"
			statement["action_statement"] = "Risk accepted until " + until.UTC().Format(time.RFC3339) + ": " + reason
		case "suppressed":
			statement["status"] = "affected"
			statement["action_statement"] = "Suppressed by policy in the SCRS risk register: " + reason
		default:
			statement["status"] = "affected"
			action := "Upgrade to a fixed version and rerun the assessment."
			if len(guidance.Fixed) > 0 {
				action = "Upgrade to " + strings.Join(guidance.Fixed, " or ") + " and rerun the assessment."
			}
			statement["action_statement"] = action
		}
		statements = append(statements, statement)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	timestamp := a.CreatedAt
	if a.CompletedAt != nil {
		timestamp = *a.CompletedAt
	}
	return json.Marshal(map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        notify.Link("/assessments/" + id.String() + "/vex"),
		"author":     "SCRS",
		"timestamp":  timestamp.UTC().Format(time.RFC3339),
		"version":    1,
		"tooling":    "SCRS register export",
		"statements": statements,
	})
}
