package assessments

import (
	"context"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Summary is the default event payload (TRG-008): ids, verdict, counts and
// links. It carries no file contents, evidence or secrets.
func Summary(a Assessment) map[string]any {
	kind := "scan"
	if a.Request.Remediation != nil {
		kind = "remediation_plan"
	}
	self := "/assessments/" + a.ID.String()
	return map[string]any{
		"assessment": map[string]any{
			"id": a.ID, "kind": kind, "status": a.Status, "verdict": a.Verdict, "counts": a.Counts,
			"asset_id": a.AssetID, "connection_id": a.ConnectionID, "repository": a.Request.Target.Repository,
			"ref": a.Request.Target.Ref, "commit": a.Commit, "ref_moved": a.RefMoved, "pull_request": a.Request.Target.PullRequest,
			"requested_by": a.RequestedBy, "trigger": a.Request.Trigger, "request_id": a.RequestID, "error": a.Error,
			"created_at": a.CreatedAt, "completed_at": a.CompletedAt,
		},
		"links": map[string]string{
			"self": notify.Link(self), "findings": notify.Link(self + "/findings"), "sbom": notify.Link(self + "/sbom"),
			"report": notify.Link(self + "/report?format=md"), "context": notify.Link(self + "/context?profile=full"),
		},
	}
}

func findingBrief(f Finding) map[string]any {
	return map[string]any{
		"id": f.ID, "type": f.Type, "severity": f.Severity, "score": f.Score, "advisory_id": f.AdvisoryID,
		"title": f.Title, "change": f.Change, "component": f.Component, "link": notify.Link("/register/" + f.ID.String() + "/events"),
	}
}

// emitCompletion publishes assessment.completed plus, for new register
// entries, finding.created and (for integrity entries) integrity.alert.
func (s *Store) emitCompletion(ctx context.Context, tx pgx.Tx, a Assessment, created []Finding) error {
	if _, err := notify.Emit(ctx, tx, s.schema, "assessment.completed", Summary(a), a.Request.Notify); err != nil {
		return err
	}
	if len(created) == 0 {
		return nil
	}
	var briefs, integrity []map[string]any
	for _, f := range created {
		if len(briefs) < 100 {
			briefs = append(briefs, findingBrief(f))
		}
		if f.Type == "integrity" {
			integrity = append(integrity, findingBrief(f))
		}
	}
	base := map[string]any{"assessment_id": a.ID, "asset_id": a.AssetID, "repository": a.Request.Target.Repository, "ref": a.Request.Target.Ref, "commit": a.Commit}
	data := map[string]any{"total": len(created), "truncated": len(created) > len(briefs), "findings": briefs}
	for k, v := range base {
		data[k] = v
	}
	if _, err := notify.Emit(ctx, tx, s.schema, "finding.created", data, nil); err != nil {
		return err
	}
	if len(integrity) > 0 {
		alert := map[string]any{"source": "assessment", "findings": integrity}
		for k, v := range base {
			alert[k] = v
		}
		if _, err := notify.Emit(ctx, tx, s.schema, "integrity.alert", alert, nil); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) emitFailed(ctx context.Context, tx pgx.Tx, id uuid.UUID) error {
	a, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE id=$1`, id))
	if err != nil {
		return err
	}
	_, err = notify.Emit(ctx, tx, s.schema, "assessment.failed", Summary(a), a.Request.Notify)
	return err
}
