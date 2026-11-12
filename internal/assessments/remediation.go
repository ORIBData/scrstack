package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"path"
	"strings"

	"github.com/google/uuid"
)

func (s *Store) EnqueuePlan(ctx context.Context, parentID, asset, actor uuid.UUID, name, key, manifest, strategy string) (Assessment, bool, error) {
	if strategy == "" {
		strategy = "in-place"
	}
	if strategy != "in-place" || len(manifest) > 512 || path.Base(manifest) != "package-lock.json" || path.Clean(manifest) != manifest || (strings.HasPrefix(manifest, "/") || strings.HasPrefix(manifest, "../")) || strings.Contains(manifest, "\\") {
		return Assessment{}, false, ErrInput
	}
	parent, err := s.Get(ctx, parentID)
	if err != nil {
		return Assessment{}, false, err
	}
	if parent.AssetID != asset || parent.Status != "succeeded" || parent.Commit == "" || parent.Request.Remediation != nil {
		return Assessment{}, false, ErrInput
	}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.components WHERE assessment_id=$1 AND body->>'path'=$2 AND body->>'ecosystem'='npm')`, parentID, manifest).Scan(&exists); err != nil {
		return Assessment{}, false, err
	}
	if !exists {
		return Assessment{}, false, ErrInput
	}
	request := parent.Request
	request.Target.Commit = parent.Commit
	request.Connection = parent.ConnectionID.String()
	request.Trigger.DeliveryID = ""
	request.Remediation = &RemediationRequest{Manifest: manifest, Strategy: strategy, Parent: parentID}
	return s.Enqueue(ctx, request, actor, name, key)
}
func (s *Store) CompletePlan(ctx context.Context, a Assessment, key, digest string) error {
	if a.Request.Remediation == nil || !digestPattern.MatchString(digest) || key != "remediation/"+digest+".json" {
		return ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var valid bool
	if err := tx.QueryRow(ctx, `SELECT status='running' AND lease=$2 AND lease_until>clock_timestamp() FROM `+s.schema+`.assessments WHERE id=$1 FOR UPDATE`, a.ID, a.Lease).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrLease
	}
	if err := tx.QueryRow(ctx, `SELECT enabled AND configuration_revision=$2 FROM `+s.schema+`.connections WHERE id=$1 FOR SHARE`, a.ConnectionID, a.ConnectionRevision).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrScope
	}
	if err := tx.QueryRow(ctx, `SELECT flags->>'in_scope'='true' AND flags->>'accessible'='true' FROM `+s.schema+`.assets WHERE id=$1 FOR SHARE`, a.AssetID).Scan(&valid); err != nil {
		return err
	}
	if !valid {
		return ErrScope
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.remediation_results(assessment_id,artifact_key,sha256) VALUES($1,$2,$3)`, a.ID, key, digest); err != nil {
		return err
	}
	stages, _ := json.Marshal([]Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}, {Name: "remediation_plan", Status: "ok", Detail: "Advice only; repository unchanged; verify proposed changes with a fresh assessment"}})
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.assessments SET status='succeeded',verdict='incomplete',stages=$2,completed_at=clock_timestamp(),lease=NULL,lease_until=NULL WHERE id=$1`, a.ID, stages); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"sha256": digest, "parent_assessment_id": a.Request.Remediation.Parent})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('remediation.plan_created',$1,$2)`, a.ID, details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) PlanKey(ctx context.Context, id uuid.UUID) (string, error) {
	var key string
	err := s.pool.QueryRow(ctx, `SELECT artifact_key FROM `+s.schema+`.remediation_results WHERE assessment_id=$1`, id).Scan(&key)
	return key, err
}

// DispatchAutomaticPlan uses a durable outbox. A crash after enqueue is recovered
// by looking up the parent/manifest pair before enqueueing again.
func (s *Store) DispatchAutomaticPlan(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	// A dispatcher calls admission on another pooled connection. Let competing
	// dispatchers return immediately instead of each holding a pool slot waiting.
	var dispatch bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext($1))`, s.schema+".automatic_remediation_dispatch").Scan(&dispatch); err != nil {
		return err
	}
	if !dispatch {
		return nil
	}
	var parent uuid.UUID
	var manifest string
	err = tx.QueryRow(ctx, `SELECT parent_id,manifest FROM `+s.schema+`.automatic_remediations WHERE status='pending' ORDER BY parent_id,manifest LIMIT 1 FOR UPDATE SKIP LOCKED`).Scan(&parent, &manifest)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	var id uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM `+s.schema+`.assessments WHERE request->'remediation'->>'parent_assessment_id'=$1 AND request->'remediation'->>'manifest'=$2 LIMIT 1`, parent.String(), manifest).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		a, loadErr := s.Get(ctx, parent)
		if loadErr != nil {
			return loadErr
		}
		plan, _, enqueueErr := s.EnqueuePlan(ctx, parent, a.AssetID, a.ActorID, a.RequestedBy, "auto-"+Hash([]byte(parent.String()+manifest)), manifest, "in-place")
		if enqueueErr != nil {
			if errors.Is(enqueueErr, ErrScope) || errors.Is(enqueueErr, ErrInput) {
				_, err = tx.Exec(ctx, `UPDATE `+s.schema+`.automatic_remediations SET status='blocked',error='Asset scope or parent eligibility changed' WHERE parent_id=$1 AND manifest=$2`, parent, manifest)
				if err != nil {
					return err
				}
				return tx.Commit(ctx)
			}
			return enqueueErr
		}
		id = plan.ID
	} else if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE `+s.schema+`.automatic_remediations SET status='queued',assessment_id=$3 WHERE parent_id=$1 AND manifest=$2`, parent, manifest, id)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) AutomaticPlans(ctx context.Context, parent uuid.UUID) ([]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, `SELECT jsonb_build_object('manifest',p.manifest,'dispatch_status',p.status,'assessment_id',p.assessment_id,'job_status',a.status,'error',p.error) FROM `+s.schema+`.automatic_remediations p LEFT JOIN `+s.schema+`.assessments a ON a.id=p.assessment_id WHERE p.parent_id=$1 ORDER BY manifest`, parent)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		out = append(out, raw)
	}
	return out, rows.Err()
}
