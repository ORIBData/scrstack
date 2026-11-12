package assessments

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) Complete(ctx context.Context, a Assessment, r Result) error {
	if !commitPattern.MatchString(r.Commit) || len(r.Components) > 20000 || len(r.Findings) > 10000 || !digestPattern.MatchString(r.SBOMSHA256) || r.SBOMKey != "sbom/"+r.SBOMSHA256+".cdx.json" {
		return ErrInput
	}
	required := map[string]bool{"resolve": false, "fetch": false, "inventory": false, "sbom": false, "match_vuln": false, "match_malicious": false, "malware": false, "ioc": false, "integrity": false}
	for _, stage := range r.Stages {
		if _, ok := required[stage.Name]; ok {
			required[stage.Name] = stage.Status == "ok"
		}
	}
	for _, ok := range required {
		if !ok {
			r.Complete = false
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var valid bool
	err = tx.QueryRow(ctx, `SELECT status='running' AND lease=$2 AND lease_until>clock_timestamp() FROM `+s.schema+`.assessments WHERE id=$1 FOR UPDATE`, a.ID, a.Lease).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrLease
	}
	err = tx.QueryRow(ctx, `SELECT enabled AND configuration_revision=$2 FROM `+s.schema+`.connections WHERE id=$1 FOR SHARE`, a.ConnectionID, a.ConnectionRevision).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrScope
	}
	err = tx.QueryRow(ctx, `SELECT flags->>'in_scope'='true' AND flags->>'accessible'='true' FROM `+s.schema+`.assets WHERE id=$1 AND connection_id=$2 FOR SHARE`, a.AssetID, a.ConnectionID).Scan(&valid)
	if err != nil {
		return err
	}
	if !valid {
		return ErrScope
	}
	batch := &pgx.Batch{}
	for i, component := range r.Components {
		body, _ := json.Marshal(component)
		batch.Queue(`INSERT INTO `+s.schema+`.components(assessment_id,ordinal,body) VALUES($1,$2,$3)`, a.ID, i, body)
	}
	seen := map[string]bool{}
	unique := []Finding{}
	for _, f := range r.Findings {
		f.Fingerprint = fingerprint(a, f)
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		unique = append(unique, f)
		f.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(f.Fingerprint))
		f.AssetID = a.AssetID
		f.Ref = a.Request.Target.Ref
		f.Status = "open"
		f.FirstSeen = time.Now().UTC()
		f.LastSeen = f.FirstSeen
		if !json.Valid(f.Evidence) || !json.Valid(f.Guidance) || f.Score < 0 || f.Score > 100 {
			return ErrInput
		}
		component, _ := json.Marshal(f.Component)
		snapshot, _ := json.Marshal(f)
		batch.Queue(`INSERT INTO `+s.schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance,last_assessment_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(fingerprint) DO UPDATE SET last_seen=clock_timestamp(),last_assessment_id=EXCLUDED.last_assessment_id,evidence=EXCLUDED.evidence,guidance=EXCLUDED.guidance,severity=EXCLUDED.severity,score=EXCLUDED.score,status=CASE WHEN findings.status='fixed' OR (findings.status='accepted' AND findings.waiver_until<=clock_timestamp()) THEN 'open' ELSE findings.status END,revision=findings.revision+1`, f.ID, f.AssetID, f.Fingerprint, f.Ref, f.Type, f.AdvisoryID, f.Title, f.Severity, f.Score, component, f.Evidence, f.Guidance, a.ID)
		batch.Queue(`INSERT INTO `+s.schema+`.assessment_findings(assessment_id,finding_id,snapshot) VALUES($1,$2,$3)`, a.ID, f.ID, snapshot)
		batch.Queue(`INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'detected',$2)`, f.ID, json.RawMessage(`{"assessment_id":"`+a.ID.String()+`"}`))
	}
	if err = tx.SendBatch(ctx, batch).Close(); err != nil {
		return err
	}
	// Only complete scans of a currently resolved ref can close prior findings.
	if r.Complete && !r.RefMoved && a.Request.Target.Commit == "" && a.Request.Target.Ref != "" {
		_, err = tx.Exec(ctx, `WITH closed AS (UPDATE `+s.schema+`.findings SET status='fixed',revision=revision+1 WHERE asset_id=$1 AND ref=$2 AND last_assessment_id<>$3 AND status IN ('open','triaged','in_progress') RETURNING id) INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) SELECT id,'fixed_by_complete_scan',jsonb_build_object('assessment_id',$3::text) FROM closed`, a.AssetID, a.Request.Target.Ref, a.ID)
		if err != nil {
			return err
		}
	}
	r.Findings = unique
	v, counts := verdict(r)
	stages, _ := json.Marshal(r.Stages)
	countJSON, _ := json.Marshal(counts)
	_, err = tx.Exec(ctx, `UPDATE `+s.schema+`.assessments SET status='succeeded',verdict=$2,stages=$3,counts=$4,resolved_commit=$5,ref_moved=$6,sbom_key=$7,sbom_sha256=$8,completed_at=clock_timestamp(),lease=NULL,lease_until=NULL WHERE id=$1`, a.ID, v, stages, countJSON, r.Commit, r.RefMoved, r.SBOMKey, r.SBOMSHA256)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('assessment.completed',$1,$2)`, a.ID, countJSON); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) Components(ctx context.Context, id uuid.UUID, after int) ([]Component, error) {
	rows, err := s.pool.Query(ctx, `SELECT body FROM `+s.schema+`.components WHERE assessment_id=$1 AND ordinal>$2 ORDER BY ordinal LIMIT 101`, id, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Component{}
	for rows.Next() {
		var raw []byte
		var c Component
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) Findings(ctx context.Context, assessment, asset, after uuid.UUID) ([]Finding, error) {
	if assessment != uuid.Nil {
		rows, err := s.pool.Query(ctx, `SELECT snapshot FROM `+s.schema+`.assessment_findings WHERE assessment_id=$1 AND finding_id>$2 ORDER BY finding_id LIMIT 101`, assessment, after)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		out := []Finding{}
		for rows.Next() {
			var raw []byte
			var f Finding
			if err := rows.Scan(&raw); err != nil {
				return nil, err
			}
			if err := json.Unmarshal(raw, &f); err != nil {
				return nil, err
			}
			out = append(out, f)
		}
		return out, rows.Err()
	}

	rows, err := s.pool.Query(ctx, `SELECT f.id,f.asset_id,f.fingerprint,f.ref,f.type,f.advisory_id,f.title,f.severity,f.score,CASE WHEN f.status='accepted' AND f.waiver_until<=clock_timestamp() THEN 'open' ELSE f.status END,f.component,f.evidence,f.guidance,f.first_seen,f.last_seen,f.waiver_until FROM `+s.schema+`.findings f WHERE f.id>$1 AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR f.asset_id=$2) AND ($3='00000000-0000-0000-0000-000000000000'::uuid OR EXISTS(SELECT 1 FROM `+s.schema+`.assessment_findings af WHERE af.assessment_id=$3 AND af.finding_id=f.id)) ORDER BY f.id LIMIT 101`, after, asset, assessment)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		var f Finding
		var component []byte
		if err := rows.Scan(&f.ID, &f.AssetID, &f.Fingerprint, &f.Ref, &f.Type, &f.AdvisoryID, &f.Title, &f.Severity, &f.Score, &f.Status, &component, &f.Evidence, &f.Guidance, &f.FirstSeen, &f.LastSeen, &f.WaiverUntil); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(component, &f.Component); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
func (s *Store) Transition(ctx context.Context, id, actor uuid.UUID, status, reason string, until *time.Time) error {
	if len(reason) < 8 || len(reason) > 2000 {
		return ErrInput
	}
	switch status {
	case "open", "triaged", "in_progress", "false_positive", "suppressed":
		if until != nil {
			return ErrInput
		}
	case "accepted":
		if until == nil || !until.After(time.Now()) || until.After(time.Now().Add(90*24*time.Hour)) {
			return ErrInput
		}
	default:
		return ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.findings SET status=$2,waiver_until=$3,revision=revision+1 WHERE id=$1`, id, status, until)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	details, _ := json.Marshal(map[string]any{"status": status, "reason": reason, "expires_at": until, "actor_id": actor})
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,actor_id,action,details) VALUES($1,$2,'status_changed',$3)`, id, actor, details); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('finding.status_changed',$1,$2)`, id, details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) FindingHistory(ctx context.Context, id uuid.UUID) ([]json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, `SELECT jsonb_build_object('id',id,'action',action,'actor_id',actor_id,'details',details,'created_at',created_at) FROM `+s.schema+`.finding_events WHERE finding_id=$1 ORDER BY id DESC LIMIT 100`, id)
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
