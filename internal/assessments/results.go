package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) Complete(ctx context.Context, a Assessment, r Result) error {
	if !validRevision(r.Commit) || len(r.Components) > 20000 || len(r.Findings) > 10000 || len(r.Files) > 10000 {
		return ErrInput
	}
	required := map[string]bool{"resolve": false, "fetch": false, "inventory": false, "sbom": false, "match_vuln": false, "match_malicious": false, "malware": false, "yara": false, "ioc": false, "integrity": false}
	imported := a.Request.Import != nil
	if imported {
		// An import is complete for what its tool reports; it carries no SBOM.
		required = map[string]bool{"import": false}
	}
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
	if r.SBOMKey == "" {
		if !imported {
			r.Complete = false
		}
		if r.SBOMSHA256 != "" {
			return ErrInput
		}
	} else if !digestPattern.MatchString(r.SBOMSHA256) || r.SBOMKey != "sbom/"+r.SBOMSHA256+".cdx.json" {
		return ErrInput
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
	// Compare immutable file inventories within the same asset/ref. This is a
	// change baseline, not a last-known-good security designation.
	if len(r.Files) > 0 {
		var previous []byte
		previousErr := tx.QueryRow(ctx, `SELECT f.body FROM `+s.schema+`.assessment_files f JOIN `+s.schema+`.assessments p ON p.id=f.assessment_id WHERE p.asset_id=$1 AND p.request->'target'->>'ref'=$2 AND p.status='succeeded' AND p.request->'remediation' IS NULL AND p.request->'import' IS NULL ORDER BY p.created_at DESC,p.id DESC LIMIT 1`, a.AssetID, a.Request.Target.Ref).Scan(&previous)
		if previousErr != nil && previousErr != pgx.ErrNoRows {
			return previousErr
		}
		if previousErr == nil {
			var prior []FileEvidence
			if json.Unmarshal(previous, &prior) != nil {
				return ErrInput
			}
			before := map[string]string{}
			after := map[string]string{}
			for _, f := range prior {
				if strings.HasPrefix(f.Path, ".github/workflows/") {
					before[f.Path] = f.SHA256
				}
			}
			for _, f := range r.Files {
				if strings.HasPrefix(f.Path, ".github/workflows/") {
					after[f.Path] = f.SHA256
				}
			}
			changes := map[string]string{}
			for path, digest := range after {
				if before[path] != digest {
					changes[path] = "added_or_modified"
				}
			}
			for path := range before {
				if after[path] == "" {
					changes[path] = "deleted"
				}
			}
			for path, change := range changes {
				if len(r.Findings) >= 10000 {
					r.Complete = false
					break
				}
				evidence, _ := json.Marshal(map[string]string{"path": path, "change": change, "before_sha256": before[path], "after_sha256": after[path]})
				r.Findings = append(r.Findings, Finding{Type: "integrity", AdvisoryID: "SCRS-WORKFLOW-CHANGE", Title: "Workflow file changed since prior assessed revision", Severity: "high", Score: 60, Component: Component{Path: path}, Evidence: evidence, Guidance: json.RawMessage(`{"summary":"Review workflow permissions, secret access, external actions and triggering branches before promotion.","automatic_changes":false}`)})
			}
		}
	}
	files, err := json.Marshal(r.Files)
	if err != nil {
		return ErrInput
	}
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.assessment_files(assessment_id,body) VALUES($1,$2)`, a.ID, files); err != nil {
		return err
	}
	// Baseline: the newest prior successful scan of the same ref, or of the
	// base branch for a pull request. It decides new versus existing (TRG-006).
	baseRef := a.Request.Target.Ref
	if pr := a.Request.Target.PullRequest; pr != nil {
		baseRef = pr.BaseRef
	}
	var baseline uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM `+s.schema+`.assessments WHERE asset_id=$1 AND request->'target'->>'ref'=$2 AND status='succeeded' AND request->'remediation' IS NULL AND request->'import' IS NULL AND id<>$3 ORDER BY created_at DESC,id DESC LIMIT 1`, a.AssetID, baseRef, a.ID).Scan(&baseline)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	baseFindings, err := stringSet(ctx, tx, `SELECT concat_ws(chr(31),snapshot->>'type',snapshot->>'advisory_id',snapshot->'component'->>'purl',snapshot->'component'->>'path') FROM `+s.schema+`.assessment_findings WHERE assessment_id=$1`, baseline)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	unique := []Finding{}
	for _, f := range r.Findings {
		f.Fingerprint = fingerprint(a, f)
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		f.Change = "new"
		if baseline != uuid.Nil && baseFindings[strings.Join([]string{f.Type, f.AdvisoryID, f.Component.PURL, f.Component.Path}, "\x1f")] {
			f.Change = "existing"
		}
		unique = append(unique, f)
	}
	fingerprints := make([]string, len(unique))
	for i, f := range unique {
		fingerprints[i] = f.Fingerprint
	}
	// Register entries that did not exist before this scan drive finding.created.
	registered, err := stringSet(ctx, tx, `SELECT fingerprint FROM `+s.schema+`.findings WHERE fingerprint=ANY($1)`, fingerprints)
	if err != nil {
		return err
	}
	diff, err := s.componentDiff(ctx, tx, baseline, r.Components)
	if err != nil {
		return err
	}
	batch := &pgx.Batch{}
	for i, component := range r.Components {
		body, _ := json.Marshal(component)
		batch.Queue(`INSERT INTO `+s.schema+`.components(assessment_id,ordinal,body) VALUES($1,$2,$3)`, a.ID, i, body)
	}
	var created []Finding
	for i := range unique {
		f := &unique[i]
		f.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(f.Fingerprint))
		f.AssetID = a.AssetID
		f.Ref = a.Request.Target.Ref
		f.Status = "open"
		f.FirstSeen = time.Now().UTC()
		f.LastSeen = f.FirstSeen
		if !json.Valid(f.Evidence) || !json.Valid(f.Guidance) || f.Score < 0 || f.Score > 100 {
			return ErrInput
		}
		if !registered[f.Fingerprint] {
			created = append(created, *f)
		}
		component, _ := json.Marshal(f.Component)
		snapshot, _ := json.Marshal(f)
		batch.Queue(`INSERT INTO `+s.schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance,last_assessment_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(fingerprint) DO UPDATE SET last_seen=clock_timestamp(),last_assessment_id=EXCLUDED.last_assessment_id,evidence=EXCLUDED.evidence,guidance=EXCLUDED.guidance,severity=EXCLUDED.severity,score=EXCLUDED.score,status=CASE WHEN findings.status='fixed' OR (findings.status='accepted' AND findings.waiver_until<=clock_timestamp()) THEN 'open' ELSE findings.status END,revision=findings.revision+1`, f.ID, f.AssetID, f.Fingerprint, f.Ref, f.Type, f.AdvisoryID, f.Title, f.Severity, f.Score, component, f.Evidence, f.Guidance, a.ID)
		batch.Queue(`INSERT INTO `+s.schema+`.assessment_findings(assessment_id,finding_id,snapshot) VALUES($1,$2,$3)`, a.ID, f.ID, snapshot)
		batch.Queue(`INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'detected',$2)`, f.ID, json.RawMessage(`{"assessment_id":"`+a.ID.String()+`"}`))
	}
	if a.Request.AutoRemediation && a.Request.Remediation == nil {
		manifests := map[string]bool{}
		for _, c := range r.Components {
			if (c.Ecosystem == "npm" && path.Base(c.Path) == "package-lock.json") || (c.Ecosystem == "Maven" && path.Base(c.Path) == "pom.xml") {
				manifests[c.Path] = true
			}
		}
		for manifest := range manifests {
			batch.Queue(`INSERT INTO `+s.schema+`.automatic_remediations(parent_id,manifest) VALUES($1,$2) ON CONFLICT DO NOTHING`, a.ID, manifest)
		}
	}
	if err = tx.SendBatch(ctx, batch).Close(); err != nil {
		return err
	}
	// Only a scan of the ref's current head can close prior findings, and only
	// for finding types whose producing stages completed. A webhook push names
	// both commit and ref; ref_moved tells whether that commit is still the head.
	// Change records (workflow changes, provider events) need human review and
	// are never closed by absence.
	if closable := closableTypes(r.Stages); len(closable) > 0 && !r.RefMoved && a.Request.Target.Ref != "" {
		_, err = tx.Exec(ctx, `WITH closed AS (UPDATE `+s.schema+`.findings SET status='fixed',revision=revision+1 WHERE asset_id=$1 AND ref=$2 AND last_assessment_id<>$3 AND type=ANY($4) AND advisory_id<>'SCRS-WORKFLOW-CHANGE' AND advisory_id NOT LIKE 'SCRS-EVENT-%' AND COALESCE(evidence->>'source','') NOT IN ('trivy','sarif') AND status IN ('open','triaged','in_progress') RETURNING id) INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) SELECT id,'fixed_by_complete_scan',jsonb_build_object('assessment_id',$3::text) FROM closed`, a.AssetID, a.Request.Target.Ref, a.ID, closable)
		if err != nil {
			return err
		}
	}
	// Imported findings are closed only by a later import of the same tool
	// whose caller declares it the tool's full result for this ref
	// (replace_previous). A partial run, such as secrets only, must not mark
	// the tool's other findings fixed. SCRS's own scans never close them:
	// tools name the same issue differently (CVE versus GHSA ids).
	if imp := a.Request.Import; imp != nil && imp.Replace && a.Request.Target.Ref != "" {
		tool := ""
		if imp.Format == "sarif" {
			tool = imp.Tool
		}
		_, err = tx.Exec(ctx, `WITH closed AS (UPDATE `+s.schema+`.findings SET status='fixed',revision=revision+1 WHERE asset_id=$1 AND ref=$2 AND last_assessment_id<>$3 AND evidence->>'source'=$4 AND ($5='' OR lower(evidence->>'tool')=$5) AND status IN ('open','triaged','in_progress') RETURNING id) INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) SELECT id,'fixed_by_import',jsonb_build_object('assessment_id',$3::text) FROM closed`, a.AssetID, a.Request.Target.Ref, a.ID, imp.Format, tool)
		if err != nil {
			return err
		}
	}
	r.Findings = unique
	// Register triage (waivers, suppressions) applies to the gate; snapshots keep the raw detection.
	waived, err := stringSet(ctx, tx, `SELECT fingerprint FROM `+s.schema+`.findings WHERE fingerprint=ANY($1) AND (status IN ('suppressed','false_positive') OR (status='accepted' AND waiver_until>clock_timestamp()))`, fingerprints)
	if err != nil {
		return err
	}
	v, counts := verdict(r, waived)
	stages, _ := json.Marshal(r.Stages)
	countJSON, _ := json.Marshal(counts)
	_, err = tx.Exec(ctx, `UPDATE `+s.schema+`.assessments SET status='succeeded',verdict=$2,stages=$3,counts=$4,resolved_commit=$5,ref_moved=$6,sbom_key=$7,sbom_sha256=$8,diff=$9,completed_at=clock_timestamp(),lease=NULL,lease_until=NULL WHERE id=$1`, a.ID, v, stages, countJSON, r.Commit, r.RefMoved, r.SBOMKey, r.SBOMSHA256, diff)
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('assessment.completed',$1,$2)`, a.ID, countJSON); err != nil {
		return err
	}
	done, err := scan(tx.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE id=$1`, a.ID))
	if err != nil {
		return err
	}
	if err := s.emitCompletion(ctx, tx, done, created); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// stringSet runs a single-column query and returns its values as a set.
func stringSet(ctx context.Context, tx pgx.Tx, query string, args ...any) (map[string]bool, error) {
	out := map[string]bool{}
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var v *string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		if v != nil {
			out[*v] = true
		}
	}
	return out, rows.Err()
}

// componentDiff compares package identities with the baseline (OUT-006 diff).
func (s *Store) componentDiff(ctx context.Context, tx pgx.Tx, baseline uuid.UUID, current []Component) ([]byte, error) {
	if baseline == uuid.Nil {
		return []byte(`{"base_assessment_id":null}`), nil
	}
	before, err := stringSet(ctx, tx, `SELECT body->>'purl' FROM `+s.schema+`.components WHERE assessment_id=$1`, baseline)
	if err != nil {
		return nil, err
	}
	after := map[string]bool{}
	for _, c := range current {
		after[c.PURL] = true
	}
	added, removed := []string{}, []string{}
	for purl := range after {
		if !before[purl] {
			added = append(added, purl)
		}
	}
	for purl := range before {
		if !after[purl] {
			removed = append(removed, purl)
		}
	}
	slices.Sort(added)
	slices.Sort(removed)
	addedTotal, removedTotal := len(added), len(removed)
	added, removed = added[:min(len(added), 200)], removed[:min(len(removed), 200)]
	return json.Marshal(map[string]any{"base_assessment_id": baseline, "components_added": added, "components_removed": removed, "added_total": addedTotal, "removed_total": removedTotal, "truncated": addedTotal > len(added) || removedTotal > len(removed)})
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
	var previous string
	var asset uuid.UUID
	err = tx.QueryRow(ctx, `SELECT status,asset_id FROM `+s.schema+`.findings WHERE id=$1 FOR UPDATE`, id).Scan(&previous, &asset)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `UPDATE `+s.schema+`.findings SET status=$2,waiver_until=$3,revision=revision+1 WHERE id=$1`, id, status, until); err != nil {
		return err
	}
	if _, err := notify.Emit(ctx, tx, s.schema, "finding.status_changed", map[string]any{"finding_id": id, "asset_id": asset, "previous_status": previous, "status": status, "waiver_until": until, "actor_id": actor, "link": notify.Link("/register/" + id.String() + "/events")}, nil); err != nil {
		return err
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

func (s *Store) Files(ctx context.Context, id uuid.UUID) (json.RawMessage, error) {
	var body json.RawMessage
	err := s.pool.QueryRow(ctx, `SELECT body FROM `+s.schema+`.assessment_files WHERE assessment_id=$1`, id).Scan(&body)
	return body, err
}
