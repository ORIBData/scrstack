package assessments

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Revision is one assessed revision (ref and commit) of an asset, described
// by its newest successful assessment.
type Revision struct {
	Ref          string     `json:"ref"`
	Commit       string     `json:"commit"`
	AssessmentID uuid.UUID  `json:"assessment_id"`
	Assessments  int        `json:"assessments"`
	Verdict      string     `json:"verdict"`
	Imported     bool       `json:"imported"`
	HasSBOM      bool       `json:"has_sbom"`
	CreatedAt    time.Time  `json:"created_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

// Revisions lists the revisions of an asset that have a successful
// assessment, newest first. ref narrows to one ref; before pages by
// created_at; limit is at most 200.
func (s *Store) Revisions(ctx context.Context, asset uuid.UUID, ref string, before *time.Time, limit int) ([]Revision, error) {
	if limit < 1 || limit > 200 || len(ref) > 255 {
		return nil, ErrInput
	}
	rows, err := s.pool.Query(ctx, `SELECT ref,commit,id,n,verdict,imported,sbom_key<>'',created_at,completed_at FROM (
		SELECT request->'target'->>'ref' AS ref,resolved_commit AS commit,id,verdict,request->'import' IS NOT NULL AS imported,sbom_key,created_at,completed_at,
			count(*) OVER w AS n,row_number() OVER (w ORDER BY created_at DESC,id DESC) AS rn
		FROM `+s.schema+`.assessments
		WHERE asset_id=$1 AND status='succeeded' AND resolved_commit<>'' AND request->'remediation' IS NULL AND ($2='' OR request->'target'->>'ref'=$2)
		WINDOW w AS (PARTITION BY request->'target'->>'ref',resolved_commit)) x
		WHERE rn=1 AND ($3::timestamptz IS NULL OR created_at<$3) ORDER BY created_at DESC,id DESC LIMIT $4`, asset, ref, before, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Revision{}
	for rows.Next() {
		var r Revision
		var kept *string
		if err := rows.Scan(&kept, &r.Commit, &r.AssessmentID, &r.Assessments, &r.Verdict, &r.Imported, &r.HasSBOM, &r.CreatedAt, &r.CompletedAt); err != nil {
			return nil, err
		}
		if kept != nil {
			r.Ref = *kept
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
