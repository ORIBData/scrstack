package assessments

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Job is the common view of the platform's queued work: assessments, QA runs
// and test generation, AI summaries and reviews, compliance reports, git
// mirrors and Dependency-Track uploads. Each keeps its own table and its own
// endpoints; this view only normalises how they are listed.
type Job struct {
	ID   uuid.UUID `json:"id"`
	Kind string    `json:"kind"`
	// Status is queued, running, succeeded, failed or cancelled for every
	// kind; State is the kind's own value (a QA run is `passed` or `failed`
	// when its tests did, both a succeeded job).
	Status       string     `json:"status"`
	State        string     `json:"state"`
	AssetID      *uuid.UUID `json:"asset_id"`
	AssessmentID *uuid.UUID `json:"assessment_id"`
	RequestedBy  string     `json:"requested_by"`
	Attempts     int        `json:"attempts"`
	Error        string     `json:"error,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	CompletedAt  *time.Time `json:"completed_at"`
	// Resource is the path of the kind's own endpoint for this job.
	Resource string `json:"resource"`
}

// JobKinds lists the kinds in the order the contract documents them.
var JobKinds = []string{"assessment", "qa_run", "qa_generation", "ai_summary", "ai_review", "report", "mirror", "dependency_track_upload"}

// JobStatuses are the normalised statuses.
var JobStatuses = []string{"queued", "running", "succeeded", "failed", "cancelled"}

// JobFilter narrows a job listing; zero values match everything. The page
// starts after (BeforeAt, BeforeID) in newest-first order.
type JobFilter struct {
	Kind, Status string
	Asset        uuid.UUID
	Since        *time.Time
	BeforeAt     *time.Time
	BeforeID     uuid.UUID
	Limit        int
}

func (s *Store) jobsSQL() string {
	sc := s.schema
	return `SELECT kind,id,asset_id,assessment_id,state,status,requested_by,attempts,error,created_at,completed_at FROM (
SELECT 'assessment' AS kind,id,asset_id,id AS assessment_id,status AS state,CASE status WHEN 'superseded' THEN 'cancelled' ELSE status END AS status,requested_by,attempts,error,created_at,completed_at FROM ` + sc + `.assessments
UNION ALL SELECT 'qa_run',id,asset_id,assessment_id,status,CASE status WHEN 'queued' THEN 'queued' WHEN 'submitted' THEN 'running' WHEN 'running' THEN 'running' WHEN 'passed' THEN 'succeeded' WHEN 'failed' THEN 'succeeded' WHEN 'error' THEN 'failed' ELSE 'cancelled' END,requested_by,attempts,error,created_at,completed_at FROM ` + sc + `.qa_runs
UNION ALL SELECT 'qa_generation',id,asset_id,assessment_id,status,status,requested_by,attempts,error,created_at,completed_at FROM ` + sc + `.qa_generations
UNION ALL SELECT 'ai_summary',id,asset_id,assessment_id,status,status,requested_by,attempts,error,created_at,completed_at FROM ` + sc + `.ai_summaries
UNION ALL SELECT 'ai_review',id,asset_id,assessment_id,status,status,requested_by,attempts,error,created_at,completed_at FROM ` + sc + `.ai_reviews
UNION ALL SELECT 'report',id,NULL::uuid,NULL::uuid,status,status,COALESCE(requested_by::text,''),attempts,error,created_at,completed_at FROM ` + sc + `.reports
UNION ALL SELECT 'mirror',id,asset_id,NULL::uuid,status,CASE status WHEN 'pruned' THEN 'succeeded' ELSE status END,requested_by,0,error,created_at,completed_at FROM ` + sc + `.asset_mirrors
UNION ALL SELECT 'dependency_track_upload',id,asset_id,assessment_id,status,CASE status WHEN 'sending' THEN 'running' WHEN 'uploaded' THEN 'succeeded' ELSE status END,'',attempts,error,created_at,uploaded_at FROM ` + sc + `.dtrack_uploads
) j`
}

func scanJob(row pgx.Row) (Job, error) {
	var j Job
	err := row.Scan(&j.Kind, &j.ID, &j.AssetID, &j.AssessmentID, &j.State, &j.Status, &j.RequestedBy, &j.Attempts, &j.Error, &j.CreatedAt, &j.CompletedAt)
	j.Resource = jobResource(j)
	return j, err
}

// jobResource names the endpoint that serves a job of each kind.
func jobResource(j Job) string {
	id := j.ID.String()
	switch j.Kind {
	case "assessment":
		return "/assessments/" + id
	case "qa_run":
		return "/qa/runs/" + id
	case "qa_generation":
		return "/qa/generations/" + id
	case "ai_summary":
		return "/summary-jobs/" + id
	case "ai_review":
		return "/ai-reviews/" + id
	case "report":
		return "/reports/" + id
	case "mirror":
		if j.AssetID != nil {
			return "/assets/" + j.AssetID.String() + "/mirrors"
		}
	case "dependency_track_upload":
		return "/integrations/dependency-track/uploads"
	}
	return ""
}

func validJobKind(kind string) bool {
	for _, k := range JobKinds {
		if k == kind {
			return true
		}
	}
	return false
}

func validJobStatus(status string) bool {
	for _, v := range JobStatuses {
		if v == status {
			return true
		}
	}
	return false
}

// Jobs lists jobs of every kind, newest first (at most 200 per page).
func (s *Store) Jobs(ctx context.Context, f JobFilter) ([]Job, error) {
	if (f.Kind != "" && !validJobKind(f.Kind)) || (f.Status != "" && !validJobStatus(f.Status)) {
		return nil, ErrInput
	}
	if f.Limit < 1 || f.Limit > 200 {
		f.Limit = 50
	}
	rows, err := s.pool.Query(ctx, s.jobsSQL()+` WHERE ($1='' OR kind=$1) AND ($2='' OR status=$2) AND ($3='00000000-0000-0000-0000-000000000000'::uuid OR asset_id=$3) AND ($4::timestamptz IS NULL OR created_at>=$4) AND ($5::timestamptz IS NULL OR (created_at,id)<($5,$6)) ORDER BY created_at DESC,id DESC LIMIT $7`,
		f.Kind, f.Status, f.Asset, f.Since, f.BeforeAt, f.BeforeID, f.Limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// JobByID finds a job in whichever table holds it.
func (s *Store) JobByID(ctx context.Context, id uuid.UUID) (Job, error) {
	j, err := scanJob(s.pool.QueryRow(ctx, s.jobsSQL()+` WHERE id=$1 LIMIT 1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Job{}, ErrNotFound
	}
	return j, err
}

// ErrJobNotCancellable means the job's kind has no way to stop it.
var ErrJobNotCancellable = errors.New("this kind of job cannot be cancelled")

// CancelJob stops a queued or running job of a kind that supports it:
// assessments and QA runs. A finished job answers ErrConflict (assessments) or
// ErrQAState (QA runs).
func (s *Store) CancelJob(ctx context.Context, id, actor uuid.UUID, by string) (Job, error) {
	j, err := s.JobByID(ctx, id)
	if err != nil {
		return Job{}, err
	}
	switch j.Kind {
	case "assessment":
		err = s.Cancel(ctx, id, actor)
	case "qa_run":
		_, err = s.CancelQARun(ctx, id, by)
	default:
		return j, ErrJobNotCancellable
	}
	if err != nil {
		return j, err
	}
	return s.JobByID(ctx, id)
}
