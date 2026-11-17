package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AI advisories and summaries. A job asks a language model, hosted or
// self-hosted, to write an assessment summary and advisories for the most
// important findings of one assessment. The model is shown only the fields of
// the findings-and-advisory-text allowlist (see internal/summarize), never
// code, evidence or paths. Results are stored as documents in the asset's
// chronicle (internal/knowledge), each superseding the one before it.

func aiSummarySchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.ai_summaries(id uuid PRIMARY KEY,asset_id uuid NOT NULL,assessment_id uuid NOT NULL,provider_id uuid REFERENCES ` + s + `.llm_providers(id) ON DELETE SET NULL,provider_name text NOT NULL DEFAULT '',model text NOT NULL DEFAULT '',ref text NOT NULL DEFAULT '',commit text NOT NULL DEFAULT '',options jsonb NOT NULL DEFAULT '{}',status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed')),requested_by text NOT NULL,attempts integer NOT NULL DEFAULT 0,run_after timestamptz NOT NULL DEFAULT clock_timestamp(),lease_until timestamptz,findings_considered integer NOT NULL DEFAULT 0,findings_excluded integer NOT NULL DEFAULT 0,advisories integer NOT NULL DEFAULT 0,input_tokens bigint NOT NULL DEFAULT 0,output_tokens bigint NOT NULL DEFAULT 0,incomplete text NOT NULL DEFAULT '',redactions jsonb NOT NULL DEFAULT '{}',summary_document_id uuid,error text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz)`,
		`CREATE INDEX IF NOT EXISTS ai_summaries_assessment_idx ON ` + s + `.ai_summaries(assessment_id,created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS ai_summaries_due_idx ON ` + s + `.ai_summaries(run_after) WHERE status IN ('queued','running')`,
	}
}

// ErrAISummaryProvider means the provider does not exist or is disabled.
var ErrAISummaryProvider = errors.New("llm provider not found or disabled")

// AISummaryOptions bound one job.
type AISummaryOptions struct {
	// MaxAdvisories is how many findings get an advisory, most important
	// first (default 10, at most 30).
	MaxAdvisories int `json:"max_advisories,omitempty"`
}

// AISummary is one summary job.
type AISummary struct {
	ID                 uuid.UUID        `json:"id"`
	AssetID            uuid.UUID        `json:"asset_id"`
	AssessmentID       uuid.UUID        `json:"assessment_id"`
	ProviderID         *uuid.UUID       `json:"provider_id"`
	ProviderName       string           `json:"provider_name"`
	Model              string           `json:"model"`
	Ref                string           `json:"ref"`
	Commit             string           `json:"commit"`
	Options            AISummaryOptions `json:"options"`
	Status             string           `json:"status"`
	RequestedBy        string           `json:"requested_by"`
	Attempts           int              `json:"attempts"`
	FindingsConsidered int              `json:"findings_considered"`
	FindingsExcluded   int              `json:"findings_excluded"`
	Advisories         int              `json:"advisories"`
	InputTokens        int64            `json:"input_tokens"`
	OutputTokens       int64            `json:"output_tokens"`
	Incomplete         string           `json:"incomplete,omitempty"`
	Redactions         map[string]int   `json:"redactions"`
	SummaryDocumentID  *uuid.UUID       `json:"summary_document_id,omitempty"`
	Error              string           `json:"error,omitempty"`
	CreatedAt          time.Time        `json:"created_at"`
	CompletedAt        *time.Time       `json:"completed_at,omitempty"`
}

const aiSummaryColumns = `id,asset_id,assessment_id,provider_id,provider_name,model,ref,commit,options,status,requested_by,attempts,findings_considered,findings_excluded,advisories,input_tokens,output_tokens,incomplete,redactions,summary_document_id,error,created_at,completed_at`

func scanAISummary(row pgx.Row) (AISummary, error) {
	var r AISummary
	var options, redactions []byte
	err := row.Scan(&r.ID, &r.AssetID, &r.AssessmentID, &r.ProviderID, &r.ProviderName, &r.Model, &r.Ref, &r.Commit, &options, &r.Status, &r.RequestedBy, &r.Attempts, &r.FindingsConsidered, &r.FindingsExcluded, &r.Advisories, &r.InputTokens, &r.OutputTokens, &r.Incomplete, &redactions, &r.SummaryDocumentID, &r.Error, &r.CreatedAt, &r.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	if err == nil && (json.Unmarshal(options, &r.Options) != nil || json.Unmarshal(redactions, &r.Redactions) != nil) {
		return r, errors.New("invalid AI summary data")
	}
	return r, err
}

// EnqueueAISummary queues advisories and a summary for a succeeded assessment.
// Any enabled provider may be used: the prompts hold only the allowlisted
// finding fields.
func (s *Store) EnqueueAISummary(ctx context.Context, assessment, provider uuid.UUID, o AISummaryOptions, by string) (AISummary, error) {
	if o.MaxAdvisories < 0 || o.MaxAdvisories > 30 {
		return AISummary{}, ErrInput
	}
	p, err := s.LLMProviderByID(ctx, provider)
	if err != nil || !p.Enabled {
		return AISummary{}, ErrAISummaryProvider
	}
	a, err := s.Get(ctx, assessment)
	if err != nil {
		return AISummary{}, err
	}
	if a.Status != "succeeded" || a.AssetID == uuid.Nil {
		return AISummary{}, ErrConflict
	}
	if o.MaxAdvisories == 0 {
		o.MaxAdvisories = 10
	}
	options, _ := json.Marshal(o)
	return scanAISummary(s.pool.QueryRow(ctx, `INSERT INTO `+s.schema+`.ai_summaries(id,asset_id,assessment_id,provider_id,provider_name,model,ref,commit,options,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+aiSummaryColumns, uuid.New(), a.AssetID, a.ID, p.ID, p.Name, p.Model, a.Request.Target.Ref, a.Commit, options, clip(by, 100)))
}

// AISummaryLease bounds one job between claims.
const AISummaryLease = 30 * time.Minute

// ClaimAISummary leases the next queued job, or one whose worker died. A job
// is attempted at most three times.
func (s *Store) ClaimAISummary(ctx context.Context) (AISummary, error) {
	if _, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.ai_summaries SET status='failed',error='attempts exhausted',completed_at=clock_timestamp() WHERE status='running' AND lease_until<clock_timestamp() AND attempts>=3`); err != nil {
		return AISummary{}, err
	}
	return scanAISummary(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.ai_summaries SET status='running',attempts=attempts+1,lease_until=clock_timestamp()+($1*interval '1 second') WHERE id=(SELECT id FROM `+s.schema+`.ai_summaries WHERE (status='queued' AND run_after<=clock_timestamp()) OR (status='running' AND lease_until<clock_timestamp()) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+aiSummaryColumns, int64(AISummaryLease.Seconds())))
}

// FinishAISummary ends a failed job; a failure with retry requeues it.
func (s *Store) FinishAISummary(ctx context.Context, r AISummary, failure string, retry bool) error {
	status := "failed"
	if retry && r.Attempts < 3 {
		status = "queued"
	}
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.ai_summaries SET status=$2,error=$3,lease_until=NULL,run_after=clock_timestamp()+interval '2 minutes',completed_at=CASE WHEN $2='queued' THEN NULL ELSE clock_timestamp() END WHERE id=$1`, r.ID, status, clip(failure, 1000))
	return err
}

// AISummaryResult is what a finished job produced.
type AISummaryResult struct {
	Considered, Excluded, Advisories int
	InputTokens, OutputTokens        int64
	Incomplete                       string
	Redactions                       map[string]int
	SummaryDocumentID                *uuid.UUID
}

// CompleteAISummary records a finished job.
func (s *Store) CompleteAISummary(ctx context.Context, r AISummary, res AISummaryResult) (AISummary, error) {
	redactions, _ := json.Marshal(res.Redactions)
	if res.Redactions == nil {
		redactions = []byte(`{}`)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AISummary{}, err
	}
	defer tx.Rollback(ctx)
	done, err := scanAISummary(tx.QueryRow(ctx, `UPDATE `+s.schema+`.ai_summaries SET status='succeeded',findings_considered=$2,findings_excluded=$3,advisories=$4,input_tokens=$5,output_tokens=$6,incomplete=$7,redactions=$8,summary_document_id=$9,error='',lease_until=NULL,completed_at=clock_timestamp() WHERE id=$1 AND status='running' RETURNING `+aiSummaryColumns,
		r.ID, res.Considered, res.Excluded, res.Advisories, res.InputTokens, res.OutputTokens, clip(res.Incomplete, 300), redactions, res.SummaryDocumentID))
	if errors.Is(err, ErrNotFound) {
		return AISummary{}, ErrConflict
	}
	if err != nil {
		return AISummary{}, err
	}
	details, _ := json.Marshal(map[string]any{"summary_job_id": r.ID, "assessment_id": r.AssessmentID, "advisories": res.Advisories, "model": r.Model})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('ai_summary.completed',$1,$2)`, r.AssetID, details); err != nil {
		return AISummary{}, err
	}
	return done, tx.Commit(ctx)
}

// AISummaryByID returns one job.
func (s *Store) AISummaryByID(ctx context.Context, id uuid.UUID) (AISummary, error) {
	return scanAISummary(s.pool.QueryRow(ctx, `SELECT `+aiSummaryColumns+` FROM `+s.schema+`.ai_summaries WHERE id=$1`, id))
}

// AISummaries lists an assessment's jobs, newest first.
func (s *Store) AISummaries(ctx context.Context, assessment uuid.UUID, limit int) ([]AISummary, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `SELECT `+aiSummaryColumns+` FROM `+s.schema+`.ai_summaries WHERE assessment_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2`, assessment, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AISummary{}
	for rows.Next() {
		r, err := scanAISummary(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AdvisoryTexts returns the upstream summary and details of advisories by ID
// (OSV, NVD and CVE.org records already fetched by SCRS), for the ids given.
func (s *Store) AdvisoryTexts(ctx context.Context, ids []string) (map[string]string, error) {
	out := map[string]string{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT id,COALESCE(record->>'summary',''),COALESCE(record->>'details','') FROM `+s.schema+`.advisory_records WHERE id=ANY($1) OR cve=ANY($1) ORDER BY origin`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id, summary, details string
		if err := rows.Scan(&id, &summary, &details); err != nil {
			return nil, err
		}
		text := strings.TrimSpace(summary)
		if details != "" {
			text = strings.TrimSpace(text + " " + details)
		}
		if _, seen := out[id]; !seen && text != "" {
			out[id] = clip(text, 1500)
		}
	}
	return out, rows.Err()
}
