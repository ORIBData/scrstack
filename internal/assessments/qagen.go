package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Test generation (QA module): a generation asks the profile's LLM provider
// for Karate API features (from the OpenAPI document) or unit tests (from
// source files without tests) at an assessed commit. Every file becomes a
// draft suite; drafts that fail the static checks are stored as rejected
// with their problems. API features run only after approval; unit tests are
// downloaded and committed by developers.

// QAGenerationOptions bound one generation.
type QAGenerationOptions struct {
	// MaxOperations caps API operations (api kind); untested ones go first.
	MaxOperations int `json:"max_operations,omitempty"`
	// Operations restricts generation to these "METHOD /path" keys.
	Operations []string `json:"operations,omitempty"`
	// MaxFiles caps source files (unit kind).
	MaxFiles int `json:"max_files,omitempty"`
	// Paths restricts unit generation to these source files.
	Paths []string `json:"paths,omitempty"`
}

// QAGeneration is one test-generation job.
type QAGeneration struct {
	ID           uuid.UUID           `json:"id"`
	AssetID      uuid.UUID           `json:"asset_id"`
	Kind         string              `json:"kind"`
	ProviderID   *uuid.UUID          `json:"provider_id"`
	ProviderName string              `json:"provider_name"`
	Model        string              `json:"model"`
	AssessmentID *uuid.UUID          `json:"assessment_id"`
	Ref          string              `json:"ref"`
	Commit       string              `json:"commit"`
	Options      QAGenerationOptions `json:"options"`
	Status       string              `json:"status"`
	RequestedBy  string              `json:"requested_by"`
	Attempts     int                 `json:"attempts"`
	InputTokens  int64               `json:"input_tokens"`
	OutputTokens int64               `json:"output_tokens"`
	Accepted     int                 `json:"accepted"`
	Rejected     int                 `json:"rejected"`
	Error        string              `json:"error,omitempty"`
	CreatedAt    time.Time           `json:"created_at"`
	CompletedAt  *time.Time          `json:"completed_at,omitempty"`
}

const genColumns = `id,asset_id,kind,provider_id,provider_name,model,assessment_id,ref,commit,options,status,requested_by,attempts,input_tokens,output_tokens,accepted,rejected,error,created_at,completed_at`

func scanGeneration(row pgx.Row) (QAGeneration, error) {
	var g QAGeneration
	var options []byte
	err := row.Scan(&g.ID, &g.AssetID, &g.Kind, &g.ProviderID, &g.ProviderName, &g.Model, &g.AssessmentID, &g.Ref, &g.Commit, &options, &g.Status, &g.RequestedBy, &g.Attempts, &g.InputTokens, &g.OutputTokens, &g.Accepted, &g.Rejected, &g.Error, &g.CreatedAt, &g.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return g, ErrNotFound
	}
	if err == nil && json.Unmarshal(options, &g.Options) != nil {
		return g, errors.New("invalid QA generation data")
	}
	return g, err
}

// ErrQAProvider means the profile names no enabled LLM provider, or unit
// generation was asked for without allow_source_upload.
var ErrQAProvider = errors.New("the QA profile needs an enabled llm_provider_id (and allow_source_upload for unit tests)")

// EnqueueQAGeneration queues a generation for the asset's latest
// successful git assessment.
func (s *Store) EnqueueQAGeneration(ctx context.Context, asset uuid.UUID, kind string, o QAGenerationOptions, by string) (QAGeneration, error) {
	if kind != "api" && kind != "unit" || o.MaxOperations < 0 || o.MaxOperations > 200 || o.MaxFiles < 0 || o.MaxFiles > 20 || len(o.Operations) > 200 || len(o.Paths) > 20 {
		return QAGeneration{}, ErrInput
	}
	for _, v := range append(append([]string{}, o.Operations...), o.Paths...) {
		if v == "" || len(v) > 512 {
			return QAGeneration{}, ErrInput
		}
	}
	p, err := s.QAProfileFor(ctx, asset)
	if errors.Is(err, ErrNotFound) || (err == nil && !p.Enabled) {
		return QAGeneration{}, ErrQAProfile
	}
	if err != nil {
		return QAGeneration{}, err
	}
	if p.LLMProviderID == nil || (kind == "unit" && !p.AllowSourceUpload) {
		return QAGeneration{}, ErrQAProvider
	}
	provider, err := s.LLMProviderByID(ctx, *p.LLMProviderID)
	if err != nil || !provider.Enabled {
		return QAGeneration{}, ErrQAProvider
	}
	a, err := s.qaAssessment(ctx, asset, nil)
	if err != nil {
		return QAGeneration{}, err
	}
	if a.Verdict == "fail" {
		return QAGeneration{}, ErrQABlocked
	}
	if o.MaxOperations == 0 {
		o.MaxOperations = 30
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = 5
	}
	options, _ := json.Marshal(o)
	return scanGeneration(s.pool.QueryRow(ctx, `INSERT INTO `+s.schema+`.qa_generations(id,asset_id,kind,provider_id,provider_name,model,assessment_id,ref,commit,options,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+genColumns, uuid.New(), asset, kind, provider.ID, provider.Name, provider.Model, a.ID, a.Request.Target.Ref, a.Commit, options, clip(by, 100)))
}

// QAGenerationLease bounds a generation between progress records.
const QAGenerationLease = 20 * time.Minute

// ClaimQAGeneration leases the next queued generation, or one whose worker
// died. A generation is attempted at most three times.
func (s *Store) ClaimQAGeneration(ctx context.Context) (QAGeneration, error) {
	if _, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.qa_generations SET status='failed',error='generation attempts exhausted',completed_at=clock_timestamp() WHERE status='running' AND lease_until<clock_timestamp() AND attempts>=3`); err != nil {
		return QAGeneration{}, err
	}
	return scanGeneration(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.qa_generations SET status='running',attempts=attempts+1,lease_until=clock_timestamp()+($1*interval '1 second') WHERE id=(SELECT id FROM `+s.schema+`.qa_generations WHERE (status='queued' AND run_after<=clock_timestamp()) OR (status='running' AND lease_until<clock_timestamp()) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+genColumns, int64(QAGenerationLease.Seconds())))
}

// QASuite is one generated test file.
type QASuite struct {
	ID           uuid.UUID  `json:"id"`
	AssetID      uuid.UUID  `json:"asset_id"`
	GenerationID *uuid.UUID `json:"generation_id"`
	Kind         string     `json:"kind"`
	Path         string     `json:"path"`
	Source       string     `json:"source"`
	Content      string     `json:"content,omitempty"`
	SHA256       string     `json:"sha256"`
	Status       string     `json:"status"`
	Problems     []string   `json:"problems"`
	ReviewedBy   string     `json:"reviewed_by,omitempty"`
	ReviewedAt   *time.Time `json:"reviewed_at,omitempty"`
	Note         string     `json:"note,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

const suiteColumns = `id,asset_id,generation_id,kind,path,source,sha256,status,problems,reviewed_by,reviewed_at,note,created_at`

func scanSuite(row pgx.Row, extra ...any) (QASuite, error) {
	var q QASuite
	var problems []byte
	targets := append([]any{&q.ID, &q.AssetID, &q.GenerationID, &q.Kind, &q.Path, &q.Source, &q.SHA256, &q.Status, &problems, &q.ReviewedBy, &q.ReviewedAt, &q.Note, &q.CreatedAt}, extra...)
	err := row.Scan(targets...)
	if errors.Is(err, pgx.ErrNoRows) {
		return q, ErrNotFound
	}
	if err == nil && json.Unmarshal(problems, &q.Problems) != nil {
		return q, errors.New("invalid QA suite data")
	}
	return q, err
}

// AddQASuites stores a batch of generated files and extends the lease.
// A file with problems is stored rejected; a new draft supersedes older
// drafts of the same path.
func (s *Store) AddQASuites(ctx context.Context, g QAGeneration, files []QASuite, inputTokens, outputTokens int) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	accepted, rejected := 0, 0
	for _, f := range files {
		status := "draft"
		if len(f.Problems) > 0 {
			status = "rejected"
			rejected++
		} else {
			accepted++
			if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.qa_suites SET status='superseded' WHERE asset_id=$1 AND kind=$2 AND path=$3 AND status='draft'`, g.AssetID, g.Kind, f.Path); err != nil {
				return err
			}
		}
		problems, _ := json.Marshal(nonNil(f.Problems))
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.qa_suites(id,asset_id,generation_id,kind,path,source,content,sha256,status,problems) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, uuid.New(), g.AssetID, g.ID, g.Kind, clip(f.Path, 1024), clip(f.Source, 1024), f.Content, Hash([]byte(f.Content)), status, problems); err != nil {
			return err
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.qa_generations SET accepted=accepted+$2,rejected=rejected+$3,input_tokens=input_tokens+$4,output_tokens=output_tokens+$5,lease_until=clock_timestamp()+($6*interval '1 second') WHERE id=$1 AND status='running'`, g.ID, accepted, rejected, inputTokens, outputTokens, int64(QAGenerationLease.Seconds()))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLease
	}
	return tx.Commit(ctx)
}

// FinishQAGeneration ends a generation; a failure with retry requeues it.
func (s *Store) FinishQAGeneration(ctx context.Context, g QAGeneration, failure string, retry bool) error {
	status := "succeeded"
	if failure != "" {
		status = "failed"
		if retry && g.Attempts < 3 {
			status = "queued"
		}
	}
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.qa_generations SET status=$2,error=$3,lease_until=NULL,run_after=clock_timestamp()+interval '2 minutes',completed_at=CASE WHEN $2='queued' THEN NULL ELSE clock_timestamp() END WHERE id=$1`, g.ID, status, clip(failure, 1000))
	return err
}

// QAGenerationByID returns one generation.
func (s *Store) QAGenerationByID(ctx context.Context, id uuid.UUID) (QAGeneration, error) {
	return scanGeneration(s.pool.QueryRow(ctx, `SELECT `+genColumns+` FROM `+s.schema+`.qa_generations WHERE id=$1`, id))
}

// QAGenerations lists an asset's generations, newest first.
func (s *Store) QAGenerations(ctx context.Context, asset uuid.UUID, limit int) ([]QAGeneration, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `SELECT `+genColumns+` FROM `+s.schema+`.qa_generations WHERE asset_id=$1 ORDER BY created_at DESC LIMIT $2`, asset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QAGeneration{}
	for rows.Next() {
		g, err := scanGeneration(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// QASuiteFilter selects suites; empty fields match everything.
type QASuiteFilter struct {
	Asset        uuid.UUID
	Generation   uuid.UUID
	Kind, Status string
	// Content includes file contents (bundles and downloads).
	Content bool
}

// QASuites lists suites by path, newest first within a path.
func (s *Store) QASuites(ctx context.Context, f QASuiteFilter) ([]QASuite, error) {
	content := `''`
	if f.Content {
		content = `content`
	}
	rows, err := s.pool.Query(ctx, `SELECT `+suiteColumns+`,`+content+` FROM `+s.schema+`.qa_suites WHERE ($1='00000000-0000-0000-0000-000000000000'::uuid OR asset_id=$1) AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR generation_id=$2) AND ($3='' OR kind=$3) AND ($4='' OR status=$4) ORDER BY path,created_at DESC LIMIT 2000`, f.Asset, f.Generation, f.Kind, f.Status)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QASuite{}
	for rows.Next() {
		var body string
		q, err := scanSuite(rows, &body)
		if err != nil {
			return nil, err
		}
		q.Content = body
		out = append(out, q)
	}
	return out, rows.Err()
}

// QASuiteByID returns a suite with its content.
func (s *Store) QASuiteByID(ctx context.Context, id uuid.UUID) (QASuite, error) {
	var body string
	q, err := scanSuite(s.pool.QueryRow(ctx, `SELECT `+suiteColumns+`,content FROM `+s.schema+`.qa_suites WHERE id=$1`, id), &body)
	q.Content = body
	return q, err
}

// ReviewQASuite approves or rejects a draft. Only a draft without problems
// can be approved; approving replaces the previously approved file at the
// same path, which becomes superseded.
func (s *Store) ReviewQASuite(ctx context.Context, id uuid.UUID, approve bool, by, note string) (QASuite, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return QASuite{}, err
	}
	defer tx.Rollback(ctx)
	var body string
	q, err := scanSuite(tx.QueryRow(ctx, `SELECT `+suiteColumns+`,content FROM `+s.schema+`.qa_suites WHERE id=$1 FOR UPDATE`, id), &body)
	if err != nil {
		return q, err
	}
	if q.Status != "draft" || (approve && len(q.Problems) > 0) {
		return q, ErrQAState
	}
	status := "rejected"
	if approve {
		status = "approved"
		if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.qa_suites SET status='superseded' WHERE asset_id=$1 AND kind=$2 AND path=$3 AND status='approved'`, q.AssetID, q.Kind, q.Path); err != nil {
			return q, err
		}
	}
	q, err = scanSuite(tx.QueryRow(ctx, `UPDATE `+s.schema+`.qa_suites SET status=$2,reviewed_by=$3,reviewed_at=clock_timestamp(),note=$4 WHERE id=$1 RETURNING `+suiteColumns+`,content`, id, status, clip(by, 100), clip(note, 1000)), &body)
	if err != nil {
		return q, err
	}
	q.Content = body
	details, _ := json.Marshal(map[string]any{"by": by, "status": status, "path": q.Path, "kind": q.Kind, "sha256": q.SHA256})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('qa_suite.reviewed',$1,$2)`, id, details); err != nil {
		return q, err
	}
	return q, tx.Commit(ctx)
}
