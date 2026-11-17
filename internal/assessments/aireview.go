package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/ORIBData/scrstack/internal/knowledge"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/review"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AI code review (the "AI assessment"). A review reads the source of an
// assessed commit with a language model and records what it finds
// as report-only "ai_review" entries in the risk register. Source code goes
// to a provider the operator runs, or to a hosted one only under
// llm.SourcePolicy (platform switch and acknowledgement). Entries are
// unverified model output: they never change an assessment's verdict, and a
// later review closes the ones it no longer reports.

func aiReviewSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.ai_reviews(id uuid PRIMARY KEY,asset_id uuid NOT NULL REFERENCES ` + s + `.assets(id),provider_id uuid REFERENCES ` + s + `.llm_providers(id) ON DELETE SET NULL,provider_name text NOT NULL DEFAULT '',model text NOT NULL DEFAULT '',assessment_id uuid REFERENCES ` + s + `.assessments(id),ref text NOT NULL DEFAULT '',commit text NOT NULL DEFAULT '',options jsonb NOT NULL DEFAULT '{}',status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed')),requested_by text NOT NULL,attempts integer NOT NULL DEFAULT 0,run_after timestamptz NOT NULL DEFAULT clock_timestamp(),lease_until timestamptz,files_reviewed integer NOT NULL DEFAULT 0,files_skipped integer NOT NULL DEFAULT 0,findings integer NOT NULL DEFAULT 0,input_tokens bigint NOT NULL DEFAULT 0,output_tokens bigint NOT NULL DEFAULT 0,incomplete text NOT NULL DEFAULT '',redactions jsonb NOT NULL DEFAULT '{}',document_id uuid,error text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz)`,
		`ALTER TABLE ` + s + `.ai_reviews ADD COLUMN IF NOT EXISTS locality text NOT NULL DEFAULT ''`,
		`ALTER TABLE ` + s + `.llm_providers ADD COLUMN IF NOT EXISTS managed boolean NOT NULL DEFAULT false`,
		`ALTER TABLE ` + s + `.llm_providers ADD COLUMN IF NOT EXISTS source_ack_by text NOT NULL DEFAULT ''`,
		`ALTER TABLE ` + s + `.llm_providers ADD COLUMN IF NOT EXISTS source_ack_at timestamptz`,
		`ALTER TABLE ` + s + `.llm_providers ADD COLUMN IF NOT EXISTS source_ack_note text NOT NULL DEFAULT ''`,
		`CREATE INDEX IF NOT EXISTS ai_reviews_asset_idx ON ` + s + `.ai_reviews(asset_id,created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS ai_reviews_due_idx ON ` + s + `.ai_reviews(run_after) WHERE status IN ('queued','running')`,
	}
}

var (
	// ErrAIReviewProvider means the provider does not exist or is disabled.
	ErrAIReviewProvider = errors.New("llm provider not found or disabled")
	// ErrAIReviewSource means the provider may not receive source code. A
	// self-hosted provider always may; a hosted one only when the platform
	// switch SCRS_LLM_ALLOW_SOURCE_TO_HOSTED is on and an administrator
	// acknowledged it (POST /llm/providers/{id}:allow-source).
	ErrAIReviewSource = errors.New("this provider may not receive source code: use a self-hosted provider (host listed in SCRS_LLM_PRIVATE_HOSTS), or for a hosted provider set SCRS_LLM_ALLOW_SOURCE_TO_HOSTED=true and acknowledge it with POST /llm/providers/{id}:allow-source")
)

// ErrQASource means unit-test generation, which sends source files, was asked
// of a provider that may not receive source code (see ErrAIReviewSource).
var ErrQASource = errors.New("unit-test generation sends source files, so the provider must be self-hosted, or hosted with SCRS_LLM_ALLOW_SOURCE_TO_HOSTED=true and an acknowledgement (POST /llm/providers/{id}:allow-source)")

// AIReviewOptions bound one review.
type AIReviewOptions struct {
	// MaxFiles caps the files read (default 10, at most 40).
	MaxFiles int `json:"max_files,omitempty"`
	// Paths restricts the review to these source files.
	Paths []string `json:"paths,omitempty"`
}

// AIReview is one code-review job.
type AIReview struct {
	ID           uuid.UUID  `json:"id"`
	AssetID      uuid.UUID  `json:"asset_id"`
	ProviderID   *uuid.UUID `json:"provider_id"`
	ProviderName string     `json:"provider_name"`
	Model        string     `json:"model"`
	// Locality is where the source went: "local" or "hosted".
	Locality      string          `json:"locality"`
	AssessmentID  *uuid.UUID      `json:"assessment_id"`
	Ref           string          `json:"ref"`
	Commit        string          `json:"commit"`
	Options       AIReviewOptions `json:"options"`
	Status        string          `json:"status"`
	RequestedBy   string          `json:"requested_by"`
	Attempts      int             `json:"attempts"`
	FilesReviewed int             `json:"files_reviewed"`
	FilesSkipped  int             `json:"files_skipped"`
	Findings      int             `json:"findings"`
	InputTokens   int64           `json:"input_tokens"`
	OutputTokens  int64           `json:"output_tokens"`
	Incomplete    string          `json:"incomplete,omitempty"`
	Redactions    map[string]int  `json:"redactions"`
	DocumentID    *uuid.UUID      `json:"document_id,omitempty"`
	Error         string          `json:"error,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
	CompletedAt   *time.Time      `json:"completed_at,omitempty"`
}

const aiReviewColumns = `id,asset_id,provider_id,provider_name,model,locality,assessment_id,ref,commit,options,status,requested_by,attempts,files_reviewed,files_skipped,findings,input_tokens,output_tokens,incomplete,redactions,document_id,error,created_at,completed_at`

func scanAIReview(row pgx.Row) (AIReview, error) {
	var r AIReview
	var options, redactions []byte
	err := row.Scan(&r.ID, &r.AssetID, &r.ProviderID, &r.ProviderName, &r.Model, &r.Locality, &r.AssessmentID, &r.Ref, &r.Commit, &options, &r.Status, &r.RequestedBy, &r.Attempts, &r.FilesReviewed, &r.FilesSkipped, &r.Findings, &r.InputTokens, &r.OutputTokens, &r.Incomplete, &redactions, &r.DocumentID, &r.Error, &r.CreatedAt, &r.CompletedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	if err == nil {
		if json.Unmarshal(options, &r.Options) != nil || json.Unmarshal(redactions, &r.Redactions) != nil {
			return r, errors.New("invalid AI review data")
		}
	}
	return r, err
}

// Knowledge returns the knowledge store on the same database.
func (s *Store) Knowledge() *knowledge.Store { return knowledge.New(s.pool, s.schema) }

// EnqueueAIReview queues a review of the asset's latest successful git
// assessment with the given provider. source decides whether the provider may
// receive source code and reports where it runs; without it, or when it says
// no, nothing is queued.
func (s *Store) EnqueueAIReview(ctx context.Context, asset, provider uuid.UUID, o AIReviewOptions, by string, source func(LLMProvider) (locality string, ok bool)) (AIReview, error) {
	if o.MaxFiles < 0 || o.MaxFiles > 40 || len(o.Paths) > 40 {
		return AIReview{}, ErrInput
	}
	for _, p := range o.Paths {
		if p == "" || len(p) > 512 {
			return AIReview{}, ErrInput
		}
	}
	p, err := s.LLMProviderByID(ctx, provider)
	if err != nil || !p.Enabled {
		return AIReview{}, ErrAIReviewProvider
	}
	if source == nil {
		return AIReview{}, ErrAIReviewSource
	}
	locality, ok := source(p)
	if !ok {
		return AIReview{}, ErrAIReviewSource
	}
	a, err := s.qaAssessment(ctx, asset, nil)
	if err != nil {
		return AIReview{}, err
	}
	if a.Verdict == "fail" {
		return AIReview{}, ErrQABlocked
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = 10
	}
	options, _ := json.Marshal(o)
	return scanAIReview(s.pool.QueryRow(ctx, `INSERT INTO `+s.schema+`.ai_reviews(id,asset_id,provider_id,provider_name,model,locality,assessment_id,ref,commit,options,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING `+aiReviewColumns, uuid.New(), asset, p.ID, p.Name, p.Model, locality, a.ID, a.Request.Target.Ref, a.Commit, options, clip(by, 100)))
}

// AIReviewLease bounds one review between claims. A review reads at most 40
// files one model call at a time, so it fits well inside this.
const AIReviewLease = 30 * time.Minute

// ClaimAIReview leases the next queued review, or one whose worker died. A
// review is attempted at most three times.
func (s *Store) ClaimAIReview(ctx context.Context) (AIReview, error) {
	if _, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.ai_reviews SET status='failed',error='review attempts exhausted',completed_at=clock_timestamp() WHERE status='running' AND lease_until<clock_timestamp() AND attempts>=3`); err != nil {
		return AIReview{}, err
	}
	return scanAIReview(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.ai_reviews SET status='running',attempts=attempts+1,lease_until=clock_timestamp()+($1*interval '1 second') WHERE id=(SELECT id FROM `+s.schema+`.ai_reviews WHERE (status='queued' AND run_after<=clock_timestamp()) OR (status='running' AND lease_until<clock_timestamp()) ORDER BY created_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+aiReviewColumns, int64(AIReviewLease.Seconds())))
}

// FinishAIReview ends a review that failed; a failure with retry requeues it.
func (s *Store) FinishAIReview(ctx context.Context, r AIReview, failure string, retry bool) error {
	status := "failed"
	if retry && r.Attempts < 3 {
		status = "queued"
	}
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.ai_reviews SET status=$2,error=$3,lease_until=NULL,run_after=clock_timestamp()+interval '2 minutes',completed_at=CASE WHEN $2='queued' THEN NULL ELSE clock_timestamp() END WHERE id=$1`, r.ID, status, clip(failure, 1000))
	return err
}

// AIReviewByID returns one review.
func (s *Store) AIReviewByID(ctx context.Context, id uuid.UUID) (AIReview, error) {
	return scanAIReview(s.pool.QueryRow(ctx, `SELECT `+aiReviewColumns+` FROM `+s.schema+`.ai_reviews WHERE id=$1`, id))
}

// AIReviews lists an asset's reviews, newest first.
func (s *Store) AIReviews(ctx context.Context, asset uuid.UUID, limit int) ([]AIReview, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `SELECT `+aiReviewColumns+` FROM `+s.schema+`.ai_reviews WHERE asset_id=$1 ORDER BY created_at DESC,id DESC LIMIT $2`, asset, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AIReview{}
	for rows.Next() {
		r, err := scanAIReview(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// AIIssue is one validated issue in one file.
type AIIssue struct {
	Path     string
	Language string
	review.Issue
}

// AIReviewResult is what a review found.
type AIReviewResult struct {
	Issues        []AIIssue
	Reviewed      []string
	Skipped       int
	Incomplete    string
	InputTokens   int64
	OutputTokens  int64
	Redactions    map[string]int
	DocumentID    *uuid.UUID
	ReviewModel   string
	PromptVersion string
}

func aiFinding(r AIReview, i AIIssue) Finding {
	severity := i.Severity // low, medium or high: a model's opinion is never critical
	title := i.Title
	evidence, _ := json.Marshal(map[string]any{
		"source": "ai_review", "tool": "model-review", "category": i.Category, "path": i.Path, "line_start": i.LineStart, "line_end": i.LineEnd,
		"confidence": i.Confidence, "explanation": i.Explanation, "model": r.Model, "review_id": r.ID, "prompt_version": review.PromptVersion,
		"unverified": true,
	})
	guidance, _ := json.Marshal(map[string]any{"summary": i.Explanation, "suggested_fix": i.SuggestedFix, "automatic_changes": false, "note": "Written by a language model and not verified. Confirm it in the code before acting."})
	return Finding{
		Type: "ai_review", AdvisoryID: "SCRS-AI-REVIEW:" + i.Category + ":" + Hash([]byte(i.Path + "\x00" + i.Category + "\x00" + title))[:10],
		Title: clip("AI review: "+title, 512), Severity: severity, Score: severityScore[severity],
		Component: Component{Name: i.Path, Path: i.Path, Ecosystem: i.Language}, Evidence: evidence, Guidance: guidance,
	}
}

// CompleteAIReview records a finished review in one transaction: its issues
// become register entries (reopened if they were fixed, history kept in the
// finding events), entries in the files it read that it no longer reports are
// closed, and the review row gets its counts. Entries the model found
// elsewhere are left alone.
func (s *Store) CompleteAIReview(ctx context.Context, r AIReview, res AIReviewResult) (AIReview, error) {
	if r.AssessmentID == nil {
		return AIReview{}, ErrQANoAssessment
	}
	scope := Assessment{AssetID: r.AssetID, Request: Request{Target: Target{Ref: r.Ref}}}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AIReview{}, err
	}
	defer tx.Rollback(ctx)
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT status='running' FROM `+s.schema+`.ai_reviews WHERE id=$1 FOR UPDATE`, r.ID).Scan(&ok); err != nil || !ok {
		return AIReview{}, ErrConflict
	}
	var created []Finding
	current := []string{}
	seen := map[string]bool{}
	for _, issue := range res.Issues {
		f := aiFinding(r, issue)
		f.Fingerprint = fingerprint(scope, f)
		if seen[f.Fingerprint] {
			continue
		}
		seen[f.Fingerprint] = true
		current = append(current, f.Fingerprint)
		f.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(f.Fingerprint))
		component, _ := json.Marshal(f.Component)
		var inserted bool
		var previous string
		err := tx.QueryRow(ctx, `WITH old AS (SELECT status FROM `+s.schema+`.findings WHERE fingerprint=$3) INSERT INTO `+s.schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance,last_assessment_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(fingerprint) DO UPDATE SET last_seen=clock_timestamp(),last_assessment_id=EXCLUDED.last_assessment_id,evidence=EXCLUDED.evidence,guidance=EXCLUDED.guidance,severity=EXCLUDED.severity,score=EXCLUDED.score,title=EXCLUDED.title,status=CASE WHEN findings.status='fixed' OR (findings.status='accepted' AND findings.waiver_until<=clock_timestamp()) THEN 'open' ELSE findings.status END,revision=findings.revision+1 RETURNING xmax=0,COALESCE((SELECT status FROM old),'')`,
			f.ID, r.AssetID, f.Fingerprint, r.Ref, f.Type, f.AdvisoryID, f.Title, f.Severity, f.Score, component, f.Evidence, f.Guidance, *r.AssessmentID).Scan(&inserted, &previous)
		if err != nil {
			return AIReview{}, err
		}
		action, detail := "detected", map[string]any{"source": "ai_review", "review_id": r.ID, "model": r.Model}
		if !inserted {
			action = "re_reported_by_ai_review"
			if previous == "fixed" {
				action = "reopened_by_ai_review"
			}
		} else {
			created = append(created, f)
		}
		raw, _ := json.Marshal(detail)
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,$2,$3)`, f.ID, action, raw); err != nil {
			return AIReview{}, err
		}
	}
	// Entries in the files this review read that it no longer reports.
	if len(res.Reviewed) > 0 {
		rows, err := tx.Query(ctx, `UPDATE `+s.schema+`.findings SET status='fixed',revision=revision+1 WHERE asset_id=$1 AND ref=$2 AND type='ai_review' AND component->>'path'=ANY($3) AND fingerprint<>ALL($4) AND status IN ('open','triaged','in_progress') RETURNING id`, r.AssetID, r.Ref, res.Reviewed, current)
		if err != nil {
			return AIReview{}, err
		}
		var ids []uuid.UUID
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return AIReview{}, err
			}
			ids = append(ids, id)
		}
		rows.Close()
		for _, id := range ids {
			raw, _ := json.Marshal(map[string]any{"review_id": r.ID})
			if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'fixed_by_ai_review',$2)`, id, raw); err != nil {
				return AIReview{}, err
			}
		}
	}
	if len(created) > 0 {
		var briefs []map[string]any
		for _, f := range created {
			if len(briefs) < 100 {
				briefs = append(briefs, findingBrief(f))
			}
		}
		data := map[string]any{"assessment_id": r.AssessmentID, "asset_id": r.AssetID, "ref": r.Ref, "commit": r.Commit, "total": len(created), "truncated": len(created) > len(briefs), "findings": briefs}
		if _, err := notify.EmitScoped(ctx, tx, s.schema, "finding.created", data, nil, notify.Scope{Asset: r.AssetID}); err != nil {
			return AIReview{}, err
		}
	}
	redactions, _ := json.Marshal(res.Redactions)
	if res.Redactions == nil {
		redactions = []byte(`{}`)
	}
	sort.Strings(res.Reviewed)
	done, err := scanAIReview(tx.QueryRow(ctx, `UPDATE `+s.schema+`.ai_reviews SET status='succeeded',files_reviewed=$2,files_skipped=$3,findings=$4,input_tokens=$5,output_tokens=$6,incomplete=$7,redactions=$8,document_id=$9,error='',lease_until=NULL,completed_at=clock_timestamp() WHERE id=$1 RETURNING `+aiReviewColumns,
		r.ID, len(res.Reviewed), res.Skipped, len(current), res.InputTokens, res.OutputTokens, clip(res.Incomplete, 300), redactions, res.DocumentID))
	if err != nil {
		return AIReview{}, err
	}
	details, _ := json.Marshal(map[string]any{"review_id": r.ID, "files": len(res.Reviewed), "findings": len(current), "model": r.Model})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('ai_review.completed',$1,$2)`, r.AssetID, details); err != nil {
		return AIReview{}, err
	}
	return done, tx.Commit(ctx)
}
