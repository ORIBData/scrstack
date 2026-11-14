package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// E2E QA (Karate): a repository asset with a QA profile gets a QA run after
// each successful assessment of a matching ref. The worker sends the
// commit's Karate suites to the operator's runner, which tests the profile's
// deployed base URL; SCRS stores the report, scenarios, API coverage and
// report-only qa_* findings. Runs never change an assessment's verdict.

var (
	// ErrQAProfile means the asset has no enabled QA profile.
	ErrQAProfile = errors.New("asset has no enabled QA profile")
	// ErrQANoAssessment means the asset has no successful git assessment to test.
	ErrQANoAssessment = errors.New("asset has no successful assessment to test; run one first")
	// ErrQABlocked means the commit failed its security gate.
	ErrQABlocked = errors.New("the assessment's verdict is fail; QA does not run code that failed its security gate")
	// ErrQAState means the run or suite is not in a state that allows the action.
	ErrQAState = errors.New("not allowed in the current state")
)

func qaSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.llm_providers(id uuid PRIMARY KEY,name text NOT NULL UNIQUE,kind text NOT NULL,base_url text NOT NULL DEFAULT '',model text NOT NULL,max_tokens integer NOT NULL CHECK(max_tokens BETWEEN 256 AND 131072),temperature double precision,enabled boolean NOT NULL DEFAULT true,credential bytea,revision bigint NOT NULL DEFAULT 1,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),last_test_at timestamptz,last_test_error text NOT NULL DEFAULT '')`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.qa_profiles(asset_id uuid PRIMARY KEY REFERENCES ` + s + `.assets(id),enabled boolean NOT NULL DEFAULT true,auto_run boolean NOT NULL DEFAULT true,refs jsonb NOT NULL DEFAULT '[]',base_url text NOT NULL,environment text NOT NULL DEFAULT '',tags jsonb NOT NULL DEFAULT '[]',threads integer NOT NULL DEFAULT 1 CHECK(threads BETWEEN 1 AND 16),timeout_seconds integer NOT NULL DEFAULT 900 CHECK(timeout_seconds BETWEEN 60 AND 7200),test_path text NOT NULL DEFAULT 'karate',openapi_path text NOT NULL DEFAULT '',auth jsonb NOT NULL DEFAULT '{}',variable_names jsonb NOT NULL DEFAULT '[]',variables bytea,perf jsonb,llm_provider_id uuid REFERENCES ` + s + `.llm_providers(id) ON DELETE SET NULL,allow_source_upload boolean NOT NULL DEFAULT false,revision bigint NOT NULL DEFAULT 1,updated_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.qa_runs(id uuid PRIMARY KEY,asset_id uuid NOT NULL REFERENCES ` + s + `.assets(id),assessment_id uuid REFERENCES ` + s + `.assessments(id),kind text NOT NULL CHECK(kind IN ('functional','performance')),trigger text NOT NULL,requested_by text NOT NULL,ref text NOT NULL DEFAULT '',commit text NOT NULL DEFAULT '',include_drafts boolean NOT NULL DEFAULT false,status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','submitted','running','passed','failed','error','cancelled','skipped')),cleanup boolean NOT NULL DEFAULT false,attempts integer NOT NULL DEFAULT 0,run_after timestamptz NOT NULL DEFAULT clock_timestamp(),lease uuid,lease_until timestamptz,submitted_at timestamptz,started_at timestamptz,completed_at timestamptz,base_url text NOT NULL DEFAULT '',operations jsonb NOT NULL DEFAULT '[]',base_paths jsonb NOT NULL DEFAULT '[]',summary jsonb NOT NULL DEFAULT '{}',coverage jsonb,perf jsonb,report_key text NOT NULL DEFAULT '',report_sha256 text NOT NULL DEFAULT '',error text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE INDEX IF NOT EXISTS qa_runs_queue_idx ON ` + s + `.qa_runs(run_after) WHERE status IN ('queued','submitted','running') OR cleanup`,
		`CREATE INDEX IF NOT EXISTS qa_runs_asset_idx ON ` + s + `.qa_runs(asset_id,created_at DESC)`,
		`CREATE INDEX IF NOT EXISTS qa_runs_assessment_idx ON ` + s + `.qa_runs(assessment_id)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.qa_scenarios(run_id uuid NOT NULL REFERENCES ` + s + `.qa_runs(id) ON DELETE CASCADE,ordinal integer NOT NULL,body jsonb NOT NULL,PRIMARY KEY(run_id,ordinal))`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.qa_generations(id uuid PRIMARY KEY,asset_id uuid NOT NULL REFERENCES ` + s + `.assets(id),kind text NOT NULL CHECK(kind IN ('api','unit')),provider_id uuid REFERENCES ` + s + `.llm_providers(id) ON DELETE SET NULL,provider_name text NOT NULL DEFAULT '',model text NOT NULL DEFAULT '',assessment_id uuid REFERENCES ` + s + `.assessments(id),ref text NOT NULL DEFAULT '',commit text NOT NULL DEFAULT '',options jsonb NOT NULL DEFAULT '{}',status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed')),requested_by text NOT NULL,attempts integer NOT NULL DEFAULT 0,run_after timestamptz NOT NULL DEFAULT clock_timestamp(),lease_until timestamptz,input_tokens bigint NOT NULL DEFAULT 0,output_tokens bigint NOT NULL DEFAULT 0,accepted integer NOT NULL DEFAULT 0,rejected integer NOT NULL DEFAULT 0,error text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz)`,
		`CREATE INDEX IF NOT EXISTS qa_generations_queue_idx ON ` + s + `.qa_generations(run_after) WHERE status IN ('queued','running')`,
		`CREATE INDEX IF NOT EXISTS qa_generations_asset_idx ON ` + s + `.qa_generations(asset_id,created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.qa_suites(id uuid PRIMARY KEY,asset_id uuid NOT NULL REFERENCES ` + s + `.assets(id),generation_id uuid REFERENCES ` + s + `.qa_generations(id),kind text NOT NULL CHECK(kind IN ('api','unit')),path text NOT NULL,source text NOT NULL DEFAULT '',content text NOT NULL,sha256 text NOT NULL,status text NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved','rejected','superseded')),problems jsonb NOT NULL DEFAULT '[]',reviewed_by text NOT NULL DEFAULT '',reviewed_at timestamptz,note text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE INDEX IF NOT EXISTS qa_suites_asset_idx ON ` + s + `.qa_suites(asset_id,kind,status,path)`,
		`CREATE UNIQUE INDEX IF NOT EXISTS qa_suites_approved_uq ON ` + s + `.qa_suites(asset_id,kind,path) WHERE status='approved'`,
	}
}

// QAAAD binds a profile's sealed variables to its asset.
func QAAAD(asset uuid.UUID) []byte { return []byte("qa:" + asset.String()) }

// QAAuth adds an authentication header to every generated request:
// Header: Prefix + the value of variable Variable.
type QAAuth struct {
	Header   string `json:"header,omitempty"`
	Variable string `json:"variable,omitempty"`
	Prefix   string `json:"prefix,omitempty"`
}

// QAPerf is a profile's load profile; AutoRun adds a performance run after
// each functional run that passes.
type QAPerf struct {
	qa.Perf
	AutoRun bool `json:"auto_run"`
}

// QAProfile is an asset's QA settings; variable values are write-only.
type QAProfile struct {
	AssetID           uuid.UUID  `json:"asset_id"`
	Enabled           bool       `json:"enabled"`
	AutoRun           bool       `json:"auto_run"`
	Refs              []string   `json:"refs"`
	BaseURL           string     `json:"base_url"`
	Environment       string     `json:"environment"`
	Tags              []string   `json:"tags"`
	Threads           int        `json:"threads"`
	TimeoutSeconds    int        `json:"timeout_seconds"`
	TestPath          string     `json:"test_path"`
	OpenAPIPath       string     `json:"openapi_path"`
	Auth              QAAuth     `json:"auth"`
	VariableNames     []string   `json:"variable_names"`
	Perf              *QAPerf    `json:"perf"`
	LLMProviderID     *uuid.UUID `json:"llm_provider_id"`
	AllowSourceUpload bool       `json:"allow_source_upload"`
	Revision          int64      `json:"revision"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

const profileColumns = `asset_id,enabled,auto_run,refs,base_url,environment,tags,threads,timeout_seconds,test_path,openapi_path,auth,variable_names,perf,llm_provider_id,allow_source_upload,revision,updated_at`

func scanProfile(row pgx.Row, extra ...any) (QAProfile, error) {
	var p QAProfile
	var refs, tags, auth, names, perf []byte
	targets := append([]any{&p.AssetID, &p.Enabled, &p.AutoRun, &refs, &p.BaseURL, &p.Environment, &tags, &p.Threads, &p.TimeoutSeconds, &p.TestPath, &p.OpenAPIPath, &auth, &names, &perf, &p.LLMProviderID, &p.AllowSourceUpload, &p.Revision, &p.UpdatedAt}, extra...)
	if err := row.Scan(targets...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return p, ErrNotFound
		}
		return p, err
	}
	if json.Unmarshal(refs, &p.Refs) != nil || json.Unmarshal(tags, &p.Tags) != nil || json.Unmarshal(auth, &p.Auth) != nil || json.Unmarshal(names, &p.VariableNames) != nil {
		return p, errors.New("invalid QA profile data")
	}
	if len(perf) > 0 && string(perf) != "null" {
		p.Perf = &QAPerf{}
		if json.Unmarshal(perf, p.Perf) != nil {
			return p, errors.New("invalid QA profile data")
		}
	}
	return p, nil
}

// ValidQAPath checks a repository-relative directory or file path.
func ValidQAPath(p string, file bool) bool {
	if p == "" {
		return !file
	}
	return len(p) <= 512 && !strings.ContainsAny(p, "\\\x00") && !strings.HasPrefix(p, "/") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../")
}

// Validate checks a profile; the QA package checks the shared parts.
func (p QAProfile) Validate() error {
	if err := qa.ValidBaseURL(p.BaseURL); err != nil {
		return err
	}
	switch {
	case p.Environment != "" && !envPattern.MatchString(p.Environment):
		return errors.New("environment must be a short lower-case karate.env name")
	case p.Threads < 1 || p.Threads > 16:
		return errors.New("threads must be 1 to 16")
	case p.TimeoutSeconds < 60 || p.TimeoutSeconds > 7200:
		return errors.New("timeout_seconds must be 60 to 7200")
	case !ValidQAPath(p.TestPath, false):
		return errors.New("test_path must be a relative directory")
	case !ValidQAPath(p.OpenAPIPath, false):
		return errors.New("openapi_path must be a relative file path")
	case len(p.Refs) > 20:
		return errors.New("at most 20 refs")
	case len(p.VariableNames) > 32:
		return errors.New("at most 32 variables")
	}
	for _, ref := range p.Refs {
		if ref == "" || len(ref) > 255 || strings.ContainsAny(ref, "\x00\r\n") {
			return errors.New("refs are branch names or patterns such as main, release/* or pull/*")
		}
		if _, err := path.Match(ref, ""); err != nil {
			return errors.New("ref pattern " + ref + " is malformed")
		}
	}
	if err := qa.ValidTags(p.Tags); err != nil {
		return err
	}
	if p.Auth.Header != "" || p.Auth.Variable != "" {
		if !headerName.MatchString(p.Auth.Header) || !slices.Contains(p.VariableNames, p.Auth.Variable) || len(p.Auth.Prefix) > 32 || strings.ContainsAny(p.Auth.Prefix, "'\"\\\r\n") {
			return errors.New("auth needs a header name, the name of one of the profile's variables and an optional short prefix")
		}
	}
	if p.Perf != nil {
		if err := p.Perf.Validate(); err != nil {
			return err
		}
	}
	return nil
}

var (
	envPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	headerName = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
)

// QAProfileFor returns an asset's profile.
func (s *Store) QAProfileFor(ctx context.Context, asset uuid.UUID) (QAProfile, error) {
	return scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileColumns+` FROM `+s.schema+`.qa_profiles WHERE asset_id=$1`, asset))
}

// QAProfileSecret returns a profile with its sealed variables.
func (s *Store) QAProfileSecret(ctx context.Context, asset uuid.UUID) (QAProfile, []byte, error) {
	var sealed []byte
	p, err := scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileColumns+`,COALESCE(variables,''::bytea) FROM `+s.schema+`.qa_profiles WHERE asset_id=$1`, asset), &sealed)
	return p, sealed, err
}

// PutQAProfile creates or replaces an asset's profile. expected is the
// revision being replaced (0 creates); a nil sealed keeps the stored
// variables. The asset must be an in-scope git repository.
func (s *Store) PutQAProfile(ctx context.Context, p QAProfile, expected int64, sealed []byte, actor uuid.UUID) (QAProfile, error) {
	if err := p.Validate(); err != nil {
		return p, errors.Join(ErrInput, err)
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return p, err
	}
	defer tx.Rollback(ctx)
	var kind string
	err = tx.QueryRow(ctx, `SELECT type FROM `+s.schema+`.assets WHERE id=$1 AND flags->>'in_scope'='true' FOR SHARE`, p.AssetID).Scan(&kind)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && kind != "github_repo" && kind != "gitlab_repo") {
		return p, ErrScope
	}
	if err != nil {
		return p, err
	}
	if p.LLMProviderID != nil {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.llm_providers WHERE id=$1)`, *p.LLMProviderID).Scan(&exists); err != nil {
			return p, err
		}
		if !exists {
			return p, errors.Join(ErrInput, errors.New("llm_provider_id does not name a provider"))
		}
	}
	refs, _ := json.Marshal(nonNil(p.Refs))
	tags, _ := json.Marshal(nonNil(p.Tags))
	auth, _ := json.Marshal(p.Auth)
	names, _ := json.Marshal(nonNil(p.VariableNames))
	var perf []byte
	if p.Perf != nil {
		perf, _ = json.Marshal(p.Perf)
	}
	var saved QAProfile
	if expected == 0 {
		saved, err = scanProfile(tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.qa_profiles(asset_id,enabled,auto_run,refs,base_url,environment,tags,threads,timeout_seconds,test_path,openapi_path,auth,variable_names,variables,perf,llm_provider_id,allow_source_upload) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17) ON CONFLICT(asset_id) DO NOTHING RETURNING `+profileColumns, p.AssetID, p.Enabled, p.AutoRun, refs, p.BaseURL, p.Environment, tags, p.Threads, p.TimeoutSeconds, p.TestPath, p.OpenAPIPath, auth, names, sealed, perf, p.LLMProviderID, p.AllowSourceUpload))
	} else {
		saved, err = scanProfile(tx.QueryRow(ctx, `UPDATE `+s.schema+`.qa_profiles SET enabled=$3,auto_run=$4,refs=$5,base_url=$6,environment=$7,tags=$8,threads=$9,timeout_seconds=$10,test_path=$11,openapi_path=$12,auth=$13,variable_names=$14,variables=COALESCE($15,variables),perf=$16,llm_provider_id=$17,allow_source_upload=$18,revision=revision+1,updated_at=clock_timestamp() WHERE asset_id=$1 AND revision=$2 RETURNING `+profileColumns, p.AssetID, expected, p.Enabled, p.AutoRun, refs, p.BaseURL, p.Environment, tags, p.Threads, p.TimeoutSeconds, p.TestPath, p.OpenAPIPath, auth, names, sealed, perf, p.LLMProviderID, p.AllowSourceUpload))
	}
	if errors.Is(err, ErrNotFound) {
		return p, ErrConflict
	}
	if err != nil {
		return p, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "base_url": saved.BaseURL, "enabled": saved.Enabled, "auto_run": saved.AutoRun, "variables_changed": sealed != nil, "llm_provider_id": saved.LLMProviderID, "allow_source_upload": saved.AllowSourceUpload})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('qa_profile.saved',$1,$2)`, p.AssetID, details); err != nil {
		return p, err
	}
	return saved, tx.Commit(ctx)
}

// DeleteQAProfile removes an asset's profile; runs and suites are kept.
func (s *Store) DeleteQAProfile(ctx context.Context, asset, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.qa_profiles WHERE asset_id=$1`, asset)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('qa_profile.deleted',$1,$2)`, asset, details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// refMatches reports whether a ref is covered by a profile's patterns;
// none means every ref.
func refMatches(patterns []string, ref string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, p := range patterns {
		if ok, _ := path.Match(p, ref); ok {
			return true
		}
	}
	return false
}

// QARun is one QA execution against an assessed commit.
type QARun struct {
	ID            uuid.UUID          `json:"id"`
	AssetID       uuid.UUID          `json:"asset_id"`
	AssessmentID  *uuid.UUID         `json:"assessment_id"`
	Kind          string             `json:"kind"`
	Trigger       string             `json:"trigger"`
	RequestedBy   string             `json:"requested_by"`
	Ref           string             `json:"ref"`
	Commit        string             `json:"commit"`
	IncludeDrafts bool               `json:"include_drafts"`
	Status        string             `json:"status"`
	Attempts      int                `json:"attempts"`
	BaseURL       string             `json:"base_url"`
	Summary       qa.Summary         `json:"summary"`
	Coverage      *QACoverageSummary `json:"coverage,omitempty"`
	Perf          *qa.PerfStats      `json:"perf,omitempty"`
	ReportSHA256  string             `json:"report_sha256,omitempty"`
	Error         string             `json:"error,omitempty"`
	CreatedAt     time.Time          `json:"created_at"`
	SubmittedAt   *time.Time         `json:"submitted_at,omitempty"`
	StartedAt     *time.Time         `json:"started_at,omitempty"`
	CompletedAt   *time.Time         `json:"completed_at,omitempty"`
	// Worker-only state.
	Lease      uuid.UUID      `json:"-"`
	ReportKey  string         `json:"-"`
	Cleanup    bool           `json:"-"`
	Operations []qa.Operation `json:"-"`
	BasePaths  []string       `json:"-"`
}

// QACoverageSummary is a run's API coverage without the per-operation list.
type QACoverageSummary struct {
	Total   int     `json:"total"`
	Covered int     `json:"covered"`
	Percent float64 `json:"percent"`
	Spec    string  `json:"spec,omitempty"`
	// Problems are setup issues found preparing the run (qa_config).
	Problems []string `json:"problems,omitempty"`
}

const qaRunColumns = `id,asset_id,assessment_id,kind,trigger,requested_by,ref,commit,include_drafts,status,attempts,base_url,summary,coverage,perf,report_sha256,error,created_at,submitted_at,started_at,completed_at,COALESCE(lease,'00000000-0000-0000-0000-000000000000'::uuid),report_key,cleanup,operations,base_paths`

func scanQARun(row pgx.Row) (QARun, error) {
	var r QARun
	var summary, coverage, perf, ops, bases []byte
	err := row.Scan(&r.ID, &r.AssetID, &r.AssessmentID, &r.Kind, &r.Trigger, &r.RequestedBy, &r.Ref, &r.Commit, &r.IncludeDrafts, &r.Status, &r.Attempts, &r.BaseURL, &summary, &coverage, &perf, &r.ReportSHA256, &r.Error, &r.CreatedAt, &r.SubmittedAt, &r.StartedAt, &r.CompletedAt, &r.Lease, &r.ReportKey, &r.Cleanup, &ops, &bases)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	if err != nil {
		return r, err
	}
	if json.Unmarshal(summary, &r.Summary) != nil || json.Unmarshal(ops, &r.Operations) != nil || json.Unmarshal(bases, &r.BasePaths) != nil {
		return r, errors.New("invalid QA run data")
	}
	if len(coverage) > 0 {
		var c qa.Coverage
		var setup struct {
			Spec     string   `json:"spec"`
			Problems []string `json:"problems"`
		}
		if json.Unmarshal(coverage, &c) == nil {
			_ = json.Unmarshal(coverage, &setup)
			r.Coverage = &QACoverageSummary{Total: c.Total, Covered: c.Covered, Percent: c.Percent, Spec: setup.Spec, Problems: setup.Problems}
		}
	}
	if len(perf) > 0 {
		r.Perf = &qa.PerfStats{}
		if json.Unmarshal(perf, r.Perf) != nil {
			return r, errors.New("invalid QA run data")
		}
	}
	return r, nil
}

// queueQA records the QA runs a completed assessment triggers, in the same
// transaction: a functional run when the asset's profile is enabled, set to
// run automatically and covers the ref. A commit whose verdict is fail is
// recorded as skipped, so its code never reaches the runner.
func (s *Store) queueQA(ctx context.Context, tx pgx.Tx, a Assessment, verdict string) error {
	if a.Request.Target.Type != "git" || a.Request.Import != nil || a.Request.Remediation != nil {
		return nil
	}
	p, err := scanProfile(tx.QueryRow(ctx, `SELECT `+profileColumns+` FROM `+s.schema+`.qa_profiles WHERE asset_id=$1`, a.AssetID))
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !p.Enabled || !p.AutoRun || !refMatches(p.Refs, a.Request.Target.Ref) {
		return nil
	}
	status, failure := "queued", ""
	if verdict == "fail" {
		status, failure = "skipped", ErrQABlocked.Error()
	}
	run, err := scanQARun(tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.qa_runs(id,asset_id,assessment_id,kind,trigger,requested_by,ref,commit,status,error,completed_at) VALUES($1,$2,$3,'functional','assessment',$4,$5,$6,$7,$8,CASE WHEN $7='skipped' THEN clock_timestamp() END) RETURNING `+qaRunColumns, uuid.New(), a.AssetID, a.ID, "scrs", a.Request.Target.Ref, a.Commit, status, failure))
	if err != nil || status != "skipped" {
		return err
	}
	return s.emitQA(ctx, tx, run, nil)
}

// unconfiguredQA returns a qa_unconfigured finding when a complete scan
// found an OpenAPI document in a repository that has no QA profile.
func (s *Store) unconfiguredQA(ctx context.Context, tx pgx.Tx, a Assessment, r Result) (*Finding, error) {
	if a.Request.Target.Type != "git" || a.Request.Import != nil || a.Request.Remediation != nil {
		return nil, nil
	}
	paths := make([]string, 0, len(r.Files))
	for _, f := range r.Files {
		paths = append(paths, f.Path)
	}
	spec := qa.FindSpec(paths)
	if spec == "" {
		return nil, nil
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.qa_profiles WHERE asset_id=$1)`, a.AssetID).Scan(&exists); err != nil || exists {
		return nil, err
	}
	evidence, _ := json.Marshal(map[string]string{"openapi": spec})
	return &Finding{Type: "qa_unconfigured", AdvisoryID: "SCRS-QA-UNCONFIGURED", Title: "API has an OpenAPI document but no QA profile", Severity: "low", Score: severityScore["low"], Component: Component{Name: "qa-profile", Path: spec}, Evidence: evidence, Guidance: json.RawMessage(`{"summary":"Add a QA profile (PUT /assets/{id}/qa/profile) with the deployed base URL, then commit Karate features or generate drafts from the OpenAPI document.","automatic_changes":false}`)}, nil
}

// EnqueueQARun queues a run of an asset's latest successful git assessment,
// or of the given one. Performance runs need the profile's perf settings.
func (s *Store) EnqueueQARun(ctx context.Context, asset uuid.UUID, assessment *uuid.UUID, kind string, includeDrafts bool, by string) (QARun, error) {
	if kind != qa.KindFunctional && kind != qa.KindPerformance {
		return QARun{}, ErrInput
	}
	p, err := s.QAProfileFor(ctx, asset)
	if errors.Is(err, ErrNotFound) || (err == nil && !p.Enabled) {
		return QARun{}, ErrQAProfile
	}
	if err != nil {
		return QARun{}, err
	}
	if kind == qa.KindPerformance && p.Perf == nil {
		return QARun{}, errors.Join(ErrInput, errors.New("the QA profile has no perf settings"))
	}
	a, err := s.qaAssessment(ctx, asset, assessment)
	if err != nil {
		return QARun{}, err
	}
	if a.Verdict == "fail" {
		return QARun{}, ErrQABlocked
	}
	return scanQARun(s.pool.QueryRow(ctx, `INSERT INTO `+s.schema+`.qa_runs(id,asset_id,assessment_id,kind,trigger,requested_by,ref,commit,include_drafts) VALUES($1,$2,$3,$4,'manual',$5,$6,$7,$8) RETURNING `+qaRunColumns, uuid.New(), asset, a.ID, kind, clip(by, 100), a.Request.Target.Ref, a.Commit, includeDrafts))
}

// qaAssessment returns the named assessment of the asset, or its latest
// successful git scan.
func (s *Store) qaAssessment(ctx context.Context, asset uuid.UUID, id *uuid.UUID) (Assessment, error) {
	var a Assessment
	var err error
	if id != nil {
		a, err = scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE id=$1 AND asset_id=$2 AND status='succeeded' AND request->'target'->>'type'='git' AND request->'import' IS NULL AND request->'remediation' IS NULL`, *id, asset))
	} else {
		a, err = scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE asset_id=$1 AND status='succeeded' AND request->'target'->>'type'='git' AND request->'import' IS NULL AND request->'remediation' IS NULL AND resolved_commit<>'' ORDER BY created_at DESC,id DESC LIMIT 1`, asset))
	}
	if errors.Is(err, ErrNotFound) {
		return a, ErrQANoAssessment
	}
	return a, err
}

// QALease bounds one worker step on a run; steps are short (submit, poll,
// ingest), so a dead worker frees the run quickly.
const QALease = 10 * time.Minute

// ClaimQARun leases the next run that needs work: a cancelled run whose
// runner job must be removed, an active run due for a poll, or a queued
// run while fewer than maxActive runs are on the runner.
func (s *Store) ClaimQARun(ctx context.Context, maxActive int) (QARun, error) {
	lease := uuid.New()
	return scanQARun(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.qa_runs SET lease=$1,lease_until=clock_timestamp()+($2*interval '1 second'),attempts=attempts+CASE WHEN status='queued' THEN 1 ELSE 0 END WHERE id=(SELECT id FROM `+s.schema+`.qa_runs r WHERE (r.status IN ('queued','submitted','running') OR r.cleanup) AND r.run_after<=clock_timestamp() AND (r.lease_until IS NULL OR r.lease_until<clock_timestamp()) AND (r.status<>'queued' OR r.cleanup OR (SELECT count(*) FROM `+s.schema+`.qa_runs a WHERE a.status IN ('submitted','running'))<$3) ORDER BY r.cleanup DESC,(r.status='queued'),r.run_after LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+qaRunColumns, lease, int64(QALease.Seconds()), maxActive))
}

// QAStep records a step that leaves the run active: its new status, when to
// look at it next, and what the worker learned on the way.
type QAStep struct {
	Status     string
	Delay      time.Duration
	Error      string
	BaseURL    string
	Operations []qa.Operation
	BasePaths  []string
	// Spec and Problems record the OpenAPI document used and setup issues.
	Spec     string
	Problems []string
	Started  *time.Time
}

// AdvanceQARun records a step and releases the lease.
func (s *Store) AdvanceQARun(ctx context.Context, r QARun, step QAStep) error {
	var ops, bases, setup []byte
	if step.Operations != nil {
		ops, _ = json.Marshal(step.Operations)
		bases, _ = json.Marshal(nonNil(step.BasePaths))
	}
	if step.Spec != "" || len(step.Problems) > 0 {
		setup, _ = json.Marshal(map[string]any{"spec": step.Spec, "problems": nonNil(step.Problems)})
	}
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.qa_runs SET status=$3,run_after=clock_timestamp()+($4*interval '1 millisecond'),error=$5,base_url=CASE WHEN $6='' THEN base_url ELSE $6 END,operations=COALESCE($7,operations),base_paths=COALESCE($8,base_paths),coverage=COALESCE($9,coverage),submitted_at=CASE WHEN $3='submitted' AND submitted_at IS NULL THEN clock_timestamp() ELSE submitted_at END,started_at=COALESCE(started_at,$10),lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, r.ID, r.Lease, step.Status, step.Delay.Milliseconds(), clip(step.Error, 1000), step.BaseURL, ops, bases, setup, step.Started)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrLease
	}
	return err
}

// QAOutcome is a finished run: the parsed report and the findings it makes.
type QAOutcome struct {
	Status       string
	Error        string
	Report       *qa.Report
	Coverage     *qa.Coverage
	ReportKey    string
	ReportSHA256 string
	Findings     []Finding
	// Closes lists the finding types this run fully re-evaluated: open
	// findings of those types the run did not report are marked fixed.
	Closes []string
}

// FinishQARun records a run's end: scenarios, coverage, findings, events.
func (s *Store) FinishQARun(ctx context.Context, r QARun, o QAOutcome) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var summary, coverage, perf []byte
	summary = []byte("{}")
	if o.Report != nil {
		summary, _ = json.Marshal(o.Report.Summary)
		if o.Report.Perf != nil {
			perf, _ = json.Marshal(o.Report.Perf)
		}
	}
	if o.Coverage != nil {
		var setup QACoverageSummary
		if r.Coverage != nil {
			setup = *r.Coverage
		}
		withSetup := struct {
			qa.Coverage
			Spec     string   `json:"spec,omitempty"`
			Problems []string `json:"problems,omitempty"`
		}{*o.Coverage, setup.Spec, setup.Problems}
		coverage, _ = json.Marshal(withSetup)
	}
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.qa_runs SET status=$3,error=$4,summary=$5,coverage=COALESCE($6,coverage),perf=$7,report_key=$8,report_sha256=$9,completed_at=clock_timestamp(),lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, r.ID, r.Lease, o.Status, clip(o.Error, 1000), summary, coverage, perf, o.ReportKey, o.ReportSHA256)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLease
	}
	batch := &pgx.Batch{}
	if o.Report != nil {
		for i, sc := range o.Report.Scenarios {
			body, _ := json.Marshal(sc)
			batch.Queue(`INSERT INTO `+s.schema+`.qa_scenarios(run_id,ordinal,body) VALUES($1,$2,$3)`, r.ID, i, body)
		}
	}
	created, current, err := s.recordQAFindings(ctx, tx, batch, r, o)
	if err != nil {
		return err
	}
	if err := tx.SendBatch(ctx, batch).Close(); err != nil {
		return err
	}
	if len(o.Closes) > 0 && r.Ref != "" {
		if _, err := tx.Exec(ctx, `WITH closed AS (UPDATE `+s.schema+`.findings SET status='fixed',revision=revision+1 WHERE asset_id=$1 AND ref=$2 AND type=ANY($3) AND fingerprint<>ALL($4) AND status IN ('open','triaged','in_progress') RETURNING id) INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) SELECT id,'fixed_by_qa_run',jsonb_build_object('qa_run_id',$5::text) FROM closed`, r.AssetID, r.Ref, o.Closes, current, r.ID.String()); err != nil {
			return err
		}
	}
	done, err := scanQARun(tx.QueryRow(ctx, `SELECT `+qaRunColumns+` FROM `+s.schema+`.qa_runs WHERE id=$1`, r.ID))
	if err != nil {
		return err
	}
	if err := s.emitQA(ctx, tx, done, created); err != nil {
		return err
	}
	// A passing functional run may start the profile's automatic load test.
	if done.Kind == qa.KindFunctional && done.Status == qa.StatePassed {
		var auto bool
		err := tx.QueryRow(ctx, `SELECT enabled AND COALESCE((perf->>'auto_run')::boolean,false) FROM `+s.schema+`.qa_profiles WHERE asset_id=$1`, r.AssetID).Scan(&auto)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if auto {
			if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.qa_runs(id,asset_id,assessment_id,kind,trigger,requested_by,ref,commit) VALUES($1,$2,$3,'performance','functional_pass','scrs',$4,$5)`, uuid.New(), r.AssetID, r.AssessmentID, r.Ref, r.Commit); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}

// recordQAFindings upserts a run's findings into the register and returns
// the new ones and every fingerprint the run reported.
func (s *Store) recordQAFindings(ctx context.Context, tx pgx.Tx, batch *pgx.Batch, r QARun, o QAOutcome) ([]Finding, []string, error) {
	scope := Assessment{AssetID: r.AssetID, Request: Request{Target: Target{Ref: r.Ref}}}
	seen := map[string]bool{}
	unique := []Finding{}
	for _, f := range o.Findings {
		f.Fingerprint = fingerprint(scope, f)
		if seen[f.Fingerprint] || len(unique) >= 10000 {
			continue
		}
		seen[f.Fingerprint] = true
		unique = append(unique, f)
	}
	fingerprints := make([]string, len(unique))
	for i, f := range unique {
		fingerprints[i] = f.Fingerprint
	}
	registered, err := stringSet(ctx, tx, `SELECT fingerprint FROM `+s.schema+`.findings WHERE fingerprint=ANY($1)`, fingerprints)
	if err != nil {
		return nil, nil, err
	}
	var created []Finding
	detail, _ := json.Marshal(map[string]string{"qa_run_id": r.ID.String()})
	for i := range unique {
		f := &unique[i]
		f.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(f.Fingerprint))
		f.AssetID, f.Ref, f.Status = r.AssetID, r.Ref, "open"
		f.FirstSeen = time.Now().UTC()
		f.LastSeen = f.FirstSeen
		if !json.Valid(f.Evidence) || !json.Valid(f.Guidance) || f.Score < 0 || f.Score > 100 {
			return nil, nil, ErrInput
		}
		if !registered[f.Fingerprint] {
			created = append(created, *f)
		}
		component, _ := json.Marshal(f.Component)
		snapshot, _ := json.Marshal(f)
		batch.Queue(`INSERT INTO `+s.schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance,last_assessment_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(fingerprint) DO UPDATE SET last_seen=clock_timestamp(),last_assessment_id=COALESCE(EXCLUDED.last_assessment_id,findings.last_assessment_id),evidence=EXCLUDED.evidence,guidance=EXCLUDED.guidance,severity=EXCLUDED.severity,score=EXCLUDED.score,title=EXCLUDED.title,status=CASE WHEN findings.status='fixed' OR (findings.status='accepted' AND findings.waiver_until<=clock_timestamp()) THEN 'open' ELSE findings.status END,revision=findings.revision+1`, f.ID, f.AssetID, f.Fingerprint, f.Ref, f.Type, f.AdvisoryID, f.Title, f.Severity, f.Score, component, f.Evidence, f.Guidance, r.AssessmentID)
		if r.AssessmentID != nil {
			batch.Queue(`INSERT INTO `+s.schema+`.assessment_findings(assessment_id,finding_id,snapshot) VALUES($1,$2,$3) ON CONFLICT(assessment_id,finding_id) DO UPDATE SET snapshot=EXCLUDED.snapshot`, *r.AssessmentID, f.ID, snapshot)
		}
		batch.Queue(`INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'detected',$2)`, f.ID, detail)
	}
	return created, fingerprints, nil
}

// QASummary is the event payload of a run.
func QASummary(r QARun) map[string]any {
	self := "/qa/runs/" + r.ID.String()
	return map[string]any{
		"qa_run": map[string]any{
			"id": r.ID, "kind": r.Kind, "status": r.Status, "trigger": r.Trigger, "asset_id": r.AssetID, "assessment_id": r.AssessmentID,
			"ref": r.Ref, "commit": r.Commit, "summary": r.Summary, "coverage": r.Coverage, "perf": r.Perf, "error": r.Error,
			"created_at": r.CreatedAt, "completed_at": r.CompletedAt,
		},
		"links": map[string]string{"self": notify.Link(self), "scenarios": notify.Link(self + "/scenarios"), "coverage": notify.Link(self + "/coverage"), "report": notify.Link(self + "/report")},
	}
}

func (s *Store) emitQA(ctx context.Context, tx pgx.Tx, r QARun, created []Finding) error {
	event := "qa.completed"
	if r.Status == qa.StateError || r.Status == "skipped" {
		event = "qa.failed"
	}
	if r.Status == qa.StateCancelled {
		return nil
	}
	if _, err := notify.Emit(ctx, tx, s.schema, event, QASummary(r), nil); err != nil {
		return err
	}
	if len(created) == 0 {
		return nil
	}
	var briefs []map[string]any
	for _, f := range created {
		if len(briefs) < 100 {
			briefs = append(briefs, findingBrief(f))
		}
	}
	_, err := notify.Emit(ctx, tx, s.schema, "finding.created", map[string]any{"qa_run_id": r.ID, "assessment_id": r.AssessmentID, "asset_id": r.AssetID, "ref": r.Ref, "commit": r.Commit, "total": len(created), "truncated": len(created) > len(briefs), "findings": briefs}, nil)
	return err
}

// QARunByID returns one run.
func (s *Store) QARunByID(ctx context.Context, id uuid.UUID) (QARun, error) {
	return scanQARun(s.pool.QueryRow(ctx, `SELECT `+qaRunColumns+` FROM `+s.schema+`.qa_runs WHERE id=$1`, id))
}

// QARunFilter selects runs; zero values match everything.
type QARunFilter struct {
	Asset      uuid.UUID
	Assessment uuid.UUID
	Kind       string
	Status     string
	Before     *time.Time
	Limit      int
}

// QARuns lists runs newest first.
func (s *Store) QARuns(ctx context.Context, f QARunFilter) ([]QARun, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	rows, err := s.pool.Query(ctx, `SELECT `+qaRunColumns+` FROM `+s.schema+`.qa_runs WHERE ($1='00000000-0000-0000-0000-000000000000'::uuid OR asset_id=$1) AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR assessment_id=$2) AND ($3='' OR kind=$3) AND ($4='' OR status=$4) AND ($5::timestamptz IS NULL OR created_at<$5) ORDER BY created_at DESC,id DESC LIMIT $6`, f.Asset, f.Assessment, f.Kind, f.Status, f.Before, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QARun{}
	for rows.Next() {
		r, err := scanQARun(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// QAScenarios pages a run's scenarios after an ordinal; status filters to
// one outcome. next is the cursor for the following page, or -1.
func (s *Store) QAScenarios(ctx context.Context, run uuid.UUID, after int, status string) ([]qa.Scenario, int, error) {
	rows, err := s.pool.Query(ctx, `SELECT ordinal,body FROM `+s.schema+`.qa_scenarios WHERE run_id=$1 AND ordinal>$2 AND ($3='' OR body->>'status'=$3) ORDER BY ordinal LIMIT 501`, run, after, status)
	if err != nil {
		return nil, -1, err
	}
	defer rows.Close()
	out := []qa.Scenario{}
	next, last := -1, after
	for rows.Next() {
		var body []byte
		var ordinal int
		if err := rows.Scan(&ordinal, &body); err != nil {
			return nil, -1, err
		}
		if len(out) == 500 {
			next = last
			break
		}
		var sc qa.Scenario
		if json.Unmarshal(body, &sc) != nil {
			return nil, -1, errors.New("invalid QA scenario data")
		}
		out = append(out, sc)
		last = ordinal
	}
	return out, next, rows.Err()
}

// QARunCoverage returns a run's full coverage document.
func (s *Store) QARunCoverage(ctx context.Context, id uuid.UUID) (json.RawMessage, error) {
	var body []byte
	err := s.pool.QueryRow(ctx, `SELECT coverage FROM `+s.schema+`.qa_runs WHERE id=$1`, id).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err == nil && len(body) == 0 {
		return nil, ErrNotFound
	}
	return body, err
}

// CancelQARun stops a run that has not finished. A run already on the
// runner keeps a cleanup mark until the worker removes the runner job.
func (s *Store) CancelQARun(ctx context.Context, id uuid.UUID, by string) (QARun, error) {
	r, err := scanQARun(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.qa_runs SET status='cancelled',cleanup=status IN ('submitted','running'),error=$2,completed_at=clock_timestamp(),run_after=clock_timestamp(),lease=NULL,lease_until=NULL WHERE id=$1 AND status IN ('queued','submitted','running') RETURNING `+qaRunColumns, id, clip("cancelled by "+by, 200)))
	if errors.Is(err, ErrNotFound) {
		if _, getErr := s.QARunByID(ctx, id); getErr != nil {
			return r, getErr
		}
		return r, ErrQAState
	}
	return r, err
}

// QACleaned clears a cancelled run's cleanup mark.
func (s *Store) QACleaned(ctx context.Context, r QARun) error {
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.qa_runs SET cleanup=false,lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, r.ID, r.Lease)
	return err
}

// QACoveragePoint is one functional run in an asset's coverage history.
type QACoveragePoint struct {
	RunID     uuid.UUID `json:"run_id"`
	CreatedAt time.Time `json:"created_at"`
	Ref       string    `json:"ref"`
	Commit    string    `json:"commit"`
	Status    string    `json:"status"`
	Total     int       `json:"total"`
	Covered   int       `json:"covered"`
	Percent   float64   `json:"percent"`
	Passed    int       `json:"passed"`
	Failed    int       `json:"failed"`
}

// QACoverageHistory lists finished functional runs with coverage, oldest
// first, for trend charts.
func (s *Store) QACoverageHistory(ctx context.Context, asset uuid.UUID, ref string, limit int) ([]QACoveragePoint, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT id,created_at,ref,commit,status,COALESCE((coverage->>'total')::int,0),COALESCE((coverage->>'covered')::int,0),COALESCE((coverage->>'percent')::float8,0),COALESCE((summary->>'passed')::int,0),COALESCE((summary->>'failed')::int,0) FROM (SELECT * FROM `+s.schema+`.qa_runs WHERE asset_id=$1 AND kind='functional' AND status IN ('passed','failed') AND coverage ? 'total' AND ($2='' OR ref=$2) ORDER BY created_at DESC LIMIT $3) recent ORDER BY created_at`, asset, ref, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []QACoveragePoint{}
	for rows.Next() {
		var p QACoveragePoint
		if err := rows.Scan(&p.RunID, &p.CreatedAt, &p.Ref, &p.Commit, &p.Status, &p.Total, &p.Covered, &p.Percent, &p.Passed, &p.Failed); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// QAContext returns what the worker needs to prepare a run: the assessment
// and the profile with its sealed variables.
func (s *Store) QAContext(ctx context.Context, r QARun) (Assessment, QAProfile, []byte, error) {
	if r.AssessmentID == nil {
		return Assessment{}, QAProfile{}, nil, ErrQANoAssessment
	}
	a, err := s.Get(ctx, *r.AssessmentID)
	if err != nil {
		return a, QAProfile{}, nil, err
	}
	p, sealed, err := s.QAProfileSecret(ctx, r.AssetID)
	if errors.Is(err, ErrNotFound) {
		return a, p, nil, ErrQAProfile
	}
	return a, p, sealed, err
}
