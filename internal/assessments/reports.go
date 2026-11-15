package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/compliance"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Compliance evidence reports (CMP-001 to CMP-006): framework packs, report
// jobs built by the worker, files stored in S3 under the "reports"
// retention class.

func reportSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.reports(id uuid PRIMARY KEY,framework text NOT NULL,scope jsonb NOT NULL,params jsonb NOT NULL DEFAULT '{}',format text NOT NULL CHECK(format IN ('json','csv','md')),status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','running','succeeded','failed')),s3_key text,sha256 text,size bigint,data_as_of timestamptz,scrs_version text,feed_freshness jsonb,summary jsonb,error text NOT NULL DEFAULT '',requested_by uuid,lease uuid,lease_until timestamptz,attempts integer NOT NULL DEFAULT 0,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),completed_at timestamptz)`,
		`ALTER TABLE ` + s + `.reports ADD COLUMN IF NOT EXISTS since timestamptz`,
		// P2: PDF reports.
		`ALTER TABLE ` + s + `.reports DROP CONSTRAINT IF EXISTS reports_format_check`,
		`ALTER TABLE ` + s + `.reports ADD CONSTRAINT reports_format_check CHECK(format IN ('json','csv','md','pdf'))`,
		`ALTER TABLE ` + s + `.reports ADD COLUMN IF NOT EXISTS until timestamptz`,
		`CREATE INDEX IF NOT EXISTS reports_queue_idx ON ` + s + `.reports(created_at) WHERE status IN ('queued','running')`,
		`CREATE INDEX IF NOT EXISTS reports_created_idx ON ` + s + `.reports(created_at DESC,id DESC)`,
		// CMP-005: uploaded CWE-mapping packs.
		`CREATE TABLE IF NOT EXISTS ` + s + `.framework_packs(id text PRIMARY KEY,body jsonb NOT NULL,created_by uuid,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
	}
}

// FrameworkPacks lists shipped and uploaded packs.
func (s *Store) FrameworkPacks(ctx context.Context) ([]compliance.Pack, error) {
	out := compliance.Builtin()
	rows, err := s.pool.Query(ctx, `SELECT body FROM `+s.schema+`.framework_packs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var p compliance.Pack
		if json.Unmarshal(raw, &p) == nil {
			out = append(out, p)
		}
	}
	return out, rows.Err()
}

// FrameworkPack returns one shipped or uploaded pack.
func (s *Store) FrameworkPack(ctx context.Context, id string) (compliance.Pack, error) {
	if p, ok := compliance.BuiltinPack(id); ok {
		return p, nil
	}
	var raw []byte
	err := s.pool.QueryRow(ctx, `SELECT body FROM `+s.schema+`.framework_packs WHERE id=$1`, id).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return compliance.Pack{}, ErrNotFound
	}
	if err != nil {
		return compliance.Pack{}, err
	}
	var p compliance.Pack
	return p, json.Unmarshal(raw, &p)
}

// SaveFrameworkPack stores or replaces an uploaded pack (CMP-005).
func (s *Store) SaveFrameworkPack(ctx context.Context, p compliance.Pack, actor uuid.UUID) error {
	body, _ := json.Marshal(p)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.framework_packs(id,body,created_by) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body,updated_at=clock_timestamp()`, p.ID, body, actor); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "pack": p.ID, "version": p.Version, "categories": len(p.Categories)})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('framework_pack.saved',$1)`, details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// DeleteFrameworkPack removes an uploaded pack.
func (s *Store) DeleteFrameworkPack(ctx context.Context, id string, actor uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM `+s.schema+`.framework_packs WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "pack": id})
	_, err = s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('framework_pack.deleted',$1)`, details)
	return err
}

// ReportRequest asks for one evidence report (CMP-006).
type ReportRequest struct {
	Framework string            `json:"framework"`
	Scope     compliance.Scope  `json:"scope"`
	Since     *time.Time        `json:"since,omitempty"`
	Until     *time.Time        `json:"until,omitempty"`
	Format    string            `json:"format"`
	Params    compliance.Params `json:"params"`
}

// ReportJob is a stored report request and its result.
type ReportJob struct {
	ID          uuid.UUID         `json:"id"`
	Framework   string            `json:"framework"`
	Scope       compliance.Scope  `json:"scope"`
	Since       time.Time         `json:"since"`
	Until       time.Time         `json:"until"`
	Format      string            `json:"format"`
	Params      compliance.Params `json:"params"`
	Status      string            `json:"status"`
	SHA256      string            `json:"sha256,omitempty"`
	Size        int64             `json:"size,omitempty"`
	DataAsOf    *time.Time        `json:"data_as_of,omitempty"`
	Version     string            `json:"scrs_version,omitempty"`
	Feeds       json.RawMessage   `json:"feed_freshness,omitempty"`
	Summary     json.RawMessage   `json:"summary,omitempty"`
	Error       string            `json:"error,omitempty"`
	RequestedBy *uuid.UUID        `json:"requested_by,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	CompletedAt *time.Time        `json:"completed_at,omitempty"`
	Key         string            `json:"-"`
	Lease       uuid.UUID         `json:"-"`
}

const reportColumns = `id,framework,scope,since,until,format,params,status,COALESCE(sha256,''),COALESCE(size,0),data_as_of,COALESCE(scrs_version,''),feed_freshness,summary,error,requested_by,created_at,completed_at,COALESCE(s3_key,''),COALESCE(lease,'00000000-0000-0000-0000-000000000000'::uuid)`

func scanReport(row pgx.Row) (ReportJob, error) {
	var j ReportJob
	var scope, params []byte
	var feeds, summary []byte
	err := row.Scan(&j.ID, &j.Framework, &scope, &j.Since, &j.Until, &j.Format, &params, &j.Status, &j.SHA256, &j.Size, &j.DataAsOf, &j.Version, &feeds, &summary, &j.Error, &j.RequestedBy, &j.CreatedAt, &j.CompletedAt, &j.Key, &j.Lease)
	if err != nil {
		return j, err
	}
	_ = json.Unmarshal(scope, &j.Scope)
	_ = json.Unmarshal(params, &j.Params)
	if len(feeds) > 0 {
		j.Feeds = feeds
	}
	if len(summary) > 0 {
		j.Summary = summary
	}
	return j, nil
}

var reportFramework = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{2,63}$`)

// CreateReport validates a request and queues it for the worker.
func (s *Store) CreateReport(ctx context.Context, r ReportRequest, actor uuid.UUID) (ReportJob, error) {
	if !reportFramework.MatchString(r.Framework) {
		return ReportJob{}, ErrInput
	}
	if _, err := s.FrameworkPack(ctx, r.Framework); err != nil {
		return ReportJob{}, err
	}
	if r.Format == "" {
		r.Format = "json"
	}
	if !slices.Contains(compliance.Formats, r.Format) {
		return ReportJob{}, ErrInput
	}
	until := time.Now().UTC()
	if r.Until != nil {
		until = r.Until.UTC()
	}
	since := until.Add(-90 * 24 * time.Hour)
	if r.Since != nil {
		since = r.Since.UTC()
	}
	if !since.Before(until) || until.Sub(since) > 366*24*time.Hour || until.After(time.Now().Add(time.Hour)) {
		return ReportJob{}, ErrInput
	}
	p := r.Params
	if p.SBOMMaxAgeDays < 0 || p.SBOMMaxAgeDays > 3650 || p.SLACriticalDays < 0 || p.SLACriticalDays > 3650 || p.SLAHighDays < 0 || p.SLAHighDays > 3650 {
		return ReportJob{}, ErrInput
	}
	switch r.Scope.Kind {
	case "portfolio":
		r.Scope.ID = nil
	case "asset", "owner":
		if r.Scope.ID == nil {
			return ReportJob{}, ErrInput
		}
		table := "assets"
		column := "locator"
		if r.Scope.Kind == "owner" {
			table, column = "owners", "name"
		}
		if err := s.pool.QueryRow(ctx, `SELECT `+column+` FROM `+s.schema+`.`+table+` WHERE id=$1`, *r.Scope.ID).Scan(&r.Scope.Name); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ReportJob{}, ErrNotFound
			}
			return ReportJob{}, err
		}
	default:
		return ReportJob{}, ErrInput
	}
	scope, _ := json.Marshal(r.Scope)
	params, _ := json.Marshal(p)
	id := uuid.New()
	if _, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.reports(id,framework,scope,since,until,format,params,requested_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8)`, id, r.Framework, scope, since, until, r.Format, params, actor); err != nil {
		return ReportJob{}, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "framework": r.Framework, "scope": r.Scope, "format": r.Format})
	if _, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('report.requested',$1,$2)`, id, details); err != nil {
		return ReportJob{}, err
	}
	return s.Report(ctx, id)
}

// Report returns one report job.
func (s *Store) Report(ctx context.Context, id uuid.UUID) (ReportJob, error) {
	j, err := scanReport(s.pool.QueryRow(ctx, `SELECT `+reportColumns+` FROM `+s.schema+`.reports WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return j, ErrNotFound
	}
	return j, err
}

// Reports lists report jobs, newest first, before the cursor.
func (s *Store) Reports(ctx context.Context, before uuid.UUID, limit int) ([]ReportJob, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `SELECT `+reportColumns+` FROM `+s.schema+`.reports WHERE ($1='00000000-0000-0000-0000-000000000000'::uuid OR (created_at,id)<(SELECT created_at,id FROM `+s.schema+`.reports WHERE id=$1)) ORDER BY created_at DESC,id DESC LIMIT $2`, before, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReportJob{}
	for rows.Next() {
		j, err := scanReport(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

// ClaimReport leases the oldest queued report (or one whose lease expired).
func (s *Store) ClaimReport(ctx context.Context) (*ReportJob, error) {
	lease := uuid.New()
	j, err := scanReport(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.reports SET status='running',lease=$1,lease_until=clock_timestamp()+interval '10 minutes',attempts=attempts+1 WHERE id=(SELECT id FROM `+s.schema+`.reports WHERE (status='queued' OR (status='running' AND lease_until<clock_timestamp())) AND attempts<3 ORDER BY created_at FOR UPDATE SKIP LOCKED LIMIT 1) RETURNING `+reportColumns, lease))
	if errors.Is(err, pgx.ErrNoRows) {
		// Reports that kept failing their lease are failed, not retried forever.
		_, _ = s.pool.Exec(ctx, `UPDATE `+s.schema+`.reports SET status='failed',error='report generation did not complete after 3 attempts',completed_at=clock_timestamp(),lease=NULL,lease_until=NULL WHERE status='running' AND lease_until<clock_timestamp() AND attempts>=3`)
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &j, nil
}

// FinishReport records a generated report.
func (s *Store) FinishReport(ctx context.Context, j ReportJob, key, digest string, size int64, dataAsOf time.Time, version string, feeds, summary any) error {
	feedJSON, _ := json.Marshal(feeds)
	summaryJSON, _ := json.Marshal(summary)
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.reports SET status='succeeded',s3_key=$3,sha256=$4,size=$5,data_as_of=$6,scrs_version=$7,feed_freshness=$8,summary=$9,completed_at=clock_timestamp(),lease=NULL,lease_until=NULL,error='' WHERE id=$1 AND lease=$2`, j.ID, j.Lease, key, digest, size, dataAsOf, version, feedJSON, summaryJSON)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLease
	}
	return nil
}

// FailReport records a generation failure.
func (s *Store) FailReport(ctx context.Context, j ReportJob, reason string) error {
	if len(reason) > 500 {
		reason = reason[:500]
	}
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.reports SET status='failed',error=$3,completed_at=clock_timestamp(),lease=NULL,lease_until=NULL WHERE id=$1 AND lease=$2`, j.ID, j.Lease, reason)
	return err
}

var cveInText = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)

// ReportInput reads the assets, register entries and feed state a report
// covers. CWEs come from the finding's advisory (OSV cwe_ids), imported
// tool data, and NVD and CVE Program records for its CVE aliases.
func (s *Store) ReportInput(ctx context.Context, j ReportJob) (compliance.Pack, compliance.Input, error) {
	pack, err := s.FrameworkPack(ctx, j.Framework)
	if err != nil {
		return pack, compliance.Input{}, err
	}
	in := compliance.Input{ID: j.ID, Scope: j.Scope, Since: j.Since, Until: j.Until, Format: j.Format, Params: j.Params, Assets: []compliance.Asset{}, Findings: []compliance.Finding{}}
	scopeSQL := `TRUE`
	args := []any{j.Since, j.Until}
	switch j.Scope.Kind {
	case "asset":
		scopeSQL, args = `a.id=$3`, append(args, *j.Scope.ID)
	case "owner":
		scopeSQL, args = `a.owner_id=$3`, append(args, *j.Scope.ID)
	}
	rows, err := s.pool.Query(ctx, `SELECT a.id,a.locator,a.type,COALESCE(o.name,''),
		(SELECT max(x.completed_at) FROM `+s.schema+`.assessments x WHERE x.asset_id=a.id AND x.status='succeeded' AND x.completed_at<=$2),
		(SELECT max(x.completed_at) FROM `+s.schema+`.assessments x WHERE x.asset_id=a.id AND x.status='succeeded' AND x.sbom_key<>'' AND x.completed_at<=$2),
		(SELECT count(DISTINCT x.resolved_commit) FROM `+s.schema+`.assessments x WHERE x.asset_id=a.id AND x.status='succeeded' AND x.sbom_key<>'' AND x.completed_at BETWEEN $1 AND $2),
		COALESCE((SELECT count(*) FROM `+s.schema+`.components c WHERE c.assessment_id=(SELECT x.id FROM `+s.schema+`.assessments x WHERE x.asset_id=a.id AND x.status='succeeded' AND x.sbom_key<>'' AND x.completed_at<=$2 ORDER BY x.completed_at DESC LIMIT 1)),0)
		FROM `+s.schema+`.assets a LEFT JOIN `+s.schema+`.owners o ON o.id=a.owner_id
		WHERE `+scopeSQL+` AND a.flags->>'in_scope'='true' ORDER BY a.locator LIMIT 5000`, args...)
	if err != nil {
		return pack, in, err
	}
	for rows.Next() {
		var a compliance.Asset
		if err := rows.Scan(&a.ID, &a.Locator, &a.Type, &a.Owner, &a.LastAssessed, &a.LastSBOM, &a.SBOMs, &a.Components); err != nil {
			rows.Close()
			return pack, in, err
		}
		in.Assets = append(in.Assets, a)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return pack, in, err
	}
	ids := make([]uuid.UUID, len(in.Assets))
	for i, a := range in.Assets {
		ids[i] = a.ID
	}
	// Entries open at some point in the window: seen before it ended and
	// not closed before it began.
	rows, err = s.pool.Query(ctx, `SELECT f.id,f.asset_id,f.type,f.severity,f.status,f.advisory_id,f.first_seen,
		(SELECT max(e.created_at) FROM `+s.schema+`.finding_events e WHERE e.finding_id=f.id AND e.action IN ('fixed_by_complete_scan','fixed_by_import')),
		COALESCE(f.evidence->'database_specific'->'cwe_ids','[]'::jsonb) || COALESCE(CASE WHEN jsonb_typeof(f.evidence->'cwe')='array' THEN f.evidence->'cwe' END,'[]'::jsonb),
		COALESCE(CASE WHEN jsonb_typeof(f.guidance->'aliases')='array' THEN f.guidance->'aliases' END,'[]'::jsonb),
		COALESCE((f.guidance->>'kev')::boolean,false)
		FROM `+s.schema+`.findings f WHERE f.asset_id=ANY($1) AND f.first_seen<=$2 LIMIT 200000`, ids, j.Until)
	if err != nil {
		return pack, in, err
	}
	cves := map[string]bool{}
	type pending struct {
		index int
		cves  []string
	}
	var lookups []pending
	for rows.Next() {
		var f compliance.Finding
		var cweRaw, aliasRaw []byte
		if err := rows.Scan(&f.ID, &f.AssetID, &f.Type, &f.Severity, &f.Status, &f.AdvisoryID, &f.FirstSeen, &f.ClosedAt, &cweRaw, &aliasRaw, &f.KEV); err != nil {
			rows.Close()
			return pack, in, err
		}
		if f.Status == "fixed" && f.ClosedAt != nil && f.ClosedAt.Before(j.Since) {
			continue
		}
		var cweText, aliases []string
		_ = json.Unmarshal(cweRaw, &cweText)
		_ = json.Unmarshal(aliasRaw, &aliases)
		f.CWEs = cweNumbers(cweText)
		if len(f.CWEs) == 0 {
			ids := cveInText.FindAllString(f.AdvisoryID+" "+strings.Join(aliases, " "), -1)
			if len(ids) > 0 {
				lookups = append(lookups, pending{len(in.Findings), ids})
				for _, id := range ids {
					cves[id] = true
				}
			}
		}
		in.Findings = append(in.Findings, f)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return pack, in, err
	}
	if len(cves) > 0 {
		list := make([]string, 0, len(cves))
		for id := range cves {
			list = append(list, id)
		}
		byCVE := map[string][]int{}
		rows, err = s.pool.Query(ctx, `SELECT cve,COALESCE(record->'database_specific'->'cwe','[]'::jsonb) FROM `+s.schema+`.advisory_records WHERE cve=ANY($1)`, list)
		if err != nil {
			return pack, in, err
		}
		for rows.Next() {
			var cve string
			var raw []byte
			if err := rows.Scan(&cve, &raw); err != nil {
				rows.Close()
				return pack, in, err
			}
			var text []string
			_ = json.Unmarshal(raw, &text)
			byCVE[cve] = append(byCVE[cve], cweNumbers(text)...)
		}
		rows.Close()
		for _, p := range lookups {
			seen := map[int]bool{}
			for _, id := range p.cves {
				for _, cwe := range byCVE[id] {
					if !seen[cwe] {
						seen[cwe] = true
						in.Findings[p.index].CWEs = append(in.Findings[p.index].CWEs, cwe)
					}
				}
			}
		}
	}
	sources, err := s.VulnerabilitySources(ctx)
	if err != nil {
		return pack, in, err
	}
	for _, src := range sources {
		in.Feeds = append(in.Feeds, compliance.Feed{Key: src.Key, Name: src.Name, LastSuccess: src.LastSuccessAt, Stale: src.Stale})
	}
	return pack, in, nil
}

// cweNumbers converts "CWE-79" strings to numbers, skipping NVD's
// "NVD-CWE-Other" and "NVD-CWE-noinfo".
func cweNumbers(text []string) []int {
	out := []int{}
	seen := map[int]bool{}
	for _, t := range text {
		n, err := strconv.Atoi(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(t)), "CWE-"))
		if err != nil || n <= 0 || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}
