package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/ORIBData/scrstack/internal/advisory"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Vulnerability sources (VUL-001, VUL-010, VUL-011): every advisory source
// is a row with its licence, schedule and health. OSV, malicious packages,
// KEV and EPSS are downloaded by scrs-feed-sync and reported by the worker;
// NVD and the CVE Program are synced by the worker for the CVEs the
// register references; VEX documents are imported by operators.

func vulnSourceSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.vulnerability_sources(key text PRIMARY KEY,name text NOT NULL,kind text NOT NULL,url text NOT NULL DEFAULT '',managed_by text NOT NULL DEFAULT 'worker',schedule_minutes integer NOT NULL DEFAULT 0,licence text NOT NULL DEFAULT '',terms_url text NOT NULL DEFAULT '',restricted boolean NOT NULL DEFAULT false,enabled boolean NOT NULL DEFAULT true,state jsonb NOT NULL DEFAULT '{}',last_sync_at timestamptz,last_success_at timestamptz,next_sync_at timestamptz NOT NULL DEFAULT clock_timestamp(),lease_until timestamptz,record_count bigint NOT NULL DEFAULT 0,last_error text NOT NULL DEFAULT '',failures integer NOT NULL DEFAULT 0,stale boolean NOT NULL DEFAULT false,revision bigint NOT NULL DEFAULT 1,tracked_since timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`INSERT INTO ` + s + `.vulnerability_sources(key,name,kind,url,managed_by,schedule_minutes,licence,terms_url) VALUES
 ('osv','OSV.dev ecosystem dumps','osv_dump','https://osv-vulnerabilities.storage.googleapis.com','feed-sync',360,'CC-BY 4.0 (per-source terms vary)','https://google.github.io/osv.dev/faq/'),
 ('malicious_packages','OpenSSF malicious packages (MAL-)','malicious_packages','https://github.com/ossf/malicious-packages','feed-sync',360,'Apache-2.0','https://github.com/ossf/malicious-packages/blob/main/LICENSE'),
 ('kev','CISA Known Exploited Vulnerabilities','kev','https://www.cisa.gov/known-exploited-vulnerabilities-catalog','feed-sync',360,'US government work','https://www.cisa.gov/known-exploited-vulnerabilities-catalog'),
 ('epss','FIRST EPSS','epss','https://www.first.org/epss/','feed-sync',360,'FIRST EPSS usage terms','https://www.first.org/epss/'),
 ('nvd','NVD CVE API 2.0','nvd','https://services.nvd.nist.gov/rest/json/cves/2.0','worker',120,'NVD terms of use (public domain; attribution requested)','https://nvd.nist.gov/developers/terms-of-use'),
 ('cve_program','CVE Program (CVE Services API)','cve5','https://cveawg.mitre.org/api/cve','worker',1440,'CVE Program terms of use','https://www.cve.org/Legal/TermsOfUse'),
 ('vex','Vendor statements (VEX, CSAF, OpenVEX imports)','vex','','operator',0,'Per publisher','')
 ON CONFLICT(key) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.advisory_records(origin text NOT NULL,id text NOT NULL,cve text NOT NULL DEFAULT '',modified timestamptz,withdrawn boolean NOT NULL DEFAULT false,record jsonb NOT NULL,raw jsonb NOT NULL,fetched_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(origin,id))`,
		`CREATE INDEX IF NOT EXISTS advisory_records_cve_idx ON ` + s + `.advisory_records(cve)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.vex_documents(id uuid PRIMARY KEY,format text NOT NULL,publisher text NOT NULL DEFAULT '',title text NOT NULL DEFAULT '',issued_at timestamptz,sha256 text NOT NULL UNIQUE,statements integer NOT NULL,imported_by text NOT NULL,imported_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.vendor_statements(id bigserial PRIMARY KEY,document_id uuid NOT NULL REFERENCES ` + s + `.vex_documents(id) ON DELETE CASCADE,vulnerability text NOT NULL,purl text NOT NULL DEFAULT '',product text NOT NULL DEFAULT '',status text NOT NULL,justification text NOT NULL DEFAULT '',impact text NOT NULL DEFAULT '',action text NOT NULL DEFAULT '')`,
		`CREATE INDEX IF NOT EXISTS vendor_statements_vuln_idx ON ` + s + `.vendor_statements(vulnerability)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.scheduler_runs(job text PRIMARY KEY,interval_seconds integer NOT NULL DEFAULT 0,last_started_at timestamptz,last_finished_at timestamptz,last_status text NOT NULL DEFAULT '',last_detail jsonb NOT NULL DEFAULT '{}',next_run_at timestamptz)`,
	}
}

// VulnSource is a source's settings and health.
type VulnSource struct {
	Key             string          `json:"key"`
	Name            string          `json:"name"`
	Kind            string          `json:"kind"`
	URL             string          `json:"url"`
	ManagedBy       string          `json:"managed_by"`
	ScheduleMinutes int             `json:"schedule_minutes"`
	Licence         string          `json:"licence"`
	TermsURL        string          `json:"terms_url"`
	Restricted      bool            `json:"restricted"`
	Enabled         bool            `json:"enabled"`
	State           json.RawMessage `json:"state"`
	LastSyncAt      *time.Time      `json:"last_sync_at"`
	LastSuccessAt   *time.Time      `json:"last_success_at"`
	NextSyncAt      time.Time       `json:"next_sync_at"`
	RecordCount     int64           `json:"record_count"`
	LastError       string          `json:"last_error"`
	Failures        int             `json:"failures"`
	Stale           bool            `json:"stale"`
	// LagSeconds is the time since the last successful sync.
	LagSeconds *int64 `json:"lag_seconds"`
	Revision   int64  `json:"revision"`
}

const vulnSourceColumns = `key,name,kind,url,managed_by,schedule_minutes,licence,terms_url,restricted,enabled,state,last_sync_at,last_success_at,next_sync_at,record_count,last_error,failures,stale,revision`

func scanVulnSource(row pgx.Row) (VulnSource, error) {
	var v VulnSource
	err := row.Scan(&v.Key, &v.Name, &v.Kind, &v.URL, &v.ManagedBy, &v.ScheduleMinutes, &v.Licence, &v.TermsURL, &v.Restricted, &v.Enabled, &v.State, &v.LastSyncAt, &v.LastSuccessAt, &v.NextSyncAt, &v.RecordCount, &v.LastError, &v.Failures, &v.Stale, &v.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return v, ErrNotFound
	}
	if err == nil && v.LastSuccessAt != nil {
		lag := int64(time.Since(*v.LastSuccessAt).Seconds())
		v.LagSeconds = &lag
	}
	return v, err
}

// VulnerabilitySources lists every source.
func (s *Store) VulnerabilitySources(ctx context.Context) ([]VulnSource, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+vulnSourceColumns+` FROM `+s.schema+`.vulnerability_sources ORDER BY key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnSource{}
	for rows.Next() {
		v, err := scanVulnSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VulnerabilitySource returns one source.
func (s *Store) VulnerabilitySource(ctx context.Context, key string) (VulnSource, error) {
	return scanVulnSource(s.pool.QueryRow(ctx, `SELECT `+vulnSourceColumns+` FROM `+s.schema+`.vulnerability_sources WHERE key=$1`, key))
}

// ErrSourceManaged means scrs-feed-sync controls the source.
var ErrSourceManaged = errors.New("this source is downloaded by scrs-feed-sync; configure it with SCRS_OSV_ECOSYSTEMS and the feed-sync schedule")

// ErrTermsNotAcknowledged means a restricted source needs acknowledge_terms.
var ErrTermsNotAcknowledged = errors.New("this source's licence restricts use; set acknowledge_terms after legal review")

// UpdateVulnerabilitySource changes a worker-synced source's enabled flag
// or schedule at the expected revision. Enabling a restricted source needs
// acknowledgeTerms and is audited (VUL-011).
func (s *Store) UpdateVulnerabilitySource(ctx context.Context, key string, expected int64, enabled *bool, schedule *int, acknowledgeTerms bool, actor uuid.UUID) (VulnSource, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return VulnSource{}, err
	}
	defer tx.Rollback(ctx)
	before, err := scanVulnSource(tx.QueryRow(ctx, `SELECT `+vulnSourceColumns+` FROM `+s.schema+`.vulnerability_sources WHERE key=$1 FOR UPDATE`, key))
	if err != nil {
		return before, err
	}
	if before.Revision != expected {
		return before, ErrConflict
	}
	if before.ManagedBy != "worker" {
		return before, ErrSourceManaged
	}
	after := before
	if enabled != nil {
		after.Enabled = *enabled
	}
	if schedule != nil {
		if *schedule < 15 || *schedule > 10080 {
			return before, ErrInput
		}
		after.ScheduleMinutes = *schedule
	}
	if after.Enabled && !before.Enabled && before.Restricted && !acknowledgeTerms {
		return before, ErrTermsNotAcknowledged
	}
	updated, err := scanVulnSource(tx.QueryRow(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET enabled=$2,schedule_minutes=$3,next_sync_at=clock_timestamp(),stale=CASE WHEN $2 THEN stale ELSE false END,revision=revision+1 WHERE key=$1 RETURNING `+vulnSourceColumns, key, after.Enabled, after.ScheduleMinutes))
	if err != nil {
		return before, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "key": key, "enabled": updated.Enabled, "schedule_minutes": updated.ScheduleMinutes, "licence": updated.Licence, "terms_acknowledged": acknowledgeTerms})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('vulnerability_source.changed',$1)`, details); err != nil {
		return before, err
	}
	return updated, tx.Commit(ctx)
}

// SyncVulnerabilitySourceNow makes a worker-synced source due now.
func (s *Store) SyncVulnerabilitySourceNow(ctx context.Context, key string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET next_sync_at=clock_timestamp() WHERE key=$1 AND managed_by='worker'`, key)
	if err == nil && tag.RowsAffected() == 0 {
		if _, getErr := s.VulnerabilitySource(ctx, key); getErr != nil {
			return getErr
		}
		return ErrSourceManaged
	}
	return err
}

// ClaimVulnerabilitySource leases the most overdue enabled worker source.
func (s *Store) ClaimVulnerabilitySource(ctx context.Context, lease time.Duration) (VulnSource, error) {
	return scanVulnSource(s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET lease_until=clock_timestamp()+($1*interval '1 second'),last_sync_at=clock_timestamp() WHERE key=(SELECT key FROM `+s.schema+`.vulnerability_sources WHERE managed_by='worker' AND enabled AND next_sync_at<=clock_timestamp() AND (lease_until IS NULL OR lease_until<clock_timestamp()) ORDER BY next_sync_at LIMIT 1 FOR UPDATE SKIP LOCKED) RETURNING `+vulnSourceColumns, int64(lease.Seconds())))
}

// FinishVulnerabilitySource records a sync: the new state and record count
// on success, or the error with backoff (doubling up to a day).
func (s *Store) FinishVulnerabilitySource(ctx context.Context, key string, state json.RawMessage, syncErr error) error {
	if syncErr == nil {
		_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET state=COALESCE($2,state),lease_until=NULL,failures=0,last_error='',last_success_at=clock_timestamp(),stale=false,next_sync_at=clock_timestamp()+schedule_minutes*interval '1 minute',record_count=(SELECT count(*) FROM `+s.schema+`.advisory_records r WHERE r.origin=CASE $1 WHEN 'cve_program' THEN 'cve5' ELSE $1 END) WHERE key=$1`, key, state)
		return err
	}
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET lease_until=NULL,failures=failures+1,last_error=$2,next_sync_at=clock_timestamp()+LEAST(GREATEST(schedule_minutes,15)*power(2,LEAST(failures,6)),1440)*interval '1 minute' WHERE key=$1`, key, clip(syncErr.Error(), 1000))
	return err
}

// RecordFeedHealth stores what scrs-feed-sync last downloaded for a source.
func (s *Store) RecordFeedHealth(ctx context.Context, key string, fetchedAt *time.Time, records int64, failure string) error {
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET last_sync_at=clock_timestamp(),last_success_at=COALESCE($2,last_success_at),record_count=CASE WHEN $3>0 THEN $3 ELSE record_count END,last_error=$4,failures=CASE WHEN $4='' THEN 0 ELSE failures+1 END WHERE key=$1`, key, fetchedAt, records, clip(failure, 1000))
	return err
}

// StaleTransitions marks enabled sources whose last success (or, for one
// that never succeeded, its tracking start) is older than twice their
// schedule (VUL-010) and returns the ones that just became
// stale; sources that recovered are cleared.
func (s *Store) StaleTransitions(ctx context.Context) ([]VulnSource, error) {
	if _, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET stale=false WHERE stale AND (NOT enabled OR schedule_minutes=0 OR last_success_at>=clock_timestamp()-2*schedule_minutes*interval '1 minute')`); err != nil {
		return nil, err
	}
	rows, err := s.pool.Query(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET stale=true WHERE enabled AND NOT stale AND schedule_minutes>0 AND (last_success_at IS NULL AND tracked_since<clock_timestamp()-2*schedule_minutes*interval '1 minute' OR last_success_at<clock_timestamp()-2*schedule_minutes*interval '1 minute') RETURNING `+vulnSourceColumns)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VulnSource{}
	for rows.Next() {
		v, err := scanVulnSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// TrackedCVEs returns CVE ids that open register entries reference (as the
// advisory or an alias) and that have no record from origin fetched since
// refreshed, up to limit.
func (s *Store) TrackedCVEs(ctx context.Context, origin string, refreshed time.Time, limit int) ([]string, error) {
	rows, err := s.pool.Query(ctx, `WITH refs AS (SELECT advisory_id AS cve FROM `+s.schema+`.findings WHERE status IN ('open','triaged','in_progress','accepted') UNION SELECT jsonb_array_elements_text(guidance->'aliases') FROM `+s.schema+`.findings WHERE status IN ('open','triaged','in_progress','accepted') AND jsonb_typeof(guidance->'aliases')='array') SELECT DISTINCT cve FROM refs WHERE cve ~ '^CVE-[0-9]{4}-[0-9]{4,}$' AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.advisory_records r WHERE r.origin=$1 AND r.id=refs.cve AND r.fetched_at>=$2) ORDER BY cve LIMIT $3`, origin, refreshed, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cve string
		if err := rows.Scan(&cve); err != nil {
			return nil, err
		}
		out = append(out, cve)
	}
	return out, rows.Err()
}

// KnownAdvisoryIDs reports which ids already have a record from origin; the
// NVD's modified-window sync refreshes only those.
func (s *Store) KnownAdvisoryIDs(ctx context.Context, origin string, ids []string) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT id FROM `+s.schema+`.advisory_records WHERE origin=$1 AND id=ANY($2)`, origin, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// SaveAdvisoryRecords upserts converted records with their originals.
func (s *Store) SaveAdvisoryRecords(ctx context.Context, records []advisory.Raw) error {
	batch := &pgx.Batch{}
	for _, r := range records {
		record, _ := json.Marshal(r.Record)
		raw := r.Source
		if !json.Valid(raw) {
			raw = json.RawMessage(`{}`)
		}
		batch.Queue(`INSERT INTO `+s.schema+`.advisory_records(origin,id,cve,modified,withdrawn,record,raw) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(origin,id) DO UPDATE SET cve=EXCLUDED.cve,modified=EXCLUDED.modified,withdrawn=EXCLUDED.withdrawn,record=EXCLUDED.record,raw=EXCLUDED.raw,fetched_at=clock_timestamp()`, r.Record.Origin, r.Record.ID, r.Record.ID, r.Record.Modified, r.Record.Withdrawn != nil, record, raw)
	}
	return s.pool.SendBatch(ctx, batch).Close()
}

// AdvisoryView is everything SCRS knows about one vulnerability id.
type AdvisoryView struct {
	ID              string               `json:"id"`
	Records         []json.RawMessage    `json:"records"`
	SeveritySources []advisory.CVSS      `json:"severity_sources"`
	CWE             []string             `json:"cwe"`
	Statements      []VendorStatementRow `json:"vendor_statements"`
}

// Advisory returns a vulnerability's records from every origin, its
// severity sources and CWEs, and vendor statements (for a product purl when
// given).
func (s *Store) Advisory(ctx context.Context, id, purl string) (AdvisoryView, error) {
	view := AdvisoryView{ID: id, Records: []json.RawMessage{}, SeveritySources: []advisory.CVSS{}, CWE: []string{}}
	rows, err := s.pool.Query(ctx, `SELECT record FROM `+s.schema+`.advisory_records WHERE id=$1 OR cve=$1 ORDER BY origin`, id)
	if err != nil {
		return view, err
	}
	cwe := map[string]bool{}
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			rows.Close()
			return view, err
		}
		view.Records = append(view.Records, raw)
		var r advisory.Record
		if json.Unmarshal(raw, &r) == nil {
			view.SeveritySources = append(view.SeveritySources, r.DatabaseSpecific.CVSS...)
			for _, c := range r.DatabaseSpecific.CWE {
				if !cwe[c] {
					cwe[c] = true
					view.CWE = append(view.CWE, c)
				}
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return view, err
	}
	if view.Statements, err = s.VendorStatements(ctx, id, purl); err != nil {
		return view, err
	}
	if len(view.Records) == 0 && len(view.Statements) == 0 {
		return view, ErrNotFound
	}
	return view, nil
}

// VEXDocument is an imported VEX document.
type VEXDocument struct {
	ID         uuid.UUID  `json:"id"`
	Format     string     `json:"format"`
	Publisher  string     `json:"publisher"`
	Title      string     `json:"title"`
	IssuedAt   *time.Time `json:"issued_at"`
	SHA256     string     `json:"sha256"`
	Statements int        `json:"statements"`
	ImportedBy string     `json:"imported_by"`
	ImportedAt time.Time  `json:"imported_at"`
}

// VendorStatementRow is a stored statement with its attribution.
type VendorStatementRow struct {
	advisory.Statement
	DocumentID uuid.UUID  `json:"document_id"`
	Format     string     `json:"format"`
	Publisher  string     `json:"publisher"`
	IssuedAt   *time.Time `json:"issued_at"`
}

const vexColumns = `id,format,publisher,title,issued_at,sha256,statements,imported_by,imported_at`

func scanVEX(row pgx.Row) (VEXDocument, error) {
	var d VEXDocument
	err := row.Scan(&d.ID, &d.Format, &d.Publisher, &d.Title, &d.IssuedAt, &d.SHA256, &d.Statements, &d.ImportedBy, &d.ImportedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

// ImportVEX stores a document's statements. The same document (by digest)
// imported again is a conflict.
func (s *Store) ImportVEX(ctx context.Context, doc advisory.Document, digest, by string) (VEXDocument, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return VEXDocument{}, err
	}
	defer tx.Rollback(ctx)
	saved, err := scanVEX(tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.vex_documents(id,format,publisher,title,issued_at,sha256,statements,imported_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT(sha256) DO NOTHING RETURNING `+vexColumns, uuid.New(), doc.Format, doc.Publisher, doc.Title, doc.IssuedAt, digest, len(doc.Statements), clip(by, 100)))
	if errors.Is(err, ErrNotFound) {
		return saved, ErrConflict
	}
	if err != nil {
		return saved, err
	}
	rows := make([][]any, len(doc.Statements))
	for i, st := range doc.Statements {
		rows[i] = []any{saved.ID, st.Vulnerability, st.PURL, st.Product, st.Status, st.Justification, st.Impact, st.Action}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{trimQuotes(s.schema), "vendor_statements"}, []string{"document_id", "vulnerability", "purl", "product", "status", "justification", "impact", "action"}, pgx.CopyFromRows(rows)); err != nil {
		return saved, err
	}
	details, _ := json.Marshal(map[string]any{"by": by, "format": doc.Format, "publisher": doc.Publisher, "statements": len(doc.Statements), "sha256": digest})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('vex.imported',$1,$2)`, saved.ID, details); err != nil {
		return saved, err
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.vulnerability_sources SET last_sync_at=clock_timestamp(),last_success_at=clock_timestamp(),record_count=(SELECT count(*) FROM `+s.schema+`.vendor_statements) WHERE key='vex'`); err != nil {
		return saved, err
	}
	return saved, tx.Commit(ctx)
}

// trimQuotes undoes pgx.Identifier.Sanitize for CopyFrom, which quotes again.
func trimQuotes(s string) string {
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// VEXDocuments lists imported documents, newest first.
func (s *Store) VEXDocuments(ctx context.Context) ([]VEXDocument, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+vexColumns+` FROM `+s.schema+`.vex_documents ORDER BY imported_at DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VEXDocument{}
	for rows.Next() {
		d, err := scanVEX(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// DeleteVEXDocument removes a document and its statements.
func (s *Store) DeleteVEXDocument(ctx context.Context, id uuid.UUID, by string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.vex_documents WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	details, _ := json.Marshal(map[string]any{"by": by})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('vex.deleted',$1,$2)`, id, details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// VendorStatements returns statements about a vulnerability (empty: all)
// for a product purl (empty: all). A statement without a version applies
// to every version of its package.
func (s *Store) VendorStatements(ctx context.Context, vulnerability, purl string) ([]VendorStatementRow, error) {
	rows, err := s.pool.Query(ctx, `SELECT v.vulnerability,v.purl,v.product,v.status,v.justification,v.impact,v.action,d.id,d.format,d.publisher,d.issued_at FROM `+s.schema+`.vendor_statements v JOIN `+s.schema+`.vex_documents d ON d.id=v.document_id WHERE ($1='' OR v.vulnerability=$1) AND ($2='' OR v.purl=$2 OR (v.purl<>'' AND position('@' in v.purl)=0 AND starts_with($2,v.purl||'@'))) ORDER BY d.issued_at DESC NULLS LAST,v.id LIMIT 500`, vulnerability, purl)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []VendorStatementRow{}
	for rows.Next() {
		var r VendorStatementRow
		if err := rows.Scan(&r.Vulnerability, &r.PURL, &r.Product, &r.Status, &r.Justification, &r.Impact, &r.Action, &r.DocumentID, &r.Format, &r.Publisher, &r.IssuedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SchedulerRun is a scheduled job's last run (MNT-005).
type SchedulerRun struct {
	Job             string          `json:"job"`
	IntervalSeconds int             `json:"interval_seconds"`
	LastStartedAt   *time.Time      `json:"last_started_at"`
	LastFinishedAt  *time.Time      `json:"last_finished_at"`
	LastStatus      string          `json:"last_status"`
	LastDetail      json.RawMessage `json:"last_detail"`
	NextRunAt       *time.Time      `json:"next_run_at"`
}

// RecordJob stores a scheduled job's run: status ok or failed, and detail.
func (s *Store) RecordJob(ctx context.Context, job string, interval time.Duration, started time.Time, runErr error, detail any) error {
	status := "ok"
	if runErr != nil {
		status = "failed"
		detail = map[string]string{"error": clip(runErr.Error(), 500)}
	}
	data, _ := json.Marshal(detail)
	if !json.Valid(data) || string(data) == "null" {
		data = []byte(`{}`)
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.scheduler_runs(job,interval_seconds,last_started_at,last_finished_at,last_status,last_detail,next_run_at) VALUES($1,$2::integer,$3,clock_timestamp(),$4,$5,clock_timestamp()+($2::integer*interval '1 second')) ON CONFLICT(job) DO UPDATE SET interval_seconds=EXCLUDED.interval_seconds,last_started_at=EXCLUDED.last_started_at,last_finished_at=EXCLUDED.last_finished_at,last_status=EXCLUDED.last_status,last_detail=EXCLUDED.last_detail,next_run_at=EXCLUDED.next_run_at`, job, int(interval.Seconds()), started, status, data)
	return err
}

// SchedulerRuns lists every recorded job.
func (s *Store) SchedulerRuns(ctx context.Context) ([]SchedulerRun, error) {
	rows, err := s.pool.Query(ctx, `SELECT job,interval_seconds,last_started_at,last_finished_at,last_status,last_detail,next_run_at FROM `+s.schema+`.scheduler_runs ORDER BY job`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SchedulerRun{}
	for rows.Next() {
		var r SchedulerRun
		if err := rows.Scan(&r.Job, &r.IntervalSeconds, &r.LastStartedAt, &r.LastFinishedAt, &r.LastStatus, &r.LastDetail, &r.NextRunAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
