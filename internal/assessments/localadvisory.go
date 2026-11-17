package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/ORIBData/scrstack/internal/advisory"
	"github.com/jackc/pgx/v5"
)

// Local advisories (OSV-008) are OSV records an operator writes for what no
// public database knows, such as an internal package found compromised. They
// are stored in advisory_records with origin "local" and ids x_SCRS-<year>-<n>.
// They are searchable and show up in GET /intel/vulnerabilities/{id}; they do
// not create register entries by themselves, and `affected` lists the
// components that match them in the latest assessments.

// OriginLocal is the origin of operator-written advisories.
const OriginLocal = "local"

var (
	ecosystemPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9.:_ -]{0,40}$`)
	localIDPattern   = regexp.MustCompile(`^x_SCRS-\d{4}-\d{4,}$`)
	referenceTypes   = map[string]bool{"ADVISORY": true, "ARTICLE": true, "DETECTION": true, "DISCUSSION": true, "REPORT": true, "FIX": true, "INTRODUCED": true, "GIT": true, "PACKAGE": true, "EVIDENCE": true, "WEB": true}
	severityTypes    = map[string]bool{"CVSS_V2": true, "CVSS_V3": true, "CVSS_V4": true}
)

// LocalPackage names the package an advisory is about.
type LocalPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl,omitempty"`
}

// LocalAffected is one affected package with its explicit versions. SCRS
// carries no version comparators, so ranges are not accepted: list the
// versions, or set all_versions for a package that is bad in every release.
type LocalAffected struct {
	Package     LocalPackage `json:"package"`
	Versions    []string     `json:"versions,omitempty"`
	AllVersions bool         `json:"all_versions,omitempty"`
}

// LocalAdvisoryInput is the body of POST /advisories.
type LocalAdvisoryInput struct {
	Summary    string               `json:"summary"`
	Details    string               `json:"details"`
	Aliases    []string             `json:"aliases"`
	Severity   []advisory.Severity  `json:"severity"`
	Affected   []LocalAffected      `json:"affected"`
	References []advisory.Reference `json:"references"`
	CWE        []string             `json:"cwe"`
}

func inputError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInput, fmt.Sprintf(format, args...))
}

func printable(s string, max int) bool {
	if s == "" || len(s) > max {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (in LocalAdvisoryInput) validate() error {
	if !printable(strings.TrimSpace(in.Summary), 200) || len(strings.TrimSpace(in.Summary)) < 3 {
		return inputError("summary must be 3 to 200 printable characters")
	}
	if len(in.Details) > 8000 {
		return inputError("details is limited to 8000 characters")
	}
	if len(in.Aliases) > 20 || len(in.CWE) > 20 || len(in.References) > 50 || len(in.Severity) > 4 {
		return inputError("too many aliases, cwe, references or severity entries")
	}
	for _, a := range in.Aliases {
		if !printable(a, 128) {
			return inputError("an alias is empty or too long")
		}
	}
	for _, c := range in.CWE {
		if !regexp.MustCompile(`^CWE-\d{1,5}$`).MatchString(c) {
			return inputError("cwe entries look like CWE-79")
		}
	}
	for _, s := range in.Severity {
		if !severityTypes[s.Type] || !printable(s.Score, 200) {
			return inputError("severity type must be CVSS_V2, CVSS_V3 or CVSS_V4 with the vector as score")
		}
	}
	for _, r := range in.References {
		u, err := url.Parse(r.URL)
		if !referenceTypes[r.Type] || err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || len(r.URL) > 500 {
			return inputError("a reference needs an OSV type and an http or https url")
		}
	}
	if len(in.Affected) == 0 || len(in.Affected) > 50 {
		return inputError("1 to 50 affected packages are required")
	}
	for _, a := range in.Affected {
		switch {
		case !ecosystemPattern.MatchString(a.Package.Ecosystem) || !printable(a.Package.Name, 214) || len(a.Package.PURL) > 500:
			return inputError("each affected package needs an ecosystem and a name")
		case a.AllVersions == (len(a.Versions) > 0):
			return inputError("list the affected versions, or set all_versions, for %s", a.Package.Name)
		case len(a.Versions) > 500:
			return inputError("at most 500 versions per package")
		}
		for _, v := range a.Versions {
			if !printable(v, 100) {
				return inputError("a version is empty or too long")
			}
		}
	}
	return nil
}

// CreateLocalAdvisory stores a new local advisory and returns its record.
func (s *Store) CreateLocalAdvisory(ctx context.Context, in LocalAdvisoryInput, by string) (json.RawMessage, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Truncate(time.Second)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	// One writer at a time, so two requests never take the same number.
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".local_advisory"); err != nil {
		return nil, err
	}
	prefix := fmt.Sprintf("x_SCRS-%d-", now.Year())
	var next int
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(substring(id from '[0-9]+$')::int),0)+1 FROM `+s.schema+`.advisory_records WHERE origin=$1 AND starts_with(id,$2)`, OriginLocal, prefix).Scan(&next); err != nil {
		return nil, err
	}
	id := fmt.Sprintf("%s%04d", prefix, next)
	affected := make([]map[string]any, len(in.Affected))
	for i, a := range in.Affected {
		pkg := map[string]any{"ecosystem": a.Package.Ecosystem, "name": a.Package.Name}
		if a.Package.PURL != "" {
			pkg["purl"] = a.Package.PURL
		}
		entry := map[string]any{"package": pkg}
		if a.AllVersions {
			entry["database_specific"] = map[string]any{"all_versions": true}
		} else {
			entry["versions"] = a.Versions
		}
		affected[i] = entry
	}
	aliases, severity, references, cwe := in.Aliases, in.Severity, in.References, in.CWE
	if aliases == nil {
		aliases = []string{}
	}
	if severity == nil {
		severity = []advisory.Severity{}
	}
	if references == nil {
		references = []advisory.Reference{}
	}
	if cwe == nil {
		cwe = []string{}
	}
	record, _ := json.Marshal(map[string]any{
		"schema_version": "1.9.2", "id": id, "origin": OriginLocal,
		"modified": now.Format(time.RFC3339), "published": now.Format(time.RFC3339),
		"aliases": aliases, "summary": strings.TrimSpace(in.Summary), "details": in.Details,
		"severity": severity, "affected": affected, "references": references,
		"database_specific": map[string]any{"cwe": cwe, "created_by": by},
	})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.advisory_records(origin,id,cve,modified,withdrawn,record,raw) VALUES($1,$2,'',$3,false,$4,$4)`, OriginLocal, id, now, record); err != nil {
		return nil, err
	}
	details, _ := json.Marshal(map[string]any{"id": id, "by": by, "packages": len(in.Affected)})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('advisory.created',$1)`, details); err != nil {
		return nil, err
	}
	return record, tx.Commit(ctx)
}

// WithdrawLocalAdvisory marks a local advisory withdrawn with a reason. It is
// kept, and never deleted.
func (s *Store) WithdrawLocalAdvisory(ctx context.Context, id, reason, by string) (json.RawMessage, error) {
	if !localIDPattern.MatchString(id) {
		return nil, ErrNotFound
	}
	if len(strings.TrimSpace(reason)) < 8 || len(reason) > 1000 {
		return nil, inputError("reason must be 8 to 1000 characters")
	}
	now := time.Now().UTC().Truncate(time.Second)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	var record json.RawMessage
	var withdrawn bool
	err = tx.QueryRow(ctx, `SELECT record,withdrawn FROM `+s.schema+`.advisory_records WHERE origin=$1 AND id=$2 FOR UPDATE`, OriginLocal, id).Scan(&record, &withdrawn)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if withdrawn {
		return nil, ErrConflict
	}
	var doc map[string]any
	if err := json.Unmarshal(record, &doc); err != nil {
		return nil, err
	}
	doc["withdrawn"] = now.Format(time.RFC3339)
	doc["modified"] = now.Format(time.RFC3339)
	if spec, ok := doc["database_specific"].(map[string]any); ok {
		spec["withdrawn_reason"] = strings.TrimSpace(reason)
	}
	updated, _ := json.Marshal(doc)
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.advisory_records SET withdrawn=true,modified=$3,record=$4,raw=$4 WHERE origin=$1 AND id=$2`, OriginLocal, id, now, updated); err != nil {
		return nil, err
	}
	details, _ := json.Marshal(map[string]any{"id": id, "by": by})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('advisory.withdrawn',$1)`, details); err != nil {
		return nil, err
	}
	return updated, tx.Commit(ctx)
}

// AdvisoryFilter narrows an advisory search. Empty fields match everything.
type AdvisoryFilter struct {
	Query     string
	Origin    string
	Ecosystem string
	Package   string
	Alias     string
	Withdrawn *bool
	Since     *time.Time
	AfterID   string
	AfterOrig string
	Limit     int
}

// AdvisoryHit is one search result.
type AdvisoryHit struct {
	ID        string     `json:"id"`
	Origin    string     `json:"origin"`
	Summary   string     `json:"summary"`
	Aliases   []string   `json:"aliases"`
	Modified  *time.Time `json:"modified"`
	Withdrawn bool       `json:"withdrawn"`
}

func likeEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(s)
}

// SearchAdvisories pages advisories of every origin by id then origin. It
// reads one more row than Limit so a caller can tell whether another page
// exists.
func (s *Store) SearchAdvisories(ctx context.Context, f AdvisoryFilter) ([]AdvisoryHit, error) {
	if f.Limit < 1 || f.Limit > 200 || len(f.Query) > 100 || len(f.Package) > 214 || len(f.Alias) > 128 || len(f.Ecosystem) > 41 || len(f.Origin) > 20 {
		return nil, ErrInput
	}
	pattern := ""
	if f.Query != "" {
		pattern = "%" + likeEscape(f.Query) + "%"
	}
	rows, err := s.pool.Query(ctx, `SELECT id,origin,COALESCE(record->>'summary',''),COALESCE(record->'aliases','[]'),modified,withdrawn FROM `+s.schema+`.advisory_records
		WHERE ($1='' OR id ILIKE $1 OR cve ILIKE $1 OR record->>'summary' ILIKE $1 OR record->>'details' ILIKE $1)
		AND ($2='' OR origin=$2)
		AND ($3='' OR record->'aliases' @> to_jsonb($3::text) OR id=$3 OR cve=$3)
		AND ($4::boolean IS NULL OR withdrawn=$4)
		AND ($5::timestamptz IS NULL OR modified>=$5)
		AND (($6='' AND $7='') OR EXISTS(SELECT 1 FROM jsonb_array_elements(CASE WHEN jsonb_typeof(record->'affected')='array' THEN record->'affected' ELSE '[]'::jsonb END) a WHERE ($6='' OR lower(a->'package'->>'ecosystem')=lower($6)) AND ($7='' OR lower(a->'package'->>'name')=lower($7))))
		AND ($8='' OR (id,origin)>($8,$9))
		ORDER BY id,origin LIMIT $10`, pattern, f.Origin, f.Alias, f.Withdrawn, f.Since, f.Ecosystem, f.Package, f.AfterID, f.AfterOrig, f.Limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AdvisoryHit{}
	for rows.Next() {
		var h AdvisoryHit
		var aliases []byte
		if err := rows.Scan(&h.ID, &h.Origin, &h.Summary, &aliases, &h.Modified, &h.Withdrawn); err != nil {
			return nil, err
		}
		if json.Unmarshal(aliases, &h.Aliases) != nil || h.Aliases == nil {
			h.Aliases = []string{}
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// AffectedComponent is a component of a recent assessment that a local
// advisory names.
type AffectedComponent struct {
	AssetID      string    `json:"asset_id"`
	Locator      string    `json:"locator"`
	Ref          string    `json:"ref"`
	AssessmentID string    `json:"assessment_id"`
	Commit       string    `json:"commit"`
	Component    Component `json:"component"`
}

// AffectedBy lists, for a local advisory, the components in the newest
// successful assessment of each asset and ref that match one of its
// affected packages and versions (at most 1000 rows). It reads stored
// inventories only; nothing is rescanned and no register entry is created.
func (s *Store) AffectedBy(ctx context.Context, id string) ([]AffectedComponent, error) {
	if !localIDPattern.MatchString(id) {
		return nil, ErrNotFound
	}
	var record json.RawMessage
	err := s.pool.QueryRow(ctx, `SELECT record FROM `+s.schema+`.advisory_records WHERE origin=$1 AND id=$2 AND NOT withdrawn`, OriginLocal, id).Scan(&record)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var doc struct {
		Affected []struct {
			Package  LocalPackage `json:"package"`
			Versions []string     `json:"versions"`
			Spec     struct {
				All bool `json:"all_versions"`
			} `json:"database_specific"`
		} `json:"affected"`
	}
	if err := json.Unmarshal(record, &doc); err != nil {
		return nil, err
	}
	out := []AffectedComponent{}
	for _, a := range doc.Affected {
		if len(out) >= 1000 {
			break
		}
		rows, err := s.pool.Query(ctx, `WITH latest AS (SELECT DISTINCT ON (asset_id,request->'target'->>'ref') id,asset_id,request->'target'->>'ref' AS ref,resolved_commit FROM `+s.schema+`.assessments WHERE status='succeeded' AND request->'remediation' IS NULL AND resolved_commit<>'' ORDER BY asset_id,request->'target'->>'ref',created_at DESC,id DESC)
			SELECT l.asset_id::text,x.locator,COALESCE(l.ref,''),l.id::text,l.resolved_commit,c.body FROM latest l JOIN `+s.schema+`.components c ON c.assessment_id=l.id JOIN `+s.schema+`.assets x ON x.id=l.asset_id
			WHERE lower(c.body->>'ecosystem')=lower($1) AND lower(c.body->>'name')=lower($2) AND ($3 OR c.body->>'version'=ANY($4)) ORDER BY x.locator,l.ref,c.ordinal LIMIT $5`, a.Package.Ecosystem, a.Package.Name, a.Spec.All, a.Versions, 1000-len(out))
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var hit AffectedComponent
			var body []byte
			if err := rows.Scan(&hit.AssetID, &hit.Locator, &hit.Ref, &hit.AssessmentID, &hit.Commit, &body); err != nil {
				rows.Close()
				return nil, err
			}
			if err := json.Unmarshal(body, &hit.Component); err != nil {
				rows.Close()
				return nil, err
			}
			out = append(out, hit)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}
