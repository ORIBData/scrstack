package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/license"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Licence policy, categories and inventory (LIC-001 to LIC-009). Licence
// data is a policy aid, not legal advice.

func licenseSchema(s string) []string {
	return []string{
		// PRD 9.x policies: one active (is_default) policy per kind.
		`CREATE TABLE IF NOT EXISTS ` + s + `.policies(id uuid PRIMARY KEY,kind text NOT NULL CHECK(kind IN ('gate','license')),name text NOT NULL,body jsonb NOT NULL,is_default boolean NOT NULL DEFAULT false,revision bigint NOT NULL DEFAULT 1,updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_by uuid,UNIQUE(kind,name))`,
		`CREATE UNIQUE INDEX IF NOT EXISTS policies_active_idx ON ` + s + `.policies(kind) WHERE is_default`,
		// LIC-003: category overrides, versioned; the newest revision applies.
		`CREATE TABLE IF NOT EXISTS ` + s + `.license_category_versions(revision bigint PRIMARY KEY,overrides jsonb NOT NULL,note text NOT NULL DEFAULT '',created_by uuid,created_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		// Package metadata from deps.dev, fetched once per package version.
		`CREATE TABLE IF NOT EXISTS ` + s + `.package_metadata(system text NOT NULL,name text NOT NULL,version text NOT NULL,licenses jsonb NOT NULL DEFAULT '[]',status text NOT NULL CHECK(status IN ('ok','not_found')),fetched_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(system,name,version))`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.package_versions(system text NOT NULL,name text NOT NULL,versions jsonb NOT NULL DEFAULT '[]',status text NOT NULL CHECK(status IN ('ok','not_found')),fetched_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(system,name))`,
		`CREATE INDEX IF NOT EXISTS findings_license_idx ON ` + s + `.findings(asset_id,ref) WHERE type='license'`,
	}
}

// PolicyRecord is the active licence policy with its revision.
type PolicyRecord struct {
	Kind      string         `json:"kind"`
	Policy    license.Policy `json:"policy"`
	Revision  int64          `json:"revision"`
	Builtin   bool           `json:"builtin"`
	UpdatedAt *time.Time     `json:"updated_at,omitempty"`
	UpdatedBy *uuid.UUID     `json:"updated_by,omitempty"`
}

type querier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
	Query(context.Context, string, ...any) (pgx.Rows, error)
}

func (s *Store) licensePolicy(ctx context.Context, q querier) (PolicyRecord, error) {
	out := PolicyRecord{Kind: "license"}
	var body []byte
	var at time.Time
	var by *uuid.UUID
	err := q.QueryRow(ctx, `SELECT body,revision,updated_at,updated_by FROM `+s.schema+`.policies WHERE kind='license' AND is_default`).Scan(&body, &out.Revision, &at, &by)
	if errors.Is(err, pgx.ErrNoRows) {
		out.Policy, out.Builtin = license.CorporateDefault(), true
		return out, nil
	}
	if err != nil {
		return out, err
	}
	p, err := license.ParsePolicy(body)
	if err != nil {
		return out, err
	}
	out.Policy, out.UpdatedAt, out.UpdatedBy = p, &at, by
	return out, nil
}

// LicensePolicy returns the active licence policy; corporate-default until
// an admin stores one (revision 0).
func (s *Store) LicensePolicy(ctx context.Context) (PolicyRecord, error) {
	return s.licensePolicy(ctx, s.pool)
}

// SetLicensePolicy replaces the active licence policy when expected matches
// the current revision (0 for corporate-default). It is audited.
func (s *Store) SetLicensePolicy(ctx context.Context, p license.Policy, expected int64, actor uuid.UUID) (PolicyRecord, error) {
	if err := p.Validate(); err != nil {
		return PolicyRecord{}, err
	}
	body, _ := json.Marshal(p)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return PolicyRecord{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".policies.license"); err != nil {
		return PolicyRecord{}, err
	}
	current, err := s.licensePolicy(ctx, tx)
	if err != nil {
		return PolicyRecord{}, err
	}
	if current.Revision != expected {
		return PolicyRecord{}, ErrConflict
	}
	if current.Builtin {
		_, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.policies(id,kind,name,body,is_default,revision,updated_by) VALUES($1,'license',$2,$3,true,1,$4)`, uuid.New(), p.Name, body, actor)
	} else {
		_, err = tx.Exec(ctx, `UPDATE `+s.schema+`.policies SET name=$1,body=$2,revision=revision+1,updated_at=clock_timestamp(),updated_by=$3 WHERE kind='license' AND is_default`, p.Name, body, actor)
	}
	if err != nil {
		return PolicyRecord{}, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "name": p.Name, "enforcing": p.Enforcing, "rules": len(p.Rules), "previous_revision": current.Revision})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('license_policy.updated',$1)`, details); err != nil {
		return PolicyRecord{}, err
	}
	out, err := s.licensePolicy(ctx, tx)
	if err != nil {
		return PolicyRecord{}, err
	}
	return out, tx.Commit(ctx)
}

func (s *Store) licenseCatalog(ctx context.Context, q querier) (*license.Catalog, *time.Time, error) {
	var revision int64
	var raw []byte
	var at time.Time
	err := q.QueryRow(ctx, `SELECT revision,overrides,created_at FROM `+s.schema+`.license_category_versions ORDER BY revision DESC LIMIT 1`).Scan(&revision, &raw, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return license.DefaultCatalog(), nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	overrides := map[string]string{}
	if err := json.Unmarshal(raw, &overrides); err != nil {
		return nil, nil, err
	}
	c, err := license.NewCatalog(revision, overrides)
	return c, &at, err
}

// LicenseCatalog returns the category mapping with operator overrides.
func (s *Store) LicenseCatalog(ctx context.Context) (*license.Catalog, *time.Time, error) {
	return s.licenseCatalog(ctx, s.pool)
}

// SetLicenseCategories stores a new revision of the category overrides
// (LIC-003): versioned, audited, applied to the next evaluation.
func (s *Store) SetLicenseCategories(ctx context.Context, overrides map[string]string, note string, expected int64, actor uuid.UUID) (*license.Catalog, error) {
	if len(note) > 500 {
		return nil, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".license_categories"); err != nil {
		return nil, err
	}
	current, _, err := s.licenseCatalog(ctx, tx)
	if err != nil {
		return nil, err
	}
	if current.Revision != expected {
		return nil, ErrConflict
	}
	next, err := license.NewCatalog(current.Revision+1, overrides)
	if err != nil {
		return nil, err
	}
	raw, _ := json.Marshal(next.Overrides)
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.license_category_versions(revision,overrides,note,created_by) VALUES($1,$2,$3,$4)`, next.Revision, raw, note, actor); err != nil {
		return nil, err
	}
	changed := map[string][2]string{}
	for id, category := range next.Overrides {
		if before := current.Category(id); before != category {
			changed[id] = [2]string{before, category}
		}
	}
	for id := range current.Overrides {
		if _, kept := next.Overrides[id]; !kept {
			changed[id] = [2]string{current.Overrides[id], next.Category(id)}
		}
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "revision": next.Revision, "note": note, "changed": changed})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('license_categories.updated',$1)`, details); err != nil {
		return nil, err
	}
	return next, tx.Commit(ctx)
}

// CategoryVersion is one stored override revision.
type CategoryVersion struct {
	Revision  int64             `json:"revision"`
	Overrides map[string]string `json:"overrides"`
	Note      string            `json:"note"`
	CreatedBy *uuid.UUID        `json:"created_by,omitempty"`
	CreatedAt time.Time         `json:"created_at"`
}

// LicenseCategoryHistory lists override revisions, newest first.
func (s *Store) LicenseCategoryHistory(ctx context.Context) ([]CategoryVersion, error) {
	rows, err := s.pool.Query(ctx, `SELECT revision,overrides,note,created_by,created_at FROM `+s.schema+`.license_category_versions ORDER BY revision DESC LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []CategoryVersion{}
	for rows.Next() {
		var v CategoryVersion
		var raw []byte
		if err := rows.Scan(&v.Revision, &raw, &v.Note, &v.CreatedBy, &v.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(raw, &v.Overrides)
		out = append(out, v)
	}
	return out, rows.Err()
}

// licenseEvidence is stored on each licence entry; verdict reads it.
type licenseEvidence struct {
	Policy          string            `json:"policy"`
	PolicyRevision  int64             `json:"policy_revision"`
	Enforcing       bool              `json:"enforcing"`
	CatalogRevision int64             `json:"catalog_revision"`
	Distribution    string            `json:"distribution"`
	Decision        license.Decision  `json:"decision"`
	License         *ComponentLicense `json:"license"`
}

// licenseFindings evaluates every component's licence against the active
// policy for the asset's distribution model (LIC-004, LIC-005) and adds a
// "license" entry for each review or deny result (LIC-008). Components the
// worker could not resolve (License nil) are not evaluated; an enforcing
// policy then marks the assessment incomplete.
func (s *Store) licenseFindings(ctx context.Context, tx pgx.Tx, a Assessment, r *Result) error {
	if a.Request.Import != nil || a.Request.Remediation != nil || len(r.Components) == 0 {
		return nil
	}
	evaluated := false
	for _, c := range r.Components {
		if c.License != nil {
			evaluated = true
			break
		}
	}
	if !evaluated {
		return nil
	}
	var distribution string
	if err := tx.QueryRow(ctx, `SELECT distribution FROM `+s.schema+`.assets WHERE id=$1`, a.AssetID).Scan(&distribution); err != nil {
		return err
	}
	policy, err := s.licensePolicy(ctx, tx)
	if err != nil {
		return err
	}
	catalog, _, err := s.licenseCatalog(ctx, tx)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	unresolved := 0
	for _, c := range r.Components {
		key := c.PURL + "\x00" + c.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		if c.License == nil {
			unresolved++
			continue
		}
		d := policy.Policy.Evaluate(catalog, license.Subject{Expression: c.License.Expression, Distribution: distribution, Asset: a.AssetID, PURL: c.PURL, Path: c.Path, Dev: c.Dev()})
		if d.Effect == license.Allow {
			continue
		}
		if len(r.Findings) >= 10000 {
			r.Complete = false
			break
		}
		evidence, _ := json.Marshal(licenseEvidence{Policy: policy.Policy.Name, PolicyRevision: policy.Revision, Enforcing: policy.Policy.Enforcing, CatalogRevision: catalog.Revision, Distribution: distribution, Decision: d, License: c.License})
		score := 20
		if d.Effect == license.Deny {
			score = 50
		}
		advisory := "SCRS-LICENSE:" + d.Expression
		if len(advisory) > 200 {
			advisory = "SCRS-LICENSE:" + Hash([]byte(d.Expression))[:24]
		}
		title := fmt.Sprintf("Licence %s (%s) needs %s for a %s asset", strings.Join(d.Licenses, ", "), strings.ReplaceAll(d.Category, "_", " "), d.Effect, distribution)
		if d.Effect == license.Deny {
			title = fmt.Sprintf("Licence %s (%s) is denied for a %s asset", strings.Join(d.Licenses, ", "), strings.ReplaceAll(d.Category, "_", " "), distribution)
		}
		if d.Expression == license.NoAssertion {
			title = "No licence found for component; review before use"
		}
		guidance, _ := json.Marshal(map[string]any{
			"summary":           "A policy aid, not legal advice. Replace the component, ask counsel to approve it and record a waiver, or add a policy rule for it.",
			"policy_basis":      d.Basis,
			"reason":            d.Reason,
			"automatic_changes": false,
		})
		r.Findings = append(r.Findings, Finding{Type: "license", AdvisoryID: advisory, Title: title, Severity: policy.Policy.SeverityFor(d.Effect), Score: score, Component: c, Evidence: evidence, Guidance: guidance})
	}
	if unresolved > 0 && policy.Policy.Enforcing {
		r.Complete = false
	}
	return nil
}

// licenseGate reads a licence entry's effect: an enforcing deny fails, an
// enforcing review warns; a report-only deny warns and a report-only
// review does not gate (LIC-008, ADR-024).
func licenseGate(f Finding) (fail, warn bool) {
	var e licenseEvidence
	if json.Unmarshal(f.Evidence, &e) != nil {
		return false, true
	}
	switch {
	case e.Enforcing && e.Decision.Effect == license.Deny:
		return true, false
	case e.Decision.Effect == license.Deny, e.Enforcing && e.Decision.Effect == license.Review:
		return false, true
	}
	return false, false
}

// LicenseRow is one component in a licence inventory (LIC-007).
type LicenseRow struct {
	AssetID      uuid.UUID         `json:"asset_id"`
	Asset        string            `json:"asset"`
	AssessmentID uuid.UUID         `json:"assessment_id"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Ecosystem    string            `json:"ecosystem"`
	PURL         string            `json:"purl"`
	Path         string            `json:"path"`
	Dev          bool              `json:"dev"`
	Expression   string            `json:"expression"`
	Category     string            `json:"category"`
	Source       string            `json:"source"`
	Confidence   float64           `json:"confidence,omitempty"`
	Effect       string            `json:"policy_result"`
	Basis        string            `json:"policy_basis"`
	FindingID    *uuid.UUID        `json:"finding_id,omitempty"`
	Status       string            `json:"status,omitempty"`
	WaiverUntil  *time.Time        `json:"waiver_until,omitempty"`
	License      *ComponentLicense `json:"license,omitempty"`
}

// LicenseInventory is an asset's licences at its latest assessed revision.
type LicenseInventory struct {
	AssetID      uuid.UUID      `json:"asset_id"`
	Asset        string         `json:"asset"`
	Distribution string         `json:"distribution"`
	AssessmentID *uuid.UUID     `json:"assessment_id"`
	Revision     string         `json:"revision,omitempty"`
	Ref          string         `json:"ref,omitempty"`
	AssessedAt   *time.Time     `json:"assessed_at,omitempty"`
	Policy       string         `json:"policy"`
	Enforcing    bool           `json:"enforcing"`
	Counts       map[string]int `json:"counts"`
	Hint         string         `json:"distribution_hint,omitempty"`
	Items        []LicenseRow   `json:"items"`
}

// AssetLicenses evaluates the components of the asset's newest successful
// assessment (of ref, when given) against the current policy, with each
// licence entry's register status and waiver (LIC-006, LIC-007).
func (s *Store) AssetLicenses(ctx context.Context, asset uuid.UUID, ref string) (LicenseInventory, error) {
	out := LicenseInventory{AssetID: asset, Counts: map[string]int{}, Items: []LicenseRow{}}
	if err := s.pool.QueryRow(ctx, `SELECT locator,distribution FROM `+s.schema+`.assets WHERE id=$1`, asset).Scan(&out.Asset, &out.Distribution); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return out, ErrNotFound
		}
		return out, err
	}
	policy, err := s.LicensePolicy(ctx)
	if err != nil {
		return out, err
	}
	catalog, _, err := s.LicenseCatalog(ctx)
	if err != nil {
		return out, err
	}
	out.Policy, out.Enforcing = policy.Policy.Name, policy.Policy.Enforcing
	var id uuid.UUID
	var revision, assessedRef string
	var at time.Time
	err = s.pool.QueryRow(ctx, `SELECT id,resolved_commit,request->'target'->>'ref',completed_at FROM `+s.schema+`.assessments WHERE asset_id=$1 AND status='succeeded' AND request->'remediation' IS NULL AND request->'import' IS NULL AND ($2='' OR request->'target'->>'ref'=$2) AND EXISTS(SELECT 1 FROM `+s.schema+`.components c WHERE c.assessment_id=assessments.id) ORDER BY completed_at DESC,id DESC LIMIT 1`, asset, ref).Scan(&id, &revision, &assessedRef, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	out.AssessmentID, out.Revision, out.Ref, out.AssessedAt = &id, revision, assessedRef, &at
	components, err := s.AllComponents(ctx, id)
	if err != nil {
		return out, err
	}
	statuses, err := s.licenseStatuses(ctx, asset, assessedRef)
	if err != nil {
		return out, err
	}
	mobile := false
	seen := map[string]bool{}
	for _, c := range components {
		key := c.PURL + "\x00" + c.Path
		if seen[key] {
			continue
		}
		seen[key] = true
		base, _, _ := strings.Cut(c.Ecosystem, ":")
		mobile = mobile || base == "Pub" || base == "SwiftURL" || base == "CocoaPods"
		row := licenseRow(policy.Policy, catalog, out.Distribution, asset, out.Asset, id, c)
		if st, ok := statuses[key]; ok {
			row.FindingID, row.Status, row.WaiverUntil = &st.id, st.status, st.until
		}
		out.Counts[row.Effect]++
		out.Counts[row.Category]++
		out.Items = append(out.Items, row)
	}
	if mobile && out.Distribution != license.Distributed {
		out.Hint = "This asset has Flutter or Swift packages; if it ships to app stores, set distribution to distributed."
	}
	return out, nil
}

func licenseRow(p license.Policy, catalog *license.Catalog, distribution string, asset uuid.UUID, locator string, assessment uuid.UUID, c Component) LicenseRow {
	row := LicenseRow{AssetID: asset, Asset: locator, AssessmentID: assessment, Name: c.Name, Version: c.Version, Ecosystem: c.Ecosystem, PURL: c.PURL, Path: c.Path, Dev: c.Dev(), Expression: license.NoAssertion, Source: "unresolved", License: c.License}
	if c.License != nil {
		row.Expression, row.Source, row.Confidence = c.License.Expression, c.License.Source, c.License.Confidence
	}
	d := p.Evaluate(catalog, license.Subject{Expression: row.Expression, Distribution: distribution, Asset: asset, PURL: c.PURL, Path: c.Path, Dev: row.Dev})
	row.Effect, row.Basis, row.Category = d.Effect, d.Basis, d.Category
	return row
}

// AllComponents returns every component of an assessment in order.
func (s *Store) AllComponents(ctx context.Context, assessment uuid.UUID) ([]Component, error) {
	rows, err := s.pool.Query(ctx, `SELECT body FROM `+s.schema+`.components WHERE assessment_id=$1 ORDER BY ordinal`, assessment)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Component{}
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var c Component
		if json.Unmarshal(raw, &c) == nil {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

type licenseStatus struct {
	id     uuid.UUID
	status string
	until  *time.Time
}

func (s *Store) licenseStatuses(ctx context.Context, asset uuid.UUID, ref string) (map[string]licenseStatus, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,component->>'purl',component->>'path',status,waiver_until FROM `+s.schema+`.findings WHERE asset_id=$1 AND ref=$2 AND type='license' AND status<>'fixed'`, asset, ref)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]licenseStatus{}
	for rows.Next() {
		var st licenseStatus
		var purl, path string
		if err := rows.Scan(&st.id, &purl, &path, &st.status, &st.until); err != nil {
			return nil, err
		}
		out[purl+"\x00"+path] = st
	}
	return out, rows.Err()
}

// LicenseReport is the portfolio (or one asset's) licence inventory for
// GET /reports/licenses.
func (s *Store) LicenseReport(ctx context.Context, asset uuid.UUID) ([]LicenseInventory, error) {
	ids := []uuid.UUID{asset}
	if asset == uuid.Nil {
		rows, err := s.pool.Query(ctx, `SELECT DISTINCT a.id FROM `+s.schema+`.assets a JOIN `+s.schema+`.assessments x ON x.asset_id=a.id WHERE x.status='succeeded' AND x.request->'import' IS NULL ORDER BY a.id LIMIT 2000`)
		if err != nil {
			return nil, err
		}
		ids = ids[:0]
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	out := []LicenseInventory{}
	for _, id := range ids {
		inv, err := s.AssetLicenses(ctx, id, "")
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Asset < out[j].Asset })
	return out, nil
}

// PackageKey identifies a package version in a deps.dev system.
type PackageKey struct{ System, Name, Version string }

// PackageLicenses is cached deps.dev licence metadata.
type PackageLicenses struct {
	Licenses []string
	Found    bool
}

// CachedPackageLicenses returns cached metadata younger than 30 days (7
// days for packages deps.dev did not know).
func (s *Store) CachedPackageLicenses(ctx context.Context, keys []PackageKey) (map[PackageKey]PackageLicenses, error) {
	out := map[PackageKey]PackageLicenses{}
	if len(keys) == 0 {
		return out, nil
	}
	systems, names, versions := make([]string, len(keys)), make([]string, len(keys)), make([]string, len(keys))
	for i, k := range keys {
		systems[i], names[i], versions[i] = k.System, k.Name, k.Version
	}
	rows, err := s.pool.Query(ctx, `SELECT m.system,m.name,m.version,m.licenses,m.status FROM unnest($1::text[],$2::text[],$3::text[]) AS k(system,name,version) JOIN `+s.schema+`.package_metadata m USING(system,name,version) WHERE m.fetched_at>clock_timestamp()-CASE WHEN m.status='ok' THEN interval '30 days' ELSE interval '7 days' END`, systems, names, versions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k PackageKey
		var raw []byte
		var status string
		if err := rows.Scan(&k.System, &k.Name, &k.Version, &raw, &status); err != nil {
			return nil, err
		}
		v := PackageLicenses{Found: status == "ok"}
		_ = json.Unmarshal(raw, &v.Licenses)
		out[k] = v
	}
	return out, rows.Err()
}

// SavePackageLicenses caches deps.dev results.
func (s *Store) SavePackageLicenses(ctx context.Context, entries map[PackageKey]PackageLicenses) error {
	batch := &pgx.Batch{}
	for k, v := range entries {
		status := "not_found"
		if v.Found {
			status = "ok"
		}
		raw, _ := json.Marshal(v.Licenses)
		if v.Licenses == nil {
			raw = []byte("[]")
		}
		batch.Queue(`INSERT INTO `+s.schema+`.package_metadata(system,name,version,licenses,status) VALUES($1,$2,$3,$4,$5) ON CONFLICT(system,name,version) DO UPDATE SET licenses=EXCLUDED.licenses,status=EXCLUDED.status,fetched_at=clock_timestamp()`, k.System, k.Name, k.Version, raw, status)
	}
	if batch.Len() == 0 {
		return nil
	}
	return s.pool.SendBatch(ctx, batch).Close()
}

// CachedPackageVersions returns version lists younger than one day.
func (s *Store) CachedPackageVersions(ctx context.Context, system string, names []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(names) == 0 {
		return out, nil
	}
	rows, err := s.pool.Query(ctx, `SELECT name,versions,status FROM `+s.schema+`.package_versions WHERE system=$1 AND name=ANY($2) AND fetched_at>clock_timestamp()-interval '1 day'`, system, names)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, status string
		var raw []byte
		if err := rows.Scan(&name, &raw, &status); err != nil {
			return nil, err
		}
		list := []string{}
		_ = json.Unmarshal(raw, &list)
		out[name] = list
	}
	return out, rows.Err()
}

// SavePackageVersions caches a package's published versions (nil: unknown
// to deps.dev).
func (s *Store) SavePackageVersions(ctx context.Context, system string, entries map[string][]string) error {
	batch := &pgx.Batch{}
	for name, list := range entries {
		status := "ok"
		if list == nil {
			status, list = "not_found", []string{}
		}
		raw, _ := json.Marshal(list)
		batch.Queue(`INSERT INTO `+s.schema+`.package_versions(system,name,versions,status) VALUES($1,$2,$3,$4) ON CONFLICT(system,name) DO UPDATE SET versions=EXCLUDED.versions,status=EXCLUDED.status,fetched_at=clock_timestamp()`, system, name, raw, status)
	}
	if batch.Len() == 0 {
		return nil
	}
	return s.pool.SendBatch(ctx, batch).Close()
}

// AssessmentBySBOM returns the newest succeeded assessment whose SBOM has
// this SHA-256.
func (s *Store) AssessmentBySBOM(ctx context.Context, digest string) (Assessment, error) {
	if !digestPattern.MatchString(digest) {
		return Assessment{}, ErrNotFound
	}
	a, err := scan(s.pool.QueryRow(ctx, `SELECT `+columns+` FROM `+s.schema+`.assessments WHERE sbom_sha256=$1 AND status='succeeded' ORDER BY completed_at DESC LIMIT 1`, digest))
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}
