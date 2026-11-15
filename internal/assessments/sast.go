package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// SAST settings, custom rules and register semantics (SAST-002, SAST-006,
// SAST-007, REA-011).

func sastSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.sast_settings(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),disabled_rules jsonb NOT NULL DEFAULT '[]',excludes jsonb NOT NULL DEFAULT '[]',revision bigint NOT NULL DEFAULT 1,updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_by uuid)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.asset_sast_settings(asset_id uuid PRIMARY KEY REFERENCES ` + s + `.assets(id),enabled boolean,reachability boolean,analyzers jsonb,disabled_rules jsonb NOT NULL DEFAULT '[]',excludes jsonb NOT NULL DEFAULT '[]',revision bigint NOT NULL DEFAULT 1,updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_by uuid)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.sast_rulesets(id uuid PRIMARY KEY,name text NOT NULL UNIQUE,description text NOT NULL DEFAULT '',body text NOT NULL,sha256 text NOT NULL,enabled boolean NOT NULL DEFAULT true,revision bigint NOT NULL DEFAULT 1,created_by uuid,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE INDEX IF NOT EXISTS findings_sast_idx ON ` + s + `.findings(asset_id,ref) WHERE type='sast'`,
	}
}

// Analyzers SCRS bundles; settings may select a subset.
var SASTAnalyzers = []string{"gosec", "bandit", "opengrep", "bearer"}

// SASTDefaults are the deployment defaults (SCRS_SAST_ENABLED,
// SCRS_REACHABILITY_ENABLED).
type SASTDefaults struct {
	Enabled, Reachability bool
}

// GlobalSAST is the deployment-wide rule and path configuration.
type GlobalSAST struct {
	DisabledRules []string   `json:"disabled_rules"`
	Excludes      []string   `json:"excludes"`
	Revision      int64      `json:"revision"`
	UpdatedAt     *time.Time `json:"updated_at,omitempty"`
}

// AssetSAST is one asset's overrides; nil fields inherit the defaults.
type AssetSAST struct {
	Enabled       *bool    `json:"enabled"`
	Reachability  *bool    `json:"reachability"`
	Analyzers     []string `json:"analyzers"`
	DisabledRules []string `json:"disabled_rules"`
	Excludes      []string `json:"excludes"`
	Revision      int64    `json:"revision"`
}

// EffectiveSAST is what the worker applies to one assessment.
type EffectiveSAST struct {
	Enabled       bool     `json:"enabled"`
	Reachability  bool     `json:"reachability"`
	Analyzers     []string `json:"analyzers"`
	DisabledRules []string `json:"disabled_rules"`
	Excludes      []string `json:"excludes"`
	// CustomRules are enabled OpenGrep rulesets by name.
	CustomRules map[string]string `json:"-"`
	Rulesets    []string          `json:"custom_rulesets"`
}

var (
	ruleFilter = regexp.MustCompile(`^([a-z]+:)?[A-Za-z0-9_.*/-]{1,200}$`)
	pathGlob   = regexp.MustCompile(`^[^\x00\n\r]{1,256}$`)
)

func validList(list []string, re *regexp.Regexp, limit int) bool {
	if len(list) > limit {
		return false
	}
	for _, v := range list {
		if !re.MatchString(v) || strings.Contains(v, "..") {
			return false
		}
	}
	return true
}

func normaliseList(list []string) []string {
	if list == nil {
		return []string{}
	}
	return list
}

// GlobalSASTSettings returns the deployment-wide configuration.
func (s *Store) GlobalSASTSettings(ctx context.Context) (GlobalSAST, error) {
	out := GlobalSAST{DisabledRules: []string{}, Excludes: []string{}}
	var rules, excludes []byte
	var at time.Time
	err := s.pool.QueryRow(ctx, `SELECT disabled_rules,excludes,revision,updated_at FROM `+s.schema+`.sast_settings`).Scan(&rules, &excludes, &out.Revision, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	_ = json.Unmarshal(rules, &out.DisabledRules)
	_ = json.Unmarshal(excludes, &out.Excludes)
	out.UpdatedAt = &at
	return out, nil
}

// SetGlobalSASTSettings replaces the deployment-wide configuration when
// expected matches its revision (0 before the first change). Audited.
func (s *Store) SetGlobalSASTSettings(ctx context.Context, g GlobalSAST, expected int64, actor uuid.UUID) (GlobalSAST, error) {
	if !validList(g.DisabledRules, ruleFilter, 500) || !validList(g.Excludes, pathGlob, 200) {
		return GlobalSAST{}, ErrInput
	}
	rules, _ := json.Marshal(normaliseList(g.DisabledRules))
	excludes, _ := json.Marshal(normaliseList(g.Excludes))
	var tag interface{ RowsAffected() int64 }
	var err error
	if expected == 0 {
		tag, err = s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.sast_settings(singleton,disabled_rules,excludes,updated_by) VALUES(true,$1,$2,$3) ON CONFLICT DO NOTHING`, rules, excludes, actor)
	} else {
		tag, err = s.pool.Exec(ctx, `UPDATE `+s.schema+`.sast_settings SET disabled_rules=$1,excludes=$2,revision=revision+1,updated_at=clock_timestamp(),updated_by=$3 WHERE revision=$4`, rules, excludes, actor, expected)
	}
	if err != nil {
		return GlobalSAST{}, err
	}
	if tag.RowsAffected() == 0 {
		return GlobalSAST{}, ErrConflict
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "disabled_rules": len(g.DisabledRules), "excludes": len(g.Excludes)})
	if _, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('sast_settings.updated',$1)`, details); err != nil {
		return GlobalSAST{}, err
	}
	return s.GlobalSASTSettings(ctx)
}

// AssetSASTSettings returns one asset's overrides (revision 0: none).
func (s *Store) AssetSASTSettings(ctx context.Context, asset uuid.UUID) (AssetSAST, error) {
	out := AssetSAST{DisabledRules: []string{}, Excludes: []string{}}
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.assets WHERE id=$1)`, asset).Scan(&exists); err != nil {
		return out, err
	}
	if !exists {
		return out, ErrNotFound
	}
	var analyzers, rules, excludes []byte
	err := s.pool.QueryRow(ctx, `SELECT enabled,reachability,analyzers,disabled_rules,excludes,revision FROM `+s.schema+`.asset_sast_settings WHERE asset_id=$1`, asset).Scan(&out.Enabled, &out.Reachability, &analyzers, &rules, &excludes, &out.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return out, err
	}
	if len(analyzers) > 0 && string(analyzers) != "null" {
		_ = json.Unmarshal(analyzers, &out.Analyzers)
	}
	_ = json.Unmarshal(rules, &out.DisabledRules)
	_ = json.Unmarshal(excludes, &out.Excludes)
	return out, nil
}

// SetAssetSASTSettings replaces one asset's overrides. Audited.
func (s *Store) SetAssetSASTSettings(ctx context.Context, asset uuid.UUID, a AssetSAST, expected int64, actor uuid.UUID) (AssetSAST, error) {
	if !validList(a.DisabledRules, ruleFilter, 500) || !validList(a.Excludes, pathGlob, 200) || len(a.Analyzers) > len(SASTAnalyzers) {
		return AssetSAST{}, ErrInput
	}
	for _, name := range a.Analyzers {
		known := false
		for _, n := range SASTAnalyzers {
			known = known || n == name
		}
		if !known {
			return AssetSAST{}, ErrInput
		}
	}
	if _, err := s.AssetSASTSettings(ctx, asset); err != nil {
		return AssetSAST{}, err
	}
	var analyzers any
	if a.Analyzers != nil {
		raw, _ := json.Marshal(a.Analyzers)
		analyzers = raw
	}
	rules, _ := json.Marshal(normaliseList(a.DisabledRules))
	excludes, _ := json.Marshal(normaliseList(a.Excludes))
	var tag interface{ RowsAffected() int64 }
	var err error
	if expected == 0 {
		tag, err = s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.asset_sast_settings(asset_id,enabled,reachability,analyzers,disabled_rules,excludes,updated_by) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT DO NOTHING`, asset, a.Enabled, a.Reachability, analyzers, rules, excludes, actor)
	} else {
		tag, err = s.pool.Exec(ctx, `UPDATE `+s.schema+`.asset_sast_settings SET enabled=$2,reachability=$3,analyzers=$4,disabled_rules=$5,excludes=$6,revision=revision+1,updated_at=clock_timestamp(),updated_by=$7 WHERE asset_id=$1 AND revision=$8`, asset, a.Enabled, a.Reachability, analyzers, rules, excludes, actor, expected)
	}
	if err != nil {
		return AssetSAST{}, err
	}
	if tag.RowsAffected() == 0 {
		return AssetSAST{}, ErrConflict
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "enabled": a.Enabled, "reachability": a.Reachability, "analyzers": a.Analyzers, "disabled_rules": len(a.DisabledRules), "excludes": len(a.Excludes)})
	if _, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('asset.sast_settings_updated',$1,$2)`, asset, details); err != nil {
		return AssetSAST{}, err
	}
	return s.AssetSASTSettings(ctx, asset)
}

// EffectiveSASTSettings merges deployment defaults, global configuration,
// the asset's overrides and enabled custom rulesets.
func (s *Store) EffectiveSASTSettings(ctx context.Context, asset uuid.UUID, d SASTDefaults) (EffectiveSAST, error) {
	out := EffectiveSAST{Enabled: d.Enabled, Reachability: d.Reachability, Analyzers: append([]string(nil), SASTAnalyzers...), CustomRules: map[string]string{}, Rulesets: []string{}}
	g, err := s.GlobalSASTSettings(ctx)
	if err != nil {
		return out, err
	}
	a, err := s.AssetSASTSettings(ctx, asset)
	if err != nil {
		return out, err
	}
	if a.Enabled != nil {
		out.Enabled = *a.Enabled
	}
	if a.Reachability != nil {
		out.Reachability = *a.Reachability
	}
	if a.Analyzers != nil {
		out.Analyzers = a.Analyzers
	}
	out.DisabledRules = append(append([]string{}, g.DisabledRules...), a.DisabledRules...)
	out.Excludes = append(append([]string{}, g.Excludes...), a.Excludes...)
	rows, err := s.pool.Query(ctx, `SELECT name,body FROM `+s.schema+`.sast_rulesets WHERE enabled ORDER BY name LIMIT 50`)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var name, body string
		if err := rows.Scan(&name, &body); err != nil {
			return out, err
		}
		out.CustomRules[name] = body
		out.Rulesets = append(out.Rulesets, name)
	}
	return out, rows.Err()
}

// SASTRuleset is an uploaded OpenGrep ruleset (SAST-007).
type SASTRuleset struct {
	ID          uuid.UUID `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	SHA256      string    `json:"sha256"`
	Enabled     bool      `json:"enabled"`
	Revision    int64     `json:"revision"`
	Size        int       `json:"size"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	Body        string    `json:"body,omitempty"`
}

var rulesetName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// SaveSASTRuleset stores or replaces a validated ruleset. Audited.
func (s *Store) SaveSASTRuleset(ctx context.Context, name, description, body string, enabled bool, actor uuid.UUID) (SASTRuleset, error) {
	if !rulesetName.MatchString(name) || len(description) > 500 || body == "" || len(body) > 1<<20 {
		return SASTRuleset{}, ErrInput
	}
	digest := Hash([]byte(body))
	var r SASTRuleset
	err := s.pool.QueryRow(ctx, `INSERT INTO `+s.schema+`.sast_rulesets(id,name,description,body,sha256,enabled,created_by) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(name) DO UPDATE SET description=EXCLUDED.description,body=EXCLUDED.body,sha256=EXCLUDED.sha256,enabled=EXCLUDED.enabled,revision=sast_rulesets.revision+1,updated_at=clock_timestamp() RETURNING id,name,description,sha256,enabled,revision,length(body),created_at,updated_at`, uuid.New(), name, description, body, digest, enabled, actor).Scan(&r.ID, &r.Name, &r.Description, &r.SHA256, &r.Enabled, &r.Revision, &r.Size, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return r, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "name": name, "sha256": digest, "revision": r.Revision, "enabled": enabled})
	_, err = s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('sast_ruleset.saved',$1,$2)`, r.ID, details)
	return r, err
}

// SASTRulesets lists uploaded rulesets without their bodies.
func (s *Store) SASTRulesets(ctx context.Context) ([]SASTRuleset, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,description,sha256,enabled,revision,length(body),created_at,updated_at FROM `+s.schema+`.sast_rulesets ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []SASTRuleset{}
	for rows.Next() {
		var r SASTRuleset
		if err := rows.Scan(&r.ID, &r.Name, &r.Description, &r.SHA256, &r.Enabled, &r.Revision, &r.Size, &r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SASTRuleset returns one ruleset with its body.
func (s *Store) SASTRuleset(ctx context.Context, id uuid.UUID) (SASTRuleset, error) {
	var r SASTRuleset
	err := s.pool.QueryRow(ctx, `SELECT id,name,description,sha256,enabled,revision,length(body),created_at,updated_at,body FROM `+s.schema+`.sast_rulesets WHERE id=$1`, id).Scan(&r.ID, &r.Name, &r.Description, &r.SHA256, &r.Enabled, &r.Revision, &r.Size, &r.CreatedAt, &r.UpdatedAt, &r.Body)
	if errors.Is(err, pgx.ErrNoRows) {
		return r, ErrNotFound
	}
	return r, err
}

// DeleteSASTRuleset removes a ruleset. Audited.
func (s *Store) DeleteSASTRuleset(ctx context.Context, id, actor uuid.UUID) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM `+s.schema+`.sast_rulesets WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor})
	_, err = s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('sast_ruleset.deleted',$1,$2)`, id, details)
	return err
}

// RenewLease extends a running assessment's lease while it still holds it,
// so long analyzer runs can publish (SAST-011 budgets exceed the lease).
func (s *Store) RenewLease(ctx context.Context, a Assessment) error {
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.assessments SET lease_until=clock_timestamp()+interval '10 minutes' WHERE id=$1 AND lease=$2 AND status='running'`, a.ID, a.Lease)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrLease
	}
	return nil
}

// sastEvidence is the part of a SAST entry's evidence the gate reads.
type sastEvidence struct {
	Suppressed  bool   `json:"suppressed_in_code"`
	Suppression string `json:"suppression"`
	Tool        string `json:"tool"`
	RuleID      string `json:"rule_id"`
	Path        string `json:"path"`
	Line        int    `json:"start_line"`
}

// sastGate applies SAST-006 and SAST-007: only new entries gate (a new
// critical fails, a new high warns); entries silenced in code never gate.
func sastGate(f Finding) (fail, warn, suppressed bool) {
	var e sastEvidence
	_ = json.Unmarshal(f.Evidence, &e)
	if e.Suppressed {
		return false, false, true
	}
	if f.Change != "new" {
		return false, false, false
	}
	return f.Severity == "critical", f.Severity == "high", false
}

// suppressionsAdded raises an integrity entry when a SAST entry the
// baseline reported unsilenced is now silenced by an inline comment: a
// suppression added in the diff is itself a signal (SAST-007, INT-004).
func (s *Store) suppressionsAdded(ctx context.Context, tx pgx.Tx, baseline uuid.UUID, findings []Finding) ([]Finding, error) {
	if baseline == uuid.Nil {
		return nil, nil
	}
	open, err := stringSet(ctx, tx, `SELECT concat_ws(chr(31),snapshot->>'advisory_id',snapshot->'component'->>'path') FROM `+s.schema+`.assessment_findings WHERE assessment_id=$1 AND snapshot->>'type'='sast' AND COALESCE((snapshot->'evidence'->>'suppressed_in_code')::boolean,false)=false`, baseline)
	if err != nil {
		return nil, err
	}
	out := []Finding{}
	for _, f := range findings {
		if f.Type != "sast" || !open[f.AdvisoryID+"\x1f"+f.Component.Path] {
			continue
		}
		var e sastEvidence
		if json.Unmarshal(f.Evidence, &e) != nil || !e.Suppressed {
			continue
		}
		evidence, _ := json.Marshal(map[string]any{"path": e.Path, "line": e.Line, "tool": e.Tool, "rule_id": e.RuleID, "suppression": e.Suppression, "sast_fingerprint": f.Fingerprint})
		out = append(out, Finding{Type: "integrity", AdvisoryID: "SCRS-SAST-SUPPRESSION-ADDED", Title: "Inline suppression added for an open static-analysis finding", Severity: "medium", Score: 30, Component: Component{Path: f.Component.Path}, Evidence: evidence, Guidance: json.RawMessage(`{"summary":"Confirm the suppression was reviewed: a comment such as #nosec or nosemgrep silences the analyzer for this line. If it was not intended, remove it and fix the finding.","automatic_changes":false}`)})
	}
	return out, nil
}
