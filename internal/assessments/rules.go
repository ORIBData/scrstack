package assessments

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// YARA rulesets (TIF): team rules from the Web UI ("custom") and third-party
// packs ("external"). New rulesets hunt (record only) until an admin promotes
// them to alert or block. The API compiles rules before calling the store.

func ruleSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.yara_rulesets(id uuid PRIMARY KEY,name text NOT NULL UNIQUE,kind text NOT NULL CHECK(kind IN ('custom','external')),description text NOT NULL DEFAULT '',mode text NOT NULL DEFAULT 'hunt' CHECK(mode IN ('hunt','alert','block')),severity text NOT NULL DEFAULT 'medium' CHECK(severity IN ('critical','high','medium','low','info')),enabled boolean NOT NULL DEFAULT true,rules text NOT NULL,sha256 text NOT NULL,rule_count integer NOT NULL,origin jsonb NOT NULL DEFAULT '{}',revision bigint NOT NULL DEFAULT 1,created_by uuid,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
	}
}

// RuleOrigin records where a third-party pack came from, for attribution and
// licence review (for example YARA Forge under DRL-1.1).
type RuleOrigin struct {
	Vendor  string `json:"vendor,omitempty"`
	URL     string `json:"url,omitempty"`
	Version string `json:"version,omitempty"`
	License string `json:"license,omitempty"`
}

// RuleSetRecord is a stored ruleset; Rules is omitted from listings.
type RuleSetRecord struct {
	ID          uuid.UUID  `json:"id"`
	Name        string     `json:"name"`
	Kind        string     `json:"kind"`
	Description string     `json:"description"`
	Mode        string     `json:"mode"`
	Severity    string     `json:"severity"`
	Enabled     bool       `json:"enabled"`
	Rules       string     `json:"rules,omitempty"`
	SHA256      string     `json:"sha256"`
	RuleCount   int        `json:"rule_count"`
	Origin      RuleOrigin `json:"origin"`
	Revision    int64      `json:"revision"`
	CreatedBy   *uuid.UUID `json:"created_by"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

// RuleSetChange is a partial update; nil fields are unchanged.
type RuleSetChange struct {
	Description *string     `json:"description"`
	Mode        *string     `json:"mode"`
	Severity    *string     `json:"severity"`
	Enabled     *bool       `json:"enabled"`
	Rules       *string     `json:"rules"`
	Origin      *RuleOrigin `json:"origin"`
}

// ErrRulePackLimit means the enabled rulesets would exceed the scan limit.
var ErrRulePackLimit = errors.New("enabled rulesets exceed 32 MiB or 200 rulesets")

func validRuleSet(r RuleSetRecord) bool {
	if !intelligence.RuleSetName.MatchString(r.Name) || (r.Kind != "custom" && r.Kind != "external") || len(r.Description) > 1000 || intelligence.CheckRuleText(r.Rules) != nil {
		return false
	}
	if r.Mode != "hunt" && r.Mode != "alert" && r.Mode != "block" {
		return false
	}
	if _, ok := intelligence.RuleSeverityScore[r.Severity]; !ok {
		return false
	}
	o := r.Origin
	if len(o.Vendor) > 100 || len(o.Version) > 100 || len(o.License) > 100 || len(o.URL) > 2048 {
		return false
	}
	if o.URL != "" {
		u, err := url.Parse(o.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
			return false
		}
	}
	return true
}

const ruleColumns = `id,name,kind,description,mode,severity,enabled,sha256,rule_count,origin,revision,created_by,created_at,updated_at`

func scanRuleSet(row pgx.Row, withRules bool) (RuleSetRecord, error) {
	var r RuleSetRecord
	var origin []byte
	targets := []any{&r.ID, &r.Name, &r.Kind, &r.Description, &r.Mode, &r.Severity, &r.Enabled, &r.SHA256, &r.RuleCount, &origin, &r.Revision, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt}
	if withRules {
		targets = append(targets, &r.Rules)
	}
	if err := row.Scan(targets...); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrNotFound
		}
		return r, err
	}
	_ = json.Unmarshal(origin, &r.Origin)
	return r, nil
}

// checkPackLimit rejects a change that would make the enabled pack unscannable.
func (s *Store) checkPackLimit(ctx context.Context, tx pgx.Tx) error {
	var total, count int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(sum(octet_length(rules)),0),count(*) FROM `+s.schema+`.yara_rulesets WHERE enabled`).Scan(&total, &count); err != nil {
		return err
	}
	if total > intelligence.MaxRulePackSize || count > intelligence.MaxRuleSets {
		return ErrRulePackLimit
	}
	return nil
}

func ruleAudit(ctx context.Context, tx pgx.Tx, schema, action string, r RuleSetRecord, actor uuid.UUID) error {
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "name": r.Name, "mode": r.Mode, "enabled": r.Enabled, "sha256": r.SHA256, "revision": r.Revision})
	_, err := tx.Exec(ctx, `INSERT INTO `+schema+`.audit_log(action,target_id,details) VALUES($1,$2,$3)`, action, r.ID, details)
	return err
}

func ruleDigest(rules string) string {
	sum := sha256.Sum256([]byte(rules))
	return hex.EncodeToString(sum[:])
}

// CreateRuleSet stores a compiled-and-validated ruleset.
func (s *Store) CreateRuleSet(ctx context.Context, r RuleSetRecord, actor uuid.UUID) (RuleSetRecord, error) {
	r.Description = strings.TrimSpace(r.Description)
	if !validRuleSet(r) {
		return r, ErrInput
	}
	r.ID, r.SHA256, r.RuleCount = uuid.New(), ruleDigest(r.Rules), intelligence.CountRules(r.Rules)
	origin, _ := json.Marshal(r.Origin)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer tx.Rollback(ctx)
	row := tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.yara_rulesets(id,name,kind,description,mode,severity,enabled,rules,sha256,rule_count,origin,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING `+ruleColumns, r.ID, r.Name, r.Kind, r.Description, r.Mode, r.Severity, r.Enabled, r.Rules, r.SHA256, r.RuleCount, origin, actor)
	created, err := scanRuleSet(row, false)
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return r, ErrConflict
		}
		return r, err
	}
	if err := s.checkPackLimit(ctx, tx); err != nil {
		return r, err
	}
	if err := ruleAudit(ctx, tx, s.schema, "yara_ruleset.created", created, actor); err != nil {
		return r, err
	}
	return created, tx.Commit(ctx)
}

// RuleSets lists rulesets without their rule text.
func (s *Store) RuleSets(ctx context.Context) ([]RuleSetRecord, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+ruleColumns+` FROM `+s.schema+`.yara_rulesets ORDER BY name LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuleSetRecord{}
	for rows.Next() {
		r, err := scanRuleSet(rows, false)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// RuleSet returns one ruleset with its rule text.
func (s *Store) RuleSet(ctx context.Context, id uuid.UUID) (RuleSetRecord, error) {
	return scanRuleSet(s.pool.QueryRow(ctx, `SELECT `+ruleColumns+`,rules FROM `+s.schema+`.yara_rulesets WHERE id=$1`, id), true)
}

// UpdateRuleSet applies a change at the expected revision. authorize sees the
// ruleset before and after the change and may refuse it (scope checks).
func (s *Store) UpdateRuleSet(ctx context.Context, id uuid.UUID, expected int64, c RuleSetChange, actor uuid.UUID, authorize func(before, after RuleSetRecord) error) (RuleSetRecord, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return RuleSetRecord{}, err
	}
	defer tx.Rollback(ctx)
	before, err := scanRuleSet(tx.QueryRow(ctx, `SELECT `+ruleColumns+`,rules FROM `+s.schema+`.yara_rulesets WHERE id=$1 FOR UPDATE`, id), true)
	if err != nil {
		return RuleSetRecord{}, err
	}
	if before.Revision != expected {
		return RuleSetRecord{}, ErrConflict
	}
	after := before
	if c.Description != nil {
		after.Description = strings.TrimSpace(*c.Description)
	}
	if c.Mode != nil {
		after.Mode = *c.Mode
	}
	if c.Severity != nil {
		after.Severity = *c.Severity
	}
	if c.Enabled != nil {
		after.Enabled = *c.Enabled
	}
	if c.Rules != nil {
		after.Rules = *c.Rules
	}
	if c.Origin != nil {
		after.Origin = *c.Origin
	}
	if !validRuleSet(after) {
		return RuleSetRecord{}, ErrInput
	}
	if err := authorize(before, after); err != nil {
		return RuleSetRecord{}, err
	}
	after.SHA256, after.RuleCount = ruleDigest(after.Rules), intelligence.CountRules(after.Rules)
	origin, _ := json.Marshal(after.Origin)
	updated, err := scanRuleSet(tx.QueryRow(ctx, `UPDATE `+s.schema+`.yara_rulesets SET description=$2,mode=$3,severity=$4,enabled=$5,rules=$6,sha256=$7,rule_count=$8,origin=$9,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING `+ruleColumns, id, after.Description, after.Mode, after.Severity, after.Enabled, after.Rules, after.SHA256, after.RuleCount, origin), false)
	if err != nil {
		return RuleSetRecord{}, err
	}
	if err := s.checkPackLimit(ctx, tx); err != nil {
		return RuleSetRecord{}, err
	}
	action := "yara_ruleset.changed"
	if before.Mode != after.Mode {
		action = "yara_ruleset.mode_changed"
	}
	if err := ruleAudit(ctx, tx, s.schema, action, updated, actor); err != nil {
		return RuleSetRecord{}, err
	}
	return updated, tx.Commit(ctx)
}

// DeleteRuleSet removes a ruleset; authorize may refuse it. Findings keep
// their evidence and close on the next complete scan.
func (s *Store) DeleteRuleSet(ctx context.Context, id uuid.UUID, actor uuid.UUID, authorize func(RuleSetRecord) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	r, err := scanRuleSet(tx.QueryRow(ctx, `SELECT `+ruleColumns+` FROM `+s.schema+`.yara_rulesets WHERE id=$1 FOR UPDATE`, id), false)
	if err != nil {
		return err
	}
	if err := authorize(r); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.yara_rulesets WHERE id=$1`, id); err != nil {
		return err
	}
	if err := ruleAudit(ctx, tx, s.schema, "yara_ruleset.deleted", r, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ActiveRulePack returns the enabled rulesets as the scanner's "rules" part,
// or nil when none are enabled.
func (s *Store) ActiveRulePack(ctx context.Context) (json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,mode,severity,rules FROM `+s.schema+`.yara_rulesets WHERE enabled ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pack := intelligence.RulePack{}
	for rows.Next() {
		var set intelligence.RuleSet
		var id uuid.UUID
		if err := rows.Scan(&id, &set.Name, &set.Mode, &set.Severity, &set.Rules); err != nil {
			return nil, err
		}
		set.ID = id.String()
		pack.RuleSets = append(pack.RuleSets, set)
	}
	if err := rows.Err(); err != nil || len(pack.RuleSets) == 0 {
		return nil, err
	}
	return json.Marshal(pack)
}
