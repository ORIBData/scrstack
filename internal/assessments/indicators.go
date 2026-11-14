package assessments

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Indicator sources (TIF): each source holds its own indicators and mode,
// like a YARA ruleset. New sources hunt until an admin promotes them. Scans
// receive one merged bundle of every enabled source's unexpired indicators.

func indicatorSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.indicator_sources(id uuid PRIMARY KEY,name text NOT NULL UNIQUE,kind text NOT NULL CHECK(kind IN ('manual','stix','taxii')),description text NOT NULL DEFAULT '',mode text NOT NULL DEFAULT 'hunt' CHECK(mode IN ('hunt','alert','block')),severity text NOT NULL DEFAULT 'high' CHECK(severity IN ('critical','high','medium','low','info')),min_confidence integer NOT NULL DEFAULT 0 CHECK(min_confidence BETWEEN 0 AND 100),enabled boolean NOT NULL DEFAULT true,origin jsonb NOT NULL DEFAULT '{}',version text NOT NULL DEFAULT '',indicator_count integer NOT NULL DEFAULT 0,imported_at timestamptz,revision bigint NOT NULL DEFAULT 1,created_by uuid,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),updated_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.indicators(source_id uuid NOT NULL REFERENCES ` + s + `.indicator_sources(id) ON DELETE CASCADE,id text NOT NULL,type text NOT NULL,value text NOT NULL,confidence integer CHECK(confidence BETWEEN 0 AND 100),valid_until timestamptz NOT NULL,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(source_id,id))`,
		`CREATE INDEX IF NOT EXISTS indicators_value_idx ON ` + s + `.indicators(type,value)`,
		// Before sources existed, PUT /feeds/indicators activated one bundle
		// that blocked. Carry it over once as the block-mode "bundle" source.
		`WITH legacy AS (SELECT version,body,created_at FROM ` + s + `.indicator_bundles WHERE active AND NOT EXISTS(SELECT 1 FROM ` + s + `.indicator_sources WHERE name='` + intelligence.LegacySource + `')),
source AS (INSERT INTO ` + s + `.indicator_sources(id,name,kind,description,mode,severity,version,indicator_count,imported_at) SELECT gen_random_uuid(),'` + intelligence.LegacySource + `','manual','Indicator bundle imported with PUT /feeds/indicators','block','critical',version,jsonb_array_length(body->'indicators'),created_at FROM legacy RETURNING id)
INSERT INTO ` + s + `.indicators(source_id,id,type,value,valid_until) SELECT source.id,e->>'id',e->>'type',e->>'value',(e->>'valid_until')::timestamptz FROM source,legacy,jsonb_array_elements(legacy.body->'indicators') e`,
	}
}

// IndicatorSource is a stored source and the state of its last import.
type IndicatorSource struct {
	ID             uuid.UUID  `json:"id"`
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	Description    string     `json:"description"`
	Mode           string     `json:"mode"`
	Severity       string     `json:"severity"`
	MinConfidence  int        `json:"min_confidence"`
	Enabled        bool       `json:"enabled"`
	Origin         RuleOrigin `json:"origin"`
	Version        string     `json:"version"`
	IndicatorCount int        `json:"indicator_count"`
	ImportedAt     *time.Time `json:"imported_at"`
	Revision       int64      `json:"revision"`
	CreatedBy      *uuid.UUID `json:"created_by"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// IndicatorSourceChange is a partial update; nil fields are unchanged.
type IndicatorSourceChange struct {
	Description   *string     `json:"description"`
	Mode          *string     `json:"mode"`
	Severity      *string     `json:"severity"`
	MinConfidence *int        `json:"min_confidence"`
	Enabled       *bool       `json:"enabled"`
	Origin        *RuleOrigin `json:"origin"`
}

// ErrIndicatorLimit means enabled sources would exceed the scan bundle limit.
var ErrIndicatorLimit = fmt.Errorf("enabled indicator sources exceed %d indicators or %d MiB", intelligence.MaxScanIndicators, intelligence.MaxScanBundleBytes>>20)

func validSource(r IndicatorSource) bool {
	if !intelligence.RuleSetName.MatchString(r.Name) || r.Kind != "manual" || len(r.Description) > 1000 || r.MinConfidence < 0 || r.MinConfidence > 100 {
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

const sourceColumns = `id,name,kind,description,mode,severity,min_confidence,enabled,origin,version,indicator_count,imported_at,revision,created_by,created_at,updated_at`

func scanSource(row pgx.Row) (IndicatorSource, error) {
	var r IndicatorSource
	var origin []byte
	if err := row.Scan(&r.ID, &r.Name, &r.Kind, &r.Description, &r.Mode, &r.Severity, &r.MinConfidence, &r.Enabled, &origin, &r.Version, &r.IndicatorCount, &r.ImportedAt, &r.Revision, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return r, ErrNotFound
		}
		return r, err
	}
	_ = json.Unmarshal(origin, &r.Origin)
	return r, nil
}

func sourceAudit(ctx context.Context, tx pgx.Tx, schema, action string, r IndicatorSource, actor uuid.UUID) error {
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "name": r.Name, "mode": r.Mode, "enabled": r.Enabled, "min_confidence": r.MinConfidence, "version": r.Version, "indicators": r.IndicatorCount, "revision": r.Revision})
	_, err := tx.Exec(ctx, `INSERT INTO `+schema+`.audit_log(action,target_id,details) VALUES($1,$2,$3)`, action, r.ID, details)
	return err
}

// checkIndicatorLimit rejects a change that would make the scan bundle too
// large. The byte estimate allows for each indicator's JSON framing.
func (s *Store) checkIndicatorLimit(ctx context.Context, tx pgx.Tx) error {
	var count, size int64
	if err := tx.QueryRow(ctx, `SELECT count(*),COALESCE(sum(octet_length(i.id)+octet_length(i.value)+octet_length(src.name)+200),0) FROM `+s.schema+`.indicators i JOIN `+s.schema+`.indicator_sources src ON src.id=i.source_id WHERE src.enabled AND i.valid_until>clock_timestamp()`).Scan(&count, &size); err != nil {
		return err
	}
	if count > intelligence.MaxScanIndicators || size > intelligence.MaxScanBundleBytes {
		return ErrIndicatorLimit
	}
	return nil
}

// CreateIndicatorSource stores an empty source; indicators are imported next.
func (s *Store) CreateIndicatorSource(ctx context.Context, r IndicatorSource, actor uuid.UUID) (IndicatorSource, error) {
	r.Description = strings.TrimSpace(r.Description)
	if !validSource(r) {
		return r, ErrInput
	}
	origin, _ := json.Marshal(r.Origin)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return r, err
	}
	defer tx.Rollback(ctx)
	created, err := scanSource(tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.indicator_sources(id,name,kind,description,mode,severity,min_confidence,enabled,origin,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING `+sourceColumns, uuid.New(), r.Name, r.Kind, r.Description, r.Mode, r.Severity, r.MinConfidence, r.Enabled, origin, actor))
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return r, ErrConflict
		}
		return r, err
	}
	if err := sourceAudit(ctx, tx, s.schema, "indicator_source.created", created, actor); err != nil {
		return r, err
	}
	return created, tx.Commit(ctx)
}

// IndicatorSources lists sources without their indicators.
func (s *Store) IndicatorSources(ctx context.Context) ([]IndicatorSource, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+sourceColumns+` FROM `+s.schema+`.indicator_sources ORDER BY name LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []IndicatorSource{}
	for rows.Next() {
		r, err := scanSource(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) IndicatorSourceByID(ctx context.Context, id uuid.UUID) (IndicatorSource, error) {
	return scanSource(s.pool.QueryRow(ctx, `SELECT `+sourceColumns+` FROM `+s.schema+`.indicator_sources WHERE id=$1`, id))
}

// SourceIndicators returns a source's indicators as a bundle, in ID order.
func (s *Store) SourceIndicators(ctx context.Context, id uuid.UUID) (intelligence.Bundle, error) {
	source, err := s.IndicatorSourceByID(ctx, id)
	if err != nil {
		return intelligence.Bundle{}, err
	}
	b := intelligence.Bundle{Version: source.Version, Indicators: []intelligence.Indicator{}}
	rows, err := s.pool.Query(ctx, `SELECT id,type,value,confidence,valid_until FROM `+s.schema+`.indicators WHERE source_id=$1 ORDER BY id`, id)
	if err != nil {
		return b, err
	}
	defer rows.Close()
	for rows.Next() {
		var i intelligence.Indicator
		if err := rows.Scan(&i.ID, &i.Type, &i.Value, &i.Confidence, &i.ValidUntil); err != nil {
			return b, err
		}
		b.Indicators = append(b.Indicators, i)
	}
	return b, rows.Err()
}

// UpdateIndicatorSource applies a change at the expected revision; authorize
// sees the source before and after the change and may refuse it.
func (s *Store) UpdateIndicatorSource(ctx context.Context, id uuid.UUID, expected int64, c IndicatorSourceChange, actor uuid.UUID, authorize func(before, after IndicatorSource) error) (IndicatorSource, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return IndicatorSource{}, err
	}
	defer tx.Rollback(ctx)
	before, err := scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM `+s.schema+`.indicator_sources WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return IndicatorSource{}, err
	}
	if before.Revision != expected {
		return IndicatorSource{}, ErrConflict
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
	if c.MinConfidence != nil {
		after.MinConfidence = *c.MinConfidence
	}
	if c.Enabled != nil {
		after.Enabled = *c.Enabled
	}
	if c.Origin != nil {
		after.Origin = *c.Origin
	}
	if !validSource(after) {
		return IndicatorSource{}, ErrInput
	}
	if err := authorize(before, after); err != nil {
		return IndicatorSource{}, err
	}
	origin, _ := json.Marshal(after.Origin)
	updated, err := scanSource(tx.QueryRow(ctx, `UPDATE `+s.schema+`.indicator_sources SET description=$2,mode=$3,severity=$4,min_confidence=$5,enabled=$6,origin=$7,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING `+sourceColumns, id, after.Description, after.Mode, after.Severity, after.MinConfidence, after.Enabled, origin))
	if err != nil {
		return IndicatorSource{}, err
	}
	if err := s.checkIndicatorLimit(ctx, tx); err != nil {
		return IndicatorSource{}, err
	}
	action := "indicator_source.changed"
	if before.Mode != after.Mode {
		action = "indicator_source.mode_changed"
	}
	if err := sourceAudit(ctx, tx, s.schema, action, updated, actor); err != nil {
		return IndicatorSource{}, err
	}
	return updated, tx.Commit(ctx)
}

// DeleteIndicatorSource removes a source and its indicators; authorize may
// refuse it. Findings close on the next complete scan.
func (s *Store) DeleteIndicatorSource(ctx context.Context, id uuid.UUID, actor uuid.UUID, authorize func(IndicatorSource) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	r, err := scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM `+s.schema+`.indicator_sources WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return err
	}
	if err := authorize(r); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.indicator_sources WHERE id=$1`, id); err != nil {
		return err
	}
	if err := sourceAudit(ctx, tx, s.schema, "indicator_source.deleted", r, actor); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ImportSourceIndicators replaces a source's indicators with a parsed bundle;
// authorize sees the source and may refuse the import.
func (s *Store) ImportSourceIndicators(ctx context.Context, id uuid.UUID, b intelligence.Bundle, actor uuid.UUID, authorize func(IndicatorSource) error) (IndicatorSource, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return IndicatorSource{}, err
	}
	defer tx.Rollback(ctx)
	source, err := scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM `+s.schema+`.indicator_sources WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return source, err
	}
	if err := authorize(source); err != nil {
		return source, err
	}
	if source, err = s.replaceIndicators(ctx, tx, source.ID, b); err != nil {
		return source, err
	}
	if err := sourceAudit(ctx, tx, s.schema, "indicator_source.imported", source, actor); err != nil {
		return source, err
	}
	return source, tx.Commit(ctx)
}

func (s *Store) replaceIndicators(ctx context.Context, tx pgx.Tx, id uuid.UUID, b intelligence.Bundle) (IndicatorSource, error) {
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.indicators WHERE source_id=$1`, id); err != nil {
		return IndicatorSource{}, err
	}
	n := len(b.Indicators)
	ids, types, values, confidence, until := make([]string, n), make([]string, n), make([]string, n), make([]*int, n), make([]time.Time, n)
	for k, i := range b.Indicators {
		ids[k], types[k], values[k], confidence[k], until[k] = i.ID, i.Type, i.Value, i.Confidence, i.ValidUntil
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.indicators(source_id,id,type,value,confidence,valid_until) SELECT $1,* FROM unnest($2::text[],$3::text[],$4::text[],$5::integer[],$6::timestamptz[])`, id, ids, types, values, confidence, until); err != nil {
		return IndicatorSource{}, err
	}
	source, err := scanSource(tx.QueryRow(ctx, `UPDATE `+s.schema+`.indicator_sources SET version=$2,indicator_count=$3,imported_at=clock_timestamp(),revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING `+sourceColumns, id, b.Version, len(b.Indicators)))
	if err != nil {
		return source, err
	}
	return source, s.checkIndicatorLimit(ctx, tx)
}

// ImportIndicators activates a bundle from PUT /feeds/indicators: versions
// stay immutable in indicator_bundles, and the bundle replaces the indicators
// of the "bundle" source, created in block mode as before sources existed.
func (s *Store) ImportIndicators(ctx context.Context, actor uuid.UUID, raw []byte) (string, error) {
	b, err := intelligence.Parse(raw)
	if err != nil || len(b.Indicators) > 10000 {
		return "", ErrInput
	}
	normalized, _ := json.Marshal(b)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".indicator_import"); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE `+s.schema+`.indicator_bundles SET active=false WHERE active`); err != nil {
		return "", err
	}
	id := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.indicator_bundles(id,version,body) VALUES($1,$2,$3)`, id, b.Version, normalized); err != nil {
		var p *pgconn.PgError
		if errors.As(err, &p) && p.Code == "23505" {
			return "", ErrConflict
		}
		return "", err
	}
	var source uuid.UUID
	if err = tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.indicator_sources(id,name,kind,description,mode,severity,created_by) VALUES($1,$2,'manual','Indicator bundle imported with PUT /feeds/indicators','block','critical',$3) ON CONFLICT(name) DO UPDATE SET name=EXCLUDED.name RETURNING id`, uuid.New(), intelligence.LegacySource, actor).Scan(&source); err != nil {
		return "", err
	}
	if _, err = s.replaceIndicators(ctx, tx, source, b); err != nil {
		return "", err
	}
	detail, _ := json.Marshal(map[string]any{"actor_id": actor, "version": b.Version, "indicators": len(b.Indicators), "sha256": Hash(normalized), "source_id": source})
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('indicators.imported',$1,$2)`, id, detail); err != nil {
		return "", err
	}
	return b.Version, tx.Commit(ctx)
}

// ActiveIndicators returns the bundle last activated with PUT /feeds/indicators.
func (s *Store) ActiveIndicators(ctx context.Context) (json.RawMessage, error) {
	var raw json.RawMessage
	err := s.pool.QueryRow(ctx, `SELECT body FROM `+s.schema+`.indicator_bundles WHERE active`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}

// ScanIndicators returns every enabled source's unexpired indicators at or
// above the source's minimum confidence (an indicator without confidence
// always qualifies), each labelled with its source, mode and severity. It
// returns nil when there are none. The version is a digest of the content.
func (s *Store) ScanIndicators(ctx context.Context) (json.RawMessage, error) {
	return s.activeIndicators(ctx, nil)
}

// activeIndicators builds the merged bundle, limited to some indicator types
// when types is not nil.
func (s *Store) activeIndicators(ctx context.Context, types []string) (json.RawMessage, error) {
	rows, err := s.pool.Query(ctx, `SELECT i.id,i.type,i.value,i.confidence,i.valid_until,src.name,src.mode,src.severity FROM `+s.schema+`.indicators i JOIN `+s.schema+`.indicator_sources src ON src.id=i.source_id WHERE src.enabled AND i.valid_until>clock_timestamp() AND (i.confidence IS NULL OR i.confidence>=src.min_confidence) AND ($2::text[] IS NULL OR i.type=ANY($2)) ORDER BY src.name,i.id LIMIT $1`, intelligence.MaxScanIndicators+1, types)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	b := intelligence.Bundle{}
	for rows.Next() {
		var i intelligence.Indicator
		if err := rows.Scan(&i.ID, &i.Type, &i.Value, &i.Confidence, &i.ValidUntil, &i.Source, &i.Mode, &i.Severity); err != nil {
			return nil, err
		}
		b.Indicators = append(b.Indicators, i)
	}
	if err := rows.Err(); err != nil || len(b.Indicators) == 0 {
		return nil, err
	}
	if len(b.Indicators) > intelligence.MaxScanIndicators {
		return nil, ErrIndicatorLimit
	}
	body, _ := json.Marshal(b.Indicators)
	sum := sha256.Sum256(body)
	b.Version = "sha256:" + hex.EncodeToString(sum[:8])
	return json.Marshal(b)
}

// ActiveBundle returns the enabled event patterns (branch, commit message,
// pull request title and path) for matching GitHub events.
func (s *Store) ActiveBundle(ctx context.Context) (*intelligence.Bundle, error) {
	raw, err := s.activeIndicators(ctx, []string{"git_branch_regex", "commit_message_regex", "pr_title_regex", "file_path_regex"})
	if err != nil || len(raw) == 0 {
		return nil, err
	}
	b, err := intelligence.ParseScan(raw)
	if err != nil {
		return nil, err
	}
	return &b, nil
}
