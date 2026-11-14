package assessments

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// STIX 2.1 sources (TIF). An upload replaces the source's indicators, or with
// merge replaces only what the bundle's indicator objects produced before.
// pattern_type yara patterns are stored as 'yara' rows and compiled into one
// ruleset linked to the source, which follows the source's mode, severity and
// enabled flag and is rebuilt on every import.

// ErrLinkedName means another ruleset already has the linked ruleset's name.
var ErrLinkedName = errors.New("a YARA ruleset named stix_<source> already exists; rename or delete it")

// RuleCompiler checks that a combined ruleset compiles.
type RuleCompiler func(ctx context.Context, rules string) error

// STIXOutcome is what an import did beyond the indicators: YARA patterns left
// out of the ruleset, and the linked ruleset (nil when there is none).
type STIXOutcome struct {
	Skipped []intelligence.STIXSkip
	RuleSet *RuleSetRecord
}

// stixRuleSetName names the ruleset linked to a STIX source.
func stixRuleSetName(source string) string {
	if len(source) > 58 {
		source = source[:58]
	}
	return "stix_" + source
}

// ImportSTIX stores a parsed STIX upload in a stix source. authorize sees the
// source and may refuse the import; compile runs only when the linked
// ruleset's rules change.
func (s *Store) ImportSTIX(ctx context.Context, id uuid.UUID, imp intelligence.STIXImport, merge bool, actor uuid.UUID, authorize func(IndicatorSource) error, compile RuleCompiler) (IndicatorSource, STIXOutcome, error) {
	var out STIXOutcome
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return IndicatorSource{}, out, err
	}
	defer tx.Rollback(ctx)
	source, err := scanSource(tx.QueryRow(ctx, `SELECT `+sourceColumns+` FROM `+s.schema+`.indicator_sources WHERE id=$1 FOR UPDATE`, id))
	if err != nil {
		return source, out, err
	}
	if source.Kind != "stix" && source.Kind != "taxii" {
		return source, out, ErrSourceKind
	}
	if err := authorize(source); err != nil {
		return source, out, err
	}
	if merge {
		// Numbered rows (indicator--x#2) belong to the object indicator--x.
		_, err = tx.Exec(ctx, `DELETE FROM `+s.schema+`.indicators WHERE source_id=$1 AND split_part(id,'#',1)=ANY($2)`, id, imp.Touched)
	} else {
		_, err = tx.Exec(ctx, `DELETE FROM `+s.schema+`.indicators WHERE source_id=$1`, id)
	}
	if err != nil {
		return source, out, err
	}
	rows := append([]intelligence.Indicator{}, imp.Indicators...)
	for _, y := range imp.Yara {
		rows = append(rows, intelligence.Indicator{ID: y.ID, Type: "yara", Value: y.Rules, Confidence: y.Confidence, ValidUntil: y.ValidUntil})
	}
	if err := s.insertIndicators(ctx, tx, id, rows); err != nil {
		return source, out, err
	}
	// Expired and below-confidence patterns leave the ruleset at the next import.
	patterns, err := tx.Query(ctx, `SELECT id,value FROM `+s.schema+`.indicators WHERE source_id=$1 AND type='yara' AND valid_until>clock_timestamp() AND (confidence IS NULL OR confidence>=$2) ORDER BY id`, id, source.MinConfidence)
	if err != nil {
		return source, out, err
	}
	var ids, texts []string
	for patterns.Next() {
		var pid, text string
		if err := patterns.Scan(&pid, &text); err != nil {
			patterns.Close()
			return source, out, err
		}
		ids, texts = append(ids, pid), append(texts, text)
	}
	patterns.Close()
	if err := patterns.Err(); err != nil {
		return source, out, err
	}
	combined, reasons := intelligence.CombineRules(texts)
	for n, reason := range reasons {
		if reason != "" {
			out.Skipped = append(out.Skipped, intelligence.STIXSkip{ID: ids[n], Reason: reason})
		}
	}
	if out.RuleSet, err = s.syncSTIXRules(ctx, tx, source, combined, actor, compile); err != nil {
		return source, out, err
	}
	var linked *uuid.UUID
	if out.RuleSet != nil {
		linked = &out.RuleSet.ID
	}
	source, err = scanSource(tx.QueryRow(ctx, `UPDATE `+s.schema+`.indicator_sources SET version=$2,indicator_count=(SELECT count(*) FROM `+s.schema+`.indicators WHERE source_id=$1 AND type<>'yara'),imported_at=clock_timestamp(),yara_ruleset_id=$3,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING `+sourceColumns, id, imp.BundleID, linked))
	if err != nil {
		return source, out, err
	}
	if err := s.checkIndicatorLimit(ctx, tx); err != nil {
		return source, out, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "name": source.Name, "mode": source.Mode, "bundle": imp.BundleID, "merge": merge, "indicators": source.IndicatorCount, "yara_patterns": len(texts), "revision": source.Revision})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('indicator_source.stix_imported',$1,$2)`, source.ID, details); err != nil {
		return source, out, err
	}
	return source, out, tx.Commit(ctx)
}

// syncSTIXRules makes the source's linked ruleset hold combined, creating,
// updating or deleting it. Unchanged rules are not recompiled.
func (s *Store) syncSTIXRules(ctx context.Context, tx pgx.Tx, source IndicatorSource, combined string, actor uuid.UUID, compile RuleCompiler) (*RuleSetRecord, error) {
	var current *RuleSetRecord
	if source.YaraRulesetID != nil {
		r, err := scanRuleSet(tx.QueryRow(ctx, `SELECT `+ruleColumns+` FROM `+s.schema+`.yara_rulesets WHERE id=$1 FOR UPDATE`, *source.YaraRulesetID), false)
		switch {
		case err == nil:
			current = &r
		case !errors.Is(err, ErrNotFound):
			return nil, err
		}
	}
	if combined == "" {
		if current != nil {
			_, err := s.dropRuleSet(ctx, tx, current.ID, actor)
			return nil, err
		}
		return nil, nil
	}
	digest := ruleDigest(combined)
	if current != nil && current.SHA256 == digest {
		return current, nil
	}
	if err := compile(ctx, combined); err != nil {
		return nil, err
	}
	var saved RuleSetRecord
	var err error
	action := "yara_ruleset.changed"
	if current == nil {
		action = "yara_ruleset.created"
		r := RuleSetRecord{Name: stixRuleSetName(source.Name), Kind: "external", Description: "YARA patterns from STIX source " + source.Name + "; rebuilt on each import", Mode: source.Mode, Severity: source.Severity, Enabled: source.Enabled, Rules: combined, Origin: source.Origin}
		if !validRuleSet(r) {
			return nil, ErrInput
		}
		origin, _ := json.Marshal(r.Origin)
		saved, err = scanRuleSet(tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.yara_rulesets(id,name,kind,description,mode,severity,enabled,rules,sha256,rule_count,origin,created_by) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING `+ruleColumns, uuid.New(), r.Name, r.Kind, r.Description, r.Mode, r.Severity, r.Enabled, r.Rules, digest, intelligence.CountRules(combined), origin, actor), false)
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return nil, ErrLinkedName
		}
	} else {
		saved, err = scanRuleSet(tx.QueryRow(ctx, `UPDATE `+s.schema+`.yara_rulesets SET rules=$2,sha256=$3,rule_count=$4,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING `+ruleColumns, current.ID, combined, digest, intelligence.CountRules(combined)), false)
	}
	if err != nil {
		return nil, err
	}
	if err := s.checkPackLimit(ctx, tx); err != nil {
		return nil, err
	}
	return &saved, ruleAudit(ctx, tx, s.schema, action, saved, actor)
}

// followSource carries a source's mode, severity and enabled flag to its
// linked ruleset.
func (s *Store) followSource(ctx context.Context, tx pgx.Tx, before, after IndicatorSource, actor uuid.UUID) error {
	if after.YaraRulesetID == nil || (before.Mode == after.Mode && before.Severity == after.Severity && before.Enabled == after.Enabled) {
		return nil
	}
	r, err := scanRuleSet(tx.QueryRow(ctx, `UPDATE `+s.schema+`.yara_rulesets SET mode=$2,severity=$3,enabled=$4,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 RETURNING `+ruleColumns, *after.YaraRulesetID, after.Mode, after.Severity, after.Enabled), false)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := s.checkPackLimit(ctx, tx); err != nil {
		return err
	}
	action := "yara_ruleset.changed"
	if before.Mode != after.Mode {
		action = "yara_ruleset.mode_changed"
	}
	return ruleAudit(ctx, tx, s.schema, action, r, actor)
}

// dropRuleSet deletes a ruleset inside tx; false when it was already gone.
func (s *Store) dropRuleSet(ctx context.Context, tx pgx.Tx, id, actor uuid.UUID) (bool, error) {
	r, err := scanRuleSet(tx.QueryRow(ctx, `DELETE FROM `+s.schema+`.yara_rulesets WHERE id=$1 RETURNING `+ruleColumns, id), false)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, ruleAudit(ctx, tx, s.schema, "yara_ruleset.deleted", r, actor)
}
