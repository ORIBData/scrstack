package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Retention by data class (RET-001 to RET-007). Each class has a policy
// value (days, or null for "not set"), an environment default
// SCRS_RETENTION_DEFAULT_<CLASS>_DAYS, and guards: open register entries,
// the current revision of each tracked ref and assets under legal hold are
// never purged; the audit log keeps at least 365 days. Object storage is
// deleted explicitly after the database rows, never left to lifecycle rules.

// ObjectStore deletes stored objects (SBOMs, snapshots, plans, QA reports).
type ObjectStore interface {
	DeleteObject(ctx context.Context, key string) error
}

// UseObjects lets retention delete the objects of purged rows; without it,
// object-backed classes are skipped.
func (s *Store) UseObjects(o ObjectStore) { s.objects = o }

// AuditFloorDays is the shortest audit-log retention allowed (RET-006).
const AuditFloorDays = 365

// RetentionClass describes one class and its current setting.
type RetentionClass struct {
	Class           string     `json:"class"`
	Description     string     `json:"description"`
	Guard           string     `json:"guard"`
	Days            *int       `json:"days"`
	EffectiveDays   int        `json:"effective_days"`
	Source          string     `json:"source"`
	MinimumDays     int        `json:"minimum_days,omitempty"`
	LastPurgedAt    *time.Time `json:"last_purged_at"`
	LastPurgedCount int64      `json:"last_purged_count"`
}

type classDef struct {
	key, description, guard string
	min                     int
	objects                 bool
}

// retentionDefs lists the purgeable classes in purge order.
var retentionDefs = []classDef{
	{"inbound_events", "Raw webhook and registry events", "events of queued or running assessments", 0, false},
	{"webhook_deliveries", "Outbound delivery log", "pending and retrying deliveries", 0, false},
	{"closed_findings", "Register entries fixed, false positive or suppressed, with their history", "open, triaged, in-progress and accepted entries; assets on legal hold", 0, false},
	{"scan_artifacts", "File inventories and component lists of superseded assessments", "the newest successful assessment of each asset and ref; assessments that open entries point to; legal hold", 0, false},
	{"sbom_documents", "SBOMs of superseded assessments (S3 and index)", "the current revision of each tracked ref; legal hold", 0, true},
	{"source_snapshots", "Stored source archives of superseded assessments", "the current revision of each tracked ref; legal hold", 0, true},
	{"remediation_plans", "Stored remediation plans", "assets on legal hold", 0, true},
	{"qa_reports", "QA report archives and scenario lists of older runs", "the newest finished run of each asset and kind; legal hold", 0, true},
	{"expired_indicators", "Indicators past valid_until", "unexpired indicators", 0, false},
	{"audit_log", "Audit records", "at least 365 days are always kept", AuditFloorDays, false},
}

func retentionClassSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.retention_classes(class text PRIMARY KEY,days integer CHECK(days IS NULL OR days BETWEEN 0 AND 36500),last_purged_at timestamptz,last_purged_count bigint NOT NULL DEFAULT 0)`,
	}
}

func envDefault(class string) int {
	n, err := strconv.Atoi(os.Getenv("SCRS_RETENTION_DEFAULT_" + strings.ToUpper(class) + "_DAYS"))
	if err != nil || n < 0 || n > 36500 {
		return 0
	}
	return n
}

// retentionClasses reads every class's setting. The two original classes
// keep their policy columns (0 there means not set).
func (s *Store) retentionClasses(ctx context.Context, q pgx.Tx) ([]RetentionClass, error) {
	var events, deliveries int
	query := func(sql string, args ...any) pgx.Row {
		if q != nil {
			return q.QueryRow(ctx, sql, args...)
		}
		return s.pool.QueryRow(ctx, sql, args...)
	}
	if err := query(`SELECT inbound_event_days,webhook_delivery_days FROM `+s.schema+`.retention_policy WHERE singleton`).Scan(&events, &deliveries); err != nil {
		return nil, err
	}
	stored := map[string]RetentionClass{}
	var rows pgx.Rows
	var err error
	if q != nil {
		rows, err = q.Query(ctx, `SELECT class,days,last_purged_at,last_purged_count FROM `+s.schema+`.retention_classes`)
	} else {
		rows, err = s.pool.Query(ctx, `SELECT class,days,last_purged_at,last_purged_count FROM `+s.schema+`.retention_classes`)
	}
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c RetentionClass
		if err := rows.Scan(&c.Class, &c.Days, &c.LastPurgedAt, &c.LastPurgedCount); err != nil {
			rows.Close()
			return nil, err
		}
		stored[c.Class] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]RetentionClass, 0, len(retentionDefs))
	for _, def := range retentionDefs {
		c := stored[def.key]
		c.Class, c.Description, c.Guard, c.MinimumDays = def.key, def.description, def.guard, def.min
		switch def.key {
		case "inbound_events":
			c.Days = nil
			if events > 0 {
				c.Days = &events
			}
		case "webhook_deliveries":
			c.Days = nil
			if deliveries > 0 {
				c.Days = &deliveries
			}
		}
		if c.Days != nil {
			c.EffectiveDays, c.Source = *c.Days, "policy"
		} else {
			c.EffectiveDays, c.Source = envDefault(def.key), "default"
		}
		if def.min > 0 && c.EffectiveDays > 0 && c.EffectiveDays < def.min {
			c.EffectiveDays = def.min
		}
		out = append(out, c)
	}
	return out, nil
}

// RetentionClasses returns every class with its effective setting.
func (s *Store) RetentionClasses(ctx context.Context) ([]RetentionClass, error) {
	return s.retentionClasses(ctx, nil)
}

// SetRetentionClasses applies class settings (nil value: not set) at the
// expected policy revision, atomically and audited (RET-002).
func (s *Store) SetRetentionClasses(ctx context.Context, actor uuid.UUID, expected int64, classes map[string]*int) (Retention, error) {
	known := map[string]classDef{}
	for _, d := range retentionDefs {
		known[d.key] = d
	}
	for class, days := range classes {
		def, ok := known[class]
		if !ok || (days != nil && (*days < 0 || *days > 36500 || (def.min > 0 && *days > 0 && *days < def.min))) {
			return Retention{}, ErrInput
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Retention{}, err
	}
	defer tx.Rollback(ctx)
	before, err := s.retentionClasses(ctx, tx)
	if err != nil {
		return Retention{}, err
	}
	tag, err := tx.Exec(ctx, `UPDATE `+s.schema+`.retention_policy SET revision=revision+1 WHERE singleton AND revision=$1`, expected)
	if err != nil {
		return Retention{}, err
	}
	if tag.RowsAffected() != 1 {
		return Retention{}, ErrConflict
	}
	old, changed := map[string]any{}, map[string]any{}
	for _, c := range before {
		if days, ok := classes[c.Class]; ok {
			old[c.Class], changed[c.Class] = c.Days, days
		}
	}
	for class, days := range classes {
		switch class {
		case "inbound_events", "webhook_deliveries":
			column := map[string]string{"inbound_events": "inbound_event_days", "webhook_deliveries": "webhook_delivery_days"}[class]
			value := 0
			if days != nil {
				value = *days
			}
			if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.retention_policy SET `+column+`=$1 WHERE singleton`, value); err != nil {
				return Retention{}, err
			}
		default:
			if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.retention_classes(class,days) VALUES($1,$2) ON CONFLICT(class) DO UPDATE SET days=EXCLUDED.days`, class, days); err != nil {
				return Retention{}, err
			}
		}
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "old": old, "new": changed, "revision": expected + 1})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('retention.policy_changed',$1)`, details); err != nil {
		return Retention{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Retention{}, err
	}
	return s.Retention(ctx)
}

// supersededSQL selects assessments of an old, non-current revision: older
// than $1 days, with a newer successful assessment of the same asset and
// ref, no open entry pointing at them, and the asset not on legal hold.
func (s *Store) supersededSQL(extra string) string {
	return `SELECT x.id FROM ` + s.schema + `.assessments x JOIN ` + s.schema + `.assets a ON a.id=x.asset_id WHERE x.created_at<clock_timestamp()-($1*interval '1 day') AND NOT a.legal_hold AND x.status NOT IN ('queued','running') AND EXISTS(SELECT 1 FROM ` + s.schema + `.assessments n WHERE n.asset_id=x.asset_id AND n.request->'target'->>'ref'=x.request->'target'->>'ref' AND n.status='succeeded' AND n.created_at>x.created_at) AND NOT EXISTS(SELECT 1 FROM ` + s.schema + `.findings f WHERE f.last_assessment_id=x.id AND f.status IN ('open','triaged','in_progress','accepted')) AND ` + extra
}

// candidates returns the SQL selecting a class's purge candidates (one id
// column), with $1 the retention in days.
func (s *Store) candidates(class string) string {
	switch class {
	case "inbound_events":
		return `SELECT e.id FROM ` + s.schema + `.inbound_events e LEFT JOIN ` + s.schema + `.assessments x ON x.id=e.assessment_id LEFT JOIN ` + s.schema + `.assets a ON a.id=x.asset_id WHERE e.created_at<clock_timestamp()-($1*interval '1 day') AND (x.id IS NULL OR x.status NOT IN ('queued','running')) AND NOT COALESCE(a.legal_hold,false)`
	case "webhook_deliveries":
		return `SELECT id FROM ` + s.schema + `.webhook_deliveries WHERE status IN ('delivered','dead') AND created_at<clock_timestamp()-($1*interval '1 day')`
	case "closed_findings":
		return `SELECT f.id FROM ` + s.schema + `.findings f JOIN ` + s.schema + `.assets a ON a.id=f.asset_id WHERE f.status IN ('fixed','false_positive','suppressed') AND f.last_seen<clock_timestamp()-($1*interval '1 day') AND NOT a.legal_hold`
	case "scan_artifacts":
		return s.supersededSQL(`(EXISTS(SELECT 1 FROM ` + s.schema + `.assessment_files af WHERE af.assessment_id=x.id) OR EXISTS(SELECT 1 FROM ` + s.schema + `.components c WHERE c.assessment_id=x.id))`)
	case "sbom_documents":
		return s.supersededSQL(`x.sbom_key<>''`)
	case "source_snapshots":
		return s.supersededSQL(`x.snapshot_key<>''`)
	case "remediation_plans":
		return `SELECT r.assessment_id FROM ` + s.schema + `.remediation_results r JOIN ` + s.schema + `.assessments x ON x.id=r.assessment_id JOIN ` + s.schema + `.assets a ON a.id=x.asset_id WHERE r.created_at<clock_timestamp()-($1*interval '1 day') AND NOT a.legal_hold`
	case "qa_reports":
		return `SELECT q.id FROM ` + s.schema + `.qa_runs q JOIN ` + s.schema + `.assets a ON a.id=q.asset_id WHERE q.report_key<>'' AND q.completed_at<clock_timestamp()-($1*interval '1 day') AND NOT a.legal_hold AND EXISTS(SELECT 1 FROM ` + s.schema + `.qa_runs n WHERE n.asset_id=q.asset_id AND n.kind=q.kind AND n.report_key<>'' AND n.completed_at>q.completed_at)`
	case "expired_indicators":
		return `SELECT source_id,id FROM ` + s.schema + `.indicators WHERE valid_until<clock_timestamp()-($1*interval '1 day')`
	case "audit_log":
		return `SELECT id FROM ` + s.schema + `.audit_log WHERE occurred_at<clock_timestamp()-(GREATEST($1,` + strconv.Itoa(AuditFloorDays) + `)*interval '1 day')`
	}
	return ""
}

// PreviewRetentionClasses counts what each class would remove now with the
// given days (RET-003); nil or zero counts nothing.
func (s *Store) PreviewRetentionClasses(ctx context.Context, days map[string]*int) (map[string]int64, error) {
	out := map[string]int64{}
	for _, def := range retentionDefs {
		value, ok := days[def.key]
		if !ok {
			continue
		}
		if value == nil || *value == 0 {
			out[def.key] = 0
			continue
		}
		if *value < 0 || *value > 36500 {
			return nil, ErrInput
		}
		var n int64
		if err := s.pool.QueryRow(ctx, `SELECT count(*) FROM (`+s.candidates(def.key)+`) c`, *value).Scan(&n); err != nil {
			return nil, err
		}
		out[def.key] = n
	}
	for class := range days {
		if _, ok := out[class]; !ok {
			return nil, ErrInput
		}
	}
	return out, nil
}

// purgeBatch is the most rows one statement removes; a pass repeats up to
// purgeRounds statements per class.
const (
	purgeBatch  = 1000
	purgeRounds = 20
)

// purgeClass removes one batch of a class and returns the rows removed and
// the object keys that no remaining row references.
func (s *Store) purgeClass(ctx context.Context, tx pgx.Tx, class string, days int) (int64, []string, error) {
	pick := `SELECT * FROM (` + s.candidates(class) + `) c LIMIT ` + strconv.Itoa(purgeBatch)
	exec := func(sql string) (int64, error) {
		tag, err := tx.Exec(ctx, sql, days)
		return tag.RowsAffected(), err
	}
	keys := func(sql string) ([]string, error) {
		rows, err := tx.Query(ctx, sql, days)
		if err != nil {
			return nil, err
		}
		defer rows.Close()
		var out []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				return nil, err
			}
			out = append(out, k)
		}
		return out, rows.Err()
	}
	switch class {
	case "inbound_events":
		n, err := exec(`DELETE FROM ` + s.schema + `.inbound_events WHERE id IN (` + pick + `)`)
		return n, nil, err
	case "webhook_deliveries":
		n, err := exec(`DELETE FROM ` + s.schema + `.webhook_deliveries WHERE id IN (` + pick + `)`)
		return n, nil, err
	case "closed_findings":
		// One statement: dependent rows go first in data-modifying CTEs;
		// foreign keys are checked when the statement ends.
		n, err := exec(`WITH doomed AS (` + pick + `), i AS (UPDATE ` + s.schema + `.integrity_events SET finding_id=NULL WHERE finding_id IN (SELECT id FROM doomed) RETURNING 1), e AS (DELETE FROM ` + s.schema + `.finding_events WHERE finding_id IN (SELECT id FROM doomed) RETURNING 1), af AS (DELETE FROM ` + s.schema + `.assessment_findings WHERE finding_id IN (SELECT id FROM doomed) RETURNING 1) DELETE FROM ` + s.schema + `.findings WHERE id IN (SELECT id FROM doomed)`)
		return n, nil, err
	case "scan_artifacts":
		ids, err := keys(`SELECT id::text FROM (` + pick + `) d`)
		if err != nil || len(ids) == 0 {
			return 0, nil, err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.components WHERE assessment_id=ANY($1::uuid[])`, ids); err != nil {
			return 0, nil, err
		}
		_, err = tx.Exec(ctx, `DELETE FROM `+s.schema+`.assessment_files WHERE assessment_id=ANY($1::uuid[])`, ids)
		return int64(len(ids)), nil, err
	case "sbom_documents", "source_snapshots":
		column := map[string]string{"sbom_documents": "sbom_key", "source_snapshots": "snapshot_key"}[class]
		ids, err := keys(`SELECT id::text FROM (` + pick + `) d`)
		if err != nil || len(ids) == 0 {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `SELECT DISTINCT `+column+` FROM `+s.schema+`.assessments WHERE id=ANY($1::uuid[])`, ids)
		if err != nil {
			return 0, nil, err
		}
		var cleared []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return 0, nil, err
			}
			cleared = append(cleared, k)
		}
		rows.Close()
		if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.assessments SET `+column+`='' WHERE id=ANY($1::uuid[])`, ids); err != nil {
			return 0, nil, err
		}
		unused, err := s.unreferenced(ctx, tx, `SELECT 1 FROM `+s.schema+`.assessments WHERE `+column+`=$1`, cleared)
		return int64(len(ids)), unused, err
	case "remediation_plans":
		ids, err := keys(`SELECT assessment_id::text FROM (` + pick + `) d`)
		if err != nil || len(ids) == 0 {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `DELETE FROM `+s.schema+`.remediation_results WHERE assessment_id=ANY($1::uuid[]) RETURNING artifact_key`, ids)
		if err != nil {
			return 0, nil, err
		}
		var cleared []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return 0, nil, err
			}
			cleared = append(cleared, k)
		}
		rows.Close()
		unused, err := s.unreferenced(ctx, tx, `SELECT 1 FROM `+s.schema+`.remediation_results WHERE artifact_key=$1`, cleared)
		return int64(len(ids)), unused, err
	case "qa_reports":
		ids, err := keys(`SELECT id::text FROM (` + pick + `) d`)
		if err != nil || len(ids) == 0 {
			return 0, nil, err
		}
		rows, err := tx.Query(ctx, `WITH old AS (SELECT id,report_key FROM `+s.schema+`.qa_runs WHERE id=ANY($1::uuid[])), u AS (UPDATE `+s.schema+`.qa_runs q SET report_key='' FROM old WHERE q.id=old.id) SELECT DISTINCT report_key FROM old`, ids)
		if err != nil {
			return 0, nil, err
		}
		var cleared []string
		for rows.Next() {
			var k string
			if err := rows.Scan(&k); err != nil {
				rows.Close()
				return 0, nil, err
			}
			cleared = append(cleared, k)
		}
		rows.Close()
		if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.qa_scenarios WHERE run_id=ANY($1::uuid[])`, ids); err != nil {
			return 0, nil, err
		}
		unused, err := s.unreferenced(ctx, tx, `SELECT 1 FROM `+s.schema+`.qa_runs WHERE report_key=$1 AND NOT (id=ANY($2::uuid[]))`, cleared, ids)
		return int64(len(ids)), unused, err
	case "expired_indicators":
		rows, err := tx.Query(ctx, `DELETE FROM `+s.schema+`.indicators WHERE (source_id,id) IN (SELECT source_id,id FROM (`+s.candidates(class)+`) c LIMIT `+strconv.Itoa(purgeBatch)+`) RETURNING source_id::text`, days)
		if err != nil {
			return 0, nil, err
		}
		var n int64
		touched := map[string]bool{}
		for rows.Next() {
			var source string
			if err := rows.Scan(&source); err != nil {
				rows.Close()
				return 0, nil, err
			}
			n++
			touched[source] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return 0, nil, err
		}
		sources := make([]string, 0, len(touched))
		for id := range touched {
			sources = append(sources, id)
		}
		_, err = tx.Exec(ctx, `UPDATE `+s.schema+`.indicator_sources src SET indicator_count=(SELECT count(*) FROM `+s.schema+`.indicators i WHERE i.source_id=src.id) WHERE src.id=ANY($1::uuid[])`, sources)
		return n, nil, err
	case "audit_log":
		n, err := exec(`DELETE FROM ` + s.schema + `.audit_log WHERE id IN (` + pick + `)`)
		return n, nil, err
	}
	return 0, nil, errors.New("unknown retention class")
}

// unreferenced returns the keys no row matched by refSQL still uses.
func (s *Store) unreferenced(ctx context.Context, tx pgx.Tx, refSQL string, keys []string, extra ...any) ([]string, error) {
	var out []string
	for _, k := range keys {
		if k == "" {
			continue
		}
		var used bool
		args := append([]any{k}, extra...)
		if err := tx.QueryRow(ctx, `SELECT EXISTS(`+refSQL+`)`, args...).Scan(&used); err != nil {
			return nil, err
		}
		if !used {
			out = append(out, k)
		}
	}
	return out, nil
}
