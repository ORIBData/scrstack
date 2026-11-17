package assessments

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
)

// RegisterFilter narrows the register. Empty fields match everything.
type RegisterFilter struct {
	Asset    uuid.UUID
	Status   string
	Severity string
	Type     string
	// Assignee matches an assignee exactly (ignoring case); Unassigned
	// selects entries nobody holds. Setting both matches nothing.
	Assignee   string
	Unassigned bool
}

// effectiveStatus reads an expired waiver as open, as every register read does.
const effectiveStatus = `CASE WHEN f.status='accepted' AND f.waiver_until<=clock_timestamp() THEN 'open' ELSE f.status END`

// where builds the filter clause over alias f, with arguments starting at $first.
func (f RegisterFilter) where(first int) (string, []any) {
	args := []any{}
	clause := ""
	add := func(sql string, v any) {
		args = append(args, v)
		clause += " AND " + strings.ReplaceAll(sql, "?", "$"+strconv.Itoa(first+len(args)-1))
	}
	if f.Asset != uuid.Nil {
		add("f.asset_id=?", f.Asset)
	}
	if f.Status != "" {
		add(effectiveStatus+"=?", f.Status)
	}
	if f.Severity != "" {
		add("f.severity=?", f.Severity)
	}
	if f.Type != "" {
		add("f.type=?", f.Type)
	}
	if f.Assignee != "" {
		add("lower(f.assignee)=lower(?)", f.Assignee)
	}
	if f.Unassigned {
		clause += " AND f.assignee=''"
	}
	return clause, args
}

// FindingsFiltered pages the register in id order, 101 rows at most.
func (s *Store) FindingsFiltered(ctx context.Context, filter RegisterFilter, after uuid.UUID) ([]Finding, error) {
	clause, args := filter.where(2)
	rows, err := s.pool.Query(ctx, `SELECT f.id,f.asset_id,f.fingerprint,f.ref,f.type,f.advisory_id,f.title,f.severity,f.score,`+effectiveStatus+`,f.component,f.evidence,f.guidance,f.first_seen,f.last_seen,f.waiver_until,f.assignee,f.assigned_at,(SELECT count(*) FROM `+s.schema+`.finding_comments c WHERE c.finding_id=f.id),COALESCE((SELECT ra.locator FROM `+s.schema+`.asset_links l JOIN `+s.schema+`.assets ra ON ra.id=l.to_asset_id WHERE l.from_asset_id=f.asset_id AND l.kind='built_from' ORDER BY (l.source='manual') DESC,ra.locator LIMIT 1),'') FROM `+s.schema+`.findings f WHERE f.id>$1`+clause+` ORDER BY f.id LIMIT 101`, append([]any{after}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Finding{}
	for rows.Next() {
		var f Finding
		var component []byte
		if err := rows.Scan(&f.ID, &f.AssetID, &f.Fingerprint, &f.Ref, &f.Type, &f.AdvisoryID, &f.Title, &f.Severity, &f.Score, &f.Status, &component, &f.Evidence, &f.Guidance, &f.FirstSeen, &f.LastSeen, &f.WaiverUntil, &f.Assignee, &f.AssignedAt, &f.CommentCount, &f.SourceRepository); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(component, &f.Component); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// RegisterSummary counts the register by status, severity and type.
type RegisterSummary struct {
	Total            int            `json:"total"`
	Open             int            `json:"open"`
	ByStatus         map[string]int `json:"by_status"`
	BySeverity       map[string]int `json:"open_by_severity"`
	ByType           map[string]int `json:"open_by_type"`
	WaiversExpiring  int            `json:"waivers_expiring_30d"`
	OldestOpenAgeDay int            `json:"oldest_open_age_days"`
}

// openStatuses are the statuses that still need work.
const openStatuses = `('open','triaged','in_progress')`

func (s *Store) RegisterSummary(ctx context.Context, filter RegisterFilter) (RegisterSummary, error) {
	clause, args := filter.where(1)
	out := RegisterSummary{ByStatus: map[string]int{}, BySeverity: map[string]int{}, ByType: map[string]int{}}
	rows, err := s.pool.Query(ctx, `SELECT `+effectiveStatus+` AS st,f.severity,f.type,count(*) FROM `+s.schema+`.findings f WHERE true`+clause+` GROUP BY 1,2,3`, args...)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var status, severity, kind string
		var n int
		if err := rows.Scan(&status, &severity, &kind, &n); err != nil {
			return out, err
		}
		out.Total += n
		out.ByStatus[status] += n
		if status == "open" || status == "triaged" || status == "in_progress" {
			out.Open += n
			out.BySeverity[severity] += n
			out.ByType[kind] += n
		}
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	rows.Close()
	return out, s.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE f.status='accepted' AND f.waiver_until>clock_timestamp() AND f.waiver_until<=clock_timestamp()+interval '30 days'),COALESCE(max(floor(extract(epoch FROM clock_timestamp()-f.first_seen)/86400)) FILTER (WHERE `+effectiveStatus+` IN `+openStatuses+`),0)::int FROM `+s.schema+`.findings f WHERE true`+clause, args...).Scan(&out.WaiversExpiring, &out.OldestOpenAgeDay)
}

// RegisterPoint is one UTC day of register movement.
type RegisterPoint struct {
	Day      string `json:"day"`
	Detected int    `json:"detected"`
	Fixed    int    `json:"fixed"`
}

// RegisterTimeseries reports findings detected and fixed on each of the last
// days UTC days, oldest first, with zero-filled gaps.
func (s *Store) RegisterTimeseries(ctx context.Context, filter RegisterFilter, days int) ([]RegisterPoint, error) {
	clause, args := filter.where(2)
	rows, err := s.pool.Query(ctx, `SELECT d::date,count(e.id) FILTER (WHERE e.action='detected'),count(e.id) FILTER (WHERE e.action LIKE 'fixed%') FROM generate_series((now() AT TIME ZONE 'UTC')::date-($1::int-1),(now() AT TIME ZONE 'UTC')::date,interval '1 day') d LEFT JOIN (SELECT ev.id,ev.action,ev.created_at FROM `+s.schema+`.finding_events ev JOIN `+s.schema+`.findings f ON f.id=ev.finding_id WHERE true`+clause+`) e ON (e.created_at AT TIME ZONE 'UTC')::date=d::date GROUP BY d ORDER BY d`, append([]any{days}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RegisterPoint{}
	for rows.Next() {
		var day time.Time
		var p RegisterPoint
		if err := rows.Scan(&day, &p.Detected, &p.Fixed); err != nil {
			return nil, err
		}
		p.Day = day.Format("2006-01-02")
		out = append(out, p)
	}
	return out, rows.Err()
}

// TopAsset ranks an asset by its open findings.
type TopAsset struct {
	AssetID    uuid.UUID      `json:"asset_id"`
	Locator    string         `json:"locator"`
	Open       int            `json:"open"`
	BySeverity map[string]int `json:"open_by_severity"`
	MaxScore   int            `json:"max_score"`
}

// TopAssets returns the assets with the most open findings, critical and high
// first, at most limit.
func (s *Store) TopAssets(ctx context.Context, filter RegisterFilter, limit int) ([]TopAsset, error) {
	clause, args := filter.where(1)
	rows, err := s.pool.Query(ctx, `SELECT f.asset_id,a.locator,f.severity,count(*),max(f.score) FROM `+s.schema+`.findings f JOIN `+s.schema+`.assets a ON a.id=f.asset_id WHERE `+effectiveStatus+` IN `+openStatuses+clause+` GROUP BY f.asset_id,a.locator,f.severity`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byAsset := map[uuid.UUID]*TopAsset{}
	for rows.Next() {
		var id uuid.UUID
		var name, severity string
		var n, score int
		if err := rows.Scan(&id, &name, &severity, &n, &score); err != nil {
			return nil, err
		}
		t := byAsset[id]
		if t == nil {
			t = &TopAsset{AssetID: id, Locator: name, BySeverity: map[string]int{}}
			byAsset[id] = t
		}
		t.Open += n
		t.BySeverity[severity] += n
		if score > t.MaxScore {
			t.MaxScore = score
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]TopAsset, 0, len(byAsset))
	for _, t := range byAsset {
		out = append(out, *t)
	}
	sortTop(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func sortTop(items []TopAsset) {
	less := func(a, b TopAsset) bool {
		if a.BySeverity["critical"] != b.BySeverity["critical"] {
			return a.BySeverity["critical"] > b.BySeverity["critical"]
		}
		if a.BySeverity["high"] != b.BySeverity["high"] {
			return a.BySeverity["high"] > b.BySeverity["high"]
		}
		if a.Open != b.Open {
			return a.Open > b.Open
		}
		return a.AssetID.String() < b.AssetID.String()
	}
	for i := 1; i < len(items); i++ {
		for j := i; j > 0 && less(items[j], items[j-1]); j-- {
			items[j], items[j-1] = items[j-1], items[j]
		}
	}
}

// RegisterVEX builds one OpenVEX document from the current register state of
// every vulnerability and malicious-dependency entry the filter admits.
func (s *Store) RegisterVEX(ctx context.Context, filter RegisterFilter) (json.RawMessage, error) {
	clause, args := filter.where(1)
	rows, err := s.pool.Query(ctx, `SELECT f.advisory_id,f.component,f.guidance,`+effectiveStatus+`,f.waiver_until,COALESCE((SELECT e.details->>'reason' FROM `+s.schema+`.finding_events e WHERE e.finding_id=f.id AND e.action='status_changed' ORDER BY e.id DESC LIMIT 1),'') FROM `+s.schema+`.findings f WHERE f.type IN ('vulnerability','malicious_dependency')`+clause+` ORDER BY f.advisory_id,f.component->>'purl',f.id LIMIT 50001`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	statements := []map[string]any{}
	for rows.Next() {
		var advisory, status, reason string
		var component, guidanceRaw []byte
		var until *time.Time
		if err := rows.Scan(&advisory, &component, &guidanceRaw, &status, &until, &reason); err != nil {
			return nil, err
		}
		if len(statements) == 50000 {
			return nil, ErrInput
		}
		var c Component
		if err := json.Unmarshal(component, &c); err != nil {
			return nil, err
		}
		statements = append(statements, vexStatement(advisory, c.PURL, guidanceRaw, status, reason, until))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"@context":   "https://openvex.dev/ns/v0.2.0",
		"@id":        notify.Link("/register/vex"),
		"author":     "SCRS",
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"version":    1,
		"tooling":    "SCRS register export",
		"statements": statements,
	})
}
