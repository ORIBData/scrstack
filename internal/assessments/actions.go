package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ActionsWorkflow is one workflow of a repository and what its run history
// shows (INT-014, INT-015).
type ActionsWorkflow struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Path         string `json:"path"`
	State        string `json:"state"`
	Runs         int    `json:"runs"`
	MinRun       int    `json:"min_run"`
	MaxRun       int    `json:"max_run"`
	Missing      []int  `json:"missing,omitempty"`
	MissingCount int    `json:"missing_count"`
}

// ActionsReading is what one read of GitHub's Actions API found.
type ActionsReading struct {
	Available     bool              `json:"available"`
	Reason        string            `json:"reason,omitempty"`
	Enabled       bool              `json:"enabled"`
	Workflows     []ActionsWorkflow `json:"workflows"`
	RunsTruncated bool              `json:"runs_truncated"`
}

// ActionsState is the last inventory kept for a repository asset.
type ActionsState struct {
	AssetID uuid.UUID `json:"asset_id"`
	ActionsReading
	// Error is why the last check failed outright (an outage, not a missing
	// permission); the other fields then show the last good reading.
	Error     string    `json:"error,omitempty"`
	CheckedAt time.Time `json:"checked_at"`
}

func actionsSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.asset_actions(asset_id uuid PRIMARY KEY REFERENCES ` + s + `.assets(id),available boolean NOT NULL DEFAULT false,reason text NOT NULL DEFAULT '',enabled boolean NOT NULL DEFAULT false,workflows jsonb NOT NULL DEFAULT '[]',runs_truncated boolean NOT NULL DEFAULT false,digest text NOT NULL DEFAULT '',error text NOT NULL DEFAULT '',checked_at timestamptz NOT NULL DEFAULT clock_timestamp())`,
	}
}

// ActionsState returns the last inventory of an asset.
func (s *Store) ActionsState(ctx context.Context, asset uuid.UUID) (ActionsState, error) {
	var st ActionsState
	var workflows []byte
	err := s.pool.QueryRow(ctx, `SELECT asset_id,available,reason,enabled,workflows,runs_truncated,error,checked_at FROM `+s.schema+`.asset_actions WHERE asset_id=$1`, asset).Scan(&st.AssetID, &st.Available, &st.Reason, &st.Enabled, &workflows, &st.RunsTruncated, &st.Error, &st.CheckedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return ActionsState{}, ErrNotFound
	}
	if err != nil {
		return ActionsState{}, err
	}
	if err := json.Unmarshal(workflows, &st.Workflows); err != nil {
		return ActionsState{}, err
	}
	if st.Workflows == nil {
		st.Workflows = []ActionsWorkflow{}
	}
	return st, nil
}

// ActionsTarget is a repository due for an Actions check.
type ActionsTarget struct {
	AssetID    uuid.UUID
	Locator    string
	Connection string
}

// ActionsDue lists in-scope GitHub repositories whose Actions inventory is
// missing or older than interval, the least recently checked first.
func (s *Store) ActionsDue(ctx context.Context, interval time.Duration, limit int) ([]ActionsTarget, error) {
	rows, err := s.pool.Query(ctx, `SELECT a.id,a.locator,c.name FROM `+s.schema+`.assets a JOIN `+s.schema+`.connections c ON c.id=a.connection_id LEFT JOIN `+s.schema+`.asset_actions x ON x.asset_id=a.id WHERE a.type='github_repo' AND c.provider='github' AND c.enabled AND a.flags->>'in_scope'='true' AND a.flags->>'accessible'='true' AND (x.asset_id IS NULL OR x.checked_at<clock_timestamp()-($1*interval '1 second')) ORDER BY x.checked_at NULLS FIRST,a.locator LIMIT $2`, int64(interval.Seconds()), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ActionsTarget
	for rows.Next() {
		var t ActionsTarget
		if err := rows.Scan(&t.AssetID, &t.Locator, &t.Connection); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RecordActionsError notes that a check failed outright, keeping the last
// good reading, so a failing repository is not retried on every pass.
func (s *Store) RecordActionsError(ctx context.Context, asset uuid.UUID, message string) error {
	if len(message) > 300 {
		message = message[:300]
	}
	_, err := s.pool.Exec(ctx, `INSERT INTO `+s.schema+`.asset_actions(asset_id,error) VALUES($1,$2) ON CONFLICT(asset_id) DO UPDATE SET error=EXCLUDED.error,checked_at=clock_timestamp()`, asset, message)
	return err
}

// RecordActions stores a reading and raises what it shows: `actions_unused`
// on the asset (INT-014), a low entry when the workflow list changed since
// the last reading, and a medium entry for run-number holes (INT-015), high
// when another integrity entry for the asset is open and recent. A hole that
// was already reported does not raise again.
func (s *Store) RecordActions(ctx context.Context, asset uuid.UUID, repository string, r ActionsReading) (ActionsState, error) {
	if r.Workflows == nil {
		r.Workflows = []ActionsWorkflow{}
	}
	paths := make([]string, 0, len(r.Workflows))
	states := map[string]string{}
	for _, w := range r.Workflows {
		paths = append(paths, w.Path)
		states[w.Path] = w.State
	}
	sort.Strings(paths)
	var lines []string
	for _, p := range paths {
		lines = append(lines, p+"|"+states[p])
	}
	digest := Hash([]byte(strings.Join(lines, "\n")))
	workflows, _ := json.Marshal(r.Workflows)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return ActionsState{}, err
	}
	defer tx.Rollback(ctx)
	var hadRow, wasAvailable bool
	var previousDigest string
	var previousWorkflows []byte
	err = tx.QueryRow(ctx, `SELECT true,available,digest,workflows FROM `+s.schema+`.asset_actions WHERE asset_id=$1 FOR UPDATE`, asset).Scan(&hadRow, &wasAvailable, &previousDigest, &previousWorkflows)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return ActionsState{}, err
	}
	// A reading that could not see Actions keeps the last good inventory.
	if !r.Available {
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.asset_actions(asset_id,available,reason) VALUES($1,false,$2) ON CONFLICT(asset_id) DO UPDATE SET available=false,reason=EXCLUDED.reason,error='',checked_at=clock_timestamp()`, asset, r.Reason); err != nil {
			return ActionsState{}, err
		}
		if err := tx.Commit(ctx); err != nil {
			return ActionsState{}, err
		}
		return s.ActionsState(ctx, asset)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.asset_actions(asset_id,available,reason,enabled,workflows,runs_truncated,digest) VALUES($1,true,'',$2,$3,$4,$5) ON CONFLICT(asset_id) DO UPDATE SET available=true,reason='',enabled=EXCLUDED.enabled,workflows=EXCLUDED.workflows,runs_truncated=EXCLUDED.runs_truncated,digest=EXCLUDED.digest,error='',checked_at=clock_timestamp()`, asset, r.Enabled, workflows, r.RunsTruncated, digest); err != nil {
		return ActionsState{}, err
	}
	unused := !r.Enabled || len(r.Workflows) == 0
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.assets SET flags=flags || jsonb_build_object('actions_unused',$2::boolean) WHERE id=$1`, asset, unused); err != nil {
		return ActionsState{}, err
	}
	var related bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.findings WHERE asset_id=$1 AND type='integrity' AND status IN ('open','triaged','in_progress') AND severity IN ('critical','high','medium') AND last_seen>clock_timestamp()-interval '7 days' AND advisory_id NOT IN ('SCRS-EVENT-RUN-NUMBER-GAP','SCRS-EVENT-ACTIONS-WORKFLOWS-CHANGED'))`, asset).Scan(&related); err != nil {
		return ActionsState{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return ActionsState{}, err
	}

	var events []IntegrityEvent
	var deliveries []string
	if hadRow && wasAvailable && previousDigest != digest {
		var before []ActionsWorkflow
		_ = json.Unmarshal(previousWorkflows, &before)
		known := map[string]bool{}
		for _, w := range before {
			known[w.Path] = true
		}
		current := map[string]bool{}
		var added, removed []string
		for _, w := range r.Workflows {
			current[w.Path] = true
			if !known[w.Path] {
				added = append(added, w.Path)
			}
		}
		for _, w := range before {
			if !current[w.Path] {
				removed = append(removed, w.Path)
			}
		}
		events = append(events, IntegrityEvent{Kind: "actions_workflows_changed", Severity: "low", Title: "The repository's workflow list changed", Repository: repository, Details: map[string]any{"added": added, "removed": removed, "workflows": len(r.Workflows)}})
		deliveries = append(deliveries, "actions-list-"+asset.String()+"-"+digest[:16])
	}
	for _, w := range r.Workflows {
		if w.MissingCount == 0 {
			continue
		}
		severity := "medium"
		if related {
			severity = "high"
		}
		events = append(events, IntegrityEvent{Kind: "run_number_gap", Severity: severity, Title: "Workflow run numbers are missing", Repository: repository, Details: map[string]any{"workflow": w.Path, "missing": w.Missing, "missing_count": w.MissingCount, "min_run": w.MinRun, "max_run": w.MaxRun, "combined_with_other_signal": related}})
		deliveries = append(deliveries, "actions-gap-"+asset.String()+"-"+Hash([]byte(fmt.Sprint(w.Path, w.Missing, w.MissingCount)))[:16])
	}
	for i, e := range events {
		raw, _ := json.Marshal(map[string]any{"repository": repository, "kind": e.Kind, "details": e.Details})
		if _, err := s.RecordIntegrity(ctx, deliveries[i], SchedulerActor, raw, "scheduled", "actions_sweep", []IntegrityEvent{e}); err != nil {
			return ActionsState{}, err
		}
	}
	return s.ActionsState(ctx, asset)
}
