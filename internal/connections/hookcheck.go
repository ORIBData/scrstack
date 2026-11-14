package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// HookAPI is the GitHub side of the delivery check; NativeAdapters implements it.
type HookAPI interface {
	GitHubHooks(context.Context, Connection, json.RawMessage, string, time.Time) ([]GitHubHook, error)
	RedeliverGitHub(context.Context, Connection, json.RawMessage, GitHubHook, int64) error
}

// HookCheck is the latest delivery check of one GitHub connection.
type HookCheck struct {
	ConnectionID uuid.UUID `json:"connection_id"`
	Connection   string    `json:"connection"`
	Source       string    `json:"source"`
	State        string    `json:"state"` // unchecked, ok, degraded, failed
	CheckedAt    time.Time `json:"checked_at"`
	// LastSuccess anchors the next window, so failed checks lose no deliveries.
	LastSuccess time.Time `json:"last_success_at"`
	WindowStart time.Time `json:"window_start"`
	Hooks       int       `json:"hooks"`
	Deliveries  int       `json:"deliveries_scanned"`
	Redelivered int       `json:"redelivered"`
	Retrying    int       `json:"retrying"`
	Abandoned   int       `json:"abandoned"`
	Rejected    int       `json:"rejected"`
	Problems    []string  `json:"problems"`
}

const (
	maxRedeliveriesPerRun = 50
	maxRedeliveryAttempts = 5
	// The window overlaps the previous check so late-listed attempts are seen.
	hookCheckOverlap = 15 * time.Minute
)

// hookEvents are the GitHub events SCRS acts on. Others are acknowledged with
// 200, so a failure there loses nothing and is not redelivered.
var hookEvents = map[string]bool{"push": true, "pull_request": true, "delete": true, "create": true, "repository": true, "member": true, "organization": true}

// retryableDelivery reports failures redelivery can fix: timeouts and
// connection errors (0), throttling and server errors. Other 4xx answers mean
// a configuration problem (for example a wrong secret) and are reported.
func retryableDelivery(code int) bool {
	return code == 0 || code == 408 || code == 429 || code >= 500
}

// redeliveryDue backs off 5, 10, 20 and 40 minutes between attempts.
func redeliveryDue(attempts int, last *time.Time, now time.Time) bool {
	return attempts == 0 || last == nil || now.Sub(*last) >= (5*time.Minute)<<(attempts-1)
}

// CheckGitHubHooks reads each enabled GitHub connection's webhook delivery log,
// requests redelivery of failed events with backoff, and records the result.
// One replica runs it at a time; ran is false when another holds the lock.
func (s *Store) CheckGitHubHooks(ctx context.Context, api HookAPI, hookURL string, now time.Time) (checks []HookCheck, ran bool, err error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	defer tx.Rollback(ctx)
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtext($1))`, s.schema+".github_hook_check").Scan(&ran); err != nil || !ran {
		return nil, false, err
	}
	rows, err := tx.Query(ctx, `SELECT name,webhook_check FROM `+s.schema+`.connections WHERE provider='github' AND enabled ORDER BY name`)
	if err != nil {
		return nil, true, err
	}
	previous := map[string]HookCheck{}
	var names []string
	for rows.Next() {
		var name string
		var raw []byte
		if err := rows.Scan(&name, &raw); err != nil {
			rows.Close()
			return nil, true, err
		}
		var p HookCheck
		_ = json.Unmarshal(raw, &p)
		previous[name] = p
		names = append(names, name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, true, err
	}
	for _, name := range names {
		c, secret, err := s.Get(ctx, name)
		check, abandoned := HookCheck{ConnectionID: c.ID, Connection: name, State: "failed", CheckedAt: now, LastSuccess: previous[name].LastSuccess, Problems: []string{clipProblem(fmt.Sprint(err))}}, []abandonedDelivery(nil)
		if err == nil {
			if check, abandoned, err = s.checkConnection(ctx, tx, api, c, secret, hookURL, previous[name], now); err != nil {
				return nil, true, err
			}
		}
		if err := s.recordHookCheck(ctx, tx, c, check, previous[name], abandoned); err != nil {
			return nil, true, err
		}
		checks = append(checks, check)
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.github_redeliveries WHERE status<>'retrying' AND updated_at<$1`, now.Add(-7*24*time.Hour)); err != nil {
		return nil, true, err
	}
	return checks, true, tx.Commit(ctx)
}

type abandonedDelivery struct {
	GUID  string `json:"guid"`
	Event string `json:"event"`
}

func (s *Store) checkConnection(ctx context.Context, tx pgx.Tx, api HookAPI, c Connection, secret json.RawMessage, hookURL string, prev HookCheck, now time.Time) (HookCheck, []abandonedDelivery, error) {
	cfg, _ := parseGitHub(c, secret)
	check := HookCheck{ConnectionID: c.ID, Connection: c.Name, Source: cfg.WebhookSource, State: "ok", CheckedAt: now, LastSuccess: prev.LastSuccess, Problems: []string{}}
	floor := now.Add(-HookDeliveryRetention)
	check.WindowStart = now.Add(-24 * time.Hour)
	if !prev.LastSuccess.IsZero() {
		check.WindowStart = prev.LastSuccess.Add(-hookCheckOverlap)
		if prev.LastSuccess.Before(floor) {
			check.Problems = append(check.Problems, "last successful check was more than 3 days ago; GitHub no longer holds older deliveries, so rescan repositories changed since "+prev.LastSuccess.UTC().Format(time.RFC3339))
		}
	}
	if check.WindowStart.Before(floor) {
		check.WindowStart = floor
	}
	hooks, err := api.GitHubHooks(ctx, c, secret, hookURL, check.WindowStart)
	if err != nil {
		check.State, check.Problems = "failed", append(check.Problems, clipProblem(err.Error()))
		return check, nil, nil
	}
	check.LastSuccess = now
	for _, hook := range hooks {
		if hook.ID > 0 {
			check.Hooks++
		}
		check.Problems = append(check.Problems, hook.Problems...)
		if hook.Truncated {
			check.Problems = append(check.Problems, "delivery log longer than the page limit; older failures in this window were not examined")
		}
		check.Deliveries += len(hook.Deliveries)
		rejected, err := s.recordDeliveries(ctx, tx, c.ID, hook, now)
		if err != nil {
			return check, nil, err
		}
		check.Rejected += len(rejected)
		for code, n := range rejected {
			check.Problems = append(check.Problems, fmt.Sprintf("%d deliveries rejected with HTTP %d and not redelivered; %s", n, code, rejectionHint(code)))
		}
	}
	abandoned, err := s.redeliver(ctx, tx, api, c, secret, &check, now)
	if err != nil {
		return check, nil, err
	}
	if len(abandoned) > 0 {
		check.Problems = append(check.Problems, fmt.Sprintf("%d events could not be redelivered; rescan the affected repositories and review their recent pushes", len(abandoned)))
	}
	if len(check.Problems) > 0 {
		check.State = "degraded"
	}
	return check, abandoned, nil
}

// recordDeliveries tracks failed events by GUID. An event any attempt of which
// succeeded is settled; a retryable failure starts retrying; any other answer
// is counted once by status code.
func (s *Store) recordDeliveries(ctx context.Context, tx pgx.Tx, connection uuid.UUID, hook GitHubHook, now time.Time) (map[int]int, error) {
	delivered := map[string]bool{}
	failed := map[string]HookDelivery{}
	for _, d := range hook.Deliveries {
		if !hookEvents[d.Event] || d.GUID == "" || len(d.GUID) > 64 {
			continue
		}
		if d.StatusCode >= 200 && d.StatusCode < 300 {
			delivered[d.GUID] = true
		} else if _, seen := failed[d.GUID]; !seen {
			failed[d.GUID] = d // newest failing attempt, as the log is newest first
		}
	}
	for guid := range delivered {
		if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.github_redeliveries SET status='delivered',updated_at=$3 WHERE connection_id=$1 AND guid=$2 AND status<>'delivered'`, connection, guid, now); err != nil {
			return nil, err
		}
	}
	rejected := map[int]int{}
	for guid, d := range failed {
		if delivered[guid] {
			continue
		}
		status := "retrying"
		if !retryableDelivery(d.StatusCode) {
			status = "rejected"
		}
		tag, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.github_redeliveries(connection_id,guid,hook_source,hook_id,delivery_id,event,status,status_code,first_failed_at,updated_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(connection_id,guid) DO NOTHING`, connection, guid, hook.Source, hook.ID, d.ID, d.Event, status, d.StatusCode, d.DeliveredAt, now)
		if err != nil {
			return nil, err
		}
		if status == "rejected" && tag.RowsAffected() == 1 {
			rejected[d.StatusCode]++
		}
	}
	return rejected, nil
}

// redeliver requests due redeliveries within the per-run budget. Events past
// GitHub's retention or the attempt limit are abandoned and returned.
func (s *Store) redeliver(ctx context.Context, tx pgx.Tx, api HookAPI, c Connection, secret json.RawMessage, check *HookCheck, now time.Time) ([]abandonedDelivery, error) {
	rows, err := tx.Query(ctx, `SELECT guid,hook_source,hook_id,delivery_id,event,attempts,first_failed_at,last_attempt_at FROM `+s.schema+`.github_redeliveries WHERE connection_id=$1 AND status='retrying' ORDER BY first_failed_at LIMIT 500`, c.ID)
	if err != nil {
		return nil, err
	}
	type pending struct {
		guid, source, event string
		hook, delivery      int64
		attempts            int
		first               time.Time
		last                *time.Time
	}
	var due []pending
	for rows.Next() {
		var p pending
		if err := rows.Scan(&p.guid, &p.source, &p.hook, &p.delivery, &p.event, &p.attempts, &p.first, &p.last); err != nil {
			rows.Close()
			return nil, err
		}
		due = append(due, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	var abandoned []abandonedDelivery
	failure := ""
	// GitHub refuses redelivery shortly before its retention ends.
	expiry := now.Add(-HookDeliveryRetention + time.Hour)
	for _, p := range due {
		if p.attempts >= maxRedeliveryAttempts || p.first.Before(expiry) {
			if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.github_redeliveries SET status='abandoned',updated_at=$3 WHERE connection_id=$1 AND guid=$2`, c.ID, p.guid, now); err != nil {
				return nil, err
			}
			abandoned = append(abandoned, abandonedDelivery{GUID: p.guid, Event: p.event})
			continue
		}
		if !redeliveryDue(p.attempts, p.last, now) || check.Redelivered >= maxRedeliveriesPerRun {
			check.Retrying++
			continue
		}
		if err := api.RedeliverGitHub(ctx, c, secret, GitHubHook{Source: p.source, ID: p.hook}, p.delivery); err != nil {
			failure = "redelivery request failed: " + err.Error()
		} else {
			check.Redelivered++
		}
		check.Retrying++
		if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.github_redeliveries SET attempts=attempts+1,last_attempt_at=$3,updated_at=$3 WHERE connection_id=$1 AND guid=$2`, c.ID, p.guid, now); err != nil {
			return nil, err
		}
	}
	check.Abandoned = len(abandoned)
	if failure != "" {
		check.Problems = append(check.Problems, clipProblem(failure))
	}
	return abandoned, nil
}

// recordHookCheck stores the result and alerts on a change to an unhealthy
// state, or whenever events were abandoned or newly rejected.
func (s *Store) recordHookCheck(ctx context.Context, tx pgx.Tx, c Connection, check, prev HookCheck, abandoned []abandonedDelivery) error {
	raw, _ := json.Marshal(check)
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.connections SET webhook_check=$2 WHERE id=$1`, c.ID, raw); err != nil {
		return err
	}
	if check.Redelivered > 0 || len(abandoned) > 0 {
		details, _ := json.Marshal(map[string]any{"redelivered": check.Redelivered, "abandoned": abandoned})
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('connection.webhook_redelivery',$1,$2)`, c.ID, details); err != nil {
			return err
		}
	}
	worsened := check.State != "ok" && (prev.State == "" || prev.State == "ok" || prev.State == "unchecked")
	if worsened || len(abandoned) > 0 || check.Rejected > 0 {
		data := map[string]any{"connection_id": c.ID, "name": c.Name, "provider": c.Provider, "check": "github_webhook_deliveries", "state": check.State, "problems": check.Problems, "abandoned": abandoned, "link": notify.Link("/system/github-webhooks")}
		if _, err := notify.Emit(ctx, tx, s.schema, "connection.degraded", data, nil); err != nil {
			return err
		}
	}
	return nil
}

// GitHubHookChecks returns the latest check of every GitHub connection.
func (s *Store) GitHubHookChecks(ctx context.Context) ([]HookCheck, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,webhook_check FROM `+s.schema+`.connections WHERE provider='github' ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	checks := []HookCheck{}
	for rows.Next() {
		var check HookCheck
		var id uuid.UUID
		var name string
		var raw []byte
		if err := rows.Scan(&id, &name, &raw); err != nil {
			return nil, err
		}
		if json.Unmarshal(raw, &check) != nil || check.State == "" {
			check = HookCheck{State: "unchecked", Problems: []string{}}
		}
		check.ConnectionID, check.Connection = id, name
		checks = append(checks, check)
	}
	return checks, rows.Err()
}

func rejectionHint(code int) string {
	switch code {
	case 401:
		return "the webhook secret in GitHub does not match SCRS_GITHUB_WEBHOOK_SECRET"
	case 413:
		return "the payload exceeded the 1 MiB receiver limit"
	case 400:
		return "the payload or delivery headers were invalid; check the content type is application/json"
	}
	return "check the webhook configuration and SCRS logs"
}

func clipProblem(s string) string {
	if len(s) > 300 {
		s = s[:300]
	}
	return strings.ToValidUTF8(s, "")
}
