package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Incident is a sweep of what a set of claimed actors touched in a time
// window (INT-018). The report is read-only evidence: SCRS never suspends an
// account, rotates a secret or restores code; that is for people or a runbook.
type Incident struct {
	ID        uuid.UUID `json:"id"`
	Title     string    `json:"title"`
	Actors    []string  `json:"actors"`
	Since     time.Time `json:"since"`
	Until     time.Time `json:"until"`
	CreatedBy string    `json:"created_by"`
	CreatedAt time.Time `json:"created_at"`
	// Report is what the sweep found, written once when the incident is
	// created; Reassessments carries the live state of the scans it queued.
	Report         IncidentReport     `json:"report"`
	Reassessments  []IncidentReassess `json:"reassessments"`
	ReassessCounts map[string]int     `json:"reassessment_counts,omitempty"`
	ActorsNote     string             `json:"actors_note"`
}

// IncidentTouch is one revision an actor triggered an assessment of.
type IncidentTouch struct {
	AssetID      uuid.UUID `json:"asset_id"`
	Locator      string    `json:"locator"`
	Ref          string    `json:"ref"`
	Commit       string    `json:"commit"`
	AssessmentID uuid.UUID `json:"assessment_id"`
	Verdict      string    `json:"verdict"`
	Actor        string    `json:"actor"`
	At           time.Time `json:"at"`
}

// IncidentSignal is an integrity event raised for one of the actors.
type IncidentSignal struct {
	Kind       string    `json:"kind"`
	Severity   string    `json:"severity"`
	Repository string    `json:"repository"`
	Ref        string    `json:"ref,omitempty"`
	Commit     string    `json:"commit,omitempty"`
	Actor      string    `json:"actor"`
	At         time.Time `json:"at"`
}

// IncidentRef is a branch or pull request an actor touched.
type IncidentRef struct {
	Repository string    `json:"repository"`
	Ref        string    `json:"ref,omitempty"`
	Number     int       `json:"number,omitempty"`
	Title      string    `json:"title,omitempty"`
	Event      string    `json:"event"`
	Actor      string    `json:"actor"`
	At         time.Time `json:"at"`
}

// IncidentChange is a workflow or install-hook entry found in a touched
// revision.
type IncidentChange struct {
	AssetID      uuid.UUID `json:"asset_id"`
	Locator      string    `json:"locator"`
	Commit       string    `json:"commit"`
	AssessmentID uuid.UUID `json:"assessment_id"`
	AdvisoryID   string    `json:"advisory_id"`
	Title        string    `json:"title"`
	Severity     string    `json:"severity"`
	Path         string    `json:"path,omitempty"`
}

// IncidentRecovery is where to restore each touched asset and ref from.
type IncidentRecovery struct {
	AssetID       uuid.UUID `json:"asset_id"`
	Locator       string    `json:"locator"`
	Ref           string    `json:"ref"`
	LastKnownGood *struct {
		Commit       string    `json:"commit"`
		AssessmentID uuid.UUID `json:"assessment_id"`
		At           time.Time `json:"at"`
	} `json:"last_known_good"`
	Mirrors []IncidentMirror `json:"mirrors"`
}

// IncidentMirror is a stored git bundle of an asset.
type IncidentMirror struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Head      string    `json:"head"`
	SizeBytes int64     `json:"size_bytes"`
}

// IncidentReport is the evidence a sweep collects. Each list is cut at
// IncidentListCap and `truncated` names the lists that were.
type IncidentReport struct {
	Touched      []IncidentTouch    `json:"touched"`
	Signals      []IncidentSignal   `json:"signals"`
	Branches     []IncidentRef      `json:"branches"`
	PullRequests []IncidentRef      `json:"pull_requests"`
	Changes      []IncidentChange   `json:"changes"`
	Recovery     []IncidentRecovery `json:"recovery"`
	Truncated    []string           `json:"truncated"`
}

// IncidentReassess is a scan the sweep queued, with its current state.
type IncidentReassess struct {
	AssessmentID uuid.UUID `json:"assessment_id"`
	AssetID      uuid.UUID `json:"asset_id"`
	Commit       string    `json:"commit"`
	Ref          string    `json:"ref"`
	Status       string    `json:"status"`
	Verdict      string    `json:"verdict"`
}

// IncidentRequest asks for a sweep.
type IncidentRequest struct {
	Title  string
	Actors []string
	Since  time.Time
	Until  time.Time
	// Reassess queues a fresh scan of each touched revision, at most
	// MaxReassess of them (default 50, at most 200).
	Reassess    bool
	MaxReassess int
}

// IncidentListCap bounds each list in a report.
const IncidentListCap = 500

// incidentWindow is the longest window a sweep may cover.
const incidentWindow = 366 * 24 * time.Hour

func incidentSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.incidents(id uuid PRIMARY KEY,title text NOT NULL DEFAULT '',actors text[] NOT NULL,since timestamptz NOT NULL,until timestamptz NOT NULL,created_by text NOT NULL,created_by_id uuid,created_at timestamptz NOT NULL DEFAULT clock_timestamp(),report jsonb NOT NULL DEFAULT '{}',reassessments jsonb NOT NULL DEFAULT '[]')`,
		`CREATE INDEX IF NOT EXISTS incidents_created_idx ON ` + s + `.incidents(created_at DESC,id)`,
	}
}

// CreateIncident sweeps what the actors touched, queues the re-assessments
// asked for, stores the report and returns the incident.
func (s *Store) CreateIncident(ctx context.Context, req IncidentRequest, creator uuid.UUID, createdBy string) (Incident, error) {
	var actors []string
	seen := map[string]bool{}
	for _, a := range req.Actors {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" || len(a) > 100 || strings.IndexFunc(a, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return Incident{}, ErrInput
		}
		if !seen[a] {
			seen[a] = true
			actors = append(actors, a)
		}
	}
	if len(actors) == 0 || len(actors) > 20 || len(req.Title) > 200 || req.Since.IsZero() || !req.Until.After(req.Since) || req.Until.Sub(req.Since) > incidentWindow {
		return Incident{}, ErrInput
	}
	if req.MaxReassess <= 0 {
		req.MaxReassess = 50
	}
	if req.MaxReassess > 200 {
		return Incident{}, ErrInput
	}
	report, targets, err := s.sweep(ctx, actors, req.Since, req.Until)
	if err != nil {
		return Incident{}, err
	}
	id := uuid.New()
	var queued []IncidentReassess
	if req.Reassess {
		for _, t := range targets {
			if len(queued) >= req.MaxReassess {
				report.Truncated = appendUnique(report.Truncated, "reassessments")
				break
			}
			request := Request{Target: Target{Type: "git", Repository: strings.ToLower(t.locator), Ref: t.ref, Commit: t.commit}, Connection: t.connection}
			request.Trigger.Origin, request.Trigger.Event = "incident", "incident.sweep"
			request.Trigger.Context = map[string]string{"incident": id.String()}
			a, _, err := s.Enqueue(ctx, request, SchedulerActor, "incident", "incident-"+id.String()+"-"+Hash([]byte(t.asset.String() + t.commit))[:16])
			if errors.Is(err, ErrCapacity) {
				report.Truncated = appendUnique(report.Truncated, "reassessments")
				break
			}
			if err != nil {
				continue // a revision that can no longer be fetched is reported, not retried
			}
			queued = append(queued, IncidentReassess{AssessmentID: a.ID, AssetID: t.asset, Commit: t.commit, Ref: t.ref, Status: string(a.Status), Verdict: a.Verdict})
		}
	}
	reportJSON, _ := json.Marshal(report)
	queuedJSON, _ := json.Marshal(queued)
	if queued == nil {
		queuedJSON = []byte("[]")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Incident{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.incidents(id,title,actors,since,until,created_by,created_by_id,report,reassessments) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, id, strings.TrimSpace(req.Title), actors, req.Since, req.Until, createdBy, nullUUID(creator), reportJSON, queuedJSON); err != nil {
		return Incident{}, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": creator, "actors": actors, "since": req.Since, "until": req.Until, "touched": len(report.Touched), "reassessments": len(queued)})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('incident.created',$1,$2)`, id, details); err != nil {
		return Incident{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return Incident{}, err
	}
	return s.Incident(ctx, id)
}

func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

type sweepTarget struct {
	asset                uuid.UUID
	locator, ref, commit string
	connection           string
}

// sweep collects the evidence for a set of actors in a window.
func (s *Store) sweep(ctx context.Context, actors []string, since, until time.Time) (IncidentReport, []sweepTarget, error) {
	report := IncidentReport{Touched: []IncidentTouch{}, Signals: []IncidentSignal{}, Branches: []IncidentRef{}, PullRequests: []IncidentRef{}, Changes: []IncidentChange{}, Recovery: []IncidentRecovery{}, Truncated: []string{}}
	cap := IncidentListCap + 1
	// Revisions the actors triggered a scan of: one row per asset and revision.
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ON (x.asset_id,COALESCE(NULLIF(x.resolved_commit,''),x.request->'target'->>'commit')) x.id,x.asset_id,a.locator,c.name,x.request->'target'->>'ref',COALESCE(NULLIF(x.resolved_commit,''),x.request->'target'->>'commit'),x.verdict,lower(x.request->'trigger'->>'actor'),x.created_at FROM `+s.schema+`.assessments x JOIN `+s.schema+`.assets a ON a.id=x.asset_id JOIN `+s.schema+`.connections c ON c.id=a.connection_id WHERE a.type IN ('github_repo','gitlab_repo') AND x.status='succeeded' AND x.request->'remediation' IS NULL AND x.request->'import' IS NULL AND lower(x.request->'trigger'->>'actor')=ANY($1) AND x.created_at>=$2 AND x.created_at<$3 AND COALESCE(NULLIF(x.resolved_commit,''),x.request->'target'->>'commit')<>'' ORDER BY x.asset_id,COALESCE(NULLIF(x.resolved_commit,''),x.request->'target'->>'commit'),x.created_at DESC LIMIT $4`, actors, since, until, cap)
	if err != nil {
		return report, nil, err
	}
	var targets []sweepTarget
	for rows.Next() {
		var t IncidentTouch
		var connection string
		if err := rows.Scan(&t.AssessmentID, &t.AssetID, &t.Locator, &connection, &t.Ref, &t.Commit, &t.Verdict, &t.Actor, &t.At); err != nil {
			rows.Close()
			return report, nil, err
		}
		report.Touched = append(report.Touched, t)
		targets = append(targets, sweepTarget{asset: t.AssetID, locator: t.Locator, ref: t.Ref, commit: t.Commit, connection: connection})
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return report, nil, err
	}
	sort.Slice(report.Touched, func(i, j int) bool { return report.Touched[i].At.After(report.Touched[j].At) })
	if len(report.Touched) > IncidentListCap {
		report.Touched, targets = report.Touched[:IncidentListCap], targets[:IncidentListCap]
		report.Truncated = append(report.Truncated, "touched")
	}
	// Integrity events raised for the actors (force pushes, deletions, new authors, campaign patterns).
	srows, err := s.pool.Query(ctx, `SELECT kind,severity,repository,ref,COALESCE(details->>'commit',''),lower(actor),created_at FROM `+s.schema+`.integrity_events WHERE lower(actor)=ANY($1) AND created_at>=$2 AND created_at<$3 ORDER BY created_at DESC LIMIT $4`, actors, since, until, cap)
	if err != nil {
		return report, nil, err
	}
	for srows.Next() {
		var e IncidentSignal
		if err := srows.Scan(&e.Kind, &e.Severity, &e.Repository, &e.Ref, &e.Commit, &e.Actor, &e.At); err != nil {
			srows.Close()
			return report, nil, err
		}
		report.Signals = append(report.Signals, e)
	}
	srows.Close()
	if err := srows.Err(); err != nil {
		return report, nil, err
	}
	if len(report.Signals) > IncidentListCap {
		report.Signals = report.Signals[:IncidentListCap]
		report.Truncated = append(report.Truncated, "signals")
	}
	// Branches and pull requests, from the stored deliveries (still within retention).
	brows, err := s.pool.Query(ctx, `SELECT event_type,lower(COALESCE(body->'repository'->>'full_name',body->'project'->>'path_with_namespace','')),COALESCE(body->>'ref',''),COALESCE((body->'pull_request'->>'number')::int,0),COALESCE(body->'pull_request'->>'title',''),COALESCE(body->'pull_request'->'head'->>'ref',''),lower(COALESCE(NULLIF(body->'pusher'->>'name',''),body->'sender'->>'login',body->'trigger'->>'actor','')),created_at FROM `+s.schema+`.inbound_events WHERE event_type IN ('push','create','delete','pull_request') AND lower(COALESCE(NULLIF(body->'pusher'->>'name',''),body->'sender'->>'login',body->'trigger'->>'actor',''))=ANY($1) AND created_at>=$2 AND created_at<$3 ORDER BY created_at DESC LIMIT $4`, actors, since, until, cap*2)
	if err != nil {
		return report, nil, err
	}
	branchSeen, prSeen := map[string]bool{}, map[string]bool{}
	for brows.Next() {
		var event, repo, ref, title, head, actor string
		var number int
		var at time.Time
		if err := brows.Scan(&event, &repo, &ref, &number, &title, &head, &actor, &at); err != nil {
			brows.Close()
			return report, nil, err
		}
		if event == "pull_request" {
			key := repo + "#" + strconv.Itoa(number)
			if prSeen[key] || number == 0 {
				continue
			}
			prSeen[key] = true
			report.PullRequests = append(report.PullRequests, IncidentRef{Repository: repo, Ref: head, Number: number, Title: title, Event: event, Actor: actor, At: at})
			continue
		}
		key := repo + "\x00" + ref + "\x00" + event
		if ref == "" || branchSeen[key] {
			continue
		}
		branchSeen[key] = true
		report.Branches = append(report.Branches, IncidentRef{Repository: repo, Ref: ref, Event: event, Actor: actor, At: at})
	}
	brows.Close()
	if err := brows.Err(); err != nil {
		return report, nil, err
	}
	if len(report.Branches) > IncidentListCap {
		report.Branches = report.Branches[:IncidentListCap]
		report.Truncated = append(report.Truncated, "branches")
	}
	if len(report.PullRequests) > IncidentListCap {
		report.PullRequests = report.PullRequests[:IncidentListCap]
		report.Truncated = append(report.Truncated, "pull_requests")
	}
	// Workflow and install-hook entries seen in the touched revisions.
	if len(report.Touched) > 0 {
		ids := make([]uuid.UUID, len(report.Touched))
		for i, t := range report.Touched {
			ids[i] = t.AssessmentID
		}
		crows, err := s.pool.Query(ctx, `SELECT x.asset_id,a.locator,COALESCE(NULLIF(x.resolved_commit,''),x.request->'target'->>'commit'),x.id,af.snapshot->>'advisory_id',af.snapshot->>'title',af.snapshot->>'severity',COALESCE(af.snapshot->'component'->>'path','') FROM `+s.schema+`.assessment_findings af JOIN `+s.schema+`.assessments x ON x.id=af.assessment_id JOIN `+s.schema+`.assets a ON a.id=x.asset_id WHERE af.assessment_id=ANY($1) AND af.snapshot->>'advisory_id' IN ('SCRS-WORKFLOW-CHANGE','SCRS-WORKFLOW-SECRETS','SCRS-INSTALL-HOOK','SCRS-HIDDEN-CI-HELPER','SCRS-REMOTE-EXEC','SCRS-CI-FILE-GROWTH','SCRS-LARGE-NEW-FILE') ORDER BY x.created_at DESC LIMIT $2`, ids, cap)
		if err != nil {
			return report, nil, err
		}
		for crows.Next() {
			var c IncidentChange
			if err := crows.Scan(&c.AssetID, &c.Locator, &c.Commit, &c.AssessmentID, &c.AdvisoryID, &c.Title, &c.Severity, &c.Path); err != nil {
				crows.Close()
				return report, nil, err
			}
			report.Changes = append(report.Changes, c)
		}
		crows.Close()
		if err := crows.Err(); err != nil {
			return report, nil, err
		}
		if len(report.Changes) > IncidentListCap {
			report.Changes = report.Changes[:IncidentListCap]
			report.Truncated = append(report.Truncated, "changes")
		}
	}
	// Where to restore from: the last known good revision and the newest mirrors, per touched asset and ref.
	done := map[string]bool{}
	for _, t := range report.Touched {
		key := t.AssetID.String() + "\x00" + t.Ref
		if done[key] || len(report.Recovery) >= 100 {
			continue
		}
		done[key] = true
		recovery := IncidentRecovery{AssetID: t.AssetID, Locator: t.Locator, Ref: t.Ref, Mirrors: []IncidentMirror{}}
		if good, err := s.LastKnownGood(ctx, t.AssetID, t.Ref); err == nil {
			recovery.LastKnownGood = &struct {
				Commit       string    `json:"commit"`
				AssessmentID uuid.UUID `json:"assessment_id"`
				At           time.Time `json:"at"`
			}{Commit: good.Commit, AssessmentID: good.ID, At: good.CreatedAt}
		} else if !errors.Is(err, pgx.ErrNoRows) && !errors.Is(err, ErrNotFound) {
			return report, nil, err
		}
		if mirrors, err := s.Mirrors(ctx, t.AssetID); err == nil {
			for _, m := range mirrors {
				if m.Status == "succeeded" && len(recovery.Mirrors) < 5 {
					recovery.Mirrors = append(recovery.Mirrors, IncidentMirror{ID: m.ID, CreatedAt: m.CreatedAt, Head: m.Head, SizeBytes: m.SizeBytes})
				}
			}
		}
		report.Recovery = append(report.Recovery, recovery)
	}
	return report, targets, nil
}

// Incident returns one incident with the live state of its re-assessments.
func (s *Store) Incident(ctx context.Context, id uuid.UUID) (Incident, error) {
	var in Incident
	var report, queued []byte
	err := s.pool.QueryRow(ctx, `SELECT id,title,actors,since,until,created_by,created_at,report,reassessments FROM `+s.schema+`.incidents WHERE id=$1`, id).Scan(&in.ID, &in.Title, &in.Actors, &in.Since, &in.Until, &in.CreatedBy, &in.CreatedAt, &report, &queued)
	if errors.Is(err, pgx.ErrNoRows) {
		return Incident{}, ErrNotFound
	}
	if err != nil {
		return Incident{}, err
	}
	if err := json.Unmarshal(report, &in.Report); err != nil {
		return Incident{}, err
	}
	if err := json.Unmarshal(queued, &in.Reassessments); err != nil {
		return Incident{}, err
	}
	if in.Reassessments == nil {
		in.Reassessments = []IncidentReassess{}
	}
	in.ActorsNote = "Actors are the identities named in provider events and in trigger.actor: claims, not verified identities."
	if len(in.Reassessments) > 0 {
		ids := make([]uuid.UUID, len(in.Reassessments))
		for i, r := range in.Reassessments {
			ids[i] = r.AssessmentID
		}
		rows, err := s.pool.Query(ctx, `SELECT id,status,verdict FROM `+s.schema+`.assessments WHERE id=ANY($1)`, ids)
		if err != nil {
			return Incident{}, err
		}
		live := map[uuid.UUID][2]string{}
		for rows.Next() {
			var rid uuid.UUID
			var status, verdict string
			if err := rows.Scan(&rid, &status, &verdict); err != nil {
				rows.Close()
				return Incident{}, err
			}
			live[rid] = [2]string{status, verdict}
		}
		rows.Close()
		in.ReassessCounts = map[string]int{}
		for i := range in.Reassessments {
			if v, ok := live[in.Reassessments[i].AssessmentID]; ok {
				in.Reassessments[i].Status, in.Reassessments[i].Verdict = v[0], v[1]
			}
			in.ReassessCounts[in.Reassessments[i].Status]++
		}
	}
	return in, nil
}

// Incidents lists incidents newest first, without their reports.
func (s *Store) Incidents(ctx context.Context, beforeAt *time.Time, beforeID uuid.UUID, limit int) ([]Incident, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	rows, err := s.pool.Query(ctx, `SELECT id,title,actors,since,until,created_by,created_at FROM `+s.schema+`.incidents WHERE ($1::timestamptz IS NULL OR (created_at,id)<($1,$2)) ORDER BY created_at DESC,id DESC LIMIT $3`, beforeAt, beforeID, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Incident{}
	for rows.Next() {
		var in Incident
		if err := rows.Scan(&in.ID, &in.Title, &in.Actors, &in.Since, &in.Until, &in.CreatedBy, &in.CreatedAt); err != nil {
			return nil, err
		}
		in.Reassessments = []IncidentReassess{}
		out = append(out, in)
	}
	return out, rows.Err()
}
