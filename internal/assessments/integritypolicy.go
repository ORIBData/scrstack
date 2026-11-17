package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// IntegrityPolicy switches on the behavioural and size signals of INT-003 and
// INT-012. Every one is off until an admin enables it: each can flag ordinary
// work (a new contributor, a late push, a generated file), so they raise
// medium or low entries for review rather than blocking anything.
type IntegrityPolicy struct {
	Revision int64 `json:"revision"`
	// AuthorNewDays flags a commit author not seen in a repository for that
	// many days, or never; 0 turns it off.
	AuthorNewDays int `json:"author_new_days"`
	// OffHours flags a push at an hour the author rarely pushes at, once the
	// author has at least MinHistoryPushes recorded pushes.
	OffHours bool `json:"off_hours"`
	// PusherDiffers flags a push whose pusher is not the commit author.
	PusherDiffers bool `json:"pusher_differs"`
	// LargeFileBytes flags a file above this size that is new since the
	// previous scan of the ref; 0 turns it off.
	LargeFileBytes int64 `json:"large_file_bytes"`
	// CIGrowthBytes flags a CI or build file that grew by more than this many
	// bytes since the previous scan of the ref; 0 turns it off.
	CIGrowthBytes int64      `json:"ci_growth_bytes"`
	UpdatedAt     *time.Time `json:"updated_at"`
}

// MinHistoryPushes is how many pushes an author needs before a push time can
// be called unusual.
const MinHistoryPushes = 20

// maxIntegrityBytes bounds the size settings (1 GiB).
const maxIntegrityBytes = 1 << 30

func integritySchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.integrity_policy(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),revision bigint NOT NULL DEFAULT 1,author_new_days integer NOT NULL DEFAULT 0 CHECK(author_new_days BETWEEN 0 AND 3650),off_hours boolean NOT NULL DEFAULT false,pusher_differs boolean NOT NULL DEFAULT false,large_file_bytes bigint NOT NULL DEFAULT 0 CHECK(large_file_bytes BETWEEN 0 AND 1073741824),ci_growth_bytes bigint NOT NULL DEFAULT 0 CHECK(ci_growth_bytes BETWEEN 0 AND 1073741824),updated_at timestamptz,updated_by uuid)`,
		`INSERT INTO ` + s + `.integrity_policy(singleton) VALUES(true) ON CONFLICT DO NOTHING`,
		// What each author has done in each repository, so a change in behaviour can be seen.
		// Hours are UTC pushes per hour of day; first_push_commit is the head the first observed push left.
		`CREATE TABLE IF NOT EXISTS ` + s + `.integrity_authors(repository text NOT NULL,author text NOT NULL,first_seen_at timestamptz NOT NULL,last_seen_at timestamptz NOT NULL,pushes integer NOT NULL DEFAULT 0,hours integer[] NOT NULL DEFAULT '{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}',first_push_commit text NOT NULL DEFAULT '',PRIMARY KEY(repository,author))`,
	}
}

// IntegrityPolicy returns the current settings.
func (s *Store) IntegrityPolicy(ctx context.Context) (IntegrityPolicy, error) {
	return s.integrityPolicy(ctx, s.pool)
}

type rowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func (s *Store) integrityPolicy(ctx context.Context, q rowQuerier) (IntegrityPolicy, error) {
	var p IntegrityPolicy
	err := q.QueryRow(ctx, `SELECT revision,author_new_days,off_hours,pusher_differs,large_file_bytes,ci_growth_bytes,updated_at FROM `+s.schema+`.integrity_policy WHERE singleton`).Scan(&p.Revision, &p.AuthorNewDays, &p.OffHours, &p.PusherDiffers, &p.LargeFileBytes, &p.CIGrowthBytes, &p.UpdatedAt)
	return p, err
}

// SetIntegrityPolicy replaces the settings when expected is the current
// revision (ErrConflict otherwise). It is audited.
func (s *Store) SetIntegrityPolicy(ctx context.Context, expected int64, p IntegrityPolicy, actor uuid.UUID) (IntegrityPolicy, error) {
	if p.AuthorNewDays < 0 || p.AuthorNewDays > 3650 || p.LargeFileBytes < 0 || p.LargeFileBytes > maxIntegrityBytes || p.CIGrowthBytes < 0 || p.CIGrowthBytes > maxIntegrityBytes {
		return IntegrityPolicy{}, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return IntegrityPolicy{}, err
	}
	defer tx.Rollback(ctx)
	var locked bool
	err = tx.QueryRow(ctx, `SELECT true FROM `+s.schema+`.integrity_policy WHERE singleton AND revision=$1 FOR UPDATE`, expected).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return IntegrityPolicy{}, ErrConflict
	}
	if err != nil {
		return IntegrityPolicy{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.integrity_policy SET author_new_days=$1,off_hours=$2,pusher_differs=$3,large_file_bytes=$4,ci_growth_bytes=$5,revision=revision+1,updated_at=clock_timestamp(),updated_by=$6 WHERE singleton`, p.AuthorNewDays, p.OffHours, p.PusherDiffers, p.LargeFileBytes, p.CIGrowthBytes, nullUUID(actor)); err != nil {
		return IntegrityPolicy{}, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "previous_revision": expected, "author_new_days": p.AuthorNewDays, "off_hours": p.OffHours, "pusher_differs": p.PusherDiffers, "large_file_bytes": p.LargeFileBytes, "ci_growth_bytes": p.CIGrowthBytes})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('integrity_policy.updated',$1)`, details); err != nil {
		return IntegrityPolicy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return IntegrityPolicy{}, err
	}
	return s.IntegrityPolicy(ctx)
}

// AuthoredCommit is what a push event says about one commit.
type AuthoredCommit struct {
	// Author is the commit author's login when the provider gives one, else
	// the lower-cased email address.
	Author string
	// Login is the author's login alone; empty when only an email is known.
	Login string
	At    time.Time
	// Routine marks commits that say nothing about the pusher's identity:
	// merges and commits made by the host itself (a web merge).
	Routine bool
}

// PushObservation is one push, for author-behaviour signals.
type PushObservation struct {
	Repository string
	Ref        string
	// Commit is the head the push left, the revision a scan will assess.
	Commit        string
	Pusher        string
	DefaultBranch bool
	Commits       []AuthoredCommit
}

// ObservePush records who pushed and returns the behavioural signals the
// policy asks for (INT-003). Observation is always recorded, even with every
// signal off, so enabling one later has history to compare with. A repository
// with no recorded authors yet only gets a baseline, never a signal: every
// author would otherwise look new.
func (s *Store) ObservePush(ctx context.Context, o PushObservation) ([]IntegrityEvent, error) {
	repository := strings.ToLower(o.Repository)
	if repository == "" || len(o.Commits) == 0 {
		return nil, nil
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)
	policy, err := s.integrityPolicy(ctx, tx)
	if err != nil {
		return nil, err
	}
	var known bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.integrity_authors WHERE repository=$1)`, repository).Scan(&known); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var fresh, offHours, differs []string
	seen := map[string]bool{}
	for _, c := range o.Commits {
		author := strings.ToLower(strings.TrimSpace(c.Author))
		if author == "" || seen[author] {
			continue
		}
		seen[author] = true
		at := c.At
		if at.IsZero() {
			at = now
		}
		var last time.Time
		var pushes int
		var hours []int32
		err := tx.QueryRow(ctx, `SELECT last_seen_at,pushes,hours FROM `+s.schema+`.integrity_authors WHERE repository=$1 AND author=$2 FOR UPDATE`, repository, author).Scan(&last, &pushes, &hours)
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
		if known {
			if policy.AuthorNewDays > 0 && (!exists || now.Sub(last) > time.Duration(policy.AuthorNewDays)*24*time.Hour) {
				fresh = append(fresh, author)
			}
			if policy.OffHours && exists && pushes >= MinHistoryPushes && len(hours) == 24 && int(hours[at.UTC().Hour()])*20 < pushes {
				offHours = append(offHours, author)
			}
		}
		if policy.PusherDiffers && !c.Routine && c.Login != "" && o.Pusher != "" && !strings.EqualFold(c.Login, o.Pusher) {
			differs = append(differs, author)
		}
		if exists {
			if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.integrity_authors SET last_seen_at=$3,pushes=pushes+1,hours[$4]=hours[$4]+1 WHERE repository=$1 AND author=$2`, repository, author, now, at.UTC().Hour()+1); err != nil {
				return nil, err
			}
			continue
		}
		hist := make([]int32, 24)
		hist[at.UTC().Hour()] = 1
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.integrity_authors(repository,author,first_seen_at,last_seen_at,pushes,hours,first_push_commit) VALUES($1,$2,$3,$3,1,$4,$5)`, repository, author, now, hist, o.Commit); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	event := func(kind, title, severity string, authors []string, details map[string]any) IntegrityEvent {
		if details == nil {
			details = map[string]any{}
		}
		details["authors"] = authors
		return IntegrityEvent{Kind: kind, Severity: severity, Title: title, Repository: o.Repository, Ref: o.Ref, Commit: o.Commit, Actor: o.Pusher, Details: details}
	}
	var out []IntegrityEvent
	if len(fresh) > 0 {
		severity := "medium"
		if o.DefaultBranch {
			severity = "high"
		}
		out = append(out, event("author_new", "Commit author not seen recently in this repository", severity, fresh, map[string]any{"quiet_days": policy.AuthorNewDays}))
	}
	if len(offHours) > 0 {
		out = append(out, event("author_off_hours", "Push at an hour the author rarely pushes at", "low", offHours, map[string]any{"min_history_pushes": MinHistoryPushes}))
	}
	if len(differs) > 0 {
		out = append(out, event("pusher_differs_from_author", "Pusher is not the commit author", "low", differs, nil))
	}
	return out, nil
}

// FirstTimeAuthor reports whether the pusher's first push to the repository
// left this commit as its head, so the scan of that commit is a first-time
// author's push.
func (s *Store) firstTimeAuthor(ctx context.Context, q rowQuerier, repository, actor, commit string) bool {
	if actor == "" || commit == "" {
		return false
	}
	var first bool
	err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.integrity_authors WHERE repository=$1 AND author=$2 AND first_push_commit=$3)`, strings.ToLower(repository), strings.ToLower(actor), commit).Scan(&first)
	return err == nil && first
}

// ciFile reports whether a path is a CI or build definition, the files whose
// growth INT-012 watches.
func ciFile(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	switch {
	case strings.HasPrefix(lower, ".github/workflows/"), strings.HasPrefix(lower, ".circleci/"), strings.HasPrefix(lower, ".buildkite/"), strings.HasPrefix(lower, ".azure-pipelines/"):
		return true
	case base == ".gitlab-ci.yml", base == "jenkinsfile", base == "makefile", base == "gnumakefile", base == "package.json", base == "pom.xml",
		base == "build.gradle", base == "build.gradle.kts", base == "setup.py", base == "pyproject.toml", base == "cargo.toml", base == "go.mod",
		base == "azure-pipelines.yml", base == "bitbucket-pipelines.yml", base == ".travis.yml", base == "cloudbuild.yaml", base == "build.rs":
		return true
	case base == "dockerfile", strings.HasPrefix(base, "dockerfile."), strings.HasSuffix(base, ".dockerfile"):
		return true
	}
	return false
}

// sizeFindings applies the INT-012 checks to two file inventories of the same
// ref. A path missing from the earlier inventory counts as new only when that
// inventory was a whole walk (priorWalked); a changed path needs no such care.
func sizeFindings(policy IntegrityPolicy, prior, current []FileEvidence, priorWalked, firstTimeAuthor bool) []Finding {
	if policy.LargeFileBytes == 0 && policy.CIGrowthBytes == 0 {
		return nil
	}
	before := make(map[string]int64, len(prior))
	for _, f := range prior {
		before[f.Path] = f.Size
	}
	var out []Finding
	add := func(advisory, title, severity string, p string, evidence map[string]any) {
		body, _ := json.Marshal(evidence)
		guidance, _ := json.Marshal(map[string]any{"summary": "A large addition is a place to hide a payload. Open the file and its commit, confirm who added it and why, and confirm it is meant to be in the repository.", "steps": []string{"Read the file or diff it against the previous revision.", "Ask the author through a separate channel if it is unexpected.", "If it is expected, accept this entry with a reason."}})
		out = append(out, Finding{Type: "integrity", AdvisoryID: advisory, Title: title, Severity: severity, Score: integrityScore(severity), Component: Component{Path: p}, Evidence: body, Guidance: guidance})
	}
	for _, f := range current {
		old, known := before[f.Path]
		switch {
		case !known && policy.LargeFileBytes > 0 && f.Size > policy.LargeFileBytes && priorWalked && len(prior) > 0:
			severity := "medium"
			if firstTimeAuthor {
				severity = "high"
			}
			add("SCRS-LARGE-NEW-FILE", "Large file added since the previous scan", severity, f.Path, map[string]any{"path": f.Path, "size": f.Size, "threshold": policy.LargeFileBytes, "first_time_author": firstTimeAuthor})
		case known && policy.CIGrowthBytes > 0 && ciFile(f.Path) && f.Size-old > policy.CIGrowthBytes:
			add("SCRS-CI-FILE-GROWTH", "CI or build file grew sharply since the previous scan", "medium", f.Path, map[string]any{"path": f.Path, "size_before": old, "size_after": f.Size, "threshold": policy.CIGrowthBytes, "first_time_author": firstTimeAuthor})
		}
	}
	return out
}
