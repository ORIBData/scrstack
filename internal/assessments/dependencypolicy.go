package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// DependencyPolicy switches on the optional package checks (MAL-005, MAL-006).
// Both are off until an admin enables them: the release-age check calls
// deps.dev, and the typosquat check can flag a legitimate neighbour of a
// popular name. Their entries inform and never gate.
type DependencyPolicy struct {
	Revision int64 `json:"revision"`
	// MinReleaseAgeDays flags a package version published fewer than this
	// many days ago; 0 turns the check off.
	MinReleaseAgeDays int `json:"min_release_age_days"`
	// Typosquat flags a package name one edit away from a popular package.
	Typosquat bool       `json:"typosquat"`
	UpdatedAt *time.Time `json:"updated_at"`
}

// MaxMinReleaseAgeDays bounds the release-age setting.
const MaxMinReleaseAgeDays = 365

func dependencyPolicySchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.dependency_policy(singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),revision bigint NOT NULL DEFAULT 1,min_release_age_days integer NOT NULL DEFAULT 0 CHECK(min_release_age_days BETWEEN 0 AND 365),typosquat boolean NOT NULL DEFAULT false,updated_at timestamptz,updated_by uuid)`,
		`INSERT INTO ` + s + `.dependency_policy(singleton) VALUES(true) ON CONFLICT DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.package_published(system text NOT NULL,name text NOT NULL,version text NOT NULL,published_at timestamptz,status text NOT NULL CHECK(status IN ('ok','not_found')),fetched_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(system,name,version))`,
	}
}

// DependencyPolicy returns the current settings.
func (s *Store) DependencyPolicy(ctx context.Context) (DependencyPolicy, error) {
	var p DependencyPolicy
	err := s.pool.QueryRow(ctx, `SELECT revision,min_release_age_days,typosquat,updated_at FROM `+s.schema+`.dependency_policy WHERE singleton`).Scan(&p.Revision, &p.MinReleaseAgeDays, &p.Typosquat, &p.UpdatedAt)
	return p, err
}

// SetDependencyPolicy replaces the settings when expected is the current
// revision (ErrConflict otherwise). It is audited.
func (s *Store) SetDependencyPolicy(ctx context.Context, expected int64, minAgeDays int, typosquat bool, actor uuid.UUID) (DependencyPolicy, error) {
	if minAgeDays < 0 || minAgeDays > MaxMinReleaseAgeDays {
		return DependencyPolicy{}, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DependencyPolicy{}, err
	}
	defer tx.Rollback(ctx)
	var before DependencyPolicy
	err = tx.QueryRow(ctx, `SELECT min_release_age_days,typosquat FROM `+s.schema+`.dependency_policy WHERE singleton AND revision=$1 FOR UPDATE`, expected).Scan(&before.MinReleaseAgeDays, &before.Typosquat)
	if errors.Is(err, pgx.ErrNoRows) {
		return DependencyPolicy{}, ErrConflict
	}
	if err != nil {
		return DependencyPolicy{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.dependency_policy SET min_release_age_days=$1,typosquat=$2,revision=revision+1,updated_at=clock_timestamp(),updated_by=$3 WHERE singleton`, minAgeDays, typosquat, nullUUID(actor)); err != nil {
		return DependencyPolicy{}, err
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "min_release_age_days": minAgeDays, "typosquat": typosquat, "previous_min_release_age_days": before.MinReleaseAgeDays, "previous_typosquat": before.Typosquat, "previous_revision": expected})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('dependency_policy.updated',$1)`, details); err != nil {
		return DependencyPolicy{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return DependencyPolicy{}, err
	}
	return s.DependencyPolicy(ctx)
}

// PackagePublished is a cached publish date; Found is false when deps.dev
// did not know the version.
type PackagePublished struct {
	At    time.Time
	Found bool
}

// CachedPublished returns cached publish dates. A date never changes, so a
// known one is kept for good; "not known" is retried after a week.
func (s *Store) CachedPublished(ctx context.Context, keys []PackageKey) (map[PackageKey]PackagePublished, error) {
	out := map[PackageKey]PackagePublished{}
	if len(keys) == 0 {
		return out, nil
	}
	systems, names, versions := make([]string, len(keys)), make([]string, len(keys)), make([]string, len(keys))
	for i, k := range keys {
		systems[i], names[i], versions[i] = k.System, k.Name, k.Version
	}
	rows, err := s.pool.Query(ctx, `SELECT m.system,m.name,m.version,m.published_at,m.status FROM unnest($1::text[],$2::text[],$3::text[]) AS k(system,name,version) JOIN `+s.schema+`.package_published m USING(system,name,version) WHERE m.status='ok' OR m.fetched_at>clock_timestamp()-interval '7 days'`, systems, names, versions)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var k PackageKey
		var at *time.Time
		var status string
		if err := rows.Scan(&k.System, &k.Name, &k.Version, &at, &status); err != nil {
			return nil, err
		}
		v := PackagePublished{Found: status == "ok" && at != nil}
		if at != nil {
			v.At = *at
		}
		out[k] = v
	}
	return out, rows.Err()
}

// SavePublished caches publish dates read from deps.dev.
func (s *Store) SavePublished(ctx context.Context, entries map[PackageKey]PackagePublished) error {
	batch := &pgx.Batch{}
	for k, v := range entries {
		status, at := "not_found", any(nil)
		if v.Found {
			status, at = "ok", v.At
		}
		batch.Queue(`INSERT INTO `+s.schema+`.package_published(system,name,version,published_at,status) VALUES($1,$2,$3,$4,$5) ON CONFLICT(system,name,version) DO UPDATE SET published_at=EXCLUDED.published_at,status=EXCLUDED.status,fetched_at=clock_timestamp()`, k.System, k.Name, k.Version, at, status)
	}
	if batch.Len() == 0 {
		return nil
	}
	return s.pool.SendBatch(ctx, batch).Close()
}
