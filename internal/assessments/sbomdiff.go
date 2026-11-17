package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// maxDiffComponents bounds the components read per side of a diff.
const maxDiffComponents = 200000

// DiffSide names one side of a comparison.
type DiffSide struct {
	AssessmentID uuid.UUID `json:"assessment_id"`
	Ref          string    `json:"ref"`
	Commit       string    `json:"commit"`
	Components   int       `json:"components"`
}

// DiffEntry is one package that differs between two revisions.
type DiffEntry struct {
	Name        string   `json:"name"`
	Ecosystem   string   `json:"ecosystem"`
	Versions    []string `json:"versions,omitempty"`
	FromVersion []string `json:"from_versions,omitempty"`
	ToVersion   []string `json:"to_versions,omitempty"`
	FromLicense string   `json:"from_license,omitempty"`
	ToLicense   string   `json:"to_license,omitempty"`
	Dev         bool     `json:"dev"`
}

// SBOMDiff compares the packages of two revisions of one asset.
type SBOMDiff struct {
	From           DiffSide       `json:"from"`
	To             DiffSide       `json:"to"`
	Added          []DiffEntry    `json:"added"`
	Removed        []DiffEntry    `json:"removed"`
	Changed        []DiffEntry    `json:"changed"`
	LicenseChanged []DiffEntry    `json:"license_changed"`
	Unchanged      int            `json:"unchanged"`
	Totals         map[string]int `json:"totals"`
	Truncated      bool           `json:"truncated"`
}

// ResolveRevision finds the successful assessment a revision names: an
// assessment id of the asset, or a commit (or image digest), for which the
// newest successful assessment is used.
func (s *Store) ResolveRevision(ctx context.Context, asset uuid.UUID, revision string) (DiffSide, error) {
	var side DiffSide
	var ref *string
	query := `SELECT id,request->'target'->>'ref',resolved_commit FROM ` + s.schema + `.assessments WHERE asset_id=$1 AND status='succeeded' AND request->'remediation' IS NULL AND `
	var row pgx.Row
	if id, err := uuid.Parse(revision); err == nil {
		row = s.pool.QueryRow(ctx, query+`id=$2`, asset, id)
	} else if validRevision(revision) {
		row = s.pool.QueryRow(ctx, query+`resolved_commit=$2 ORDER BY created_at DESC,id DESC LIMIT 1`, asset, strings.ToLower(revision))
	} else {
		return side, ErrInput
	}
	if err := row.Scan(&side.AssessmentID, &ref, &side.Commit); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return side, ErrNotFound
		}
		return side, err
	}
	if ref != nil {
		side.Ref = *ref
	}
	return side, nil
}

type packageSet struct {
	name, ecosystem string
	versions        map[string]bool
	licenses        map[string]bool
	dev             bool
}

func (s *Store) packages(ctx context.Context, assessment uuid.UUID) (map[string]*packageSet, int, error) {
	rows, err := s.pool.Query(ctx, `SELECT body FROM `+s.schema+`.components WHERE assessment_id=$1 ORDER BY ordinal LIMIT $2`, assessment, maxDiffComponents+1)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := map[string]*packageSet{}
	n := 0
	for rows.Next() {
		var raw []byte
		var c Component
		if err := rows.Scan(&raw); err != nil {
			return nil, 0, err
		}
		if err := json.Unmarshal(raw, &c); err != nil {
			return nil, 0, err
		}
		n++
		if n > maxDiffComponents {
			return nil, 0, ErrInput
		}
		key := c.Ecosystem + "|" + c.Name
		p := out[key]
		if p == nil {
			p = &packageSet{name: c.Name, ecosystem: c.Ecosystem, versions: map[string]bool{}, licenses: map[string]bool{}, dev: true}
			out[key] = p
		}
		p.versions[c.Version] = true
		if c.License != nil && c.License.Expression != "" {
			p.licenses[c.License.Expression] = true
		}
		p.dev = p.dev && c.Dev()
	}
	return out, n, rows.Err()
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// DiffSBOM compares the packages of two successful assessments of an asset
// (the same asset only) and lists what was added, removed, changed in version
// or changed in licence. Lists are cut at limit entries each, with totals.
func (s *Store) DiffSBOM(ctx context.Context, asset uuid.UUID, from, to string, limit int) (SBOMDiff, error) {
	var d SBOMDiff
	if limit < 1 || limit > 5000 {
		return d, ErrInput
	}
	var err error
	if d.From, err = s.ResolveRevision(ctx, asset, from); err != nil {
		return d, err
	}
	if d.To, err = s.ResolveRevision(ctx, asset, to); err != nil {
		return d, err
	}
	before, nBefore, err := s.packages(ctx, d.From.AssessmentID)
	if err != nil {
		return d, err
	}
	after, nAfter, err := s.packages(ctx, d.To.AssessmentID)
	if err != nil {
		return d, err
	}
	d.From.Components, d.To.Components = nBefore, nAfter
	d.Added, d.Removed, d.Changed, d.LicenseChanged = []DiffEntry{}, []DiffEntry{}, []DiffEntry{}, []DiffEntry{}
	names := make([]string, 0, len(before)+len(after))
	seen := map[string]bool{}
	for k := range before {
		seen[k] = true
		names = append(names, k)
	}
	for k := range after {
		if !seen[k] {
			names = append(names, k)
		}
	}
	slices.Sort(names)
	for _, k := range names {
		b, a := before[k], after[k]
		switch {
		case b == nil:
			d.Added = append(d.Added, DiffEntry{Name: a.name, Ecosystem: a.ecosystem, Versions: keys(a.versions), ToLicense: strings.Join(keys(a.licenses), " "), Dev: a.dev})
		case a == nil:
			d.Removed = append(d.Removed, DiffEntry{Name: b.name, Ecosystem: b.ecosystem, Versions: keys(b.versions), FromLicense: strings.Join(keys(b.licenses), " "), Dev: b.dev})
		case !slices.Equal(keys(b.versions), keys(a.versions)):
			d.Changed = append(d.Changed, DiffEntry{Name: a.name, Ecosystem: a.ecosystem, FromVersion: keys(b.versions), ToVersion: keys(a.versions), FromLicense: strings.Join(keys(b.licenses), " "), ToLicense: strings.Join(keys(a.licenses), " "), Dev: a.dev})
		case !slices.Equal(keys(b.licenses), keys(a.licenses)):
			d.LicenseChanged = append(d.LicenseChanged, DiffEntry{Name: a.name, Ecosystem: a.ecosystem, Versions: keys(a.versions), FromLicense: strings.Join(keys(b.licenses), " "), ToLicense: strings.Join(keys(a.licenses), " "), Dev: a.dev})
		default:
			d.Unchanged++
		}
	}
	d.Totals = map[string]int{"added": len(d.Added), "removed": len(d.Removed), "changed": len(d.Changed), "license_changed": len(d.LicenseChanged)}
	for _, list := range []*[]DiffEntry{&d.Added, &d.Removed, &d.Changed, &d.LicenseChanged} {
		if len(*list) > limit {
			*list = (*list)[:limit]
			d.Truncated = true
		}
	}
	return d, nil
}
