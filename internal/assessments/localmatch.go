package assessments

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/ORIBData/scrstack/internal/semver"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// A local advisory (OSV-008) becomes register entries: at every assessment
// whose inventory holds an affected component, and at once, from the stored
// inventories, when the advisory is created. A malicious one becomes a
// `malicious_dependency` entry, which fails the gate (MAL-007); any other a
// `vulnerability` entry at the advisory's rating. Withdrawing the advisory
// closes its entries.

// localRange is one OSV range as stored.
type localRange struct {
	Type   string              `json:"type"`
	Events []map[string]string `json:"events"`
}

type localAffected struct {
	Package  LocalPackage `json:"package"`
	Versions []string     `json:"versions"`
	Ranges   []localRange `json:"ranges"`
	Spec     struct {
		All bool `json:"all_versions"`
	} `json:"database_specific"`
}

// localAdvisory is a stored local advisory, parsed for matching.
type localAdvisory struct {
	ID         string          `json:"id"`
	Summary    string          `json:"summary"`
	Details    string          `json:"details"`
	Aliases    []string        `json:"aliases"`
	Affected   []localAffected `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
	Spec struct {
		Malicious bool   `json:"malicious"`
		Rating    string `json:"rating"`
	} `json:"database_specific"`
}

// intervals reads an affected entry's SEMVER ranges: one interval per
// introduced event, closed by the fixed or last_affected event that follows.
func (a localAffected) intervals() []semver.Range {
	var out []semver.Range
	for _, r := range a.Ranges {
		if r.Type != "SEMVER" {
			continue
		}
		var current *semver.Range
		for _, e := range r.Events {
			switch {
			case e["introduced"] != "":
				if current != nil {
					out = append(out, *current)
				}
				current = &semver.Range{Introduced: e["introduced"]}
			case e["fixed"] != "" && current != nil:
				current.Fixed = e["fixed"]
				out = append(out, *current)
				current = nil
			case e["last_affected"] != "" && current != nil:
				current.LastAffected = e["last_affected"]
				out = append(out, *current)
				current = nil
			}
		}
		if current != nil {
			out = append(out, *current)
		}
	}
	return out
}

// ecosystemMatches compares an advisory's ecosystem with a component's: equal
// ignoring case, or the component's with a `:` suffix (`Alpine:v3.19`).
func ecosystemMatches(advisory, component string) bool {
	advisory, component = strings.ToLower(advisory), strings.ToLower(component)
	return advisory == component || strings.HasPrefix(component, advisory+":")
}

// sameName compares package names; PyPI names fold case and `_`, `.`, `-`.
func sameName(ecosystem, a, b string) bool {
	if strings.EqualFold(strings.SplitN(ecosystem, ":", 2)[0], "PyPI") {
		fold := strings.NewReplacer("_", "-", ".", "-")
		return strings.EqualFold(fold.Replace(a), fold.Replace(b))
	}
	return strings.EqualFold(a, b)
}

// matches reports whether a component is affected by the advisory.
func (l localAdvisory) matches(c Component) bool {
	for _, a := range l.Affected {
		if !ecosystemMatches(a.Package.Ecosystem, c.Ecosystem) || !sameName(c.Ecosystem, a.Package.Name, c.Name) {
			continue
		}
		if a.Spec.All {
			return true
		}
		for _, v := range a.Versions {
			if v == c.Version {
				return true
			}
		}
		if semver.Supported(c.Ecosystem) {
			for _, r := range a.intervals() {
				if r.Contains(c.Version) {
					return true
				}
			}
		}
	}
	return false
}

// fixedVersions lists the versions that end an affected range.
func (l localAdvisory) fixedVersions() []string {
	seen := map[string]bool{}
	var out []string
	for _, a := range l.Affected {
		for _, r := range a.intervals() {
			if r.Fixed != "" && !seen[r.Fixed] {
				seen[r.Fixed] = true
				out = append(out, r.Fixed)
			}
		}
	}
	sort.Strings(out)
	return out
}

var ratingScore = map[string]int{"critical": 95, "high": 75, "medium": 50, "low": 25}

// finding builds the register entry for a component the advisory affects.
func (l localAdvisory) finding(c Component) Finding {
	kind, severity := "vulnerability", l.Spec.Rating
	if ratingScore[severity] == 0 {
		severity = "high"
	}
	if l.Spec.Malicious {
		kind, severity = "malicious_dependency", "critical"
	}
	score := ratingScore[severity]
	if l.Spec.Malicious {
		score = 100
	}
	evidence, _ := json.Marshal(map[string]any{"source": "local_advisory", "advisory": l.ID, "aliases": l.Aliases})
	var refs []string
	for _, r := range l.References {
		refs = append(refs, r.URL)
	}
	steps := []string{"Read the advisory (GET /advisories/" + l.ID + ") and confirm the component is the one it names."}
	if fixed := l.fixedVersions(); len(fixed) > 0 {
		steps = append(steps, "Upgrade to a fixed version: "+strings.Join(fixed, ", ")+".")
	} else {
		steps = append(steps, "Replace or remove the component; the advisory names no fixed version.")
	}
	guidance, _ := json.Marshal(map[string]any{"summary": l.Summary, "steps": steps, "references": refs, "fixed_versions": l.fixedVersions(), "source": "local advisory written by your team"})
	return Finding{Type: kind, AdvisoryID: l.ID, Title: l.Summary, Severity: severity, Score: score, Component: c, Evidence: evidence, Guidance: guidance}
}

// activeLocalAdvisories loads every local advisory that is not withdrawn.
func (s *Store) activeLocalAdvisories(ctx context.Context, q interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}) ([]localAdvisory, error) {
	rows, err := q.Query(ctx, `SELECT record FROM `+s.schema+`.advisory_records WHERE origin=$1 AND NOT withdrawn ORDER BY id LIMIT 2000`, OriginLocal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []localAdvisory
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var adv localAdvisory
		if json.Unmarshal(raw, &adv) == nil {
			out = append(out, adv)
		}
	}
	return out, rows.Err()
}

// localAdvisoryFindings adds the entries local advisories raise for an
// assessment's components (OSV-008). Imports and remediation plans bring no
// inventory of their own and are skipped.
func (s *Store) localAdvisoryFindings(ctx context.Context, tx pgx.Tx, a Assessment, r *Result) error {
	if a.Request.Import != nil || a.Request.Remediation != nil || len(r.Components) == 0 {
		return nil
	}
	advisories, err := s.activeLocalAdvisories(ctx, tx)
	if err != nil || len(advisories) == 0 {
		return err
	}
	seen := map[string]bool{}
	for _, adv := range advisories {
		for _, c := range r.Components {
			key := adv.ID + "\x00" + c.PURL + "\x00" + c.Path
			if seen[key] || !adv.matches(c) {
				continue
			}
			seen[key] = true
			if len(r.Findings) >= 10000 {
				r.Complete = false
				return nil
			}
			r.Findings = append(r.Findings, adv.finding(c))
		}
	}
	return nil
}

// applyLocalAdvisory opens entries for the components the newest successful
// assessment of each asset and ref already holds, without rescanning (UC3).
// It returns how many entries it opened.
func (s *Store) applyLocalAdvisory(ctx context.Context, tx pgx.Tx, adv localAdvisory) (int, error) {
	opened := 0
	type group struct {
		assessment, asset, connection uuid.UUID
		locator, ref, commit          string
		created                       []Finding
	}
	groups := map[uuid.UUID]*group{}
	var order []uuid.UUID
	for _, a := range adv.Affected {
		rows, err := tx.Query(ctx, `WITH latest AS (SELECT DISTINCT ON (asset_id,request->'target'->>'ref') id,asset_id,connection_id,request->'target'->>'ref' AS ref,resolved_commit FROM `+s.schema+`.assessments WHERE status='succeeded' AND request->'remediation' IS NULL AND request->'import' IS NULL ORDER BY asset_id,request->'target'->>'ref',created_at DESC)
			SELECT l.id,l.asset_id,l.connection_id,x.locator,COALESCE(l.ref,''),l.resolved_commit,c.body FROM latest l JOIN `+s.schema+`.components c ON c.assessment_id=l.id JOIN `+s.schema+`.assets x ON x.id=l.asset_id WHERE lower(c.body->>'name')=lower($1) OR lower(replace(replace(c.body->>'name','_','-'),'.','-'))=lower(replace(replace($1,'_','-'),'.','-')) ORDER BY x.locator,l.ref,c.ordinal LIMIT 5000`, a.Package.Name)
		if err != nil {
			return opened, err
		}
		type hit struct {
			g *group
			c Component
		}
		var hits []hit
		for rows.Next() {
			var id, asset, connection uuid.UUID
			var locator, ref, commit string
			var body []byte
			if err := rows.Scan(&id, &asset, &connection, &locator, &ref, &commit, &body); err != nil {
				rows.Close()
				return opened, err
			}
			var c Component
			if json.Unmarshal(body, &c) != nil || !adv.matches(c) {
				continue
			}
			g := groups[id]
			if g == nil {
				g = &group{assessment: id, asset: asset, connection: connection, locator: locator, ref: ref, commit: commit}
				groups[id] = g
				order = append(order, id)
			}
			hits = append(hits, hit{g, c})
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return opened, err
		}
		for _, h := range hits {
			f := adv.finding(h.c)
			target := Assessment{AssetID: h.g.asset}
			target.Request.Target.Ref = h.g.ref
			f.Fingerprint = fingerprint(target, f)
			f.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(f.Fingerprint))
			f.AssetID, f.Ref, f.Status, f.Change = h.g.asset, h.g.ref, "open", "new"
			component, _ := json.Marshal(f.Component)
			tag, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance,last_assessment_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(fingerprint) DO NOTHING`, f.ID, f.AssetID, f.Fingerprint, f.Ref, f.Type, f.AdvisoryID, f.Title, f.Severity, f.Score, component, f.Evidence, f.Guidance, h.g.assessment)
			if err != nil {
				return opened, err
			}
			if tag.RowsAffected() == 0 {
				continue
			}
			if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'detected',$2)`, f.ID, json.RawMessage(fmt.Sprintf(`{"advisory":%q,"assessment_id":%q,"retroactive":true}`, adv.ID, h.g.assessment))); err != nil {
				return opened, err
			}
			h.g.created = append(h.g.created, f)
			opened++
		}
	}
	// Tell automation, per asset and ref, as an assessment would.
	for _, id := range order {
		g := groups[id]
		if len(g.created) == 0 {
			continue
		}
		var briefs, malicious []map[string]any
		for _, f := range g.created {
			if len(briefs) < 100 {
				briefs = append(briefs, findingBrief(f))
			}
			if f.Type == "malicious_dependency" && len(malicious) < 100 {
				malicious = append(malicious, findingBrief(f))
			}
		}
		base := map[string]any{"assessment_id": g.assessment, "asset_id": g.asset, "repository": g.locator, "ref": g.ref, "commit": g.commit, "source": "local_advisory"}
		scope := notify.Scope{Connection: g.connection}
		created := map[string]any{"total": len(g.created), "truncated": len(g.created) > len(briefs), "findings": briefs}
		for k, v := range base {
			created[k] = v
		}
		if _, err := notify.EmitScoped(ctx, tx, s.schema, "finding.created", created, nil, scope); err != nil {
			return opened, err
		}
		if len(malicious) > 0 {
			reported := map[string]any{"findings": malicious}
			for k, v := range base {
				reported[k] = v
			}
			if _, err := notify.EmitScoped(ctx, tx, s.schema, "malicious_dependency.reported", reported, nil, scope); err != nil {
				return opened, err
			}
		}
	}
	return opened, nil
}

// closeLocalAdvisoryFindings closes the open entries of a withdrawn advisory
// and records why in each entry's history.
func (s *Store) closeLocalAdvisoryFindings(ctx context.Context, tx pgx.Tx, id, reason string) (int64, error) {
	details, _ := json.Marshal(map[string]any{"advisory": id, "reason": reason})
	tag, err := tx.Exec(ctx, `WITH closed AS (UPDATE `+s.schema+`.findings SET status='fixed',revision=revision+1 WHERE advisory_id=$1 AND type IN ('vulnerability','malicious_dependency') AND status<>'fixed' RETURNING id) INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) SELECT id,'advisory_withdrawn',$2::jsonb FROM closed`, id, details)
	return tag.RowsAffected(), err
}
