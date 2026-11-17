package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/dtrack"
	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Dependency-Track read-back. Dependency-Track analyses each uploaded SBOM with
// every vulnerability source and analyzer it has enabled. A sync reads those
// findings for the project of an uploaded assessment and:
//   - joins each with the register entry SCRS already has for the same
//     component and vulnerability (matching on package URL and on the
//     vulnerability ID or any alias), so one vulnerability is one entry;
//   - records the rest as report-only "dt_vulnerability" entries, which
//     close when Dependency-Track stops reporting them;
//   - shares triage decisions (see dtrackStatusFor and dtrackImportStatus).
// Imported entries never change an assessment's verdict.

func dtrackSyncSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.dtrack_projects(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),project_name text NOT NULL,project_version text NOT NULL,asset_id uuid NOT NULL,ref text NOT NULL DEFAULT '',assessment_id uuid NOT NULL,project_uuid uuid,status text NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','ok','error')),error text NOT NULL DEFAULT '',attempts integer NOT NULL DEFAULT 0,findings integer NOT NULL DEFAULT 0,next_sync_at timestamptz NOT NULL DEFAULT clock_timestamp(),last_synced_at timestamptz,UNIQUE(project_name,project_version))`,
		`CREATE INDEX IF NOT EXISTS dtrack_projects_due_idx ON ` + s + `.dtrack_projects(next_sync_at)`,
		`CREATE TABLE IF NOT EXISTS ` + s + `.dtrack_findings(id uuid PRIMARY KEY DEFAULT gen_random_uuid(),project_id uuid NOT NULL REFERENCES ` + s + `.dtrack_projects(id) ON DELETE CASCADE,asset_id uuid NOT NULL,component_uuid uuid NOT NULL,vulnerability_uuid uuid NOT NULL,finding_id uuid REFERENCES ` + s + `.findings(id) ON DELETE SET NULL,matched boolean NOT NULL,vuln_id text NOT NULL,vuln_source text NOT NULL DEFAULT '',analyzer text NOT NULL DEFAULT '',purl text NOT NULL DEFAULT '',severity text NOT NULL DEFAULT 'unknown',ids jsonb NOT NULL DEFAULT '[]',analysis_state text NOT NULL DEFAULT 'NOT_SET',suppressed boolean NOT NULL DEFAULT false,pushed_status text NOT NULL DEFAULT '',first_seen timestamptz NOT NULL DEFAULT clock_timestamp(),last_seen timestamptz NOT NULL DEFAULT clock_timestamp(),UNIQUE(project_id,component_uuid,vulnerability_uuid))`,
		`CREATE INDEX IF NOT EXISTS dtrack_findings_finding_idx ON ` + s + `.dtrack_findings(finding_id)`,
		`CREATE INDEX IF NOT EXISTS dtrack_findings_asset_idx ON ` + s + `.dtrack_findings(asset_id)`,
	}
}

// DTrackSyncEvery is how often a project's findings are read again.
const DTrackSyncEvery = 30 * time.Minute

// dtrackPushLimit bounds the triage decisions written in one sync.
const dtrackPushLimit = 200

// DTrackProject is an uploaded Dependency-Track project to keep in sync.
type DTrackProject struct {
	ID           uuid.UUID `json:"id"`
	Name         string    `json:"project"`
	Version      string    `json:"version"`
	AssetID      uuid.UUID `json:"asset_id"`
	Ref          string    `json:"ref"`
	AssessmentID uuid.UUID `json:"assessment_id"`
	ProjectUUID  string    `json:"-"`
	Attempts     int       `json:"-"`
}

// ClaimDTrackSync picks a project whose findings are due, while importing is
// enabled; ErrNotFound when none is. The claim only pushes the next sync back
// five minutes, so a crashed worker is retried.
func (s *Store) ClaimDTrackSync(ctx context.Context) (DTrackProject, error) {
	var p DTrackProject
	err := s.pool.QueryRow(ctx, `UPDATE `+s.schema+`.dtrack_projects SET attempts=attempts+1,next_sync_at=clock_timestamp()+interval '5 minutes' WHERE id=(SELECT p.id FROM `+s.schema+`.dtrack_projects p,`+s.schema+`.dtrack_settings d WHERE d.id=1 AND d.enabled AND d.import_findings AND p.next_sync_at<=clock_timestamp() ORDER BY p.next_sync_at LIMIT 1 FOR UPDATE OF p SKIP LOCKED) RETURNING id,project_name,project_version,asset_id,ref,assessment_id,COALESCE(project_uuid::text,''),attempts`).Scan(&p.ID, &p.Name, &p.Version, &p.AssetID, &p.Ref, &p.AssessmentID, &p.ProjectUUID, &p.Attempts)
	if errors.Is(err, pgx.ErrNoRows) {
		return p, ErrNotFound
	}
	return p, err
}

// FinishDTrackSync records a sync: failed (retried with backoff) or done.
// more asks for another pass soon, when a limit left work over.
func (s *Store) FinishDTrackSync(ctx context.Context, p DTrackProject, syncErr string, findings int, more bool) error {
	if syncErr != "" {
		backoff := time.Duration(1<<min(p.Attempts, 6)) * time.Minute
		_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_projects SET status='error',error=left($2,500),next_sync_at=clock_timestamp()+($3*interval '1 second') WHERE id=$1`, p.ID, syncErr, int64(backoff.Seconds()))
		return err
	}
	next := DTrackSyncEvery
	if more {
		next = 10 * time.Second
	}
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_projects SET status='ok',error='',attempts=0,findings=$2,last_synced_at=clock_timestamp(),next_sync_at=clock_timestamp()+($3*interval '1 second') WHERE id=$1`, p.ID, findings, int64(next.Seconds()))
	return err
}

// RequestDTrackSync makes every project due now.
func (s *Store) RequestDTrackSync(ctx context.Context) (int64, error) {
	tag, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_projects SET next_sync_at=clock_timestamp()`)
	return tag.RowsAffected(), err
}

// ---- pure matching and mapping ----

// normalizePURL reduces a package URL to what identifies the package version:
// no qualifiers or subpath, lower case.
func normalizePURL(p string) string {
	p = strings.TrimSpace(p)
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	return strings.ToLower(p)
}

var dtSeverityRank = map[string]int{"unknown": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

func dtSeverity(s string) string {
	s = normalizeSeverity(s)
	return s
}

// dtCluster is one vulnerability on one component, as Dependency-Track
// reports it. Dependency-Track keeps a separate finding for each source's ID
// (a CVE from NVD and its GHSA alias from GitHub), so findings of one
// component that share any ID are one cluster.
type dtCluster struct {
	PURL      string
	Component dtrack.Finding
	IDs       []string
	Canonical string
	Severity  string
	CVSS      float64
	Title     string
	Reference string
	CWEs      []int
	Analyzers []string
	Sources   []string
	Members   []dtrack.Finding
}

func upperIDs(ids []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, id := range ids {
		id = strings.ToUpper(strings.TrimSpace(id))
		if id != "" && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func canonicalID(ids []string) string {
	for _, prefix := range []string{"CVE-", "GHSA-"} {
		for _, id := range ids {
			if strings.HasPrefix(id, prefix) {
				return id
			}
		}
	}
	return ids[0]
}

func clusterDTrackFindings(in []dtrack.Finding) []dtCluster {
	byComponent := map[string][]dtrack.Finding{}
	order := []string{}
	for _, f := range in {
		key := normalizePURL(f.PURL)
		if key == "" {
			key = strings.ToLower(f.ComponentGroup + ":" + f.ComponentName + "@" + f.ComponentVersion)
		}
		if _, ok := byComponent[key]; !ok {
			order = append(order, key)
		}
		byComponent[key] = append(byComponent[key], f)
	}
	var out []dtCluster
	for _, key := range order {
		group := byComponent[key]
		parent := make([]int, len(group))
		for i := range parent {
			parent[i] = i
		}
		var find func(int) int
		find = func(i int) int {
			for parent[i] != i {
				parent[i] = parent[parent[i]]
				i = parent[i]
			}
			return i
		}
		owner := map[string]int{}
		for i, f := range group {
			for _, id := range upperIDs(f.IDs) {
				if j, ok := owner[id]; ok {
					parent[find(i)] = find(j)
				} else {
					owner[id] = i
				}
			}
		}
		clusters := map[int]*dtCluster{}
		roots := []int{}
		for i, f := range group {
			r := find(i)
			c, ok := clusters[r]
			if !ok {
				c = &dtCluster{PURL: key, Component: f, Severity: "unknown"}
				clusters[r] = c
				roots = append(roots, r)
			}
			c.Members = append(c.Members, f)
			c.IDs = upperIDs(append(c.IDs, f.IDs...))
			if dtSeverityRank[dtSeverity(f.Severity)] > dtSeverityRank[c.Severity] {
				c.Severity = dtSeverity(f.Severity)
			}
			if f.CVSS > c.CVSS {
				c.CVSS = f.CVSS
			}
			if c.Title == "" {
				c.Title = f.Title
			}
			if c.Reference == "" {
				c.Reference = f.ReferenceURL
			}
			c.CWEs = append(c.CWEs, f.CWEs...)
			c.Analyzers = addUnique(c.Analyzers, f.Analyzer)
			c.Sources = addUnique(c.Sources, f.Source)
		}
		for _, r := range roots {
			c := clusters[r]
			c.Canonical = canonicalID(c.IDs)
			sort.Strings(c.Analyzers)
			sort.Strings(c.Sources)
			out = append(out, *c)
		}
	}
	return out
}

func addUnique(list []string, v string) []string {
	if v == "" {
		return list
	}
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// dtrackStatusFor maps a register status to the analysis written to
// Dependency-Track. ok is false for statuses that are not written (fixed is
// decided by scans, not by people). "open" resets a decision SCRS wrote
// earlier.
func dtrackStatusFor(status string, until *time.Time) (a dtrack.Analysis, ok bool) {
	switch status {
	case "open":
		return dtrack.Analysis{State: "NOT_SET", Details: "Reopened in the SCRS risk register."}, true
	case "triaged", "in_progress":
		return dtrack.Analysis{State: "IN_TRIAGE", Details: "Triaged in the SCRS risk register (" + status + ")."}, true
	case "accepted":
		d := "Risk accepted in the SCRS risk register."
		if until != nil {
			d = "Risk accepted in the SCRS risk register until " + until.UTC().Format("2006-01-02") + "."
		}
		return dtrack.Analysis{State: "EXPLOITABLE", Response: "WILL_NOT_FIX", Details: d}, true
	case "false_positive":
		return dtrack.Analysis{State: "FALSE_POSITIVE", Suppressed: true, Details: "Marked a false positive in the SCRS risk register."}, true
	case "suppressed":
		return dtrack.Analysis{State: "NOT_AFFECTED", Suppressed: true, Details: "Suppressed in the SCRS risk register."}, true
	}
	return a, false
}

// dtrackImportStatus is the register status for a cluster's Dependency-Track
// analyses, or "" for none. Hiding a finding needs every member to agree;
// any other analysed mix only marks it triaged, so one analyst's decision on
// one source's finding never silences another source's.
func dtrackImportStatus(members []dtrack.Finding) string {
	statuses := map[string]bool{}
	analysed := 0
	for _, m := range members {
		status := ""
		switch {
		case m.AnalysisState == "FALSE_POSITIVE":
			status = "false_positive"
		case m.AnalysisState == "NOT_AFFECTED" || (m.Suppressed && m.AnalysisState == "NOT_SET"):
			status = "suppressed"
		case m.AnalysisState == "EXPLOITABLE" || m.AnalysisState == "IN_TRIAGE":
			status = "triaged"
		}
		if status != "" {
			analysed++
			statuses[status] = true
		}
	}
	switch {
	case analysed == 0:
		return ""
	case analysed == len(members) && len(statuses) == 1:
		for s := range statuses {
			return s
		}
	}
	return "triaged"
}

// ---- applying a sync ----

// DTrackPush is a triage decision to write to Dependency-Track.
type DTrackPush struct {
	MemberID                          uuid.UUID
	Project, Component, Vulnerability string
	Status                            string
	Analysis                          dtrack.Analysis
}

// DTrackSyncResult is what applying a sync produced.
type DTrackSyncResult struct {
	Total, Matched, Created, Closed, Imported int
	Pushes                                    []DTrackPush
	MorePushes                                bool
}

type scrsVuln struct {
	ID      uuid.UUID
	Status  string
	PURL    string
	IDs     map[string]bool
	Created bool
}

func idSet(advisory string, aliases []string) map[string]bool {
	out := map[string]bool{}
	for _, id := range upperIDs(append([]string{advisory}, aliases...)) {
		out[id] = true
	}
	return out
}

func overlaps(set map[string]bool, ids []string) bool {
	for _, id := range ids {
		if set[id] {
			return true
		}
	}
	return false
}

func (s *Store) loadVulns(ctx context.Context, tx pgx.Tx, asset uuid.UUID, ref, typ string, skipFixed bool) ([]scrsVuln, error) {
	rows, err := tx.Query(ctx, `SELECT id,advisory_id,status,component->>'purl',COALESCE(CASE WHEN jsonb_typeof(guidance->'aliases')='array' THEN guidance->'aliases' END,'[]'::jsonb) FROM `+s.schema+`.findings WHERE asset_id=$1 AND ref=$2 AND type=$3 AND ($4=false OR status<>'fixed')`, asset, ref, typ, skipFixed)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []scrsVuln
	for rows.Next() {
		var v scrsVuln
		var advisory string
		var aliases []byte
		if err := rows.Scan(&v.ID, &advisory, &v.Status, &v.PURL, &aliases); err != nil {
			return nil, err
		}
		var list []string
		_ = json.Unmarshal(aliases, &list)
		v.IDs = idSet(advisory, list)
		v.PURL = normalizePURL(v.PURL)
		out = append(out, v)
	}
	return out, rows.Err()
}

func purlEcosystem(purl string) string {
	rest := strings.TrimPrefix(purl, "pkg:")
	if i := strings.IndexByte(rest, '/'); i > 0 {
		return rest[:i]
	}
	return ""
}

// ApplyDTrackFindings stores one project's findings in the register: joins
// them with SCRS's own entries, records the rest, closes entries
// Dependency-Track no longer reports, imports its triage where the register
// has none, and lists the register's triage to write back.
func (s *Store) ApplyDTrackFindings(ctx context.Context, p DTrackProject, projectUUID string, findings []dtrack.Finding, settings DTrackSettings) (DTrackSyncResult, error) {
	var res DTrackSyncResult
	clusters := clusterDTrackFindings(findings)
	res.Total = len(clusters)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer tx.Rollback(ctx)
	// The database's clock, not this process's: rows stamped during the run
	// are compared with it.
	var started time.Time
	if err := tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&started); err != nil {
		return res, err
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.dtrack_projects SET project_uuid=$2 WHERE id=$1`, p.ID, projectUUID); err != nil {
		return res, err
	}
	scrs, err := s.loadVulns(ctx, tx, p.AssetID, p.Ref, "vulnerability", true)
	if err != nil {
		return res, err
	}
	existing, err := s.loadVulns(ctx, tx, p.AssetID, p.Ref, "dt_vulnerability", false)
	if err != nil {
		return res, err
	}
	var created []Finding
	// imports maps a register entry to the status to import into it.
	imports := map[uuid.UUID]string{}
	linked := map[uuid.UUID]bool{}
	scope := Assessment{AssetID: p.AssetID, Request: Request{Target: Target{Ref: p.Ref}}}
	for _, c := range clusters {
		var findingID uuid.UUID
		matched := false
		for _, v := range scrs {
			if v.PURL == c.PURL && overlaps(v.IDs, c.IDs) {
				findingID, matched = v.ID, true
				break
			}
		}
		if matched {
			res.Matched++
		} else {
			f := Finding{Type: "dt_vulnerability", AdvisoryID: c.Canonical, Severity: c.Severity, Score: severityScore[c.Severity], AssetID: p.AssetID, Ref: p.Ref}
			f.Title = clip(firstOf(c.Title, c.Canonical+" in "+c.Component.ComponentName), 512)
			f.Component = Component{Name: clip(c.Component.ComponentName, 256), Version: clip(c.Component.ComponentVersion, 128), Ecosystem: purlEcosystem(c.PURL), PURL: clip(c.Component.PURL, 512)}
			evidence, _ := json.Marshal(map[string]any{"source": "dependency-track", "analyzers": c.Analyzers, "vulnerability_sources": c.Sources, "cvss": c.CVSS, "cwe": CWEs(cweTexts(c.CWEs)...)})
			aliases := []string{}
			for _, id := range c.IDs {
				if id != c.Canonical {
					aliases = append(aliases, id)
				}
			}
			guidance, _ := json.Marshal(map[string]any{"summary": "Reported by Dependency-Track (" + strings.Join(c.Analyzers, ", ") + "); SCRS's own scan did not report it. Review it in Dependency-Track and upgrade the package.", "reference": c.Reference, "aliases": aliases, "automatic_changes": false})
			f.Evidence, f.Guidance = evidence, guidance
			var reuse *scrsVuln
			for i := range existing {
				if existing[i].PURL == c.PURL && overlaps(existing[i].IDs, c.IDs) {
					reuse = &existing[i]
					break
				}
			}
			component, _ := json.Marshal(f.Component)
			if reuse != nil {
				findingID = reuse.ID
				if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.findings SET title=$2,severity=$3,score=$4,component=$5,evidence=$6,guidance=$7,advisory_id=$8,last_seen=clock_timestamp(),last_assessment_id=$9,status=CASE WHEN status='fixed' OR (status='accepted' AND waiver_until<=clock_timestamp()) THEN 'open' ELSE status END,revision=revision+1 WHERE id=$1`, findingID, f.Title, f.Severity, f.Score, component, f.Evidence, f.Guidance, f.AdvisoryID, p.AssessmentID); err != nil {
					return res, err
				}
				if reuse.Status == "fixed" {
					if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'reopened_by_dependency_track','{}')`, findingID); err != nil {
						return res, err
					}
				}
			} else {
				f.Fingerprint = fingerprint(scope, f)
				f.ID = uuid.NewSHA1(uuid.NameSpaceOID, []byte(f.Fingerprint))
				findingID = f.ID
				var inserted bool
				err := tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance,last_assessment_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) ON CONFLICT(fingerprint) DO UPDATE SET last_seen=clock_timestamp(),last_assessment_id=EXCLUDED.last_assessment_id,evidence=EXCLUDED.evidence,guidance=EXCLUDED.guidance,severity=EXCLUDED.severity,score=EXCLUDED.score,title=EXCLUDED.title,status=CASE WHEN findings.status='fixed' OR (findings.status='accepted' AND findings.waiver_until<=clock_timestamp()) THEN 'open' ELSE findings.status END,revision=findings.revision+1 RETURNING xmax=0`, f.ID, p.AssetID, f.Fingerprint, p.Ref, f.Type, f.AdvisoryID, f.Title, f.Severity, f.Score, component, f.Evidence, f.Guidance, p.AssessmentID).Scan(&inserted)
				if err != nil {
					return res, err
				}
				if inserted {
					created = append(created, f)
					res.Created++
					if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'detected','{"source":"dependency-track"}')`, findingID); err != nil {
						return res, err
					}
				}
				existing = append(existing, scrsVuln{ID: findingID, Status: "open", PURL: c.PURL, IDs: idSet(f.AdvisoryID, aliases)})
			}
		}
		linked[findingID] = true
		fresh := false
		for _, m := range c.Members {
			ids, _ := json.Marshal(upperIDs(m.IDs))
			var inserted bool
			if err := tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.dtrack_findings(project_id,asset_id,component_uuid,vulnerability_uuid,finding_id,matched,vuln_id,vuln_source,analyzer,purl,severity,ids,analysis_state,suppressed) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14) ON CONFLICT(project_id,component_uuid,vulnerability_uuid) DO UPDATE SET finding_id=EXCLUDED.finding_id,matched=EXCLUDED.matched,vuln_id=EXCLUDED.vuln_id,vuln_source=EXCLUDED.vuln_source,analyzer=EXCLUDED.analyzer,purl=EXCLUDED.purl,severity=EXCLUDED.severity,ids=EXCLUDED.ids,analysis_state=EXCLUDED.analysis_state,suppressed=EXCLUDED.suppressed,last_seen=clock_timestamp() RETURNING xmax=0`,
				p.ID, p.AssetID, m.ComponentUUID, m.VulnerabilityUUID, findingID, matched, clip(m.VulnID, 128), clip(m.Source, 32), clip(m.Analyzer, 64), clip(m.PURL, 512), dtSeverity(m.Severity), ids, orNotSetState(m.AnalysisState), m.Suppressed).Scan(&inserted); err != nil {
				return res, err
			}
			fresh = fresh || inserted
		}
		if matched && fresh {
			detail, _ := json.Marshal(map[string]any{"analyzers": c.Analyzers, "vulnerability_sources": c.Sources, "severity": c.Severity})
			if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'corroborated_by_dependency_track',$2)`, findingID, detail); err != nil {
				return res, err
			}
		}
		if status := dtrackImportStatus(c.Members); status != "" {
			imports[findingID] = status
		}
	}

	// Entries Dependency-Track no longer reports. Links first, then the
	// register entries that lost their last link.
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.dtrack_findings WHERE project_id=$1 AND last_seen<$2`, p.ID, started); err != nil {
		return res, err
	}
	rows, err := tx.Query(ctx, `UPDATE `+s.schema+`.findings f SET status='fixed',revision=revision+1 WHERE f.asset_id=$1 AND f.ref=$2 AND f.type='dt_vulnerability' AND f.status IN ('open','triaged','in_progress') AND NOT EXISTS(SELECT 1 FROM `+s.schema+`.dtrack_findings x WHERE x.finding_id=f.id) RETURNING f.id`, p.AssetID, p.Ref)
	if err != nil {
		return res, err
	}
	var closed []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return res, err
		}
		closed = append(closed, id)
	}
	rows.Close()
	for _, id := range closed {
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'fixed_by_dependency_track_sync','{}')`, id); err != nil {
			return res, err
		}
	}
	res.Closed = len(closed)

	if len(created) > 0 {
		var briefs []map[string]any
		for _, f := range created {
			if len(briefs) < 100 {
				briefs = append(briefs, findingBrief(f))
			}
		}
		data := map[string]any{"assessment_id": p.AssessmentID, "asset_id": p.AssetID, "ref": p.Ref, "commit": "", "total": len(created), "truncated": len(created) > len(briefs), "findings": briefs}
		if _, err := notify.EmitScoped(ctx, tx, s.schema, "finding.created", data, nil, notify.Scope{Asset: p.AssetID}); err != nil {
			return res, err
		}
	}

	// Triage to import: only where SCRS has no decision of its own (the entry
	// is open and SCRS never wrote one to Dependency-Track).
	type importItem struct {
		id     uuid.UUID
		status string
	}
	var todo []importItem
	if settings.SyncTriage {
		for id, status := range imports {
			var current string
			var wrote bool
			if err := tx.QueryRow(ctx, `SELECT CASE WHEN f.status='accepted' AND f.waiver_until<=clock_timestamp() THEN 'open' ELSE f.status END,EXISTS(SELECT 1 FROM `+s.schema+`.dtrack_findings x WHERE x.finding_id=f.id AND x.pushed_status<>'') FROM `+s.schema+`.findings f WHERE f.id=$1`, id).Scan(&current, &wrote); err != nil {
				return res, err
			}
			if current == "open" && !wrote {
				todo = append(todo, importItem{id, status})
			}
		}
		sort.Slice(todo, func(i, j int) bool { return todo[i].id.String() < todo[j].id.String() })
	}

	// Triage to write back.
	if settings.SyncTriage {
		prow, err := tx.Query(ctx, `SELECT x.id,x.component_uuid::text,x.vulnerability_uuid::text,CASE WHEN f.status='accepted' AND f.waiver_until<=clock_timestamp() THEN 'open' ELSE f.status END,f.waiver_until,x.pushed_status FROM `+s.schema+`.dtrack_findings x JOIN `+s.schema+`.findings f ON f.id=x.finding_id WHERE x.project_id=$1 ORDER BY x.id`, p.ID)
		if err != nil {
			return res, err
		}
		importing := map[uuid.UUID]bool{}
		for _, it := range todo {
			importing[it.id] = true
		}
		for prow.Next() {
			var id uuid.UUID
			var component, vulnerability, status, pushed string
			var until *time.Time
			if err := prow.Scan(&id, &component, &vulnerability, &status, &until, &pushed); err != nil {
				prow.Close()
				return res, err
			}
			if status == pushed || (status == "open" && pushed == "") {
				continue
			}
			a, ok := dtrackStatusFor(status, until)
			if !ok {
				continue
			}
			a.Project, a.Component, a.Vulnerability = projectUUID, component, vulnerability
			if len(res.Pushes) >= dtrackPushLimit {
				res.MorePushes = true
				break
			}
			res.Pushes = append(res.Pushes, DTrackPush{MemberID: id, Project: projectUUID, Component: component, Vulnerability: vulnerability, Status: status, Analysis: a})
		}
		prow.Close()
	}
	if err := tx.Commit(ctx); err != nil {
		return res, err
	}

	for _, it := range todo {
		err := s.Transition(ctx, it.id, uuid.Nil, it.status, "Imported from the Dependency-Track analysis of this vulnerability.", nil)
		if err != nil {
			continue
		}
		res.Imported++
		// Already in step with Dependency-Track: do not write it back.
		if _, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_findings SET pushed_status=$2 WHERE finding_id=$1`, it.id, it.status); err != nil {
			return res, err
		}
	}
	return res, nil
}

func orNotSetState(s string) string {
	switch s {
	case "EXPLOITABLE", "IN_TRIAGE", "FALSE_POSITIVE", "NOT_AFFECTED", "RESOLVED":
		return s
	}
	return "NOT_SET"
}

func cweTexts(ids []int) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, "CWE-"+strconv.Itoa(id))
	}
	return out
}

// MarkDTrackPushed records that a decision reached Dependency-Track.
func (s *Store) MarkDTrackPushed(ctx context.Context, member uuid.UUID, status string) error {
	_, err := s.pool.Exec(ctx, `UPDATE `+s.schema+`.dtrack_findings SET pushed_status=$2 WHERE id=$1`, member, status)
	return err
}

// ---- listing ----

// DTrackFinding is one Dependency-Track finding and its register entry.
type DTrackFinding struct {
	ID                  uuid.UUID  `json:"id"`
	AssetID             uuid.UUID  `json:"asset_id"`
	Project             string     `json:"project"`
	Version             string     `json:"version"`
	FindingID           *uuid.UUID `json:"finding_id,omitempty"`
	Matched             bool       `json:"matched"`
	VulnerabilityID     string     `json:"vulnerability_id"`
	VulnerabilitySource string     `json:"vulnerability_source,omitempty"`
	Analyzer            string     `json:"analyzer,omitempty"`
	IDs                 []string   `json:"ids"`
	PURL                string     `json:"purl,omitempty"`
	Severity            string     `json:"severity"`
	AnalysisState       string     `json:"analysis_state"`
	Suppressed          bool       `json:"suppressed"`
	PushedStatus        string     `json:"pushed_status,omitempty"`
	FirstSeen           time.Time  `json:"first_seen"`
	LastSeen            time.Time  `json:"last_seen"`
}

// DTrackFindings lists Dependency-Track findings by id, optionally for one
// asset and only matched (also reported by SCRS) or only unmatched ones.
func (s *Store) DTrackFindings(ctx context.Context, asset uuid.UUID, matched *bool, after uuid.UUID, limit int) ([]DTrackFinding, error) {
	rows, err := s.pool.Query(ctx, `SELECT x.id,x.asset_id,p.project_name,p.project_version,x.finding_id,x.matched,x.vuln_id,x.vuln_source,x.analyzer,x.ids,x.purl,x.severity,x.analysis_state,x.suppressed,x.pushed_status,x.first_seen,x.last_seen FROM `+s.schema+`.dtrack_findings x JOIN `+s.schema+`.dtrack_projects p ON p.id=x.project_id WHERE x.id>$1 AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR x.asset_id=$2) AND ($3::boolean IS NULL OR x.matched=$3) ORDER BY x.id LIMIT $4`, after, asset, matched, limit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DTrackFinding{}
	for rows.Next() {
		var f DTrackFinding
		var ids []byte
		if err := rows.Scan(&f.ID, &f.AssetID, &f.Project, &f.Version, &f.FindingID, &f.Matched, &f.VulnerabilityID, &f.VulnerabilitySource, &f.Analyzer, &ids, &f.PURL, &f.Severity, &f.AnalysisState, &f.Suppressed, &f.PushedStatus, &f.FirstSeen, &f.LastSeen); err != nil {
			return nil, err
		}
		f.IDs = []string{}
		_ = json.Unmarshal(ids, &f.IDs)
		out = append(out, f)
	}
	return out, rows.Err()
}
