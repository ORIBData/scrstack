package assessments

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInput     = errors.New("invalid assessment request")
	ErrScope     = errors.New("asset_not_registered_or_out_of_scope")
	ErrConflict  = errors.New("idempotency_conflict")
	ErrAmbiguous = errors.New("ambiguous connection; specify connection")
	ErrCapacity  = errors.New("queue capacity exceeded")
	ErrNotFound  = errors.New("not found")
	ErrLease     = errors.New("assessment lease no longer valid")
	// ErrBusy means the asset has a running assessment; retry shortly.
	ErrBusy = errors.New("asset has a running assessment")
)

// A git repository is owner/name on GitHub, or group[/subgroup...]/name on GitLab.
var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*){1,7}$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commitPattern = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

// An image locator is registry host plus repository path, as discovery records it.
var imagePattern = regexp.MustCompile(`^[a-z0-9.-]+(:[0-9]+)?(/[a-z0-9._-]+)+$`)
var contextKey = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

// validContext bounds trigger context: at most 20 keys, short printable values.
func validContext(c map[string]string) bool {
	if len(c) > 20 {
		return false
	}
	for k, v := range c {
		if !contextKey.MatchString(k) || len(v) > 256 || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
			return false
		}
	}
	return true
}

var tagPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._-]{0,127}$`)
var imageDigestPattern = regexp.MustCompile(`^sha256:[a-f0-9]{64}$`)
var platformPattern = regexp.MustCompile(`^linux/(amd64|arm64|arm/v7|386|ppc64le|s390x)$`)

// revisionPattern accepts a git commit or an image manifest digest.
func validRevision(v string) bool {
	return commitPattern.MatchString(v) || imageDigestPattern.MatchString(v)
}

type Target struct {
	Type        string       `json:"type"`
	Repository  string       `json:"repository"`
	Ref         string       `json:"ref,omitempty"`
	Commit      string       `json:"commit,omitempty"`
	PullRequest *PullRequest `json:"pull_request,omitempty"`
	// Platform selects one image of a multi-architecture index (image targets).
	Platform string `json:"platform,omitempty"`
	// Provider narrows a git target to "github" or "gitlab" when both hold
	// the same repository path; empty matches either.
	Provider string `json:"provider,omitempty"`
}

// assetTypes maps a target to the asset types that may satisfy it.
func (t Target) assetTypes() []string {
	switch {
	case t.Type == "image":
		return []string{"container_image"}
	case t.Type == "upload":
		return []string{"uploaded"}
	case t.Provider == "github":
		return []string{"github_repo"}
	case t.Provider == "gitlab":
		return []string{"gitlab_repo"}
	}
	return []string{"github_repo", "gitlab_repo"}
}

// PullRequest targets a PR head commit (UC8). Ref becomes "pull/<number>" and
// the base ref supplies the baseline for new-versus-existing findings.
type PullRequest struct {
	Number  int    `json:"number"`
	BaseRef string `json:"base_ref"`
	HeadRef string `json:"head_ref,omitempty"`
	Title   string `json:"title,omitempty"`
}
type RemediationRequest struct {
	Manifest string    `json:"manifest"`
	Strategy string    `json:"strategy"`
	Parent   uuid.UUID `json:"parent_assessment_id"`
}

type Request struct {
	AutoRemediation bool `json:"auto_remediation,omitempty"`
	// SkipQA exempts this assessment from the QA runs the asset's profile
	// queues after an assessment. QA is otherwise part of every assessment
	// of an asset with an enabled, auto-run profile.
	SkipQA      bool                `json:"skip_qa,omitempty"`
	Remediation *RemediationRequest `json:"remediation,omitempty"`
	// Import is set by Store.Import; API callers cannot supply it.
	Import     *ImportSource `json:"import,omitempty"`
	Target     Target        `json:"target"`
	Connection string        `json:"connection,omitempty"`
	Notify     []string      `json:"notify,omitempty"`
	Trigger    struct {
		Origin     string `json:"origin,omitempty"`
		Event      string `json:"event,omitempty"`
		DeliveryID string `json:"delivery_id,omitempty"`
		Actor      string `json:"actor,omitempty"`
		// Context is caller correlation data (ticket, change request, n8n
		// execution) echoed in outbound events. It never affects the scan.
		Context map[string]string `json:"context,omitempty"`
	} `json:"trigger,omitempty"`
}

// uploadLocator is how an uploaded asset is named: `upload/<name>`.
var uploadLocatorPattern = regexp.MustCompile(`^upload/[a-z0-9][a-z0-9._-]{0,99}$`)

func (r *Request) Validate() error {
	if r.Target.Type == "upload" {
		// Upload targets: Repository holds the asset locator, Commit the first
		// 40 hex digits of the archive's SHA-256 and Ref a free label.
		r.Target.Repository = strings.ToLower(r.Target.Repository)
		r.Target.Commit = strings.ToLower(r.Target.Commit)
		if r.Target.Ref == "" {
			r.Target.Ref = "upload"
		}
		if !uploadLocatorPattern.MatchString(r.Target.Repository) || !commitPattern.MatchString(r.Target.Commit) || !tagPattern.MatchString(r.Target.Ref) || r.Target.PullRequest != nil || r.Target.Provider != "" || r.Target.Platform != "" || len(r.Connection) > 100 || len(r.Notify) > 10 {
			return ErrInput
		}
		if len(r.Trigger.Origin) > 100 || len(r.Trigger.Event) > 100 || len(r.Trigger.DeliveryID) > 128 || len(r.Trigger.Actor) > 100 || !validContext(r.Trigger.Context) {
			return ErrInput
		}
		return nil
	}
	if r.Target.Type == "image" {
		// Image targets: Repository holds the locator, Ref the tag, Commit the digest.
		r.Target.Repository = strings.ToLower(r.Target.Repository)
		if r.Target.Ref == "" && r.Target.Commit == "" {
			r.Target.Ref = "latest"
		}
		if r.Target.Platform == "" {
			r.Target.Platform = "linux/amd64"
		}
		if !imagePattern.MatchString(r.Target.Repository) || len(r.Target.Repository) > 255 || (r.Target.Ref != "" && !tagPattern.MatchString(r.Target.Ref)) || (r.Target.Commit != "" && !imageDigestPattern.MatchString(r.Target.Commit)) || !platformPattern.MatchString(r.Target.Platform) || r.Target.PullRequest != nil || r.Target.Provider != "" || len(r.Connection) > 100 || len(r.Notify) > 10 {
			return ErrInput
		}
		if len(r.Trigger.Origin) > 100 || len(r.Trigger.Event) > 100 || len(r.Trigger.DeliveryID) > 128 || len(r.Trigger.Actor) > 100 || !validContext(r.Trigger.Context) {
			return ErrInput
		}
		return nil
	}
	if r.Target.Type != "git" || !repositoryPattern.MatchString(r.Target.Repository) || len(r.Target.Repository) > 255 || (r.Target.Provider != "" && r.Target.Provider != "github" && r.Target.Provider != "gitlab") || len(r.Target.Ref) > 255 || strings.ContainsAny(r.Target.Ref, "\x00\r\n") || len(r.Connection) > 100 {
		return ErrInput
	}
	if r.Target.Commit != "" && !commitPattern.MatchString(r.Target.Commit) {
		return ErrInput
	}
	if pr := r.Target.PullRequest; pr != nil {
		// A PR assessment pins the head commit; the PR ref is a label, not resolved.
		if pr.Number <= 0 || r.Target.Commit == "" || pr.BaseRef == "" || len(pr.BaseRef) > 255 || len(pr.HeadRef) > 255 || len(pr.Title) > 512 || strings.ContainsAny(pr.BaseRef+pr.HeadRef, "\x00\r\n") {
			return ErrInput
		}
		r.Target.Ref = "pull/" + strconv.Itoa(pr.Number)
	}
	if r.Target.Ref == "" && r.Target.Commit == "" {
		r.Target.Ref = "HEAD"
	}
	if len(r.Notify) > 10 {
		return ErrInput
	}
	for _, name := range r.Notify {
		if name == "" || len(name) > 100 {
			return ErrInput
		}
	}
	if len(r.Trigger.Origin) > 100 || len(r.Trigger.Event) > 100 || len(r.Trigger.DeliveryID) > 128 || len(r.Trigger.Actor) > 100 || !validContext(r.Trigger.Context) {
		return ErrInput
	}
	r.Target.Repository = strings.ToLower(r.Target.Repository)
	r.Target.Commit = strings.ToLower(r.Target.Commit)
	return nil
}

type Stage struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}
type Assessment struct {
	ActorID            uuid.UUID       `json:"-"`
	ID                 uuid.UUID       `json:"id"`
	AssetID            uuid.UUID       `json:"asset_id"`
	ConnectionID       uuid.UUID       `json:"connection_id"`
	ConnectionRevision int64           `json:"-"`
	Request            Request         `json:"request"`
	RequestedBy        string          `json:"requested_by"`
	Status             string          `json:"status"`
	Verdict            string          `json:"verdict"`
	Commit             string          `json:"resolved_commit,omitempty"`
	RefMoved           bool            `json:"ref_moved"`
	Stages             []Stage         `json:"stages"`
	Counts             map[string]int  `json:"counts"`
	CreatedAt          time.Time       `json:"created_at"`
	CompletedAt        *time.Time      `json:"completed_at,omitempty"`
	Error              string          `json:"error,omitempty"`
	Attempts           int             `json:"attempts"`
	Lease              uuid.UUID       `json:"-"`
	SBOMKey            string          `json:"-"`
	SBOMSHA256         string          `json:"sbom_sha256,omitempty"`
	Diff               json.RawMessage `json:"diff,omitempty"`
	RequestID          string          `json:"request_id,omitempty"`
	SnapshotKey        string          `json:"-"`
}
type Component struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
	Path      string `json:"path"`
	// Groups are the lockfile's dependency groups, such as "dev".
	Groups []string `json:"dependency_groups,omitempty"`
	// License is the component's licence (LIC-001); nil when unknown.
	License *ComponentLicense `json:"license,omitempty"`
}

// Dev reports a development-only dependency.
func (c Component) Dev() bool {
	for _, g := range c.Groups {
		if g == "dev" {
			return true
		}
	}
	return false
}

// ComponentLicense records a component's licence and where it came from
// (LIC-001): "declared" (manifest, lockfile or package database),
// "detected" (licence file text) or "metadata" (deps.dev).
type ComponentLicense struct {
	// Expression is a normalised SPDX license expression or NOASSERTION.
	Expression string `json:"expression"`
	Source     string `json:"source"`
	// Declared is the licence text as found, when it differs.
	Declared string `json:"declared,omitempty"`
	// Confidence is set for detected licences (0 to 1).
	Confidence float64 `json:"confidence,omitempty"`
	// Evidence is the file the licence came from, or the metadata service.
	Evidence  string            `json:"evidence,omitempty"`
	Copyright []string          `json:"copyright,omitempty"`
	Refs      map[string]string `json:"refs,omitempty"`
}
type Finding struct {
	ID          uuid.UUID       `json:"id"`
	AssetID     uuid.UUID       `json:"asset_id"`
	Fingerprint string          `json:"fingerprint"`
	Ref         string          `json:"ref"`
	Type        string          `json:"type"`
	AdvisoryID  string          `json:"advisory_id"`
	Title       string          `json:"title"`
	Severity    string          `json:"severity"`
	Score       int             `json:"score"`
	Status      string          `json:"status"`
	Component   Component       `json:"component"`
	Evidence    json.RawMessage `json:"evidence"`
	Guidance    json.RawMessage `json:"guidance"`
	FirstSeen   time.Time       `json:"first_seen"`
	LastSeen    time.Time       `json:"last_seen"`
	WaiverUntil *time.Time      `json:"waiver_until,omitempty"`
	// Assignee is who the entry is assigned to (free text; empty when
	// unassigned) and CommentCount how many comments it has. Both are read
	// live from the register, not from an assessment's frozen snapshot.
	Assignee     string     `json:"assignee,omitempty"`
	AssignedAt   *time.Time `json:"assigned_at,omitempty"`
	CommentCount int        `json:"comment_count,omitempty"`
	// SourceRepository is the repository a container image was built from
	// (CON-012), when one is linked; empty for other assets.
	SourceRepository string `json:"source_repository,omitempty"`
	// Change is "new" or "existing" relative to the baseline assessment.
	Change string `json:"change,omitempty"`
}
type FileEvidence struct {
	Path    string `json:"path"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
	Malware string `json:"malware"`
}

type Result struct {
	Files      []FileEvidence
	Commit     string
	RefMoved   bool
	Stages     []Stage
	Components []Component
	Findings   []Finding
	SBOMKey    string
	SBOMSHA256 string
	Complete   bool
	// SASTTools are the analyzers that ran with full coverage; only their
	// entries can close by absence (an analyzer deselected for the asset
	// did not look, so its entries stay open).
	SASTTools []string
	// SASTDisabledRules and SASTExcludes are the filters applied to this
	// run: entries they hide are suppressed by configuration, not fixed.
	SASTDisabledRules []string
	SASTExcludes      []string
	// ProjectLicense is the repository's own detected licence; dependencies
	// are checked against it for outbound compatibility (LIC-005).
	ProjectLicense *ComponentLicense
}

func Hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func fingerprint(a Assessment, f Finding) string {
	return Hash([]byte(a.AssetID.String() + "\x00" + a.Request.Target.Ref + "\x00" + f.Type + "\x00" + f.AdvisoryID + "\x00" + f.Component.PURL + "\x00" + f.Component.Path))
}

// verdict applies the default gate (TRG-006, MAL-007). A positive detection is
// never hidden behind partial coverage: fail outranks incomplete. Malicious
// content fails whether new or existing. A new critical or high integrity entry
// fails; a new medium one, or an existing serious one, warns. A new critical
// vulnerability fails and a new high warns; a critical already present in the
// baseline still warns (stricter than "pass otherwise"), an existing high does
// not gate.
// Waived findings (keyed by fingerprint) do not gate, except that malicious
// content never drops below warn. Threat-intelligence findings carry their
// source's mode in the type: yara_match and ioc_match block like malware,
// yara_alert and ioc_alert gate by severity like a vulnerability, and
// yara_hunt and ioc_hunt never gate. E2E QA findings (qa_*) are
// report-only. SAST entries gate only when new (a new critical fails, a new
// high warns) and never when suppressed in code. Licence entries follow the licence policy: while it is
// report-only a deny warns; once enforcing, deny fails and review warns.
func verdict(r Result, waived map[string]bool) (string, map[string]int) {
	failing, warning := false, false
	counts := map[string]int{"total": len(r.Findings)}
	for _, f := range r.Findings {
		counts[f.Severity]++
		if f.Change == "new" {
			counts["new"]++
		}
		if huntOnly(f.Type) {
			counts["hunt"]++
			continue
		}
		if reportOnly(f.Type) {
			counts["qa"]++
			continue
		}
		malicious := maliciousType(f.Type)
		if waived[f.Fingerprint] {
			counts["waived"]++
			warning = warning || malicious
			continue
		}
		existing := f.Change == "existing"
		serious := f.Severity == "critical" || f.Severity == "high"
		switch {
		case malicious:
			failing = true
		case f.Type == "integrity" && !existing && serious:
			failing = true
		case f.Type == "integrity":
			warning = warning || serious || !existing
		case f.Type == "sast":
			// Only new SAST entries gate; inline-suppressed ones never do.
			fail, warn, suppressed := sastGate(f)
			if suppressed {
				counts["suppressed_in_code"]++
			}
			failing, warning = failing || fail, warning || warn
		case f.Type == "license":
			// Licence entries gate by policy result, new or existing.
			counts["license"]++
			fail, warn := licenseGate(f)
			failing, warning = failing || fail, warning || warn
		case f.Severity == "critical" && !existing:
			failing = true
		case f.Severity == "critical" || (f.Severity == "high" && !existing):
			warning = true
		}
	}
	switch {
	case failing:
		return "fail", counts
	case !r.Complete:
		return "incomplete", counts
	case warning:
		return "warn", counts
	}
	return "pass", counts
}

// maliciousType reports finding types that fail the gate whether new or existing.
func maliciousType(t string) bool {
	return t == "malware" || t == "malicious_dependency" || t == "ioc_match" || t == "yara_match"
}

// huntOnly reports findings recorded for threat hunting that never gate.
func huntOnly(t string) bool { return t == "yara_hunt" || t == "ioc_hunt" }

// reportOnly reports E2E QA findings (qa_failure, qa_untested,
// qa_performance, qa_config, qa_unconfigured) and AI code review entries
// (ai_review): they inform, never gate.
func reportOnly(t string) bool { return strings.HasPrefix(t, "qa_") || t == "ai_review" }

// closableTypes lists finding types whose producing stages all completed, so
// their absence from this scan is evidence of a fix rather than lost coverage.
func closableTypes(stages []Stage) []string {
	ok := map[string]bool{}
	for _, s := range stages {
		ok[s.Name] = s.Status == "ok"
	}
	producers := map[string][]string{
		"vulnerability":         {"inventory", "sbom", "match_vuln"},
		"malicious_dependency":  {"inventory", "match_malicious"},
		"malware":               {"malware"},
		"posture":               {"malware"},
		"ioc_match":             {"ioc"},
		"ioc_alert":             {"ioc"},
		"ioc_hunt":              {"ioc"},
		"integrity":             {"integrity"},
		"yara_match":            {"yara_x"},
		"yara_alert":            {"yara_x"},
		"yara_hunt":             {"yara_x"},
		"qa_unconfigured":       {"integrity"},
		"license":               {"inventory", "license"},
		"suspicious_dependency": {"inventory", "dependency_policy"},
		"sast":                  {"sast"},
	}
	types := []string{}
	for kind, needed := range producers {
		closable := ok["resolve"] && ok["fetch"]
		for _, stage := range needed {
			closable = closable && ok[stage]
		}
		if closable {
			types = append(types, kind)
		}
	}
	return types
}
