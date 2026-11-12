package assessments

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
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
)
var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var commitPattern = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)

type Target struct {
	Type       string `json:"type"`
	Repository string `json:"repository"`
	Ref        string `json:"ref,omitempty"`
	Commit     string `json:"commit,omitempty"`
}
type RemediationRequest struct {
	Manifest string    `json:"manifest"`
	Strategy string    `json:"strategy"`
	Parent   uuid.UUID `json:"parent_assessment_id"`
}

type Request struct {
	Remediation *RemediationRequest `json:"remediation,omitempty"`
	Target      Target              `json:"target"`
	Connection  string              `json:"connection,omitempty"`
	Trigger     struct {
		Origin     string `json:"origin,omitempty"`
		Event      string `json:"event,omitempty"`
		DeliveryID string `json:"delivery_id,omitempty"`
		Actor      string `json:"actor,omitempty"`
	} `json:"trigger,omitempty"`
}

func (r *Request) Validate() error {
	if r.Target.Type != "git" || !repositoryPattern.MatchString(r.Target.Repository) || len(r.Target.Ref) > 255 || strings.ContainsAny(r.Target.Ref, "\x00\r\n") || len(r.Connection) > 100 {
		return ErrInput
	}
	if r.Target.Commit != "" && !commitPattern.MatchString(r.Target.Commit) {
		return ErrInput
	}
	if r.Target.Ref == "" && r.Target.Commit == "" {
		r.Target.Ref = "HEAD"
	}
	if len(r.Trigger.Origin) > 100 || len(r.Trigger.Event) > 100 || len(r.Trigger.DeliveryID) > 128 || len(r.Trigger.Actor) > 100 {
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
	ActorID            uuid.UUID      `json:"-"`
	ID                 uuid.UUID      `json:"id"`
	AssetID            uuid.UUID      `json:"asset_id"`
	ConnectionID       uuid.UUID      `json:"connection_id"`
	ConnectionRevision int64          `json:"-"`
	Request            Request        `json:"request"`
	RequestedBy        string         `json:"requested_by"`
	Status             string         `json:"status"`
	Verdict            string         `json:"verdict"`
	Commit             string         `json:"resolved_commit,omitempty"`
	RefMoved           bool           `json:"ref_moved"`
	Stages             []Stage        `json:"stages"`
	Counts             map[string]int `json:"counts"`
	CreatedAt          time.Time      `json:"created_at"`
	CompletedAt        *time.Time     `json:"completed_at,omitempty"`
	Error              string         `json:"error,omitempty"`
	Attempts           int            `json:"attempts"`
	Lease              uuid.UUID      `json:"-"`
	SBOMKey            string         `json:"-"`
	SBOMSHA256         string         `json:"sbom_sha256,omitempty"`
}
type Component struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
	Path      string `json:"path"`
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
}
type Result struct {
	Commit     string
	RefMoved   bool
	Stages     []Stage
	Components []Component
	Findings   []Finding
	SBOMKey    string
	SBOMSHA256 string
	Complete   bool
}

func Hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func fingerprint(a Assessment, f Finding) string {
	return Hash([]byte(a.AssetID.String() + "\x00" + a.Request.Target.Ref + "\x00" + f.Type + "\x00" + f.AdvisoryID + "\x00" + f.Component.PURL + "\x00" + f.Component.Path))
}
func verdict(r Result) (string, map[string]int) {
	v := "pass"
	counts := map[string]int{"total": len(r.Findings)}
	for _, f := range r.Findings {
		counts[f.Severity]++
		if f.Severity == "critical" || f.Type == "malware" || f.Type == "malicious_dependency" || f.Type == "integrity" {
			v = "fail"
		} else if f.Severity == "high" && v == "pass" {
			v = "warn"
		}
	}
	if !r.Complete {
		v = "incomplete"
	}
	return v, counts
}
