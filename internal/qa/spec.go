// Package qa is the E2E QA module's shared core: the protocol between SCRS
// and the Karate runner, bundle archives, report parsing (Karate JSON Lines,
// JUnit XML, Gatling), OpenAPI coverage, and the checks and prompts for
// LLM-generated tests.
package qa

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Job kinds: a functional run executes Karate features once; a performance
// run executes chosen features under load with karate-gatling.
const (
	KindFunctional  = "functional"
	KindPerformance = "performance"
)

// Runner job states. Passed and failed mean the tests ran and reports
// exist; error means they could not run.
const (
	StateQueued    = "queued"
	StateRunning   = "running"
	StatePassed    = "passed"
	StateFailed    = "failed"
	StateError     = "error"
	StateCancelled = "cancelled"
)

// Finished reports a terminal runner state.
func Finished(state string) bool {
	return state == StatePassed || state == StateFailed || state == StateError || state == StateCancelled
}

// Suite is one top-level bundle directory run as its own Karate project,
// with its own karate-config.js: "repo" holds the repository's tests and
// "generated" the approved SCRS-generated features.
type Suite struct {
	Dir  string   `json:"dir"`
	Tags []string `json:"tags,omitempty"`
}

// Perf is a performance run's load profile and pass thresholds.
type Perf struct {
	// Features are paths inside the repo suite run under load.
	Features        []string `json:"features"`
	Users           int      `json:"users"`
	RampSeconds     int      `json:"ramp_seconds"`
	DurationSeconds int      `json:"duration_seconds"`
	P95Millis       int      `json:"p95_millis"`
	MaxErrorPercent int      `json:"max_error_percent"`
}

// JobSpec is what SCRS sends with a bundle. Variables are secrets: the
// runner passes them to the tests as QA_<NAME> environment variables and
// redacts their values from every report.
type JobSpec struct {
	ID             string            `json:"id"`
	Kind           string            `json:"kind"`
	BaseURL        string            `json:"base_url"`
	Env            string            `json:"env,omitempty"`
	Threads        int               `json:"threads"`
	TimeoutSeconds int               `json:"timeout_seconds"`
	Suites         []Suite           `json:"suites"`
	Variables      map[string]string `json:"variables,omitempty"`
	Perf           *Perf             `json:"perf,omitempty"`
}

var (
	jobID        = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
	envName      = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
	tagExpr      = regexp.MustCompile(`^~?@[A-Za-z0-9_.=:-]{1,64}(,~?@[A-Za-z0-9_.=:-]{1,64}){0,7}$`)
	variableName = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	suiteDir     = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}$`)
)

// ValidBaseURL checks a target URL: http or https, a host, no credentials,
// query or fragment.
func ValidBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(raw) > 2048 {
		return errors.New("base_url must be an http or https URL without credentials, query or fragment")
	}
	return nil
}

// ValidTags checks Karate tag expressions: each entry is ANDed, commas OR.
func ValidTags(tags []string) error {
	if len(tags) > 8 {
		return errors.New("at most 8 tag expressions")
	}
	for _, t := range tags {
		if !tagExpr.MatchString(t) {
			return fmt.Errorf("tag expression %q must look like @smoke, ~@slow or @a,@b", t)
		}
	}
	return nil
}

// ValidVariables checks secret names and sizes.
func ValidVariables(vars map[string]string) error {
	if len(vars) > 32 {
		return errors.New("at most 32 variables")
	}
	for name, value := range vars {
		if !variableName.MatchString(name) {
			return fmt.Errorf("variable %q must be upper case letters, digits and underscores", name)
		}
		if len(value) > 8192 || strings.ContainsRune(value, 0) {
			return fmt.Errorf("variable %s is too long or contains NUL", name)
		}
	}
	return nil
}

// ValidFeaturePath checks a feature path relative to a suite.
func ValidFeaturePath(p string) bool {
	return p != "" && len(p) <= 512 && strings.HasSuffix(p, ".feature") && !strings.ContainsAny(p, "\\\x00,") && path.Clean(p) == p && !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "../") && p != ".."
}

// Validate checks a spec before the runner accepts it.
func (s JobSpec) Validate() error {
	switch {
	case !jobID.MatchString(s.ID):
		return errors.New("id must be a lower-case UUID")
	case s.Kind != KindFunctional && s.Kind != KindPerformance:
		return errors.New("kind must be functional or performance")
	case s.Env != "" && !envName.MatchString(s.Env):
		return errors.New("env must be a short lower-case name")
	case s.Threads < 1 || s.Threads > 16:
		return errors.New("threads must be 1 to 16")
	case s.TimeoutSeconds < 30 || s.TimeoutSeconds > 7200:
		return errors.New("timeout_seconds must be 30 to 7200")
	case len(s.Suites) == 0 || len(s.Suites) > 4:
		return errors.New("one to four suites")
	}
	if err := ValidBaseURL(s.BaseURL); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, suite := range s.Suites {
		if !suiteDir.MatchString(suite.Dir) || seen[suite.Dir] {
			return errors.New("suite dir must be a unique lower-case name")
		}
		seen[suite.Dir] = true
		if err := ValidTags(suite.Tags); err != nil {
			return err
		}
	}
	if err := ValidVariables(s.Variables); err != nil {
		return err
	}
	if s.Kind == KindPerformance {
		if s.Perf == nil {
			return errors.New("a performance job needs perf settings")
		}
		return s.Perf.Validate()
	}
	if s.Perf != nil {
		return errors.New("perf settings belong to performance jobs")
	}
	return nil
}

// Validate checks a load profile.
func (p Perf) Validate() error {
	switch {
	case len(p.Features) == 0 || len(p.Features) > 20:
		return errors.New("perf.features lists 1 to 20 feature paths")
	case p.Users < 1 || p.Users > 500:
		return errors.New("perf.users must be 1 to 500")
	case p.RampSeconds < 0 || p.RampSeconds > 3600:
		return errors.New("perf.ramp_seconds must be 0 to 3600")
	case p.DurationSeconds < 5 || p.DurationSeconds > 3600:
		return errors.New("perf.duration_seconds must be 5 to 3600")
	case p.P95Millis < 1 || p.P95Millis > 600000:
		return errors.New("perf.p95_millis must be 1 to 600000")
	case p.MaxErrorPercent < 0 || p.MaxErrorPercent > 100:
		return errors.New("perf.max_error_percent must be 0 to 100")
	}
	for _, f := range p.Features {
		if !ValidFeaturePath(f) {
			return fmt.Errorf("perf feature %q must be a relative .feature path", f)
		}
	}
	return nil
}

// JobStatus is the runner's view of a job.
type JobStatus struct {
	ID         string     `json:"id"`
	Kind       string     `json:"kind"`
	State      string     `json:"state"`
	ExitCode   *int       `json:"exit_code,omitempty"`
	Error      string     `json:"error,omitempty"`
	QueuedAt   time.Time  `json:"queued_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	// ReportSHA256 is the digest of the report archive once finished.
	ReportSHA256 string `json:"report_sha256,omitempty"`
	ReportBytes  int64  `json:"report_bytes,omitempty"`
	// Truncated reports that HTML reports were left out to fit the limit.
	Truncated bool `json:"truncated,omitempty"`
}

// Info describes a runner.
type Info struct {
	Karate  string `json:"karate"`
	Gatling bool   `json:"gatling"`
	Slots   int    `json:"slots"`
	Queued  int    `json:"queued"`
	Running int    `json:"running"`
}

// MaxBundleBytes and MaxReportBytes bound the archives on the wire.
const (
	MaxBundleBytes = 32 << 20
	MaxReportBytes = 64 << 20
)
