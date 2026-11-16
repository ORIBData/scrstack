// Package qarunner is the Karate runner: a small REST service on an
// operator-managed host that SCRS submits QA jobs to. It runs each job's
// Karate suites with karate-cli (or a performance profile with
// karate-gatling), redacts secrets from the output and serves the reports
// as one archive. Jobs live in memory and on local disk; after a restart
// SCRS resubmits whatever the runner no longer knows.
package qarunner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ORIBData/scrstack/internal/qa"
)

// Config is the runner's operator configuration.
type Config struct {
	// Token authenticates SCRS (Authorization: Bearer); 32+ characters.
	Token   string
	WorkDir string
	// Slots is the number of jobs run at once; MaxQueued bounds waiting jobs.
	Slots, MaxQueued int
	// Karate is the karate-cli command (or java -jar karate.jar).
	Karate []string
	// Java and PerfClasspath run karate-gatling; an empty classpath disables
	// performance jobs.
	Java          string
	PerfClasspath string
	// KarateVersion is reported by /v1/info.
	KarateVersion string
	// JobUID and JobGID, when non-zero, run test processes as another user
	// so they cannot read the runner's token or other jobs' files.
	JobUID, JobGID int
	// Retention keeps finished jobs' reports for SCRS to collect.
	Retention time.Duration
	// PassEnv names runner environment variables test processes inherit.
	PassEnv []string
	Logger  *slog.Logger
}

type job struct {
	spec       qa.JobSpec
	digest     string
	status     qa.JobStatus
	dir        string
	cancel     context.CancelFunc
	cancelled  bool
	finishedAt time.Time
}

// Server holds the job table.
type Server struct {
	cfg   Config
	mu    sync.Mutex
	jobs  map[string]*job
	queue chan *job

	healthMu     sync.Mutex
	healthUntil  time.Time
	healthFailed []string
}

// New prepares a runner; it clears WorkDir, since jobs do not survive a
// restart.
func New(cfg Config) (*Server, error) {
	if len(cfg.Token) < 32 {
		return nil, errors.New("SCRS_QA_RUNNER_TOKEN must be at least 32 characters")
	}
	if cfg.Slots < 1 {
		cfg.Slots = 1
	}
	if cfg.MaxQueued < 1 {
		cfg.MaxQueued = 20
	}
	if len(cfg.Karate) == 0 {
		cfg.Karate = []string{"karate"}
	}
	if cfg.Java == "" {
		cfg.Java = "java"
	}
	if cfg.Retention <= 0 {
		cfg.Retention = 24 * time.Hour
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o711); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(cfg.WorkDir)
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		_ = os.RemoveAll(filepath.Join(cfg.WorkDir, e.Name()))
	}
	return &Server{cfg: cfg, jobs: map[string]*job{}, queue: make(chan *job, cfg.MaxQueued)}, nil
}

// Run executes queued jobs on cfg.Slots workers and prunes old ones.
func (s *Server) Run(ctx context.Context) {
	for range s.cfg.Slots {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-s.queue:
					s.execute(ctx, j)
				}
			}
		}()
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
			s.prune(time.Now())
		}
	}
}

func (s *Server) prune(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, j := range s.jobs {
		if qa.Finished(j.status.State) && now.Sub(j.finishedAt) > s.cfg.Retention {
			_ = os.RemoveAll(j.dir)
			delete(s.jobs, id)
		}
	}
}

// Handler serves the runner API.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		if failed := s.healthFailures(); len(failed) > 0 {
			writeJSON(w, 503, map[string]any{"status": "unavailable", "failed": failed})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /v1/info", s.auth(http.HandlerFunc(s.info)))
	mux.Handle("POST /v1/jobs", s.auth(http.HandlerFunc(s.submit)))
	mux.Handle("GET /v1/jobs/{id}", s.auth(http.HandlerFunc(s.get)))
	mux.Handle("GET /v1/jobs/{id}/report", s.auth(http.HandlerFunc(s.report)))
	mux.Handle("DELETE /v1/jobs/{id}", s.auth(http.HandlerFunc(s.remove)))
	return mux
}

// healthFailures names the runner's own prerequisites that are broken: the
// Karate command, a writable work directory and, when performance jobs are
// enabled, Java and the Gatling classpath. A full queue is not a failure, so
// a busy runner is never restarted. Results are cached for 10 s because the
// probe is public and polled. Names only; paths stay out of the response.
func (s *Server) healthFailures() []string {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if time.Now().Before(s.healthUntil) {
		return s.healthFailed
	}
	failed := []string{}
	if _, err := exec.LookPath(s.cfg.Karate[0]); err != nil {
		failed = append(failed, "karate")
	}
	if f, err := os.CreateTemp(s.cfg.WorkDir, ".health-*"); err != nil {
		failed = append(failed, "work_dir")
	} else {
		_ = f.Close()
		_ = os.Remove(f.Name())
	}
	if s.cfg.PerfClasspath != "" {
		if _, err := exec.LookPath(s.cfg.Java); err != nil {
			failed = append(failed, "java")
		}
		for _, entry := range filepath.SplitList(s.cfg.PerfClasspath) {
			if _, err := os.Stat(strings.TrimSuffix(entry, "/*")); err != nil {
				failed = append(failed, "gatling_classpath")
				break
			}
		}
	}
	s.healthFailed, s.healthUntil = failed, time.Now().Add(10*time.Second)
	return failed
}

func (s *Server) auth(next http.Handler) http.Handler {
	want := []byte("Bearer " + s.cfg.Token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) info(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	info := qa.Info{Karate: s.cfg.KarateVersion, Gatling: s.cfg.PerfClasspath != "", Slots: s.cfg.Slots}
	for _, j := range s.jobs {
		switch j.status.State {
		case qa.StateQueued:
			info.Queued++
		case qa.StateRunning:
			info.Running++
		}
	}
	s.mu.Unlock()
	writeJSON(w, 200, info)
}

// submit accepts a multipart body: a "spec" JSON field, then a "bundle"
// gzip tar. The same ID with the same spec and bundle returns the existing
// job; with different content it is a conflict.
func (s *Server) submit(w http.ResponseWriter, r *http.Request) {
	reader, err := r.MultipartReader()
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "multipart body with spec and bundle required"})
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, qa.MaxBundleBytes+(1<<20))
	var spec qa.JobSpec
	var bundle []byte
	for part, err := reader.NextPart(); err == nil; part, err = reader.NextPart() {
		switch part.FormName() {
		case "spec":
			data, _ := io.ReadAll(io.LimitReader(part, 128<<10))
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.DisallowUnknownFields()
			if decoder.Decode(&spec) != nil {
				writeJSON(w, 400, map[string]string{"error": "spec is not valid JSON"})
				return
			}
		case "bundle":
			bundle, err = io.ReadAll(io.LimitReader(part, qa.MaxBundleBytes+1))
			if err != nil || len(bundle) > qa.MaxBundleBytes {
				writeJSON(w, 413, map[string]string{"error": "bundle is over 32 MiB"})
				return
			}
		}
	}
	if err := spec.Validate(); err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if len(bundle) == 0 {
		writeJSON(w, 400, map[string]string{"error": "bundle required"})
		return
	}
	if spec.Kind == qa.KindPerformance && s.cfg.PerfClasspath == "" {
		writeJSON(w, 422, map[string]string{"error": "this runner has no karate-gatling classpath; performance jobs are disabled"})
		return
	}
	encoded, _ := json.Marshal(spec)
	sum := sha256.New()
	sum.Write(encoded)
	sum.Write(bundle)
	digest := hex.EncodeToString(sum.Sum(nil))

	s.mu.Lock()
	if existing, ok := s.jobs[spec.ID]; ok {
		status := existing.status
		same := existing.digest == digest
		s.mu.Unlock()
		if !same {
			writeJSON(w, 409, map[string]string{"error": "a job with this id has different content"})
			return
		}
		writeJSON(w, 200, status)
		return
	}
	if len(s.queue) >= cap(s.queue) {
		s.mu.Unlock()
		w.Header().Set("Retry-After", "30")
		writeJSON(w, 429, map[string]string{"error": "runner queue full"})
		return
	}
	dir := filepath.Join(s.cfg.WorkDir, spec.ID)
	j := &job{spec: spec, digest: digest, dir: dir, status: qa.JobStatus{ID: spec.ID, Kind: spec.Kind, State: qa.StateQueued, QueuedAt: time.Now().UTC()}}
	s.jobs[spec.ID] = j
	s.mu.Unlock()

	if err := s.prepare(j, bundle); err != nil {
		s.mu.Lock()
		delete(s.jobs, spec.ID)
		s.mu.Unlock()
		_ = os.RemoveAll(dir)
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	queued := j.status
	select {
	case s.queue <- j:
	default:
		s.mu.Lock()
		delete(s.jobs, spec.ID)
		s.mu.Unlock()
		_ = os.RemoveAll(dir)
		w.Header().Set("Retry-After", "30")
		writeJSON(w, 429, map[string]string{"error": "runner queue full"})
		return
	}
	writeJSON(w, 202, queued)
}

// prepare unpacks the bundle into the job's directory.
func (s *Server) prepare(j *job, bundle []byte) error {
	for _, sub := range []string{"bundle", "out", "home", "tmp"} {
		if err := os.MkdirAll(filepath.Join(j.dir, sub), 0o700); err != nil {
			return err
		}
	}
	if err := qa.Unpack(bytes.NewReader(bundle), filepath.Join(j.dir, "bundle"), 5000, 128<<20); err != nil {
		return err
	}
	return s.handOver(j.dir)
}

func (s *Server) lookup(r *http.Request) (*job, qa.JobStatus, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	j, ok := s.jobs[r.PathValue("id")]
	if !ok {
		return nil, qa.JobStatus{}, false
	}
	return j, j.status, true
}

func (s *Server) get(w http.ResponseWriter, r *http.Request) {
	_, status, ok := s.lookup(r)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "job not found"})
		return
	}
	writeJSON(w, 200, status)
}

func (s *Server) report(w http.ResponseWriter, r *http.Request) {
	j, status, ok := s.lookup(r)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "job not found"})
		return
	}
	if !qa.Finished(status.State) || status.ReportSHA256 == "" {
		writeJSON(w, 409, map[string]string{"error": "job has no report yet (state " + status.State + ")"})
		return
	}
	f, err := os.Open(filepath.Join(j.dir, "report.tar.gz"))
	if err != nil {
		writeJSON(w, 410, map[string]string{"error": "report no longer available"})
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("X-Content-SHA256", status.ReportSHA256)
	_, _ = io.Copy(w, f)
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	j, ok := s.jobs[r.PathValue("id")]
	if ok {
		j.cancelled = true
		if j.cancel != nil {
			j.cancel()
		}
		if j.status.State != qa.StateRunning {
			// A running job removes its own directory when it stops.
			delete(s.jobs, j.spec.ID)
			_ = os.RemoveAll(j.dir)
		}
	}
	s.mu.Unlock()
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "job not found"})
		return
	}
	w.WriteHeader(204)
}

// execute runs one job and packages its report.
func (s *Server) execute(parent context.Context, j *job) {
	s.mu.Lock()
	if j.cancelled {
		s.mu.Unlock()
		return
	}
	ctx, cancel := context.WithTimeout(parent, time.Duration(j.spec.TimeoutSeconds)*time.Second)
	defer cancel()
	j.cancel = cancel
	started := time.Now().UTC()
	j.status.State, j.status.StartedAt = qa.StateRunning, &started
	s.mu.Unlock()

	console := newCapture(1<<20, 7<<20)
	var state, failure string
	var exit *int
	if j.spec.Kind == qa.KindPerformance {
		state, exit, failure = s.runPerf(ctx, j, console)
	} else {
		state, exit, failure = s.runFunctional(ctx, j, console)
	}
	if ctx.Err() == context.DeadlineExceeded {
		state, failure = qa.StateError, "job exceeded timeout_seconds"
	}
	s.mu.Lock()
	cancelled := j.cancelled
	s.mu.Unlock()
	if cancelled {
		state, failure = qa.StateCancelled, "cancelled"
	}
	finished := time.Now().UTC()
	status := qa.JobStatus{ID: j.spec.ID, Kind: j.spec.Kind, State: state, ExitCode: exit, Error: failure, QueuedAt: j.status.QueuedAt, StartedAt: &started, FinishedAt: &finished}
	redactor := newRedactor(j.spec.Variables)
	if !cancelled {
		digest, size, truncated, err := s.pack(j, status, redactor.apply(console.Bytes()), redactor)
		if err != nil {
			status.State, status.Error = qa.StateError, "report packaging failed: "+err.Error()
		} else {
			status.ReportSHA256, status.ReportBytes, status.Truncated = digest, size, truncated
		}
	}
	// Only the report is kept; sources, outputs and caches go now.
	for _, sub := range []string{"bundle", "out", "home", "tmp"} {
		_ = os.RemoveAll(filepath.Join(j.dir, sub))
	}
	s.mu.Lock()
	j.status, j.finishedAt = status, finished
	if cancelled {
		delete(s.jobs, j.spec.ID)
		_ = os.RemoveAll(j.dir)
	}
	s.mu.Unlock()
	s.cfg.Logger.Info("qa job finished", "job", j.spec.ID, "kind", j.spec.Kind, "state", status.State, "seconds", int(finished.Sub(started).Seconds()))
}

// environment is what test processes see: allowed runner variables, the
// target and the job's QA_ secrets. The runner token is never passed.
func (s *Server) environment(j *job) []string {
	// No JAVA_TOOL_OPTIONS: the JVM's "Picked up" notice breaks karate-cli's
	// Java detection.
	env := []string{"HOME=" + filepath.Join(j.dir, "home"), "TMPDIR=" + filepath.Join(j.dir, "tmp"), "NO_COLOR=1", "LANG=C.UTF-8", "SCRS_BASE_URL=" + j.spec.BaseURL, "SCRS_ENV=" + j.spec.Env}
	for _, name := range append([]string{"PATH", "JAVA_HOME", "KARATE_HOME", "TZ"}, s.cfg.PassEnv...) {
		if value, ok := os.LookupEnv(name); ok && !strings.HasPrefix(name, "SCRS_QA_RUNNER") {
			env = append(env, name+"="+value)
		}
	}
	names := make([]string, 0, len(j.spec.Variables))
	for name := range j.spec.Variables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		env = append(env, "QA_"+name+"="+j.spec.Variables[name])
	}
	return env
}

func hasFeatures(dir string) bool {
	found := false
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(p, ".feature") {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found
}

// runFunctional runs each suite as its own Karate project with its own
// karate-config.js, writing reports to out/reports/<suite>.
func (s *Server) runFunctional(ctx context.Context, j *job, console *capture) (string, *int, string) {
	ran, failed := 0, false
	var last *int
	for _, suite := range j.spec.Suites {
		dir := filepath.Join(j.dir, "bundle", suite.Dir)
		if !hasFeatures(dir) {
			console.WriteString("suite " + suite.Dir + ": no .feature files; skipped\n")
			continue
		}
		out := filepath.Join(j.dir, "out", "reports", suite.Dir)
		args := append(append([]string{}, s.cfg.Karate[1:]...), "run", "--no-color", "--no-pom", "-f", "html,junit:xml,karate:jsonl", "-o", out, "-T", itoa(j.spec.Threads), "-w", dir, "-g", dir)
		if j.spec.Env != "" {
			args = append(args, "-e", j.spec.Env)
		}
		for _, t := range suite.Tags {
			args = append(args, "-t", t)
		}
		args = append(args, dir)
		console.WriteString("== suite " + suite.Dir + "\n")
		code, err := s.command(ctx, j, s.cfg.Karate[0], args, dir, console)
		if err != nil {
			return qa.StateError, nil, "karate could not start: " + err.Error()
		}
		if ctx.Err() != nil {
			return qa.StateError, &code, "stopped"
		}
		last = &code
		if _, statErr := os.Stat(filepath.Join(out, "karate-json", "karate-events.jsonl")); statErr != nil {
			return qa.StateError, &code, "karate wrote no report for suite " + suite.Dir + " (exit " + itoa(code) + "); see console.log"
		}
		ran++
		failed = failed || code != 0
	}
	switch {
	case ran == 0:
		return qa.StateError, nil, "no suite contains .feature files"
	case failed:
		return qa.StateFailed, last, ""
	}
	return qa.StatePassed, last, ""
}

// runPerf runs the SCRS load simulation over the repo suite's features.
// Gatling exits 2 when an assertion (threshold) fails.
func (s *Server) runPerf(ctx context.Context, j *job, console *capture) (string, *int, string) {
	dir := filepath.Join(j.dir, "bundle", "repo")
	var features []string
	for _, f := range j.spec.Perf.Features {
		p := filepath.Join(dir, filepath.FromSlash(f))
		if _, err := os.Stat(p); err != nil {
			return qa.StateError, nil, "performance feature " + f + " is not in the bundle"
		}
		features = append(features, p)
	}
	p := j.spec.Perf
	args := []string{"--add-opens=java.base/java.lang=ALL-UNNAMED",
		"-Dscrs.features=" + strings.Join(features, ","), "-Dscrs.users=" + itoa(p.Users), "-Dscrs.rampSeconds=" + itoa(p.RampSeconds),
		"-Dscrs.durationSeconds=" + itoa(p.DurationSeconds), "-Dscrs.p95Millis=" + itoa(p.P95Millis), "-Dscrs.maxErrorPercent=" + itoa(p.MaxErrorPercent),
		"-Dkarate.env=" + j.spec.Env,
		"-cp", s.cfg.PerfClasspath, "io.gatling.app.Gatling", "-s", "scrs.LoadSimulation", "-rf", filepath.Join(j.dir, "out", "gatling")}
	code, err := s.command(ctx, j, s.cfg.Java, args, dir, console)
	if err != nil {
		return qa.StateError, nil, "java could not start: " + err.Error()
	}
	switch code {
	case 0:
		return qa.StatePassed, &code, ""
	case 2:
		return qa.StateFailed, &code, ""
	}
	return qa.StateError, &code, "gatling exited " + itoa(code) + "; see console.log"
}

func itoa(n int) string { return strconv.Itoa(n) }
