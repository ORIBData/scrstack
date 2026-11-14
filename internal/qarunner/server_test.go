package qarunner

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/qa"
	"github.com/google/uuid"
)

const token = "runner-token-runner-token-runner-token"

// fakeKarate stands in for karate-cli: it writes a one-scenario event
// stream to the -o directory, echoes its environment the way Karate logs
// requests, and exits 1 when the suite is named "failing".
const fakeKarate = `#!/bin/sh
out=""; dir=""
while [ $# -gt 0 ]; do
  case "$1" in -o) out="$2"; shift;; -w) dir="$2"; shift;; esac
  shift
done
mkdir -p "$out/karate-json" "$out/junit-xml"
echo "1 > Authorization: Bearer $QA_API_TOKEN"
echo "token in body: $QA_API_TOKEN runner: $SCRS_QA_RUNNER_TOKEN"
status=true; code=0
case "$dir" in *failing*) status=false; code=1;; esac
printf '{"type":"SUITE_ENTER","data":{"version":"2.1.4"}}\n{"type":"SCENARIO_EXIT","data":{"feature":"a.feature","name":"s","line":3,"tags":[],"passed":%s,"skipped":false,"durationMillis":5,"errorReason":"boom %s"}}\n{"type":"FEATURE_EXIT","data":{"stepLog":"1 < 200 GET %s/users (1 ms)\\n1 > Authorization: Bearer %s\\n"}}\n' "$status" "$QA_API_TOKEN" "$SCRS_BASE_URL" "$QA_API_TOKEN" > "$out/karate-json/karate-events.jsonl"
exit $code
`

func newRunner(t *testing.T, karate []string) (*qa.Runner, *Server) {
	t.Helper()
	server, err := New(Config{Token: token, WorkDir: t.TempDir(), Slots: 1, MaxQueued: 2, Karate: karate, KarateVersion: "2.1.4", Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go server.Run(ctx)
	h := httptest.NewServer(server.Handler())
	t.Cleanup(h.Close)
	client, err := qa.NewRunner(h.URL, token, "", true)
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func wait(t *testing.T, client *qa.Runner, id string) qa.JobStatus {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		status, err := client.Status(context.Background(), id)
		if err != nil {
			t.Fatal(err)
		}
		if qa.Finished(status.State) {
			return status
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return qa.JobStatus{}
}

func TestRunnerLifecycle(t *testing.T) {
	script := filepath.Join(t.TempDir(), "karate")
	if err := os.WriteFile(script, []byte(fakeKarate), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SCRS_QA_RUNNER_TOKEN", token)
	client, _ := newRunner(t, []string{script})
	ctx := context.Background()
	bundle, _ := qa.Pack([]qa.File{{Path: "repo/a.feature", Data: []byte("Feature: a")}, {Path: "failing/b.feature", Data: []byte("Feature: b")}, {Path: "empty/readme.txt", Data: []byte("x")}})
	spec := qa.JobSpec{ID: uuid.NewString(), Kind: qa.KindFunctional, BaseURL: "https://staging.example.com", Threads: 1, TimeoutSeconds: 60, Suites: []qa.Suite{{Dir: "repo"}, {Dir: "failing"}, {Dir: "empty"}}, Variables: map[string]string{"API_TOKEN": "s3cr3t-value"}}
	submitted, err := client.Submit(ctx, spec, bundle)
	if err != nil || submitted.ID != spec.ID {
		t.Fatal(submitted, err)
	}
	// Resubmitting the same job is idempotent; different content conflicts.
	if again, err := client.Submit(ctx, spec, bundle); err != nil || again.ID != spec.ID {
		t.Fatal("resubmit", again, err)
	}
	changed := spec
	changed.Threads = 2
	if _, err := client.Submit(ctx, changed, bundle); err == nil || !strings.Contains(err.Error(), "different content") {
		t.Fatal("conflicting resubmit", err)
	}
	status := wait(t, client, spec.ID)
	if status.State != qa.StateFailed || status.ExitCode == nil || *status.ExitCode != 1 || status.ReportSHA256 == "" {
		t.Fatalf("status %+v", status)
	}
	archive, err := client.Report(ctx, spec.ID, status.ReportSHA256)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Report(ctx, spec.ID, strings.Repeat("0", 64)); err == nil {
		t.Fatal("digest mismatch accepted")
	}
	report, err := qa.ParseReport(archive)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Scenarios != 2 || report.Summary.Failed != 1 || len(report.Calls) != 1 || report.Calls[0].Host != "staging.example.com" {
		t.Fatalf("report %+v", report)
	}
	text := allText(archive)
	if strings.Contains(text, "s3cr3t-value") || strings.Contains(text, token) || !strings.Contains(text, "Authorization: [REDACTED]") || !strings.Contains(text, "empty: no .feature files") {
		t.Fatalf("redaction or console %s", text)
	}
	if err := client.Delete(ctx, spec.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Status(ctx, spec.ID); err != qa.ErrUnknownJob {
		t.Fatal("deleted job still known", err)
	}
	// A bundle without features is an error, not a pass.
	none := qa.JobSpec{ID: uuid.NewString(), Kind: qa.KindFunctional, BaseURL: "http://svc:8080", Threads: 1, TimeoutSeconds: 60, Suites: []qa.Suite{{Dir: "repo"}}}
	empty, _ := qa.Pack([]qa.File{{Path: "repo/notes.md", Data: []byte("x")}})
	if _, err := client.Submit(ctx, none, empty); err != nil {
		t.Fatal(err)
	}
	if status := wait(t, client, none.ID); status.State != qa.StateError || !strings.Contains(status.Error, "no suite") {
		t.Fatalf("empty bundle %+v", status)
	}
	// Performance jobs need the Gatling classpath.
	perf := none
	perf.ID, perf.Kind, perf.Perf = uuid.NewString(), qa.KindPerformance, &qa.Perf{Features: []string{"a.feature"}, Users: 1, DurationSeconds: 5, P95Millis: 100}
	if _, err := client.Submit(ctx, perf, bundle); err == nil || !strings.Contains(err.Error(), "performance jobs are disabled") {
		t.Fatal("perf without classpath", err)
	}
}

func TestRunnerAuthAndTimeout(t *testing.T) {
	script := filepath.Join(t.TempDir(), "karate")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nsleep 30\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	client, server := newRunner(t, []string{script})
	h := httptest.NewServer(server.Handler())
	defer h.Close()
	wrong, _ := qa.NewRunner(h.URL, strings.Repeat("x", 40), "", true)
	if _, err := wrong.Info(context.Background()); err == nil || !strings.Contains(err.Error(), "refused the token") {
		t.Fatal("wrong token accepted", err)
	}
	if info, err := client.Info(context.Background()); err != nil || info.Karate != "2.1.4" || info.Gatling {
		t.Fatal(info, err)
	}
	bundle, _ := qa.Pack([]qa.File{{Path: "repo/a.feature", Data: []byte("Feature: a")}})
	spec := qa.JobSpec{ID: uuid.NewString(), Kind: qa.KindFunctional, BaseURL: "http://svc", Threads: 1, TimeoutSeconds: 30, Suites: []qa.Suite{{Dir: "repo"}}}
	if _, err := client.Submit(context.Background(), spec, bundle); err != nil {
		t.Fatal(err)
	}
	// Cancelling a running job stops its process group promptly.
	time.Sleep(300 * time.Millisecond)
	started := time.Now()
	if err := client.Delete(context.Background(), spec.ID); err != nil {
		t.Fatal(err)
	}
	for time.Since(started) < 20*time.Second {
		server.mu.Lock()
		_, known := server.jobs[spec.ID]
		server.mu.Unlock()
		if !known {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("cancelled job not removed")
}

// TestRealKarate runs the pinned Karate jar when SCRS_TEST_KARATE_JAR names
// it (make qa-runner-test downloads it): a passing and a failing scenario
// against a local mock, exercising the real report formats end to end.
func TestRealKarate(t *testing.T) {
	jar := os.Getenv("SCRS_TEST_KARATE_JAR")
	if jar == "" {
		t.Skip("set SCRS_TEST_KARATE_JAR to the Karate jar")
	}
	if _, err := exec.LookPath("java"); err != nil {
		t.Skip("java not installed")
	}
	api := httptest.NewServer(nil)
	api.Config.Handler = mockAPI()
	defer api.Close()
	client, _ := newRunner(t, []string{"java", "-jar", jar})
	features := `Feature: users
Background:
* url baseUrl
* configure headers = { Authorization: '#("Bearer " + token)' }
Scenario: get user
Given path 'users', 1
When method get
Then status 200
And match response.name == 'Ada'
Scenario: wrong expectation
Given path 'users', 2
When method get
Then status 200
`
	config := "function fn() { var env = java.lang.System.getenv; return { baseUrl: env('SCRS_BASE_URL'), token: env('QA_API_TOKEN') }; }"
	bundle, _ := qa.Pack([]qa.File{{Path: "repo/users.feature", Data: []byte(features)}, {Path: "repo/karate-config.js", Data: []byte(config)}})
	spec := qa.JobSpec{ID: uuid.NewString(), Kind: qa.KindFunctional, BaseURL: api.URL, Threads: 1, TimeoutSeconds: 120, Suites: []qa.Suite{{Dir: "repo"}}, Variables: map[string]string{"API_TOKEN": "real-secret-token"}}
	if _, err := client.Submit(context.Background(), spec, bundle); err != nil {
		t.Fatal(err)
	}
	status := wait(t, client, spec.ID)
	archive, err := client.Report(context.Background(), spec.ID, status.ReportSHA256)
	if err != nil {
		t.Fatal(status, err)
	}
	report, err := qa.ParseReport(archive)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != qa.StateFailed || report.Summary.Passed != 1 || report.Summary.Failed != 1 || report.Summary.Karate != "2.1.4" || len(report.Calls) != 2 {
		t.Fatalf("status %+v report %+v", status, report)
	}
	if text := allText(archive); strings.Contains(text, "real-secret-token") || !strings.Contains(text, "Authorization: [REDACTED]") {
		t.Fatal("report contains the secret")
	}
}

// allText concatenates every file of a report archive.
func allText(archive []byte) string {
	var everything strings.Builder
	_ = qa.Walk(strings.NewReader(string(archive)), 1000, 1<<28, func(name string, _ int64, r io.Reader) error {
		data, _ := io.ReadAll(r)
		everything.WriteString(name + "\n" + string(data))
		return nil
	})
	return everything.String()
}

// mockAPI knows user 1 and requires the bearer token.
func mockAPI() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer real-secret-token" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/users/1" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":1,"name":"Ada"}`))
			return
		}
		w.WriteHeader(404)
	})
}

// TestRunnerImage exercises a running runner container (make
// qa-runner-image-test): an API scenario with a secret header, a headless
// Chromium UI scenario, and a karate-gatling load run, all against a mock
// served from this test on the host.
func TestRunnerImage(t *testing.T) {
	runnerURL, host := os.Getenv("SCRS_TEST_RUNNER_URL"), os.Getenv("SCRS_TEST_RUNNER_HOST")
	if runnerURL == "" || host == "" {
		t.Skip("set SCRS_TEST_RUNNER_URL, SCRS_TEST_RUNNER_TOKEN and SCRS_TEST_RUNNER_HOST (how the container reaches this host)")
	}
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	api := &httptest.Server{Listener: listener, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/page" {
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<html><head><title>QA page</title></head><body><h1 id="greeting">Hello</h1></body></html>`))
			return
		}
		mockAPI().ServeHTTP(w, r)
	})}}
	api.Start()
	defer api.Close()
	base := "http://" + host + ":" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	client, err := qa.NewRunner(runnerURL, os.Getenv("SCRS_TEST_RUNNER_TOKEN"), "", true)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	info, err := client.Info(ctx)
	if err != nil || info.Karate != "2.1.4" || !info.Gatling {
		t.Fatal("runner info", info, err)
	}
	config := "function fn() { var env = java.lang.System.getenv; return { baseUrl: env('SCRS_BASE_URL'), token: env('QA_API_TOKEN') }; }"
	api1 := "Feature: users\nBackground:\n* url baseUrl\n* configure headers = { Authorization: '#(\"Bearer \" + token)' }\nScenario: get user\nGiven path 'users', 1\nWhen method get\nThen status 200\nAnd match response.name == 'Ada'\n"
	ui := "@ui\nFeature: page\nScenario: title and heading\n* configure driver = { type: 'chrome', headless: true, addOptions: ['--no-sandbox', '--disable-dev-shm-usage'] }\n* driver baseUrl + '/page'\n* match driver.title == 'QA page'\n* match text('#greeting') == 'Hello'\n"
	load := "Feature: load\nBackground:\n* url baseUrl\n* header Authorization = 'Bearer ' + token\nScenario: get\nGiven path 'users', 1\nWhen method get\nThen status 200\n"
	bundle, _ := qa.Pack([]qa.File{{Path: "repo/karate-config.js", Data: []byte(config)}, {Path: "repo/users.feature", Data: []byte(api1)}, {Path: "repo/ui/page.feature", Data: []byte(ui)}, {Path: "repo/perf/load.feature", Data: []byte(load)}})
	vars := map[string]string{"API_TOKEN": "real-secret-token"}
	functional := qa.JobSpec{ID: uuid.NewString(), Kind: qa.KindFunctional, BaseURL: base, Threads: 1, TimeoutSeconds: 300, Suites: []qa.Suite{{Dir: "repo", Tags: []string{"~@perf"}}}, Variables: vars}
	if _, err := client.Submit(ctx, functional, bundle); err != nil {
		t.Fatal(err)
	}
	status := wait(t, client, functional.ID)
	archive, err := client.Report(ctx, functional.ID, status.ReportSHA256)
	if err != nil {
		t.Fatal(status, err)
	}
	report, err := qa.ParseReport(archive)
	if err != nil {
		t.Fatal(err)
	}
	text := allText(archive)
	if status.State != qa.StatePassed || report.Summary.Passed < 2 || report.Summary.Failed != 0 || strings.Contains(text, "real-secret-token") {
		t.Fatalf("functional %+v %+v\n%s", status, report.Summary, text[:min(len(text), 4000)])
	}
	perf := qa.JobSpec{ID: uuid.NewString(), Kind: qa.KindPerformance, BaseURL: base, Threads: 1, TimeoutSeconds: 300, Suites: []qa.Suite{{Dir: "repo"}}, Variables: vars, Perf: &qa.Perf{Features: []string{"perf/load.feature"}, Users: 3, RampSeconds: 1, DurationSeconds: 5, P95Millis: 2000, MaxErrorPercent: 1}}
	if _, err := client.Submit(ctx, perf, bundle); err != nil {
		t.Fatal(err)
	}
	status = wait(t, client, perf.ID)
	archive, err = client.Report(ctx, perf.ID, status.ReportSHA256)
	if err != nil {
		t.Fatal(status, err)
	}
	report, err = qa.ParseReport(archive)
	if err != nil {
		t.Fatal(err)
	}
	if status.State != qa.StatePassed || report.Perf == nil || report.Perf.Requests == 0 || report.Perf.KO != 0 || len(report.Perf.Assertions) != 2 || strings.Contains(allText(archive), "real-secret-token") {
		t.Fatalf("performance %+v %+v", status, report.Perf)
	}
}
