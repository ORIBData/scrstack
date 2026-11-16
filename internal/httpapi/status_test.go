package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
)

type fakeStatusStore struct {
	runs    []assessments.SchedulerRun
	sources []assessments.VulnSource
	err     error
}

func (f fakeStatusStore) SchedulerRuns(context.Context) ([]assessments.SchedulerRun, error) {
	return f.runs, f.err
}
func (f fakeStatusStore) VulnerabilitySources(context.Context) ([]assessments.VulnSource, error) {
	return f.sources, f.err
}

func fetchStatus(t *testing.T, h *PlatformStatus) platformStatus {
	t.Helper()
	rec := httptest.NewRecorder()
	h.serve(rec, httptest.NewRequest("GET", "/scrs/v1/system/status", nil))
	var out platformStatus
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &out) != nil {
		t.Fatal(rec.Code, rec.Body.String())
	}
	return out
}

func TestSystemStatus(t *testing.T) {
	now := time.Now()
	heartbeat := assessments.SchedulerRun{Job: "feed_monitor", LastFinishedAt: &now, LastStatus: "ok"}
	healthy := func(context.Context) map[string]error {
		return map[string]error{"postgres": nil, "redis": nil, "s3": nil}
	}

	out := fetchStatus(t, NewPlatformStatus(healthy, fakeStatusStore{runs: []assessments.SchedulerRun{heartbeat}, sources: []assessments.VulnSource{{Key: "osv", Enabled: true}}}, nil, nil))
	if out.Status != statusOK || out.Components["worker"].Status != statusOK || out.Components["scanner"].Status != statusOK || out.Components["sast"].Status != statusNotConfigured || out.Components["qa_runner"].Status != statusNotConfigured {
		t.Fatalf("healthy platform: %+v", out)
	}

	// A dead backing service takes the whole platform down, and its error
	// text stays out of the body.
	down := func(context.Context) map[string]error {
		return map[string]error{"postgres": nil, "redis": errors.New("dial tcp 10.0.0.5:6379 secret"), "s3": nil}
	}
	rec := httptest.NewRecorder()
	NewPlatformStatus(down, fakeStatusStore{runs: []assessments.SchedulerRun{heartbeat}}, nil, nil).serve(rec, httptest.NewRequest("GET", "/", nil))
	var broken platformStatus
	_ = json.Unmarshal(rec.Body.Bytes(), &broken)
	if broken.Status != statusDown || broken.Components["redis"].Status != statusDown {
		t.Fatalf("redis down: %+v", broken)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") || strings.Contains(rec.Body.String(), "secret") {
		t.Fatal("raw error leaked", rec.Body.String())
	}

	// A silent worker, a failed scanner pass and a stale source degrade.
	old := now.Add(-time.Hour)
	stale := fetchStatus(t, NewPlatformStatus(healthy, fakeStatusStore{
		runs:    []assessments.SchedulerRun{{Job: "feed_monitor", LastFinishedAt: &old, LastStatus: "failed"}},
		sources: []assessments.VulnSource{{Key: "kev", Enabled: true, Stale: true}, {Key: "epss", Enabled: false, Stale: true}},
	}, nil, nil))
	if stale.Status != statusDegraded || stale.Components["worker"].Status != statusDown || stale.Components["scanner"].Status != statusDown || stale.Components["feeds"].Status != statusDegraded {
		t.Fatalf("degraded platform: %+v", stale)
	}
	if stale.Components["feeds"].Info["stale_sources"].([]any)[0] != "kev" || len(stale.Components["feeds"].Info["stale_sources"].([]any)) != 1 {
		t.Fatal("only enabled stale sources count", stale.Components["feeds"].Info)
	}

	// No heartbeat yet is reported, not guessed healthy.
	none := fetchStatus(t, NewPlatformStatus(healthy, fakeStatusStore{}, nil, nil))
	if none.Components["worker"].Status != statusDown {
		t.Fatalf("no heartbeat: %+v", none)
	}
}

func TestSystemStatusIsCached(t *testing.T) {
	calls := 0
	probe := func(context.Context) map[string]error { calls++; return map[string]error{} }
	h := NewPlatformStatus(probe, fakeStatusStore{}, nil, nil)
	fetchStatus(t, h)
	fetchStatus(t, h)
	if calls != 1 {
		t.Fatal("status probed", calls, "times in 10 s")
	}
}

type recordingAnnouncer struct {
	mu    sync.Mutex
	calls []string
	comps [][]map[string]any
}

func (r *recordingAnnouncer) PlatformTransition(_ context.Context, status string, components []map[string]any) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, status)
	r.comps = append(r.comps, components)
	return true, nil
}

func (r *recordingAnnouncer) seen() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// A status is announced only after it holds for the confirm count, a blip is
// ignored, and the announcement names the failing components.
func TestStatusMonitorDebouncesAndAnnounces(t *testing.T) {
	var mu sync.Mutex
	redis := error(nil)
	probe := func(context.Context) map[string]error {
		mu.Lock()
		defer mu.Unlock()
		return map[string]error{"postgres": nil, "redis": redis, "s3": nil}
	}
	set := func(err error) { mu.Lock(); redis = err; mu.Unlock() }
	now := time.Now()
	store := fakeStatusStore{runs: []assessments.SchedulerRun{{Job: "feed_monitor", LastFinishedAt: &now, LastStatus: "ok"}}}
	h := NewPlatformStatus(probe, store, nil, nil)
	announcer := &recordingAnnouncer{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// The 10 s status cache is shortened for the test.
		for ctx.Err() == nil {
			h.mu.Lock()
			h.until = time.Time{}
			h.mu.Unlock()
			time.Sleep(5 * time.Millisecond)
		}
	}()
	go h.Monitor(ctx, announcer, 20*time.Millisecond, 0, 3, slog.New(slog.NewTextHandler(io.Discard, nil)))
	waitFor := func(want []string) {
		t.Helper()
		deadline := time.Now().Add(3 * time.Second)
		for time.Now().Before(deadline) {
			if strings.Join(announcer.seen(), ",") == strings.Join(want, ",") {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("announced %v, want %v", announcer.seen(), want)
	}
	waitFor([]string{"ok"})
	set(errors.New("dial tcp 10.0.0.5:6379"))
	waitFor([]string{"ok", "down"})
	announcer.mu.Lock()
	failing := announcer.comps[1]
	announcer.mu.Unlock()
	if len(failing) != 1 || failing[0]["name"] != "redis" || failing[0]["status"] != statusDown || strings.Contains(fmt.Sprint(failing), "10.0.0.5") {
		t.Fatal("failing components", failing)
	}
	set(nil)
	waitFor([]string{"ok", "down", "ok"})
	// A single failed check inside the confirm window announces nothing.
	set(errors.New("blip"))
	time.Sleep(25 * time.Millisecond)
	set(nil)
	time.Sleep(150 * time.Millisecond)
	if got := announcer.seen(); len(got) != 3 {
		t.Fatal("blip announced", got)
	}
}
