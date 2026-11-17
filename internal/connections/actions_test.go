package connections

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunGaps(t *testing.T) {
	for _, tc := range []struct {
		numbers []int
		missing []int
		total   int
	}{
		{nil, nil, 0},
		{[]int{5}, nil, 0},
		{[]int{4, 5, 6, 7}, nil, 0},
		{[]int{7, 4, 5, 6}, nil, 0},         // order does not matter
		{[]int{4, 5, 8, 9}, []int{6, 7}, 2}, // a deleted run leaves a hole
		{[]int{4, 4, 5, 8}, []int{6, 7}, 2}, // re-runs share a number
		{[]int{100, 1}, nil, 98},            // total counts them all, the list is capped below
	} {
		missing, total := RunGaps(tc.numbers)
		if tc.total == 98 {
			if total != 98 || len(missing) != MaxMissingListed || missing[0] != 2 {
				t.Errorf("%v: %d listed of %d", tc.numbers, len(missing), total)
			}
			continue
		}
		if fmt.Sprint(missing) != fmt.Sprint(tc.missing) || total != tc.total {
			t.Errorf("RunGaps(%v) = %v, %d; want %v, %d", tc.numbers, missing, total, tc.missing, tc.total)
		}
	}
}

func TestGitHubActionsReadsInventoryAndGaps(t *testing.T) {
	runs := func(numbers ...int) string {
		items := make([]string, len(numbers))
		for i, n := range numbers {
			items[i] = fmt.Sprintf(`{"run_number":%d}`, n)
		}
		return `{"workflow_runs":[` + strings.Join(items, ",") + `]}`
	}
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer pat" {
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/repos/org/api/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled":true}`))
		case "/repos/org/api/actions/workflows":
			_, _ = w.Write([]byte(`{"workflows":[{"id":1,"name":"CI","path":".github/workflows/ci.yml","state":"active"},{"id":2,"name":"Release","path":".github/workflows/release.yml","state":"active"}]}`))
		case "/repos/org/api/actions/workflows/1/runs":
			_, _ = w.Write([]byte(runs(12, 11, 9, 8, 6)))
		case "/repos/org/api/actions/workflows/2/runs":
			_, _ = w.Write([]byte(runs(3, 2, 1)))
		case "/repos/org/off/actions/permissions":
			_, _ = w.Write([]byte(`{"enabled":false}`))
		case "/repos/org/off/actions/workflows":
			_, _ = w.Write([]byte(`{"workflows":[{"id":5,"name":"Old","path":".github/workflows/old.yml","state":"disabled_manually"}]}`))
		case "/repos/org/denied/actions/permissions":
			w.WriteHeader(403)
		case "/repos/org/broken/actions/permissions":
			w.WriteHeader(500)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	a := NativeAdapters{Client: server.Client(), GitHubAPI: server.URL}
	c := Connection{Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`)}
	secret := json.RawMessage(`{"token":"pat"}`)

	info, err := a.GitHubActions(context.Background(), c, secret, "org/api")
	if err != nil || !info.Available || !info.Enabled || len(info.Workflows) != 2 {
		t.Fatalf("inventory: %+v %v", info, err)
	}
	ci, release := info.Workflows[0], info.Workflows[1]
	if ci.Runs != 5 || ci.MinRun != 6 || ci.MaxRun != 12 || fmt.Sprint(ci.Missing) != "[7 10]" || ci.MissingCount != 2 {
		t.Fatalf("CI workflow: %+v", ci)
	}
	if release.MissingCount != 0 || release.Runs != 3 {
		t.Fatalf("release workflow: %+v", release)
	}
	// Actions switched off: workflows are listed, runs are not read.
	info, err = a.GitHubActions(context.Background(), c, secret, "org/off")
	if err != nil || !info.Available || info.Enabled || len(info.Workflows) != 1 || info.Workflows[0].Runs != 0 {
		t.Fatalf("disabled: %+v %v", info, err)
	}
	for _, p := range paths {
		if strings.Contains(p, "/off/") && strings.Contains(p, "/runs") {
			t.Fatalf("runs were read although Actions is off: %s", p)
		}
	}
	// A missing permission is an answer, not an error.
	info, err = a.GitHubActions(context.Background(), c, secret, "org/denied")
	if err != nil || info.Available || !strings.Contains(info.Reason, "Actions permission") || info.Workflows == nil {
		t.Fatalf("denied: %+v %v", info, err)
	}
	// Anything else is an error, and bad input never reaches GitHub.
	if _, err := a.GitHubActions(context.Background(), c, secret, "org/broken"); err == nil {
		t.Fatal("a GitHub outage must not read as a clean inventory")
	}
	// A repository the token cannot see answers 404, which reads as a missing permission.
	if info, err := a.GitHubActions(context.Background(), c, secret, "org/unknown"); err != nil || info.Available {
		t.Fatalf("invisible repository: %+v %v", info, err)
	}
	for _, repo := range []string{"", "org", "org/", "other/api", "org/a/b", "org/ a"} {
		if _, err := a.GitHubActions(context.Background(), c, secret, repo); err == nil {
			t.Errorf("%q was accepted", repo)
		}
	}
	if _, err := a.GitHubActions(context.Background(), c, json.RawMessage(`{"token":"wrong"}`), "org/api"); err == nil {
		t.Fatal("a rejected token must be an error")
	}
}
