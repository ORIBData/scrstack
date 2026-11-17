package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// ActionsWorkflow is one GitHub Actions workflow and what its run history
// shows (INT-014, INT-015).
type ActionsWorkflow struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	State string `json:"state"`
	// Runs counts the runs listed; MinRun and MaxRun bound their run numbers.
	Runs   int `json:"runs"`
	MinRun int `json:"min_run"`
	MaxRun int `json:"max_run"`
	// Missing lists run numbers absent between MinRun and MaxRun (at most
	// MaxMissingListed); MissingCount is how many there are.
	Missing      []int `json:"missing,omitempty"`
	MissingCount int   `json:"missing_count"`
}

// ActionsInfo is what GitHub says about a repository's Actions.
type ActionsInfo struct {
	// Available is false when the credential cannot read Actions; Reason says why.
	Available bool              `json:"available"`
	Reason    string            `json:"reason,omitempty"`
	Enabled   bool              `json:"enabled"`
	Workflows []ActionsWorkflow `json:"workflows"`
	// RunsTruncated is true when a workflow has more runs than were read.
	RunsTruncated bool `json:"runs_truncated"`
}

// Limits of one inventory: workflows read, run pages per workflow, and
// missing numbers listed per workflow.
const (
	maxActionsWorkflows = 30
	maxRunPages         = 5
	MaxMissingListed    = 50
)

// RunGaps returns the run numbers missing between the lowest and highest of
// numbers, in order, and how many there are in all. A workflow's runs are
// numbered 1, 2, 3 …; a deleted run leaves a hole (INT-015). Retention expiry
// removes the oldest runs and so lowers the minimum without leaving one.
// Re-runs of a run share its number and are counted once.
func RunGaps(numbers []int) (missing []int, total int) {
	if len(numbers) < 2 {
		return nil, 0
	}
	sorted := append([]int(nil), numbers...)
	sort.Ints(sorted)
	for i := 1; i < len(sorted); i++ {
		for n := sorted[i-1] + 1; n < sorted[i]; n++ {
			total++
			if len(missing) < MaxMissingListed {
				missing = append(missing, n)
			}
		}
	}
	return missing, total
}

// GitHubActions reads whether Actions is enabled for a repository, its
// workflows, and the run-number holes in each workflow's recent runs. It needs
// the read-only Actions permission; without it the answer is `Available:
// false` with the reason, not an error.
func (a NativeAdapters) GitHubActions(ctx context.Context, c Connection, secret json.RawMessage, repository string) (ActionsInfo, error) {
	owner, name, ok := strings.Cut(repository, "/")
	if !ok || owner == "" || name == "" || strings.Contains(name, "/") || !providerSegment.MatchString(owner) || !providerSegment.MatchString(name) {
		return ActionsInfo{}, errors.New("repository must be owner/name")
	}
	token, err := a.githubToken(ctx, c, secret, owner)
	if err != nil {
		return ActionsInfo{}, err
	}
	base := strings.TrimSuffix(a.GitHubAPI, "/") + "/repos/" + url.PathEscape(owner) + "/" + url.PathEscape(name) + "/actions"
	denied := func(err error) (ActionsInfo, bool) {
		var status *StatusError
		if errors.As(err, &status) && (status.Status == http.StatusForbidden || status.Status == http.StatusNotFound) {
			return ActionsInfo{Workflows: []ActionsWorkflow{}, Reason: fmt.Sprintf("GitHub answered HTTP %d: the credential needs the read-only Actions permission on this repository", status.Status)}, true
		}
		return ActionsInfo{}, false
	}
	info := ActionsInfo{Available: true, Workflows: []ActionsWorkflow{}}
	data, err := a.request(ctx, http.MethodGet, base+"/permissions", token, nil)
	if err != nil {
		if out, ok := denied(err); ok {
			return out, nil
		}
		return ActionsInfo{}, err
	}
	var permissions struct {
		Enabled bool `json:"enabled"`
	}
	if json.Unmarshal(data, &permissions) != nil {
		return ActionsInfo{}, errors.New("GitHub Actions permissions response invalid")
	}
	info.Enabled = permissions.Enabled
	data, err = a.request(ctx, http.MethodGet, base+"/workflows?per_page=100", token, nil)
	if err != nil {
		if out, ok := denied(err); ok {
			return out, nil
		}
		return ActionsInfo{}, err
	}
	var listed struct {
		Workflows []struct {
			ID    int64  `json:"id"`
			Name  string `json:"name"`
			Path  string `json:"path"`
			State string `json:"state"`
		} `json:"workflows"`
	}
	if json.Unmarshal(data, &listed) != nil {
		return ActionsInfo{}, errors.New("GitHub workflows response invalid")
	}
	for i, w := range listed.Workflows {
		wf := ActionsWorkflow{ID: w.ID, Name: w.Name, Path: w.Path, State: w.State}
		if i < maxActionsWorkflows && info.Enabled {
			numbers := map[int]bool{}
			for page := 1; page <= maxRunPages; page++ {
				data, err := a.request(ctx, http.MethodGet, fmt.Sprintf("%s/workflows/%d/runs?per_page=100&page=%d", base, w.ID, page), token, nil)
				if err != nil {
					return ActionsInfo{}, err
				}
				var runs struct {
					Runs []struct {
						RunNumber int `json:"run_number"`
					} `json:"workflow_runs"`
				}
				if json.Unmarshal(data, &runs) != nil {
					return ActionsInfo{}, errors.New("GitHub workflow runs response invalid")
				}
				for _, r := range runs.Runs {
					numbers[r.RunNumber] = true
				}
				if len(runs.Runs) < 100 {
					break
				}
				if page == maxRunPages {
					info.RunsTruncated = true
				}
			}
			list := make([]int, 0, len(numbers))
			for n := range numbers {
				list = append(list, n)
			}
			sort.Ints(list)
			wf.Runs = len(list)
			if len(list) > 0 {
				wf.MinRun, wf.MaxRun = list[0], list[len(list)-1]
			}
			wf.Missing, wf.MissingCount = RunGaps(list)
		}
		info.Workflows = append(info.Workflows, wf)
	}
	return info, nil
}
