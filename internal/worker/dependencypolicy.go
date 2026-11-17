package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/depsdev"
	"github.com/ORIBData/scrstack/internal/scanner"
	"github.com/ORIBData/scrstack/internal/supplychain"
)

const dependencyStage = "dependency_policy"

// dependencyPolicy applies the optional package checks (MAL-005 and MAL-006)
// and adds their `suspicious_dependency` entries to the scan. The entries
// inform and never gate. The stage is `ok` only when every check the policy
// asks for covered every package, so a partial run can never close an entry
// the next scan did not repeat.
func (w Worker) dependencyPolicy(ctx context.Context, output *scanner.Output) assessments.Stage {
	stage := assessments.Stage{Name: dependencyStage}
	policy, err := w.Store.DependencyPolicy(ctx)
	if err != nil {
		stage.Status, stage.Detail = "partial", "policy unavailable"
		return stage
	}
	if policy.MinReleaseAgeDays == 0 && !policy.Typosquat {
		stage.Status, stage.Detail = "ok", "disabled by policy"
		return stage
	}
	flagged := 0
	add := func(f assessments.Finding) {
		if len(output.Findings) < 10000 {
			output.Findings = append(output.Findings, f)
			flagged++
		}
	}
	var notes []string
	if policy.Typosquat {
		seen := map[string]bool{}
		for _, c := range output.Components {
			if c.PURL == "" || seen[c.PURL] {
				continue
			}
			seen[c.PURL] = true
			if popular, ok := supplychain.Lookalike(c.Ecosystem, c.Name); ok {
				evidence, _ := json.Marshal(map[string]any{"similar_to": popular, "ecosystem": c.Ecosystem})
				guidance, _ := json.Marshal(map[string]any{"summary": "The package name is one edit away from the popular package " + popular + ". Check that it is the package you meant to depend on and who publishes it; attackers register near-identical names.", "steps": []string{"Compare the name with " + popular + " and with your manifest.", "Check the publisher and the package's history on its registry.", "If it is intended, accept or mark this entry a false positive."}})
				add(assessments.Finding{Type: "suspicious_dependency", AdvisoryID: "SCRS-TYPOSQUAT", Title: fmt.Sprintf("Package name resembles %s", popular), Severity: "medium", Score: 40, Component: c, Evidence: evidence, Guidance: guidance})
			}
		}
	}
	if policy.MinReleaseAgeDays > 0 {
		note := w.releaseAge(ctx, output, policy.MinReleaseAgeDays, add)
		if note != "" {
			notes = append(notes, note)
		}
	}
	stage.Status = "ok"
	stage.Detail = fmt.Sprintf("%d flagged", flagged)
	if len(notes) > 0 {
		stage.Status, stage.Detail = "partial", strings.Join(notes, "; ")
	}
	return stage
}

// releaseAge flags package versions published fewer than minDays ago. It
// returns a note when some packages could not be checked.
func (w Worker) releaseAge(ctx context.Context, output *scanner.Output, minDays int, add func(assessments.Finding)) string {
	if w.DepsDev == nil {
		return "release age needs deps.dev, which is not configured"
	}
	type target struct {
		key        assessments.PackageKey
		components []int
	}
	targets := map[assessments.PackageKey]*target{}
	var order []assessments.PackageKey
	for i, c := range output.Components {
		system, ok := depsdev.System(c.Ecosystem)
		if !ok || c.Version == "" {
			continue
		}
		name := c.Name
		if system == "PYPI" {
			name = strings.ToLower(name)
		}
		k := assessments.PackageKey{System: system, Name: name, Version: c.Version}
		if targets[k] == nil {
			targets[k] = &target{key: k}
			order = append(order, k)
		}
		targets[k].components = append(targets[k].components, i)
	}
	known, err := w.Store.CachedPublished(ctx, order)
	if err != nil {
		known = map[assessments.PackageKey]assessments.PackagePublished{}
	}
	var missing []assessments.PackageKey
	for _, k := range order {
		if _, ok := known[k]; !ok {
			missing = append(missing, k)
		}
	}
	limit := w.DepsDevMaxLookups
	if limit <= 0 {
		limit = defaultMetadataLookups
	}
	unchecked := 0
	if len(missing) > limit {
		unchecked = len(missing) - limit
		missing = missing[:limit]
	}
	fetched := map[assessments.PackageKey]assessments.PackagePublished{}
	var mu sync.Mutex
	jobs := make(chan assessments.PackageKey)
	var wg sync.WaitGroup
	for range lookupConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range jobs {
				at, err := w.DepsDev.PublishedAt(ctx, k.System, k.Name, k.Version)
				mu.Lock()
				switch {
				case err == nil:
					fetched[k] = assessments.PackagePublished{At: at, Found: !at.IsZero()}
				case errors.Is(err, depsdev.ErrNotFound):
					fetched[k] = assessments.PackagePublished{}
				}
				mu.Unlock()
			}
		}()
	}
feed:
	for _, k := range missing {
		select {
		case jobs <- k:
		case <-ctx.Done():
			break feed
		}
	}
	close(jobs)
	wg.Wait()
	if len(fetched) > 0 {
		// Saving is best effort: the dates are used now either way.
		_ = w.Store.SavePublished(context.WithoutCancel(ctx), fetched)
	}
	for k, v := range fetched {
		known[k] = v
	}
	now := time.Now()
	for _, k := range order {
		v, ok := known[k]
		if !ok {
			unchecked++
			continue
		}
		if !v.Found {
			continue // a version deps.dev has no date for cannot be judged
		}
		age := int(now.Sub(v.At).Hours() / 24)
		if age >= minDays {
			continue
		}
		c := output.Components[targets[k].components[0]]
		evidence, _ := json.Marshal(map[string]any{"published_at": v.At.UTC().Format(time.RFC3339), "age_days": age, "min_release_age_days": minDays, "source": "deps.dev"})
		guidance, _ := json.Marshal(map[string]any{"summary": fmt.Sprintf("This version was published %d days ago; the policy asks for at least %d. Fresh releases have had little time for malicious or broken versions to be reported.", age, minDays), "steps": []string{"Review the release and its publisher, or pin the previous version until it has aged.", "If it is intended, accept this entry with a reason."}})
		add(assessments.Finding{Type: "suspicious_dependency", AdvisoryID: "SCRS-NEW-RELEASE", Title: fmt.Sprintf("Version published %d days ago", age), Severity: "medium", Score: 40, Component: c, Evidence: evidence, Guidance: guidance})
	}
	if unchecked > 0 {
		return fmt.Sprintf("%d packages were not checked for release age", unchecked)
	}
	return ""
}
