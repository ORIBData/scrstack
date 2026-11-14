package worker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ORIBData/scrstack/internal/advisory"
	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/scanner"
)

// advisoryLease bounds one source sync.
const advisoryLease = 30 * time.Minute

// nvdState is the NVD source's sync cursor: the start of the last sync,
// from which the next one reads modified CVEs.
type nvdState struct {
	Cursor time.Time `json:"cursor"`
}

// RunAdvisorySources syncs due NVD and CVE Program sources every interval.
func (w Worker) RunAdvisorySources(ctx context.Context, every time.Duration) {
	for {
		started := time.Now()
		synced, err := w.SyncAdvisoryOnce(ctx)
		if err != nil && ctx.Err() == nil {
			w.Logger.Warn("advisory source bookkeeping failed", "error", err)
		}
		if synced != "" {
			continue
		}
		_ = w.Store.RecordJob(context.WithoutCancel(ctx), "advisory_sources", every, started, err, map[string]any{"synced": synced})
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// SyncAdvisoryOnce syncs the most overdue worker source and returns its key,
// or "" when none was due. Source errors are recorded on the source.
func (w Worker) SyncAdvisoryOnce(ctx context.Context) (string, error) {
	src, err := w.Store.ClaimVulnerabilitySource(ctx, advisoryLease)
	if errors.Is(err, assessments.ErrNotFound) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	syncCtx, cancel := context.WithTimeout(ctx, advisoryLease-time.Minute)
	defer cancel()
	var state json.RawMessage
	switch src.Key {
	case "nvd":
		state, err = w.syncNVD(syncCtx, src)
	case "cve_program":
		err = w.syncCVE5(syncCtx, src)
	default:
		err = errors.New("no sync for source " + src.Key)
	}
	if err != nil {
		w.Logger.Warn("advisory source sync failed", "source", src.Key, "error", err)
	}
	return src.Key, w.Store.FinishVulnerabilitySource(context.WithoutCancel(ctx), src.Key, state, err)
}

func (w Worker) pause(ctx context.Context, d time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(d):
		return nil
	}
}

// syncNVD refreshes known records from the NVD's modified-CVE window, then
// fetches CVEs the register references and SCRS has not stored, paced to
// the NVD's published limits (VUL-006).
func (w Worker) syncNVD(ctx context.Context, src assessments.VulnSource) (json.RawMessage, error) {
	var st nvdState
	_ = json.Unmarshal(src.State, &st)
	base := w.NVDURL
	if base == "" {
		base = src.URL
	}
	client := advisory.Client{BaseURL: base, APIKey: w.NVDAPIKey}
	pace, batch := 6*time.Second, 20
	if w.NVDAPIKey != "" {
		pace, batch = 700*time.Millisecond, 200
	}
	if w.AdvisoryPace > 0 {
		pace = w.AdvisoryPace
	}
	started := time.Now().UTC()
	if !st.Cursor.IsZero() {
		start := st.Cursor
		if started.Sub(start) > 119*24*time.Hour {
			start = started.Add(-119 * 24 * time.Hour)
		}
		for index, pages := 0, 0; pages < 50; pages++ {
			page, err := client.NVDModified(ctx, start, started, index)
			if err != nil {
				return nil, err
			}
			ids := make([]string, len(page.Records))
			for i, r := range page.Records {
				ids[i] = r.Record.ID
			}
			known, err := w.Store.KnownAdvisoryIDs(ctx, "nvd", ids)
			if err != nil {
				return nil, err
			}
			var update []advisory.Raw
			for _, r := range page.Records {
				if known[r.Record.ID] {
					update = append(update, r)
				}
			}
			if err := w.Store.SaveAdvisoryRecords(ctx, update); err != nil {
				return nil, err
			}
			index += len(page.Records)
			if len(page.Records) == 0 || index >= page.Total {
				break
			}
			if err := w.pause(ctx, pace); err != nil {
				return nil, err
			}
		}
	}
	cves, err := w.Store.TrackedCVEs(ctx, "nvd", started.AddDate(0, 0, -30), batch)
	if err != nil {
		return nil, err
	}
	for i, id := range cves {
		if i > 0 || !st.Cursor.IsZero() {
			if err := w.pause(ctx, pace); err != nil {
				return nil, err
			}
		}
		raw, err := client.NVDCVE(ctx, id)
		if errors.Is(err, advisory.ErrNotFound) {
			raw = missingRecord("nvd", id, started)
		} else if errors.Is(err, advisory.ErrRateLimited) {
			break // the rest waits for the next run
		} else if err != nil {
			return nil, err
		}
		if err := w.Store.SaveAdvisoryRecords(ctx, []advisory.Raw{raw}); err != nil {
			return nil, err
		}
	}
	state, _ := json.Marshal(nvdState{Cursor: started})
	return state, nil
}

// missingRecord remembers that a source has no record for a CVE, so it is
// asked again only after the refresh period.
func missingRecord(origin, id string, now time.Time) advisory.Raw {
	r := advisory.Record{ID: id, Origin: origin, Modified: now, Aliases: []string{}, Severity: []advisory.Severity{}, References: []advisory.Reference{}}
	r.DatabaseSpecific.CVSS, r.DatabaseSpecific.CWE, r.DatabaseSpecific.Status = []advisory.CVSS{}, []string{}, "NOT_FOUND"
	return advisory.Raw{Record: r, Source: json.RawMessage(`{}`)}
}

// syncCVE5 fetches CNA records for referenced CVEs from the CVE Services API,
// refreshing each weekly.
func (w Worker) syncCVE5(ctx context.Context, src assessments.VulnSource) error {
	base := w.CVEURL
	if base == "" {
		base = src.URL
	}
	client := advisory.Client{BaseURL: base}
	pace := 250 * time.Millisecond
	if w.AdvisoryPace > 0 {
		pace = w.AdvisoryPace
	}
	now := time.Now().UTC()
	cves, err := w.Store.TrackedCVEs(ctx, "cve5", now.AddDate(0, 0, -7), 100)
	if err != nil {
		return err
	}
	for i, id := range cves {
		if i > 0 {
			if err := w.pause(ctx, pace); err != nil {
				return err
			}
		}
		raw, err := client.CVE5(ctx, id)
		if errors.Is(err, advisory.ErrNotFound) {
			raw = missingRecord("cve5", id, now)
		} else if errors.Is(err, advisory.ErrRateLimited) {
			break
		} else if err != nil {
			return err
		}
		if err := w.Store.SaveAdvisoryRecords(ctx, []advisory.Raw{raw}); err != nil {
			return err
		}
	}
	return nil
}

// recordFeedHealth reads the scanner's feed status and records it for the
// feed-sync sources, then raises feed.stale for sources that just became
// stale (VUL-010). OSV's own staleness alert stays with MonitorFeeds.
func (w Worker) recordFeedHealth(ctx context.Context, client *http.Client) error {
	endpoint, err := url.Parse(w.ScannerURL)
	if err != nil {
		return err
	}
	endpoint.Path, endpoint.RawQuery = "/feeds", ""
	resp, err := client.Get(endpoint.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var status scanner.FeedStatus
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&status) != nil {
		return errors.New("scanner feed status unavailable")
	}
	osvCount := int64(len(status.OSV.Ecosystems))
	for _, key := range []string{"osv", "malicious_packages"} {
		if err := w.Store.RecordFeedHealth(ctx, key, status.OSV.FetchedAt, osvCount, status.OSV.Error); err != nil {
			return err
		}
	}
	for key, file := range map[string]scanner.FeedFile{"kev": status.KEV, "epss": status.EPSS} {
		failure := ""
		if !file.Present {
			failure = "not downloaded; enrichment skipped"
		}
		if err := w.Store.RecordFeedHealth(ctx, key, file.Modified, 0, failure); err != nil {
			return err
		}
	}
	stale, err := w.Store.StaleTransitions(ctx)
	if err != nil {
		return err
	}
	for _, src := range stale {
		if src.Key == "osv" || w.Notify == nil {
			continue
		}
		if err := w.Notify.EmitNow(ctx, "feed.stale", map[string]any{"feed": src.Key, "source": src.Name, "detail": src.Name + " has not synced within twice its " + time.Duration(src.ScheduleMinutes*int(time.Minute)).String() + " schedule; data from it is ageing", "failures": src.Failures}); err != nil {
			return err
		}
	}
	return nil
}
