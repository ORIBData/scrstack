package scanner

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Exploitation context (VUL-005): CISA KEV and FIRST EPSS. Both are optional
// enrichments; their absence marks the enrich stage skipped, never blocks SCA.
const (
	kevURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	epssURL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
)

func enrichmentClient() *http.Client {
	return &http.Client{Timeout: 5 * time.Minute, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		// EPSS redirects to a dated file on the same host; follow only that.
		if len(via) > 3 || req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
			return http.ErrUseLastResponse
		}
		return nil
	}}
}

func download(ctx context.Context, client *http.Client, url, destination string, limit int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New("download failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("download rejected")
	}
	f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	n, copyErr := io.Copy(f, io.LimitReader(resp.Body, limit+1))
	closeErr := f.Close()
	if copyErr != nil || closeErr != nil || n > limit {
		_ = os.Remove(destination)
		return errors.New("download failed or exceeded limit")
	}
	return nil
}

// syncEnrichment fetches KEV and EPSS into the new snapshot, falling back to
// the previous snapshot's validated copies when a source is unavailable.
func syncEnrichment(ctx context.Context, root, snapshot string) {
	client := enrichmentClient()
	for _, feed := range []struct {
		name, url string
		limit     int64
		validate  func(string) error
	}{
		{"kev.json", kevURL, 32 << 20, func(p string) error { _, err := loadKEV(p); return err }},
		{"epss.csv.gz", epssURL, 64 << 20, func(p string) error { _, err := loadEPSS(p); return err }},
	} {
		destination := filepath.Join(snapshot, feed.name)
		err := download(ctx, client, feed.url, destination, feed.limit)
		if err == nil {
			if err = feed.validate(destination); err != nil {
				_ = os.Remove(destination)
			}
		}
		if err != nil {
			slog.Warn("enrichment feed unavailable; carrying forward previous copy", "feed", feed.name, "error", err)
			if previous, linkErr := filepath.EvalSymlinks(filepath.Join(root, "current")); linkErr == nil {
				if data, readErr := os.ReadFile(filepath.Join(previous, feed.name)); readErr == nil {
					_ = os.WriteFile(destination, data, 0644)
				}
			}
		}
	}
}

func loadKEV(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var catalog struct {
		Vulnerabilities []struct {
			CVE string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if json.Unmarshal(data, &catalog) != nil || len(catalog.Vulnerabilities) < 100 {
		return nil, errors.New("invalid KEV catalog")
	}
	out := make(map[string]bool, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		if strings.HasPrefix(v.CVE, "CVE-") {
			out[v.CVE] = true
		}
	}
	return out, nil
}

func loadEPSS(path string) (map[string]float64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, errors.New("invalid EPSS archive")
	}
	defer gz.Close()
	scanner := bufio.NewScanner(io.LimitReader(gz, 256<<20))
	out := map[string]float64{}
	header := false
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") {
			continue
		}
		if !header {
			if !strings.HasPrefix(line, "cve,epss") {
				return nil, errors.New("unexpected EPSS header")
			}
			header = true
			continue
		}
		cve, rest, ok := strings.Cut(line, ",")
		score, _, _ := strings.Cut(rest, ",")
		value, err := strconv.ParseFloat(score, 64)
		if !ok || err != nil || value < 0 || value > 1 {
			return nil, errors.New("invalid EPSS row")
		}
		out[cve] = value
	}
	if scanner.Err() != nil || len(out) < 10000 {
		return nil, errors.New("EPSS data incomplete")
	}
	return out, nil
}

type enrichment struct {
	kev  map[string]bool
	epss map[string]float64
}

var enrichmentCache struct {
	sync.Mutex
	dir string
	e   *enrichment
}

// loadEnrichment parses a snapshot's feeds once and reuses them until the
// pinned snapshot changes. Returns nil when the snapshot has neither feed.
func loadEnrichment(dir string) *enrichment {
	enrichmentCache.Lock()
	defer enrichmentCache.Unlock()
	if enrichmentCache.dir == dir {
		return enrichmentCache.e
	}
	e := &enrichment{}
	e.kev, _ = loadKEV(filepath.Join(dir, "kev.json"))
	e.epss, _ = loadEPSS(filepath.Join(dir, "epss.csv.gz"))
	if e.kev == nil && e.epss == nil {
		e = nil
	}
	enrichmentCache.dir, enrichmentCache.e = dir, e
	return e
}

// apply returns exploitation context for an advisory and its aliases.
func (e *enrichment) apply(ids []string) (kev bool, epss float64) {
	for _, id := range ids {
		if e.kev[id] {
			kev = true
		}
		if v := e.epss[id]; v > epss {
			epss = v
		}
	}
	return kev, epss
}
