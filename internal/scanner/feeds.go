package scanner

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

type FeedManifest struct {
	FetchedAt  time.Time `json:"fetched_at"`
	Ecosystems []string  `json:"ecosystems"`
}

func SyncFeeds(ctx context.Context, root string, ecosystems []string) error {
	if len(ecosystems) == 0 || len(ecosystems) > 32 {
		return errors.New("invalid feed ecosystem selection")
	}
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	snapshot := filepath.Join(root, "snapshot-"+uuid.NewString())
	if err := os.Mkdir(snapshot, 0755); err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(snapshot)
		}
	}()
	client := &http.Client{Timeout: 10 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, ecosystem := range ecosystems {
		if ecosystem == "" || ecosystem == "." || ecosystem == ".." || strings.ContainsAny(ecosystem, "/\\\x00") || len(ecosystem) > 64 {
			return errors.New("invalid ecosystem")
		}
		directory := filepath.Join(snapshot, "osv-scalibr", ecosystem)
		if err := os.MkdirAll(directory, 0755); err != nil {
			return err
		}
		request, err := http.NewRequestWithContext(ctx, "GET", "https://osv-vulnerabilities.storage.googleapis.com/"+url.PathEscape(ecosystem)+"/all.zip", nil)
		if err != nil {
			return err
		}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("OSV feed unavailable")
		}
		if response.StatusCode != 200 {
			response.Body.Close()
			return errors.New("OSV feed download rejected")
		}
		destination := filepath.Join(directory, "all.zip")
		f, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
		if err != nil {
			response.Body.Close()
			return err
		}
		n, copyErr := io.Copy(f, io.LimitReader(response.Body, (512<<20)+1))
		closeErr := f.Close()
		response.Body.Close()
		if copyErr != nil || closeErr != nil || n > 512<<20 {
			return errors.New("feed download failed or exceeded limit")
		}
		if err := validateFeed(destination); err != nil {
			return err
		}
	}
	syncEnrichment(ctx, root, snapshot)
	manifest, _ := json.Marshal(FeedManifest{FetchedAt: time.Now().UTC(), Ecosystems: ecosystems})
	if err := os.WriteFile(filepath.Join(snapshot, "manifest.json"), manifest, 0644); err != nil {
		return err
	}
	link := filepath.Join(root, "current-"+uuid.NewString())
	if err := os.Symlink(filepath.Base(snapshot), link); err != nil {
		return err
	}
	defer os.Remove(link)
	if err := os.Rename(link, filepath.Join(root, "current")); err != nil {
		return err
	}
	committed = true
	// Retire only generated snapshots older than 48h. Scans reject feeds older
	// than 24h and have a 4-minute deadline, so this cannot remove an active feed.
	entries, _ := os.ReadDir(root)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "snapshot-") {
			continue
		}
		if _, err := uuid.Parse(strings.TrimPrefix(entry.Name(), "snapshot-")); err != nil {
			continue
		}
		info, err := entry.Info()
		if err == nil && time.Since(info.ModTime()) > 48*time.Hour {
			_ = os.RemoveAll(filepath.Join(root, entry.Name()))
		}
	}
	return nil
}

const maxFeedEntries = 1_000_000

func validateFeed(filename string) error {
	archive, err := zip.OpenReader(filename)
	if err != nil {
		return errors.New("invalid feed archive")
	}
	defer archive.Close()
	// The npm archive alone held ~232k records in Nov 2026 (mostly MAL- reports),
	// so the cap leaves growth headroom; size limits below bound the expansion.
	if len(archive.File) == 0 || len(archive.File) > maxFeedEntries {
		return errors.New("feed entry count exceeded")
	}
	var total uint64
	for _, entry := range archive.File {
		if entry.FileInfo().IsDir() {
			continue
		}
		total += entry.UncompressedSize64
		if entry.UncompressedSize64 > 2<<20 || total > 2<<30 {
			return errors.New("feed expansion limit exceeded")
		}
		reader, err := entry.Open()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(io.LimitReader(reader, (2<<20)+1))
		reader.Close()
		if err != nil || len(data) > 2<<20 {
			return errors.New("invalid feed record")
		}
		var record struct {
			ID       string    `json:"id"`
			Modified time.Time `json:"modified"`
		}
		if json.Unmarshal(data, &record) != nil || record.ID == "" || record.Modified.IsZero() {
			return errors.New("invalid OSV record")
		}
	}
	return nil
}
func pinnedFeed(root string) (string, error) {
	directory, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("offline feeds not initialized")
	}
	data, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return "", errors.New("feed freshness manifest missing")
	}
	var manifest FeedManifest
	if json.Unmarshal(data, &manifest) != nil || len(manifest.Ecosystems) == 0 || time.Since(manifest.FetchedAt) > 24*time.Hour || manifest.FetchedAt.After(time.Now().Add(5*time.Minute)) {
		return "", errors.New("offline feeds are stale")
	}
	return directory, nil
}
