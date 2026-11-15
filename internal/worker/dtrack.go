package worker

import (
	"context"
	"errors"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/dtrack"
)

// SBOMReader reads stored SBOMs (verified against their digest).
type SBOMReader interface {
	GetSBOM(context.Context, string) ([]byte, error)
}

// RunDependencyTrack pushes queued SBOM uploads while the export is
// enabled (P2). Several workers may run it: uploads are leased.
func (w Worker) RunDependencyTrack(ctx context.Context, every time.Duration) {
	pruned := time.Time{}
	for ctx.Err() == nil {
		for ctx.Err() == nil {
			done, err := w.PushDependencyTrackOnce(ctx)
			if err != nil {
				w.Logger.Warn("Dependency-Track upload bookkeeping failed", "error", err)
			}
			if !done || err != nil {
				break
			}
		}
		if time.Since(pruned) > time.Hour {
			if _, err := w.Store.PruneDTrack(ctx, 90*24*time.Hour); err == nil {
				pruned = time.Now()
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(every):
		}
	}
}

// PushDependencyTrackOnce uploads the most overdue SBOM, if one is due.
// Upload errors are recorded on the upload, not returned.
func (w Worker) PushDependencyTrackOnce(ctx context.Context) (bool, error) {
	if w.SBOMs == nil {
		return false, nil
	}
	u, err := w.Store.ClaimDTrack(ctx)
	if errors.Is(err, assessments.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	pushCtx, cancel := context.WithTimeout(ctx, assessments.DTrackLease-30*time.Second)
	token, pushErr := w.pushDTrack(pushCtx, u)
	cancel()
	permanent := errors.Is(pushErr, dtrack.ErrRejected)
	if pushErr != nil {
		w.Logger.Warn("Dependency-Track upload failed", "upload", u.ID, "project", u.ProjectName, "attempt", u.Attempts, "permanent", permanent, "error", pushErr)
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return true, w.Store.FinishDTrack(finishCtx, u, token, pushErr, permanent)
}

func (w Worker) pushDTrack(ctx context.Context, u assessments.DTrackUpload) (string, error) {
	settings, err := w.Store.DTrackSettings(ctx)
	if err != nil {
		return "", err
	}
	if !dtrack.ValidURL(settings.URL, w.DTrackPrivateHosts) || len(settings.Key) == 0 {
		return "", errors.Join(dtrack.ErrRejected, errors.New("URL or API key missing or not allowed"))
	}
	key, err := w.Connections.Unseal(settings.Key, assessments.DTrackAAD())
	if err != nil {
		return "", errors.Join(dtrack.ErrRejected, errors.New("API key cannot be opened with the current master key"))
	}
	bom, err := w.SBOMs.GetSBOM(ctx, u.SBOMKey)
	if err != nil {
		// Transient unless the object is gone; the attempt bound ends it.
		return "", errors.New("SBOM unavailable from artifact storage")
	}
	httpClient := w.DTrackHTTP
	if httpClient == nil {
		httpClient = dtrack.NewHTTPClient(w.DTrackPrivateHosts)
		defer httpClient.CloseIdleConnections()
	}
	client := dtrack.Client{BaseURL: settings.URL, APIKey: string(key), HTTP: httpClient}
	return client.Upload(ctx, dtrack.Upload{ProjectName: u.ProjectName, ProjectVersion: u.ProjectVersion, Parent: settings.Parent, BOM: bom})
}
