package worker

import (
	"context"
	"errors"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/dtrack"
	"github.com/google/uuid"
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
		for ctx.Err() == nil {
			done, err := w.VerifyDependencyTrackOnce(ctx)
			if err != nil {
				w.Logger.Warn("Dependency-Track processing check bookkeeping failed", "error", err)
			}
			if !done || err != nil {
				break
			}
		}
		for ctx.Err() == nil {
			done, err := w.SyncDependencyTrackOnce(ctx)
			if err != nil {
				w.Logger.Warn("Dependency-Track sync bookkeeping failed", "error", err)
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

// dtrackClient builds a client from the stored settings. cleanup closes the
// connections of a client the worker made itself.
func (w Worker) dtrackClient(ctx context.Context) (client dtrack.Client, cleanup func(), err error) {
	settings, err := w.Store.DTrackSettings(ctx)
	if err != nil {
		return client, nil, err
	}
	if !dtrack.ValidURL(settings.URL, w.DTrackPrivateHosts) || len(settings.Key) == 0 {
		return client, nil, errors.Join(dtrack.ErrRejected, errors.New("URL or API key missing or not allowed"))
	}
	key, err := w.Connections.Unseal(settings.Key, assessments.DTrackAAD())
	if err != nil {
		return client, nil, errors.Join(dtrack.ErrRejected, errors.New("API key cannot be opened with the current master key"))
	}
	httpClient, cleanup := w.DTrackHTTP, func() {}
	if httpClient == nil {
		httpClient = dtrack.NewHTTPClient(w.DTrackPrivateHosts)
		cleanup = httpClient.CloseIdleConnections
	}
	return dtrack.Client{BaseURL: settings.URL, APIKey: string(key), HTTP: httpClient}, cleanup, nil
}

func (w Worker) pushDTrack(ctx context.Context, u assessments.DTrackUpload) (string, error) {
	client, cleanup, err := w.dtrackClient(ctx)
	if err != nil {
		return "", err
	}
	defer cleanup()
	settings, err := w.Store.DTrackSettings(ctx)
	if err != nil {
		return "", err
	}
	bom, err := w.SBOMs.GetSBOM(ctx, u.SBOMKey)
	if err != nil {
		// Transient unless the object is gone; the attempt bound ends it.
		return "", errors.New("SBOM unavailable from artifact storage")
	}
	return client.Upload(ctx, dtrack.Upload{ProjectName: u.ProjectName, ProjectVersion: u.ProjectVersion, Parent: settings.Parent, BOM: bom, IsLatest: u.IsLatest, Tags: u.Tags})
}

// VerifyDependencyTrackOnce checks one accepted upload's processing, if one
// is due. Dependency-Track accepts a BOM and processes it afterwards, so
// "uploaded" alone does not mean the BOM was imported.
func (w Worker) VerifyDependencyTrackOnce(ctx context.Context) (bool, error) {
	u, err := w.Store.ClaimDTrackVerify(ctx)
	if errors.Is(err, assessments.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	outcome, detail := w.verifyDTrack(checkCtx, u)
	cancel()
	if outcome == "pending" && u.ProcessingAttempts >= assessments.DTrackVerifyAttempts {
		outcome, detail = "unconfirmed", "Dependency-Track was still processing or unreachable after about ten minutes"
	}
	if outcome == "failed" {
		w.Logger.Warn("Dependency-Track did not import a BOM", "upload", u.ID, "project", u.ProjectName, "detail", detail)
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return true, w.Store.FinishDTrackVerify(finishCtx, u, outcome, detail)
}

// verifyDTrack decides the processing outcome of one upload: pending (ask
// again later), processed, unconfirmed or failed.
func (w Worker) verifyDTrack(ctx context.Context, u assessments.DTrackUpload) (outcome, detail string) {
	client, cleanup, err := w.dtrackClient(ctx)
	if err != nil {
		return "pending", err.Error()
	}
	defer cleanup()
	// Dependency-Track tokens are UUIDs; with none, go straight to the project.
	if _, err := uuid.Parse(u.Token); err == nil {
		processing, err := client.Processing(ctx, u.Token)
		switch {
		case errors.Is(err, dtrack.ErrRejected):
			return "unconfirmed", "Dependency-Track rejected the processing check"
		case err != nil:
			return "pending", err.Error()
		case processing:
			return "pending", ""
		}
	}
	project, err := client.Project(ctx, u.ProjectName, u.ProjectVersion)
	switch {
	case errors.Is(err, dtrack.ErrForbidden):
		return "unconfirmed", "processing finished, but the API key cannot read projects (VIEW_PORTFOLIO), so the import is unconfirmed"
	case errors.Is(err, dtrack.ErrNotFound):
		return "failed", "the project does not exist in Dependency-Track after processing"
	case errors.Is(err, dtrack.ErrRejected):
		return "unconfirmed", "Dependency-Track rejected the project lookup"
	case err != nil:
		return "pending", err.Error()
	}
	// Dependency-Track stamps lastBomImport when it finishes importing. Allow
	// two minutes for the clocks of the two servers to differ.
	if u.UploadedAt != nil && project.LastBOMImport.Before(u.UploadedAt.Add(-2*time.Minute)) {
		return "failed", "Dependency-Track finished processing without importing the BOM (its last import is older than this upload); check its notifications for BOM_PROCESSING_FAILED"
	}
	return "processed", ""
}

// SyncDependencyTrackOnce reads one project's findings back, if one is due.
// Errors are recorded on the project, not returned.
func (w Worker) SyncDependencyTrackOnce(ctx context.Context) (bool, error) {
	p, err := w.Store.ClaimDTrackSync(ctx)
	if errors.Is(err, assessments.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	syncCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	res, syncErr := w.syncDTrack(syncCtx, p)
	cancel()
	text := ""
	if syncErr != nil {
		text = syncErr.Error()
		w.Logger.Warn("Dependency-Track sync failed", "project", p.Name, "version", p.Version, "error", syncErr)
	} else if res.Created+res.Closed+res.Imported+len(res.Pushes) > 0 {
		w.Logger.Info("Dependency-Track synced", "project", p.Name, "version", p.Version, "findings", res.Total, "matched", res.Matched, "only_in_dependency_track", res.Created, "closed", res.Closed, "triage_imported", res.Imported, "triage_written", len(res.Pushes))
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	return true, w.Store.FinishDTrackSync(finishCtx, p, text, res.Total, res.MorePushes)
}

// syncDTrack reads a project's findings into the register and writes the
// register's triage decisions back.
func (w Worker) syncDTrack(ctx context.Context, p assessments.DTrackProject) (assessments.DTrackSyncResult, error) {
	var res assessments.DTrackSyncResult
	client, cleanup, err := w.dtrackClient(ctx)
	if err != nil {
		return res, err
	}
	defer cleanup()
	settings, err := w.Store.DTrackSettings(ctx)
	if err != nil {
		return res, err
	}
	project, err := client.Project(ctx, p.Name, p.Version)
	switch {
	case errors.Is(err, dtrack.ErrForbidden):
		return res, errors.New("the API key cannot read projects (needs VIEW_PORTFOLIO)")
	case errors.Is(err, dtrack.ErrNotFound):
		return res, errors.New("the project is not in Dependency-Track (deleted there?); the next upload recreates it")
	case err != nil:
		return res, err
	}
	findings, err := client.Findings(ctx, project.UUID)
	switch {
	case errors.Is(err, dtrack.ErrForbidden):
		return res, errors.New("the API key cannot read findings (needs VIEW_VULNERABILITY)")
	case err != nil:
		return res, err
	}
	res, err = w.Store.ApplyDTrackFindings(ctx, p, project.UUID, findings, settings)
	if err != nil {
		return res, err
	}
	for _, push := range res.Pushes {
		err := client.SetAnalysis(ctx, push.Analysis)
		if errors.Is(err, dtrack.ErrForbidden) {
			return res, errors.New("the API key cannot write triage (needs VULNERABILITY_ANALYSIS)")
		}
		if err != nil {
			return res, err
		}
		if err := w.Store.MarkDTrackPushed(ctx, push.MemberID, push.Status); err != nil {
			return res, err
		}
	}
	return res, nil
}
