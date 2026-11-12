package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/scanner"
)

type Artifacts interface {
	PutSBOM(context.Context, []byte) (string, string, error)
	PutPlan(context.Context, []byte) (string, string, error)
}
type Snapshotter interface {
	GitHubSnapshot(context.Context, connections.Connection, json.RawMessage, string, string, string) ([]byte, string, bool, error)
}
type Worker struct {
	Source                   Snapshotter
	Store                    *assessments.Store
	Connections              *connections.Store
	Artifacts                Artifacts
	ScannerURL, ScannerToken string
	Logger                   *slog.Logger
}

func (w Worker) Run(ctx context.Context) error {
	endpoint, err := url.Parse(w.ScannerURL)
	if err != nil || (endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || len(w.ScannerToken) < 32 {
		return errors.New("invalid internal scanner configuration")
	}
	timer := time.NewTicker(2 * time.Second)
	defer timer.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		a, err := w.Store.Claim(ctx)
		if err != nil {
			if !errors.Is(err, assessments.ErrNotFound) {
				w.Logger.Error("assessment claim failed")
			}
			select {
			case <-ctx.Done():
				return nil
			case <-timer.C:
				continue
			}
		}
		jobCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		err = w.run(jobCtx, &a)
		cancel()
		if err != nil {
			failureCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
			retry := !errors.Is(err, assessments.ErrScope)
			if failErr := w.Store.Fail(failureCtx, a, "assessment stage failed; scan coverage incomplete", retry); failErr != nil && !errors.Is(failErr, assessments.ErrLease) {
				w.Logger.Error("assessment failure persistence failed", "assessment_id", a.ID)
			}
			done()
			w.Logger.Warn("assessment failed", "assessment_id", a.ID)
		}
	}
}
func (w Worker) run(ctx context.Context, a *assessments.Assessment) error {
	name, err := w.Connections.NameByID(ctx, a.ConnectionID)
	if err != nil {
		return assessments.ErrScope
	}
	c, secret, err := w.Connections.Get(ctx, name)
	if err != nil {
		return err
	}
	if !c.Enabled || c.ConfigurationRevision != a.ConnectionRevision {
		return assessments.ErrScope
	}
	revision := a.Commit
	if revision == "" {
		revision = a.Request.Target.Commit
	}
	source := w.Source
	if source == nil {
		source = connections.NewNativeAdapters()
	}
	archive, commit, moved, err := source.GitHubSnapshot(ctx, c, secret, a.Request.Target.Repository, a.Request.Target.Ref, revision)
	if err != nil {
		return err
	}
	if err = w.Store.BindRevision(ctx, *a, commit, moved); err != nil {
		return err
	}
	a.Commit = commit
	endpoint := w.ScannerURL
	if a.Request.Remediation != nil {
		target, _ := url.Parse(endpoint)
		target.Path = "/remediate"
		query := url.Values{}
		query.Set("manifest", a.Request.Remediation.Manifest)
		query.Set("strategy", a.Request.Remediation.Strategy)
		target.RawQuery = query.Encode()
		endpoint = target.String()
	}
	request, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(archive))
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+w.ScannerToken)
	request.Header.Set("Content-Type", "application/gzip")
	client := &http.Client{Timeout: 4 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("scanner unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("scanner failed")
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, (64<<20)+1))
	if err != nil || len(data) > 64<<20 {
		return errors.New("scanner result exceeded limit")
	}
	if a.Request.Remediation != nil {
		if !json.Valid(data) {
			return errors.New("invalid remediation result")
		}
		key, digest, err := w.Artifacts.PutPlan(ctx, data)
		if err != nil {
			return err
		}
		return w.Store.CompletePlan(ctx, *a, key, digest)
	}
	var output scanner.Output
	if json.Unmarshal(data, &output) != nil {
		return errors.New("invalid scanner result")
	}
	key, digest, err := w.Artifacts.PutSBOM(ctx, output.SBOM)
	if err != nil {
		return err
	}
	stages := []assessments.Stage{{Name: "resolve", Status: "ok"}, {Name: "fetch", Status: "ok"}}
	stages = append(stages, output.Stages...)
	return w.Store.Complete(ctx, *a, assessments.Result{Commit: commit, RefMoved: moved, Stages: stages, Components: output.Components, Findings: output.Findings, SBOMKey: key, SBOMSHA256: digest, Complete: true})
}
