// Package actionscheck reads a repository's GitHub Actions inventory and
// stores what it shows (INT-014, INT-015): whether Actions is in use, the
// workflow list, and holes in workflow run numbers. It only reads.
package actionscheck

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// ErrNotGitHub means the asset is not a GitHub repository with an enabled
// GitHub connection.
var ErrNotGitHub = errors.New("only repositories of an enabled GitHub connection have an Actions inventory")

// API is the part of the GitHub adapter the check needs.
type API interface {
	GitHubActions(ctx context.Context, c connections.Connection, secret json.RawMessage, repository string) (connections.ActionsInfo, error)
}

// Checker reads and records Actions inventories.
type Checker struct {
	Connections *connections.Store
	Store       *assessments.Store
	API         API
}

// Check reads one repository's inventory and records it. An outage is
// recorded and returned; a missing permission is a reading with Available
// false, not an error.
func (k Checker) Check(ctx context.Context, asset uuid.UUID) (assessments.ActionsState, error) {
	a, err := k.Connections.Asset(ctx, asset)
	if err != nil {
		return assessments.ActionsState{}, assessments.ErrNotFound
	}
	if a.Type != "github_repo" {
		return assessments.ActionsState{}, ErrNotGitHub
	}
	name, err := k.Connections.NameByID(ctx, a.ConnectionID)
	if err != nil {
		return assessments.ActionsState{}, assessments.ErrNotFound
	}
	c, secret, err := k.Connections.Get(ctx, name)
	if err != nil {
		return assessments.ActionsState{}, err
	}
	if c.Provider != "github" || !c.Enabled {
		return assessments.ActionsState{}, ErrNotGitHub
	}
	info, err := k.API.GitHubActions(ctx, c, secret, a.Locator)
	if err != nil {
		_ = k.Store.RecordActionsError(context.WithoutCancel(ctx), asset, err.Error())
		return assessments.ActionsState{}, err
	}
	raw, _ := json.Marshal(info)
	var reading assessments.ActionsReading
	if err := json.Unmarshal(raw, &reading); err != nil {
		return assessments.ActionsState{}, err
	}
	return k.Store.RecordActions(ctx, asset, a.Locator, reading)
}

// Sweep checks the repositories whose inventory is missing or older than
// interval, at most `batch` per pass, pausing between repositories to stay
// well inside GitHub's rate limits. It returns how many it checked.
func (k Checker) Sweep(ctx context.Context, interval time.Duration, batch int, pause time.Duration, logger *slog.Logger) int {
	due, err := k.Store.ActionsDue(ctx, interval, batch)
	if err != nil {
		logger.Warn("actions sweep failed to list repositories", "error", err)
		return 0
	}
	checked := 0
	for _, target := range due {
		if ctx.Err() != nil {
			break
		}
		if _, err := k.Check(ctx, target.AssetID); err != nil {
			logger.Warn("actions check failed", "repository", target.Locator, "error", err)
		}
		checked++
		select {
		case <-ctx.Done():
		case <-time.After(pause):
		}
	}
	return checked
}
