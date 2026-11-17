package connections

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ErrNotManual marks an asset a connection discovered: the connection owns it,
// so it is removed by narrowing the connection's scope, not by deleting it.
var ErrNotManual = errors.New("asset is managed by its connection")

// ErrAssetInUse marks an asset that has assessments, findings or settings.
var ErrAssetInUse = errors.New("asset has history or configuration")

var assetLocator = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]{1,299}$`)

// assetTypes maps a connection's provider to the asset type it holds.
var assetTypes = map[string]string{"github": "github_repo", "gitlab": "gitlab_repo", "dockerhub": "container_image", "gar": "container_image", "harbor": "container_image", "oci": "container_image"}

// NewAsset is one asset to register by hand under a connection (AST-001).
type NewAsset struct {
	Locator string      `json:"locator"`
	Type    string      `json:"type"`
	Change  AssetChange `json:"-"`
}

// AssetResult is the outcome for one registered asset.
type AssetResult struct {
	Index   int    `json:"index"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	InScope bool   `json:"in_scope"`
	Asset   *Asset `json:"asset,omitempty"`
}

// AddAssets registers assets under a connection, each in its own
// transaction, and reports one result per item: `created`, `exists` or
// `invalid`. Manual assets are flagged so discovery never marks them
// inaccessible; whether they are in scope follows the connection's scope.
func (s *Store) AddAssets(ctx context.Context, connection string, items []NewAsset, actor uuid.UUID) ([]AssetResult, error) {
	c, _, err := s.Get(ctx, connection)
	if err != nil {
		return nil, ErrNotFound
	}
	want := assetTypes[c.Provider]
	out := make([]AssetResult, len(items))
	if want == "" {
		for i := range out {
			out[i] = AssetResult{Index: i, Status: "invalid", Error: "assets of this connection are created with POST /uploads"}
		}
		return out, nil
	}
	for i, item := range items {
		out[i] = AssetResult{Index: i, Status: "invalid"}
		if item.Type == "" {
			item.Type = want
		}
		switch {
		case item.Type != want:
			out[i].Error = "type must be " + want + " for a " + c.Provider + " connection"
			continue
		case !assetLocator.MatchString(item.Locator) || (want != "container_image" && strings.Count(item.Locator, "/") > 8):
			out[i].Error = "locator is not valid for this asset type"
			continue
		}
		res, err := s.addAsset(ctx, c, item, actor)
		switch {
		case errors.Is(err, ErrInvalidChange):
			out[i].Error = "invalid owner or asset attributes"
		case err != nil:
			return nil, err
		default:
			out[i] = res
			out[i].Index = i
		}
	}
	return out, nil
}

func (s *Store) addAsset(ctx context.Context, c Connection, item NewAsset, actor uuid.UUID) (AssetResult, error) {
	resource := Resource{Type: item.Type, Locator: item.Locator}
	inScope := c.Scope.matchesResource(resource)
	flags, _ := json.Marshal(map[string]any{"discovered": false, "manual": true, "accessible": true, "in_scope": inScope})
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AssetResult{}, err
	}
	defer tx.Rollback(ctx)
	// Git hosts ignore case, so a differently cased locator is the same asset.
	var existing uuid.UUID
	err = tx.QueryRow(ctx, `SELECT id FROM `+s.schema+`.assets WHERE connection_id=$1 AND type=$2 AND (locator=$3 OR ($2 IN ('github_repo','gitlab_repo') AND lower(locator)=lower($3)))`, c.ID, item.Type, item.Locator).Scan(&existing)
	if err == nil {
		a, err := scanAsset(tx.QueryRow(ctx, `SELECT `+assetColumns+` FROM `+s.schema+`.assets WHERE id=$1`, existing))
		return AssetResult{Status: "exists", Asset: &a, InScope: assetInScope(a)}, err
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return AssetResult{}, err
	}
	id := uuid.New()
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.assets(id,type,locator,connection_id,flags,metadata) VALUES($1,$2,$3,$4,$5,'{}')`, id, item.Type, item.Locator, c.ID, flags); err != nil {
		return AssetResult{}, err
	}
	details, _ := json.Marshal(map[string]any{"type": item.Type, "locator": item.Locator, "connection": c.Name, "in_scope": inScope})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('asset.created',$1,$2)`, id, auditDetails(WithActor(ctx, actor), details)); err != nil {
		return AssetResult{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return AssetResult{}, err
	}
	a, err := s.Asset(ctx, id)
	if err != nil {
		return AssetResult{}, err
	}
	if hasChange(item.Change) {
		updated, err := s.UpdateAsset(ctx, id, a.Revision, item.Change, actor)
		if err != nil {
			// Never leave a half-configured asset behind.
			_, _ = s.pool.Exec(ctx, `DELETE FROM `+s.schema+`.assets WHERE id=$1`, id)
			if errors.Is(err, ErrInvalidChange) || errors.Is(err, ErrConflict) {
				return AssetResult{}, ErrInvalidChange
			}
			return AssetResult{}, err
		}
		a = updated
	}
	return AssetResult{Status: "created", Asset: &a, InScope: inScope}, nil
}

func hasChange(c AssetChange) bool {
	return len(c.OwnerID) > 0 || c.Environment != nil || c.Criticality != nil || c.Exposure != nil || c.Labels != nil || c.Distribution != nil || c.LegalHold != nil
}

func assetInScope(a Asset) bool {
	var f struct {
		InScope bool `json:"in_scope"`
	}
	_ = json.Unmarshal(a.Flags, &f)
	return f.InScope
}

// DeleteAsset removes an asset registered by hand that nothing refers to.
func (s *Store) DeleteAsset(ctx context.Context, id, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	a, err := scanAsset(tx.QueryRow(ctx, `SELECT `+assetColumns+` FROM `+s.schema+`.assets WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	var flags struct {
		Manual bool `json:"manual"`
	}
	_ = json.Unmarshal(a.Flags, &flags)
	if !flags.Manual {
		return ErrNotManual
	}
	if a.LegalHold {
		return ErrAssetInUse
	}
	if _, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.assets WHERE id=$1`, id); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23503" {
			return ErrAssetInUse
		}
		return err
	}
	details, _ := json.Marshal(map[string]any{"type": a.Type, "locator": a.Locator})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('asset.deleted',$1,$2)`, id, auditDetails(WithActor(ctx, actor), details)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
