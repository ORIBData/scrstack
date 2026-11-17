package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Asset links record that a container image was built from a source
// repository (CON-012, kind `built_from`), so an image's entries name the
// repository and a repository lists the images it produced. A link is set by
// hand or taken from the image's `org.opencontainers.image.source` label, a
// claim by whoever published the image.

// LinkKindBuiltFrom is the only kind in use.
const LinkKindBuiltFrom = "built_from"

// Link source values.
const (
	LinkSourceManual = "manual"
	LinkSourceLabel  = "oci_label"
)

// LinkedAsset names the asset at the other end of a link.
type LinkedAsset struct {
	ID      uuid.UUID `json:"id"`
	Type    string    `json:"type"`
	Locator string    `json:"locator"`
}

// AssetLink is one link as seen from an asset: Direction `out` when the asset
// is the image built from the other end, `in` when the asset is the source of
// the other.
type AssetLink struct {
	Kind      string      `json:"kind"`
	Direction string      `json:"direction"`
	Asset     LinkedAsset `json:"asset"`
	Source    string      `json:"source"`
	CreatedAt time.Time   `json:"created_at"`
}

func assetLinkSchema(s string) []string {
	return []string{
		`CREATE TABLE IF NOT EXISTS ` + s + `.asset_links(from_asset_id uuid NOT NULL REFERENCES ` + s + `.assets(id),to_asset_id uuid NOT NULL REFERENCES ` + s + `.assets(id),kind text NOT NULL CHECK(kind IN ('built_from','deployed_from')),source text NOT NULL DEFAULT 'manual' CHECK(source IN ('manual','oci_label')),created_at timestamptz NOT NULL DEFAULT clock_timestamp(),PRIMARY KEY(from_asset_id,to_asset_id,kind),CHECK(from_asset_id<>to_asset_id))`,
		`CREATE INDEX IF NOT EXISTS asset_links_to_idx ON ` + s + `.asset_links(to_asset_id,kind)`,
	}
}

// AssetLinks lists the links of an asset in both directions.
func (s *Store) AssetLinks(ctx context.Context, asset uuid.UUID) ([]AssetLink, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.assets WHERE id=$1)`, asset).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT l.kind,'out',o.id,o.type,o.locator,l.source,l.created_at FROM `+s.schema+`.asset_links l JOIN `+s.schema+`.assets o ON o.id=l.to_asset_id WHERE l.from_asset_id=$1
UNION ALL SELECT l.kind,'in',o.id,o.type,o.locator,l.source,l.created_at FROM `+s.schema+`.asset_links l JOIN `+s.schema+`.assets o ON o.id=l.from_asset_id WHERE l.to_asset_id=$1 ORDER BY 2,5`, asset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AssetLink{}
	for rows.Next() {
		var l AssetLink
		if err := rows.Scan(&l.Kind, &l.Direction, &l.Asset.ID, &l.Asset.Type, &l.Asset.Locator, &l.Source, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// sourceAssetTypes are the asset types an image can be built from.
var sourceAssetTypes = map[string]bool{"github_repo": true, "gitlab_repo": true, "uploaded": true}

// AddLink links an image to the source it was built from. A link that
// exists is returned unchanged (created is false). ErrInput is returned when
// the ends cannot be linked: `from` must be a container image and `to` a
// repository or uploaded source.
func (s *Store) AddLink(ctx context.Context, from, to uuid.UUID, source string, actor uuid.UUID) (AssetLink, bool, error) {
	if from == to || (source != LinkSourceManual && source != LinkSourceLabel) {
		return AssetLink{}, false, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return AssetLink{}, false, err
	}
	defer tx.Rollback(ctx)
	var fromType, toType, toLocator string
	err = tx.QueryRow(ctx, `SELECT type FROM `+s.schema+`.assets WHERE id=$1`, from).Scan(&fromType)
	if errors.Is(err, pgx.ErrNoRows) {
		return AssetLink{}, false, ErrNotFound
	}
	if err != nil {
		return AssetLink{}, false, err
	}
	err = tx.QueryRow(ctx, `SELECT type,locator FROM `+s.schema+`.assets WHERE id=$1`, to).Scan(&toType, &toLocator)
	if errors.Is(err, pgx.ErrNoRows) {
		return AssetLink{}, false, ErrNotFound
	}
	if err != nil {
		return AssetLink{}, false, err
	}
	if fromType != "container_image" || !sourceAssetTypes[toType] {
		return AssetLink{}, false, ErrInput
	}
	tag, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.asset_links(from_asset_id,to_asset_id,kind,source) VALUES($1,$2,'built_from',$3) ON CONFLICT DO NOTHING`, from, to, source)
	if err != nil {
		return AssetLink{}, false, err
	}
	created := tag.RowsAffected() == 1
	link := AssetLink{Kind: LinkKindBuiltFrom, Direction: "out", Asset: LinkedAsset{ID: to, Type: toType, Locator: toLocator}}
	if err := tx.QueryRow(ctx, `SELECT source,created_at FROM `+s.schema+`.asset_links WHERE from_asset_id=$1 AND to_asset_id=$2 AND kind='built_from'`, from, to).Scan(&link.Source, &link.CreatedAt); err != nil {
		return AssetLink{}, false, err
	}
	if created {
		details, _ := json.Marshal(map[string]any{"actor_id": actor, "from": from, "to": to, "source": source})
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('asset_link.created',$1,$2)`, from, details); err != nil {
			return AssetLink{}, false, err
		}
	}
	return link, created, tx.Commit(ctx)
}

// RemoveLink deletes a `built_from` link, however it was made.
func (s *Store) RemoveLink(ctx context.Context, from, to, actor uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `DELETE FROM `+s.schema+`.asset_links WHERE from_asset_id=$1 AND to_asset_id=$2 AND kind='built_from'`, from, to)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	details, _ := json.Marshal(map[string]any{"actor_id": actor, "from": from, "to": to})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('asset_link.deleted',$1,$2)`, from, details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ResolveRepository finds the repository asset a provider and path name: an
// in-scope GitHub or GitLab repository, or any when none is in scope. An empty
// provider matches either; more than one match is ErrAmbiguous.
func (s *Store) ResolveRepository(ctx context.Context, provider, path string) (uuid.UUID, error) {
	types := []string{"github_repo", "gitlab_repo"}
	switch provider {
	case "github":
		types = []string{"github_repo"}
	case "gitlab":
		types = []string{"gitlab_repo"}
	}
	rows, err := s.pool.Query(ctx, `SELECT id,flags->>'in_scope'='true' FROM `+s.schema+`.assets WHERE type=ANY($1) AND lower(locator)=lower($2)`, types, path)
	if err != nil {
		return uuid.Nil, err
	}
	defer rows.Close()
	var all, inScope []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		var in bool
		if err := rows.Scan(&id, &in); err != nil {
			return uuid.Nil, err
		}
		all = append(all, id)
		if in {
			inScope = append(inScope, id)
		}
	}
	if err := rows.Err(); err != nil {
		return uuid.Nil, err
	}
	candidates := all
	if len(inScope) > 0 {
		candidates = inScope
	}
	switch len(candidates) {
	case 0:
		return uuid.Nil, ErrNotFound
	case 1:
		return candidates[0], nil
	}
	return uuid.Nil, ErrAmbiguous
}

// LinkImageToLabel takes the source label an image carries and links the
// image to the repository asset it names, when exactly one is known. A link
// made earlier from a label that no longer points there is removed; one made
// by hand is never touched. It reports whether the image now has a label link.
func (s *Store) LinkImageToLabel(ctx context.Context, image uuid.UUID, label string) (bool, error) {
	provider, path, ok := ParseSourceLabel(label)
	var target uuid.UUID
	if ok {
		var err error
		target, err = s.ResolveRepository(ctx, provider, path)
		if err != nil && !errors.Is(err, ErrNotFound) && !errors.Is(err, ErrAmbiguous) {
			return false, err
		}
	}
	if _, err := s.pool.Exec(ctx, `DELETE FROM `+s.schema+`.asset_links WHERE from_asset_id=$1 AND kind='built_from' AND source='oci_label' AND to_asset_id<>$2`, image, target); err != nil {
		return false, err
	}
	if target == uuid.Nil {
		return false, nil
	}
	if _, _, err := s.AddLink(ctx, image, target, LinkSourceLabel, SchedulerActor); err != nil {
		return false, err
	}
	return true, nil
}

var labelPathPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*){1,7}$`)

// ParseSourceLabel reads an `org.opencontainers.image.source` value into the
// provider it names (`github` for github.com, `gitlab` for a host whose name
// starts with `gitlab`, else empty) and the repository path (`owner/name`, or
// `group/sub/project`). Anything that is not a plain repository URL (a path
// into a tree, a query, credentials) is refused.
func ParseSourceLabel(label string) (provider, path string, ok bool) {
	label = strings.TrimSpace(label)
	if label == "" || len(label) > 500 {
		return "", "", false
	}
	var host, repo string
	if rest, found := strings.CutPrefix(label, "git@"); found {
		var cut bool
		if host, repo, cut = strings.Cut(rest, ":"); !cut {
			return "", "", false
		}
	} else {
		u, err := url.Parse(label)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http" && u.Scheme != "git" && u.Scheme != "ssh") || u.User != nil && u.Scheme != "ssh" || u.RawQuery != "" || u.Fragment != "" {
			return "", "", false
		}
		host, repo = u.Hostname(), strings.TrimPrefix(u.Path, "/")
	}
	repo = strings.TrimSuffix(strings.TrimSuffix(repo, "/"), ".git")
	host = strings.ToLower(host)
	if host == "" || !labelPathPattern.MatchString(repo) {
		return "", "", false
	}
	switch {
	case host == "github.com" || host == "www.github.com":
		if strings.Count(repo, "/") != 1 {
			return "", "", false
		}
		return "github", repo, true
	case strings.HasPrefix(host, "gitlab"):
		return "gitlab", repo, true
	}
	return "", repo, true
}
