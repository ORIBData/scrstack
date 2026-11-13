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

var ErrNotFound = errors.New("not found")
var labelKey = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]{0,62}$`)

// Owner is the accountable contact for assets (AST-002). Contact fields are
// excluded from outbound payloads unless a subscription opts in (OUT-009).
type Owner struct {
	ID               uuid.UUID `json:"id"`
	Name             string    `json:"name"`
	Email            string    `json:"email"`
	Team             string    `json:"team"`
	Chat             string    `json:"chat"`
	SecondaryContact string    `json:"secondary_contact"`
	Revision         int64     `json:"revision"`
}

func validOwner(o Owner) bool {
	return strings.TrimSpace(o.Name) != "" && len(o.Name) <= 100 && len(o.Email) <= 254 && (o.Email == "" || strings.Contains(o.Email, "@")) && len(o.Team) <= 100 && len(o.Chat) <= 100 && len(o.SecondaryContact) <= 254
}

func (s *Store) CreateOwner(ctx context.Context, o Owner, actor uuid.UUID) (Owner, error) {
	o.Name = strings.TrimSpace(o.Name)
	if !validOwner(o) {
		return Owner{}, ErrInvalidChange
	}
	o.ID, o.Revision = uuid.New(), 1
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Owner{}, err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.owners(id,name,email,team,chat,secondary_contact) VALUES($1,$2,$3,$4,$5,$6)`, o.ID, o.Name, o.Email, o.Team, o.Chat, o.SecondaryContact); err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return Owner{}, ErrConflict
		}
		return Owner{}, err
	}
	details, _ := json.Marshal(map[string]any{"name": o.Name})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('owner.created',$1,$2)`, o.ID, auditDetails(WithActor(ctx, actor), details)); err != nil {
		return Owner{}, err
	}
	return o, tx.Commit(ctx)
}

func (s *Store) Owners(ctx context.Context) ([]Owner, error) {
	rows, err := s.pool.Query(ctx, `SELECT id,name,email,team,chat,secondary_contact,revision FROM `+s.schema+`.owners ORDER BY name LIMIT 1000`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Owner{}
	for rows.Next() {
		var o Owner
		if err := rows.Scan(&o.ID, &o.Name, &o.Email, &o.Team, &o.Chat, &o.SecondaryContact, &o.Revision); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// UpdateOwner replaces an owner's fields under an optimistic revision check.
func (s *Store) UpdateOwner(ctx context.Context, id uuid.UUID, expected int64, o Owner, actor uuid.UUID) (Owner, error) {
	o.Name = strings.TrimSpace(o.Name)
	if !validOwner(o) {
		return Owner{}, ErrInvalidChange
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Owner{}, err
	}
	defer tx.Rollback(ctx)
	err = tx.QueryRow(ctx, `UPDATE `+s.schema+`.owners SET name=$3,email=$4,team=$5,chat=$6,secondary_contact=$7,revision=revision+1,updated_at=clock_timestamp() WHERE id=$1 AND revision=$2 RETURNING revision`, id, expected, o.Name, o.Email, o.Team, o.Chat, o.SecondaryContact).Scan(&o.Revision)
	if errors.Is(err, pgx.ErrNoRows) {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.owners WHERE id=$1)`, id).Scan(&exists); err != nil || !exists {
			return Owner{}, ErrNotFound
		}
		return Owner{}, ErrConflict
	}
	if err != nil {
		var pg *pgconn.PgError
		if errors.As(err, &pg) && pg.Code == "23505" {
			return Owner{}, ErrConflict
		}
		return Owner{}, err
	}
	o.ID = id
	details, _ := json.Marshal(map[string]any{"name": o.Name})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('owner.changed',$1,$2)`, id, auditDetails(WithActor(ctx, actor), details)); err != nil {
		return Owner{}, err
	}
	return o, tx.Commit(ctx)
}

func (s *Store) Asset(ctx context.Context, id uuid.UUID) (Asset, error) {
	a, err := scanAsset(s.pool.QueryRow(ctx, `SELECT `+assetColumns+` FROM `+s.schema+`.assets WHERE id=$1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return a, ErrNotFound
	}
	return a, err
}

// AssetChange edits operator-owned attributes. Discovery-owned fields (type,
// locator, connection, flags) are never editable here.
type AssetChange struct {
	OwnerID     json.RawMessage    `json:"owner_id"`
	Environment *string            `json:"environment"`
	Criticality *int               `json:"criticality"`
	Exposure    *string            `json:"exposure"`
	Labels      *map[string]string `json:"labels"`
}

func (s *Store) UpdateAsset(ctx context.Context, id uuid.UUID, expected int64, c AssetChange, actor uuid.UUID) (Asset, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Asset{}, err
	}
	defer tx.Rollback(ctx)
	a, err := scanAsset(tx.QueryRow(ctx, `SELECT `+assetColumns+` FROM `+s.schema+`.assets WHERE id=$1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Asset{}, ErrNotFound
	}
	if err != nil {
		return Asset{}, err
	}
	if a.Revision != expected {
		return Asset{}, ErrConflict
	}
	if len(c.OwnerID) > 0 {
		if string(c.OwnerID) == "null" {
			a.OwnerID = nil
		} else {
			var owner uuid.UUID
			if json.Unmarshal(c.OwnerID, &owner) != nil {
				return Asset{}, ErrInvalidChange
			}
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.owners WHERE id=$1)`, owner).Scan(&exists); err != nil {
				return Asset{}, err
			}
			if !exists {
				return Asset{}, ErrInvalidChange
			}
			a.OwnerID = &owner
		}
	}
	if c.Environment != nil {
		a.Environment = *c.Environment
	}
	if c.Exposure != nil {
		a.Exposure = *c.Exposure
	}
	if c.Criticality != nil {
		a.Criticality = *c.Criticality
	}
	switch {
	case a.Environment != "" && a.Environment != "dev" && a.Environment != "stg" && a.Environment != "prod",
		a.Exposure != "" && a.Exposure != "internet" && a.Exposure != "internal" && a.Exposure != "offline",
		a.Criticality < 0 || a.Criticality > 5:
		return Asset{}, ErrInvalidChange
	}
	if c.Labels != nil {
		if len(*c.Labels) > 50 {
			return Asset{}, ErrInvalidChange
		}
		for k, v := range *c.Labels {
			if !labelKey.MatchString(k) || len(v) > 256 {
				return Asset{}, ErrInvalidChange
			}
		}
		a.Labels, _ = json.Marshal(*c.Labels)
	}
	if err := tx.QueryRow(ctx, `UPDATE `+s.schema+`.assets SET owner_id=$2,environment=$3,criticality=$4,exposure=$5,labels=$6,revision=revision+1 WHERE id=$1 RETURNING revision`, id, a.OwnerID, a.Environment, a.Criticality, a.Exposure, a.Labels).Scan(&a.Revision); err != nil {
		return Asset{}, err
	}
	details, _ := json.Marshal(map[string]any{"owner_id": a.OwnerID, "environment": a.Environment, "criticality": a.Criticality, "exposure": a.Exposure})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('asset.changed',$1,$2)`, id, auditDetails(WithActor(ctx, actor), details)); err != nil {
		return Asset{}, err
	}
	return a, tx.Commit(ctx)
}
