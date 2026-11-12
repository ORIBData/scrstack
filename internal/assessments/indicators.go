package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (s *Store) ImportIndicators(ctx context.Context, actor uuid.UUID, raw []byte) (string, error) {
	b, err := intelligence.Parse(raw)
	if err != nil {
		return "", ErrInput
	}
	normalized, _ := json.Marshal(b)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, s.schema+".indicator_import"); err != nil {
		return "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE `+s.schema+`.indicator_bundles SET active=false WHERE active`); err != nil {
		return "", err
	}
	id := uuid.New()
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.indicator_bundles(id,version,body) VALUES($1,$2,$3)`, id, b.Version, normalized); err != nil {
		var p *pgconn.PgError
		if errors.As(err, &p) && p.Code == "23505" {
			return "", ErrConflict
		}
		return "", err
	}
	detail, _ := json.Marshal(map[string]any{"actor_id": actor, "version": b.Version, "indicators": len(b.Indicators), "sha256": Hash(normalized)})
	if _, err = tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,target_id,details) VALUES('indicators.imported',$1,$2)`, id, detail); err != nil {
		return "", err
	}
	return b.Version, tx.Commit(ctx)
}
func (s *Store) ActiveIndicators(ctx context.Context) (json.RawMessage, error) {
	var raw json.RawMessage
	err := s.pool.QueryRow(ctx, `SELECT body FROM `+s.schema+`.indicator_bundles WHERE active`).Scan(&raw)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return raw, err
}
