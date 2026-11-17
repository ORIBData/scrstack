package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Comment is one note on a register entry. Author is the API token that
// wrote it; OnBehalfOf is a person's name the caller claims to act for, kept
// apart because SCRS has no user model to verify it.
type Comment struct {
	ID         uuid.UUID `json:"id"`
	FindingID  uuid.UUID `json:"finding_id"`
	Author     string    `json:"author"`
	OnBehalfOf string    `json:"on_behalf_of,omitempty"`
	Body       string    `json:"body"`
	CreatedAt  time.Time `json:"created_at"`
}

const (
	maxAssigneeLength = 100
	maxCommentLength  = 4000
	// maxCommentsPage is the most comments one listing returns.
	maxCommentsPage = 200
)

// cleanLabel trims a free-text identifier and rejects control characters
// and anything longer than max.
func cleanLabel(v string, max int) (string, bool) {
	v = strings.TrimSpace(v)
	if len(v) > max || strings.IndexFunc(v, func(r rune) bool { return r < 0x20 || r == 0x7f }) >= 0 {
		return "", false
	}
	return v, true
}

// Assign sets who holds an entry; an empty assignee clears it. Assignment is
// a free-text identifier (an email, a username or a team) because SCRS has no
// user model. The change is recorded in the entry's history.
func (s *Store) Assign(ctx context.Context, id, actor uuid.UUID, by, assignee, onBehalfOf string) error {
	assignee, ok := cleanLabel(assignee, maxAssigneeLength)
	onBehalfOf, ok2 := cleanLabel(onBehalfOf, maxAssigneeLength)
	if !ok || !ok2 {
		return ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var previous string
	err = tx.QueryRow(ctx, `SELECT assignee FROM `+s.schema+`.findings WHERE id=$1 FOR UPDATE`, id).Scan(&previous)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if previous == assignee {
		return tx.Commit(ctx) // nothing changes, so nothing is recorded
	}
	if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.findings SET assignee=$2,assigned_at=CASE WHEN $2='' THEN NULL ELSE clock_timestamp() END WHERE id=$1`, id, assignee); err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"assignee": assignee, "previous": previous, "by": by, "on_behalf_of": onBehalfOf})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,actor_id,action,details) VALUES($1,$2,'assigned',$3)`, id, nullUUID(actor), details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// AddComment appends a note to an entry's discussion.
func (s *Store) AddComment(ctx context.Context, finding, actor uuid.UUID, author, onBehalfOf, body string) (Comment, error) {
	body = strings.TrimSpace(body)
	onBehalfOf, ok := cleanLabel(onBehalfOf, maxAssigneeLength)
	if len(body) == 0 || len(body) > maxCommentLength || !ok {
		return Comment{}, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Comment{}, err
	}
	defer tx.Rollback(ctx)
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.findings WHERE id=$1)`, finding).Scan(&exists); err != nil {
		return Comment{}, err
	}
	if !exists {
		return Comment{}, ErrNotFound
	}
	c := Comment{ID: uuid.New(), FindingID: finding, Author: author, OnBehalfOf: onBehalfOf, Body: body}
	if err := tx.QueryRow(ctx, `INSERT INTO `+s.schema+`.finding_comments(id,finding_id,author,actor_id,on_behalf_of,body) VALUES($1,$2,$3,$4,$5,$6) RETURNING created_at`, c.ID, finding, author, nullUUID(actor), onBehalfOf, body).Scan(&c.CreatedAt); err != nil {
		return Comment{}, err
	}
	details, _ := json.Marshal(map[string]any{"comment_id": c.ID, "by": author, "on_behalf_of": onBehalfOf})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,actor_id,action,details) VALUES($1,$2,'comment.added',$3)`, finding, nullUUID(actor), details); err != nil {
		return Comment{}, err
	}
	return c, tx.Commit(ctx)
}

// Comments lists an entry's comments oldest first, after the comment `after`
// (zero for the first page); at most maxCommentsPage + 1 rows come back.
func (s *Store) Comments(ctx context.Context, finding, after uuid.UUID) ([]Comment, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.findings WHERE id=$1)`, finding).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, ErrNotFound
	}
	rows, err := s.pool.Query(ctx, `SELECT id,finding_id,author,on_behalf_of,body,created_at FROM `+s.schema+`.finding_comments WHERE finding_id=$1 AND ($2='00000000-0000-0000-0000-000000000000'::uuid OR (created_at,id)>(SELECT created_at,id FROM `+s.schema+`.finding_comments WHERE id=$2)) ORDER BY created_at,id LIMIT $3`, finding, after, maxCommentsPage+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Comment{}
	for rows.Next() {
		var c Comment
		if err := rows.Scan(&c.ID, &c.FindingID, &c.Author, &c.OnBehalfOf, &c.Body, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// DeleteComment removes a comment. The deletion stays in the entry's history
// (who removed whose comment), without the text.
func (s *Store) DeleteComment(ctx context.Context, finding, comment, actor uuid.UUID, by string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var author string
	err = tx.QueryRow(ctx, `DELETE FROM `+s.schema+`.finding_comments WHERE id=$1 AND finding_id=$2 RETURNING author`, comment, finding).Scan(&author)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	details, _ := json.Marshal(map[string]any{"comment_id": comment, "author": author, "by": by})
	if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,actor_id,action,details) VALUES($1,$2,'comment.deleted',$3)`, finding, nullUUID(actor), details); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func nullUUID(id uuid.UUID) any {
	if id == uuid.Nil {
		return nil
	}
	return id
}
