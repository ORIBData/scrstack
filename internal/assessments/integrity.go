package assessments

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/ORIBData/scrstack/internal/notify"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// IntegrityEvent is a provider-reported change that needs review without an
// assessment: force pushes, deletions, membership and repository changes
// (INT-001, INT-002, INT-008, INT-011). Actor and details are claims from the
// event, not verified facts.
type IntegrityEvent struct {
	Kind       string         `json:"kind"`
	Severity   string         `json:"severity"`
	Title      string         `json:"title"`
	Repository string         `json:"repository"`
	Ref        string         `json:"ref,omitempty"`
	Commit     string         `json:"commit,omitempty"`
	Actor      string         `json:"actor,omitempty"`
	Details    map[string]any `json:"details,omitempty"`
}

func integrityScore(severity string) int {
	switch severity {
	case "critical":
		return 100
	case "high":
		return 60
	case "medium":
		return 30
	}
	return 10
}

// RecordIntegrity stores the raw event once and raises one register entry and
// one integrity.alert per signal. A replayed delivery is a no-op.
func (s *Store) RecordIntegrity(ctx context.Context, delivery string, actor uuid.UUID, raw []byte, mode, eventType string, events []IntegrityEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	if !json.Valid(raw) || len(raw) > 1<<20 || delivery == "" || len(delivery) > 128 {
		return 0, ErrInput
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)
	recorded := 0
	for _, e := range events {
		if e.Kind == "" || len(e.Kind) > 64 || (e.Severity != "critical" && e.Severity != "high" && e.Severity != "medium" && e.Severity != "low") {
			return 0, ErrInput
		}
		repository := strings.ToLower(e.Repository)
		var asset *uuid.UUID
		var found uuid.UUID
		err := tx.QueryRow(ctx, `SELECT a.id FROM `+s.schema+`.assets a JOIN `+s.schema+`.connections c ON c.id=a.connection_id WHERE a.type IN ('github_repo','gitlab_repo') AND lower(a.locator)=$1 ORDER BY (a.flags->>'in_scope'='true') DESC,c.enabled DESC,a.id LIMIT 1`, repository).Scan(&found)
		if err == nil {
			asset = &found
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return 0, err
		}
		details, _ := json.Marshal(map[string]any{"repository": repository, "ref": e.Ref, "commit": e.Commit, "claimed_actor": e.Actor, "delivery_id": delivery, "event_type": eventType, "details": e.Details})
		eventID := uuid.New()
		tag, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.integrity_events(id,delivery_id,kind,severity,repository,ref,asset_id,actor,details) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(delivery_id,kind) DO NOTHING`, eventID, delivery, e.Kind, e.Severity, repository, e.Ref, asset, e.Actor, details)
		if err != nil {
			return 0, err
		}
		if tag.RowsAffected() == 0 {
			continue // replayed delivery
		}
		if recorded == 0 {
			if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.inbound_events(id,actor_id,body,mode,event_type) VALUES($1,$2,$3,$4,$5)`, uuid.New(), actor, raw, mode, eventType); err != nil {
				return 0, err
			}
		}
		recorded++
		alert := map[string]any{"source": "event", "kind": e.Kind, "severity": e.Severity, "title": e.Title, "repository": repository, "ref": e.Ref, "commit": e.Commit, "claimed_actor": e.Actor, "delivery_id": delivery, "event_type": eventType, "details": e.Details}
		if asset != nil {
			advisory := "SCRS-EVENT-" + strings.ToUpper(strings.ReplaceAll(e.Kind, "_", "-"))
			fp := Hash([]byte(asset.String() + "\x00event\x00" + e.Kind + "\x00" + delivery))
			findingID := uuid.NewSHA1(uuid.NameSpaceOID, []byte(fp))
			guidance, _ := json.Marshal(map[string]any{"summary": "Confirm with the claimed actor through a separate channel. If unexpected, treat the account as compromised: review recent pushes, workflow runs and secrets, and restore from the last known good revision.", "automatic_changes": false})
			component, _ := json.Marshal(Component{Path: e.Ref})
			if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.findings(id,asset_id,fingerprint,ref,type,advisory_id,title,severity,score,component,evidence,guidance) VALUES($1,$2,$3,$4,'integrity',$5,$6,$7,$8,$9,$10,$11) ON CONFLICT(fingerprint) DO NOTHING`, findingID, *asset, fp, e.Ref, advisory, e.Title, e.Severity, integrityScore(e.Severity), component, details, guidance); err != nil {
				return 0, err
			}
			if _, err := tx.Exec(ctx, `UPDATE `+s.schema+`.integrity_events SET finding_id=$2 WHERE id=$1`, eventID, findingID); err != nil {
				return 0, err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.finding_events(finding_id,action,details) VALUES($1,'detected',$2)`, findingID, details); err != nil {
				return 0, err
			}
			alert["asset_id"] = *asset
			alert["finding_id"] = findingID
			alert["link"] = notify.Link("/register/" + findingID.String() + "/events")
		}
		if _, err := notify.Emit(ctx, tx, s.schema, "integrity.alert", alert, nil); err != nil {
			return 0, err
		}
	}
	if recorded > 0 {
		summary, _ := json.Marshal(map[string]any{"delivery_id": delivery, "event_type": eventType, "signals": recorded, "mode": mode})
		if _, err := tx.Exec(ctx, `INSERT INTO `+s.schema+`.audit_log(action,details) VALUES('integrity.event_recorded',$1)`, summary); err != nil {
			return 0, err
		}
	}
	return recorded, tx.Commit(ctx)
}

// RecentBranchCreation reports whether a push created this ref within the
// churn window (INT-011): a branch created and deleted quickly is suspicious.
func (s *Store) RecentBranchCreation(ctx context.Context, repository, ref string, minutes int) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM `+s.schema+`.inbound_events WHERE event_type='push' AND lower(body->'repository'->>'full_name')=$1 AND body->>'ref'=$2 AND body->>'created'='true' AND created_at>clock_timestamp()-($3*interval '1 minute') UNION ALL SELECT 1 FROM `+s.schema+`.inbound_events WHERE event_type='gitlab:push' AND lower(body->'project'->>'path_with_namespace')=$1 AND body->>'ref'=$2 AND body->>'before'='`+zeroSHA+`' AND created_at>clock_timestamp()-($3*interval '1 minute'))`, strings.ToLower(repository), ref, minutes).Scan(&exists)
	return exists, err
}

const zeroSHA = "0000000000000000000000000000000000000000"
