package connections

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
)

type actorKey struct{}

func WithActor(ctx context.Context, id uuid.UUID) context.Context {
	return context.WithValue(ctx, actorKey{}, id)
}
func auditDetails(ctx context.Context, raw []byte) []byte {
	var details map[string]any
	if json.Unmarshal(raw, &details) != nil || details == nil {
		details = map[string]any{}
	}
	if actor, ok := ctx.Value(actorKey{}).(uuid.UUID); ok {
		details["actor_id"] = actor
	} else {
		details["actor"] = "local_cli"
	}
	encoded, _ := json.Marshal(details)
	return encoded
}
