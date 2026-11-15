package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Live events (OUT-004). Every emitted event is also announced with
// pg_notify inside the emitting transaction, so PostgreSQL delivers it
// only after commit and never for a rolled-back change. Each API instance
// listens on one dedicated connection and fans events out to its
// server-sent-event streams. Delivery is fire-and-forget: a client that
// reconnects, or a listener that reconnects, may miss events, and is sent
// a "resync" event so it reloads state through the API. Webhooks remain
// the guaranteed path.

// LiveEvent is the small notice a stream carries: ids to fetch, never
// evidence, file contents or secrets.
type LiveEvent struct {
	ID         uuid.UUID         `json:"id"`
	Type       string            `json:"type"`
	Time       time.Time         `json:"time"`
	Connection *uuid.UUID        `json:"connection_id,omitempty"`
	Asset      *uuid.UUID        `json:"asset_id,omitempty"`
	Refs       map[string]string `json:"refs,omitempty"`
}

// liveChannel names the NOTIFY channel of one schema (63 bytes at most).
func liveChannel(schema string) string {
	name := "scrs_events_" + strings.Trim(schema, `"`)
	if len(name) > 63 {
		sum := sha256.Sum256([]byte(schema))
		name = "scrs_events_" + hex.EncodeToString(sum[:12])
	}
	return name
}

// refKeys are the id fields copied from an event's data into its notice.
var refKeys = []string{"assessment_id", "asset_id", "connection_id", "finding_id", "run_id", "source", "id"}

// refs picks the ids a client needs to fetch the subject of an event.
func refs(data any) map[string]string {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil
	}
	out := map[string]string{}
	pick := func(prefix string, m map[string]json.RawMessage) {
		for _, k := range refKeys {
			var v string
			if json.Unmarshal(m[k], &v) == nil && v != "" && len(v) <= 128 {
				out[prefix+k] = v
			}
		}
	}
	pick("", fields)
	// The assessment summary nests its ids.
	var nested map[string]json.RawMessage
	if json.Unmarshal(fields["assessment"], &nested) == nil {
		pick("assessment.", nested)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func announce(ctx context.Context, tx pgx.Tx, schema string, e LiveEvent) error {
	payload, err := json.Marshal(e)
	if err != nil {
		return err
	}
	// NOTIFY payloads are limited to 8000 bytes; refs are bounded well
	// below that, but never fail the business transaction over a notice.
	if len(payload) > 7000 {
		e.Refs = nil
		payload, _ = json.Marshal(e)
	}
	_, err = tx.Exec(ctx, `SELECT pg_notify($1,$2)`, liveChannel(schema), string(payload))
	return err
}

// Hub fans live events out to the streams of one API instance.
type Hub struct {
	// MaxStreams bounds concurrent streams on this instance, PerToken the
	// streams of one API token.
	MaxStreams int
	PerToken   int
	Logger     *slog.Logger

	mu      sync.Mutex
	clients map[*Stream]struct{}
	tokens  map[uuid.UUID]int
}

// Stream is one subscriber. Events arrives closed when the hub drops the
// stream (slow reader or shutdown).
type Stream struct {
	Events <-chan LiveEvent
	events chan LiveEvent
	types  map[string]bool
	token  uuid.UUID
	closed bool
}

// ErrStreamLimit means the instance or token has too many open streams.
var ErrStreamLimit = errors.New("too many event streams")

// Subscribe opens a stream for the given event types (all when empty).
func (h *Hub) Subscribe(token uuid.UUID, types map[string]bool) (*Stream, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients == nil {
		h.clients, h.tokens = map[*Stream]struct{}{}, map[uuid.UUID]int{}
	}
	if len(h.clients) >= max(h.MaxStreams, 1) || h.tokens[token] >= max(h.PerToken, 1) {
		return nil, ErrStreamLimit
	}
	ch := make(chan LiveEvent, 64)
	s := &Stream{Events: ch, events: ch, types: types, token: token}
	h.clients[s] = struct{}{}
	h.tokens[token]++
	return s, nil
}

// Unsubscribe closes a stream; calling it twice is safe.
func (h *Hub) Unsubscribe(s *Stream) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drop(s)
}

func (h *Hub) drop(s *Stream) {
	if s.closed {
		return
	}
	s.closed = true
	close(s.events)
	delete(h.clients, s)
	if h.tokens[s.token]--; h.tokens[s.token] <= 0 {
		delete(h.tokens, s.token)
	}
}

// Publish delivers an event to every matching stream without blocking; a
// stream whose buffer is full is dropped, and its client reconnects.
func (h *Hub) Publish(e LiveEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.clients {
		if e.Type != "resync" && len(s.types) > 0 && !s.types[e.Type] {
			continue
		}
		select {
		case s.events <- e:
		default:
			h.drop(s)
		}
	}
}

// Close ends every stream (server shutdown); new streams can still open.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	for s := range h.clients {
		h.drop(s)
	}
}

// Streams returns the number of open streams.
func (h *Hub) Streams() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

// Listen relays the schema's NOTIFY channel to the hub until ctx ends,
// reconnecting with backoff on its own dedicated connection (the pool is
// not used, so webhook delivery keeps all its connections).
func (s *Store) Listen(ctx context.Context, h *Hub) {
	channel := liveChannel(s.schema)
	delay := time.Second
	for ctx.Err() == nil {
		err := s.listenOnce(ctx, channel, h, func() { delay = time.Second })
		if ctx.Err() != nil {
			return
		}
		if h.Logger != nil {
			h.Logger.Warn("live event listener reconnecting", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, time.Minute)
	}
}

func (s *Store) listenOnce(ctx context.Context, channel string, h *Hub, connected func()) error {
	conn, err := pgx.ConnectConfig(ctx, s.pool.Config().ConnConfig.Copy())
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	if _, err := conn.Exec(ctx, `LISTEN `+pgx.Identifier{channel}.Sanitize()); err != nil {
		return err
	}
	connected()
	// Events may have been missed while the listener was down.
	h.Publish(LiveEvent{ID: uuid.New(), Type: "resync", Time: time.Now().UTC()})
	for {
		n, err := conn.WaitForNotification(ctx)
		if err != nil {
			return err
		}
		var e LiveEvent
		if json.Unmarshal([]byte(n.Payload), &e) != nil || !Events[e.Type] {
			continue
		}
		h.Publish(e)
	}
}
