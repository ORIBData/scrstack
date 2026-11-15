package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/notify"
)

// Server-sent events (OUT-004): GET /events streams notices of committed
// events (ids to fetch, no evidence). A stream lives at most streamLifetime,
// so a revoked token stops receiving within that time; clients reconnect
// and re-authenticate. Missed events are not replayed: a client should
// reload state when it connects and on a "resync" event.

const (
	streamLifetime  = 10 * time.Minute
	streamHeartbeat = 20 * time.Second
	streamWrite     = 15 * time.Second
)

type eventStream struct {
	hub      *notify.Hub
	lifetime time.Duration
}

func (h eventStream) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	principal := r.Context().Value(principalKey{}).(connections.Token)
	if h.hub == nil {
		writeError(w, 503, "live events unavailable")
		return
	}
	types := map[string]bool{}
	if raw := r.URL.Query().Get("types"); raw != "" {
		for _, t := range strings.Split(raw, ",") {
			t = strings.TrimSpace(t)
			if !notify.Events[t] || t == "ping" || len(types) >= 20 {
				writeError(w, 400, "types must be a comma-separated list of event types")
				return
			}
			types[t] = true
		}
	}
	stream, err := h.hub.Subscribe(principal.ID, types)
	if err != nil {
		if errors.Is(err, notify.ErrStreamLimit) {
			w.Header().Set("Retry-After", "30")
			writeError(w, 429, "too many open event streams")
			return
		}
		writeError(w, 500, "event stream failed")
		return
	}
	defer h.hub.Unsubscribe(stream)
	rc := http.NewResponseController(w)
	header := w.Header()
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-store")
	header.Set("Connection", "keep-alive")
	header.Set("X-Accel-Buffering", "no")
	// Each write gets its own deadline in place of the server's
	// WriteTimeout, so a stalled client is dropped but a quiet one is not.
	write := func(format string, args ...any) bool {
		if rc.SetWriteDeadline(time.Now().Add(streamWrite)) != nil {
			return false
		}
		if _, err := fmt.Fprintf(w, format, args...); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	w.WriteHeader(200)
	if !write("retry: 5000\nevent: ready\ndata: {\"lifetime_seconds\":%d}\n\n", int(h.lifetime.Seconds())) {
		return
	}
	heartbeat := time.NewTicker(streamHeartbeat)
	defer heartbeat.Stop()
	end := time.NewTimer(h.lifetime)
	defer end.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-end.C:
			_ = write("event: reconnect\ndata: {}\n\n")
			return
		case <-heartbeat.C:
			if !write(": heartbeat\n\n") {
				return
			}
		case e, ok := <-stream.Events:
			if !ok {
				// Dropped as a slow reader; the client reconnects.
				return
			}
			data, _ := json.Marshal(e)
			if !write("id: %s\nevent: %s\ndata: %s\n\n", e.ID, e.Type, data) {
				return
			}
		}
	}
}
