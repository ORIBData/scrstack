package notify

import (
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHub(t *testing.T) {
	h := &Hub{MaxStreams: 3, PerToken: 2}
	alice, bob := uuid.New(), uuid.New()
	all, err := h.Subscribe(alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	only, _ := h.Subscribe(alice, map[string]bool{"finding.created": true})
	if _, err := h.Subscribe(alice, nil); err != ErrStreamLimit {
		t.Fatalf("per-token limit: %v", err)
	}
	slow, _ := h.Subscribe(bob, nil)
	if _, err := h.Subscribe(uuid.New(), nil); err != ErrStreamLimit {
		t.Fatalf("instance limit: %v", err)
	}
	h.Publish(LiveEvent{ID: uuid.New(), Type: "assessment.completed", Time: time.Now()})
	if e := <-all.Events; e.Type != "assessment.completed" {
		t.Fatal(e)
	}
	select {
	case e := <-only.Events:
		t.Fatalf("filtered stream got %+v", e)
	default:
	}
	// resync reaches filtered streams too.
	h.Publish(LiveEvent{Type: "resync"})
	if e := <-only.Events; e.Type != "resync" {
		t.Fatal(e)
	}
	// A reader that never drains is dropped once its buffer is full.
	for i := 0; i < 70; i++ {
		h.Publish(LiveEvent{Type: "finding.created"})
		for len(all.Events) > 0 {
			<-all.Events
		}
		for len(only.Events) > 0 {
			<-only.Events
		}
	}
	drained := 0
	for range slow.Events {
		drained++
	}
	if drained != 64 || h.Streams() != 2 {
		t.Fatalf("slow reader: drained %d, streams %d", drained, h.Streams())
	}
	h.Unsubscribe(slow) // already dropped: no panic
	h.Close()
	if _, ok := <-all.Events; ok || h.Streams() != 0 {
		t.Fatal("close")
	}
	if _, err := h.Subscribe(alice, nil); err != nil {
		t.Fatal("token count not released", err)
	}
}

func TestLiveNotice(t *testing.T) {
	r := refs(map[string]any{"assessment": map[string]any{"id": "a1", "asset_id": "x1", "evidence": "secret"}, "finding_id": "f1", "findings": []any{"big"}})
	if r["assessment.id"] != "a1" || r["assessment.asset_id"] != "x1" || r["finding_id"] != "f1" || len(r) != 3 {
		t.Fatalf("refs %+v", r)
	}
	if c := liveChannel(`"qa_1234"`); c != "scrs_events_qa_1234" {
		t.Fatal(c)
	}
	if c := liveChannel(strings.Repeat("s", 63)); len(c) > 63 {
		t.Fatal(c)
	}
}
