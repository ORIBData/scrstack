package assessments_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/storage"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// A provider declared in the environment is created once, left alone by a
// restart that changes nothing, updated when the declaration changes, and
// never overwrites one an administrator made by hand.
func TestPostgresBootstrapLLMProvider(t *testing.T) {
	url := os.Getenv("SCRS_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	schema := "qa_" + uuid.NewString()[:8]
	if err := storage.BootstrapDatabase(ctx, storage.Config{DatabaseURL: url, DatabaseSchema: schema}); err != nil {
		t.Fatal(err)
	}
	pool, _ := pgxpool.New(ctx, url)
	defer pool.Close()
	defer func() { _, _ = pool.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE") }()
	store, err := assessments.Open(ctx, url, schema)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	// The "sealed" key is its own plaintext here; the real seal is tested with
	// the connection store.
	key := "key-one"
	seal := func(uuid.UUID) ([]byte, error) { return []byte(key), nil }
	same := func(_ uuid.UUID, sealed []byte) bool { return string(sealed) == key }
	want := assessments.LLMProvider{Name: "hosted", Kind: "openai", Model: "m-1", MaxTokens: 4096}

	created, action, err := store.BootstrapLLMProvider(ctx, want, false, seal, same)
	if err != nil || action != "created" || !created.Managed || !created.Enabled || !created.HasKey || created.SourceAckAt != nil {
		t.Fatal(created, action, err)
	}
	if _, action, err := store.BootstrapLLMProvider(ctx, want, false, seal, same); err != nil || action != "unchanged" {
		t.Fatal("a restart that changes nothing writes nothing:", action, err)
	}
	if got, _ := store.LLMProviderByID(ctx, created.ID); got.Revision != created.Revision {
		t.Fatal("revision moved on an unchanged bootstrap")
	}

	// An administrator switches it off; the environment does not switch it back on.
	disabled := created
	disabled.Enabled = false
	if _, err := store.UpdateLLMProvider(ctx, disabled, created.Revision, nil, uuid.Nil); err != nil {
		t.Fatal(err)
	}
	want.Model = "m-2"
	key = "key-two"
	updated, action, err := store.BootstrapLLMProvider(ctx, want, false, seal, func(uuid.UUID, []byte) bool { return false })
	if err != nil || action != "updated" || updated.Model != "m-2" || updated.Enabled {
		t.Fatal("a changed declaration updates the provider and keeps the administrator's switch:", updated, action, err)
	}
	var sealed []byte
	_ = pool.QueryRow(ctx, `SELECT credential FROM `+schema+`.llm_providers WHERE id=$1`, created.ID).Scan(&sealed)
	if string(sealed) != "key-two" {
		t.Fatal("the key was not rotated")
	}

	// ALLOW_SOURCE is recorded as an acknowledgement by the environment, and
	// withdrawn when the variable goes; a change of endpoint clears it.
	ack, action, err := store.BootstrapLLMProvider(ctx, want, true, seal, same)
	if err != nil || action != "updated" || ack.SourceAckBy != "environment" || ack.SourceAckAt == nil {
		t.Fatal(ack, action, err)
	}
	if again, action, err := store.BootstrapLLMProvider(ctx, want, true, seal, same); err != nil || action != "unchanged" || again.Revision != ack.Revision {
		t.Fatal(action, err)
	}
	moved := want
	moved.BaseURL = "https://other.example.com/v1"
	if p, _, err := store.BootstrapLLMProvider(ctx, moved, false, seal, same); err != nil || p.SourceAckAt != nil {
		t.Fatal("a changed endpoint or a removed ALLOW_SOURCE withdraws the acknowledgement:", p, err)
	}
	// An acknowledgement an administrator recorded is theirs: the environment
	// not asking for one does not remove it.
	if _, err := store.SetLLMSourceAck(ctx, created.ID, true, "Zero-retention agreement signed 2026", "admin", uuid.Nil); err != nil {
		t.Fatal(err)
	}
	if p, action, err := store.BootstrapLLMProvider(ctx, moved, false, seal, same); err != nil || action != "unchanged" || p.SourceAckBy != "admin" {
		t.Fatal(p, action, err)
	}

	// A provider made through the API is never taken over.
	if _, err := store.CreateLLMProvider(ctx, assessments.LLMProvider{Name: "manual", Kind: "openai", Model: "m", MaxTokens: 4096, Enabled: true}, uuid.Nil, seal); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.BootstrapLLMProvider(ctx, assessments.LLMProvider{Name: "manual", Kind: "openai", Model: "other", MaxTokens: 4096}, false, seal, same); !errors.Is(err, assessments.ErrConflict) {
		t.Fatal("a hand-made provider must not be overwritten:", err)
	}
}
