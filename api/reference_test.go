package api

import (
	"os"
	"testing"
)

// docs/API_REFERENCE.md must match the contract. Regenerate it with
// `make api-reference` (UPDATE_API_REFERENCE=1).
func TestAPIReferenceIsCurrent(t *testing.T) {
	want, err := Reference()
	if err != nil {
		t.Fatal(err)
	}
	const file = "../docs/API_REFERENCE.md"
	if os.Getenv("UPDATE_API_REFERENCE") == "1" {
		if err := os.WriteFile(file, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	got, err := os.ReadFile(file)
	if err != nil || string(got) != string(want) {
		t.Fatal("docs/API_REFERENCE.md is out of date; run `make api-reference`")
	}
}
