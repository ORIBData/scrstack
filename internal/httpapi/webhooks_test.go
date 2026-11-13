package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/google/uuid"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWebhookSignatureAndEventValidation(t *testing.T) {
	secret := strings.Repeat("x", 40)
	handler := newGitHubIngest(nil, secret, true, false).direct("github")
	for _, tc := range []struct {
		event, body, signature string
		status                 int
	}{{"push", `{}`, "bad", 401}, {"ping", `{}`, "valid", 200}, {"issues", `{}`, "valid", 200}, {"push", `{"ref":"main"}`, "valid", 400}, {"push", `not json`, "valid", 400}} {
		r := httptest.NewRequest("POST", BasePath+"/webhooks/github", strings.NewReader(tc.body))
		r.Header.Set("X-GitHub-Delivery", uuid.NewString())
		r.Header.Set("X-GitHub-Event", tc.event)
		sig := tc.signature
		if sig == "valid" {
			m := hmac.New(sha256.New, []byte(secret))
			_, _ = m.Write([]byte(tc.body))
			sig = "sha256=" + hex.EncodeToString(m.Sum(nil))
		}
		r.Header.Set("X-Hub-Signature-256", sig)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("event %s: %d %s", tc.event, w.Code, w.Body)
		}
	}
}
