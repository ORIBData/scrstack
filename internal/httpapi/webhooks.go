package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/google/uuid"
)

func githubWebhook(store *assessments.Store, secret string, remediation bool) http.Handler {
	slots := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			writeError(w, 429, "webhook capacity exceeded")
			return
		}
		if len(secret) < 32 {
			writeError(w, 503, "GitHub webhook authentication not configured")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			writeError(w, 413, "webhook payload limit exceeded")
			return
		}
		supplied, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get("X-Hub-Signature-256"), "sha256="))
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write(body)
		if err != nil || !strings.HasPrefix(r.Header.Get("X-Hub-Signature-256"), "sha256=") || !hmac.Equal(supplied, mac.Sum(nil)) {
			writeError(w, 401, "invalid webhook signature")
			return
		}
		delivery, err := uuid.Parse(r.Header.Get("X-GitHub-Delivery"))
		if err != nil {
			writeError(w, 400, "valid delivery ID required")
			return
		}
		event := r.Header.Get("X-GitHub-Event")
		if event == "ping" {
			writeJSON(w, 200, map[string]string{"status": "ok"})
			return
		}
		if event != "push" {
			writeError(w, 422, "only push events supported")
			return
		}
		var payload struct {
			Ref        string `json:"ref"`
			After      string `json:"after"`
			Deleted    bool   `json:"deleted"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repository"`
		}
		if json.Unmarshal(body, &payload) != nil || !strings.HasPrefix(payload.Ref, "refs/") {
			writeError(w, 400, "invalid push payload")
			return
		}
		// Tag and other non-branch pushes are valid GitHub deliveries; acknowledge
		// them so GitHub does not record failures. Only branches are assessed.
		if !strings.HasPrefix(payload.Ref, "refs/heads/") {
			writeJSON(w, 200, map[string]string{"status": "ignored_non_branch_ref"})
			return
		}
		if payload.Deleted {
			writeJSON(w, 200, map[string]string{"status": "ignored_deleted_ref"})
			return
		}
		if len(payload.After) != 40 || payload.Ref == "refs/heads/" {
			writeError(w, 400, "immutable commit and branch required")
			return
		}
		input := assessments.Request{AutoRemediation: remediation, Target: assessments.Target{Type: "git", Repository: payload.Repository.FullName, Ref: strings.TrimPrefix(payload.Ref, "refs/heads/"), Commit: payload.After}}
		input.Trigger.Origin = "github_webhook"
		input.Trigger.Event = event
		input.Trigger.DeliveryID = delivery.String()
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		actor := uuid.NewSHA1(uuid.NameSpaceURL, []byte("scrs:github-webhook"))
		a, replay, err := store.EnqueueWebhook(ctx, input, actor, "github-webhook", delivery.String(), body)
		if err != nil {
			assessmentError(w, err)
			return
		}
		code := 202
		if replay {
			code = 200
		}
		w.Header().Set("Location", BasePath+"/assessments/"+a.ID.String())
		writeJSON(w, code, a)
	})
}
