package httpapi

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/google/uuid"
)

// githubIngest normalizes direct (HMAC) and relay (ingest:relay token)
// deliveries into one path (ING-009, ING-011). Payload content is a hint:
// SCRS resolves and fetches commits itself (TRG-003).
type githubIngest struct {
	store        *assessments.Store
	secret       string
	remediation  bool
	relayEnabled bool
	massDeletion int
	slots        chan struct{}
}

func newGitHubIngest(store *assessments.Store, secret string, remediation, relay bool) *githubIngest {
	threshold := 50
	if v, err := strconv.Atoi(os.Getenv("SCRS_MASS_DELETION_FILES")); err == nil && v > 0 {
		threshold = v
	}
	return &githubIngest{store: store, secret: secret, remediation: remediation, relayEnabled: relay, massDeletion: threshold, slots: make(chan struct{}, 8)}
}

var webhookActor = uuid.NewSHA1(uuid.NameSpaceURL, []byte("scrs:github-webhook"))

// direct verifies GitHub's HMAC over the exact raw body.
func (g *githubIngest) direct() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.acquire(w) {
			return
		}
		defer func() { <-g.slots }()
		if len(g.secret) < 32 {
			writeError(w, 503, "GitHub webhook authentication not configured")
			return
		}
		body, ok := g.read(w, r)
		if !ok {
			return
		}
		supplied, err := hex.DecodeString(strings.TrimPrefix(r.Header.Get("X-Hub-Signature-256"), "sha256="))
		mac := hmac.New(sha256.New, []byte(g.secret))
		_, _ = mac.Write(body)
		if err != nil || !strings.HasPrefix(r.Header.Get("X-Hub-Signature-256"), "sha256=") || !hmac.Equal(supplied, mac.Sum(nil)) {
			writeError(w, 401, "invalid webhook signature")
			return
		}
		g.process(w, r, body, "direct", webhookActor, "github-webhook")
	})
}

// relay accepts the provider's unchanged body from automation holding an
// ingest:relay token (TRG-002). Wrap it with Security.protect.
func (g *githubIngest) relay() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.relayEnabled {
			writeError(w, 503, "relay ingestion disabled; set SCRS_RELAY_ENABLED=true")
			return
		}
		if !g.acquire(w) {
			return
		}
		defer func() { <-g.slots }()
		principal := r.Context().Value(principalKey{}).(connections.Token)
		body, ok := g.read(w, r)
		if !ok {
			return
		}
		g.process(w, r, body, "relay", principal.ID, principal.Name)
	})
}

// acquire bounds concurrent ingestion; the caller must release on true.
func (g *githubIngest) acquire(w http.ResponseWriter) bool {
	w.Header().Set("Cache-Control", "no-store")
	select {
	case g.slots <- struct{}{}:
		return true
	default:
		writeError(w, 429, "webhook capacity exceeded")
		return false
	}
}

func (g *githubIngest) read(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, 413, "webhook payload limit exceeded")
		return nil, false
	}
	return body, true
}

type githubPayload struct {
	Ref        string `json:"ref"`
	RefType    string `json:"ref_type"`
	After      string `json:"after"`
	Created    bool   `json:"created"`
	Deleted    bool   `json:"deleted"`
	Forced     bool   `json:"forced"`
	Action     string `json:"action"`
	Repository struct {
		FullName      string `json:"full_name"`
		DefaultBranch string `json:"default_branch"`
	} `json:"repository"`
	Sender struct {
		Login string `json:"login"`
	} `json:"sender"`
	Pusher struct {
		Name string `json:"name"`
	} `json:"pusher"`
	Commits []struct {
		ID       string   `json:"id"`
		Message  string   `json:"message"`
		Added    []string `json:"added"`
		Removed  []string `json:"removed"`
		Modified []string `json:"modified"`
	} `json:"commits"`
	PullRequest struct {
		Number int    `json:"number"`
		Title  string `json:"title"`
		Head   struct {
			Ref string `json:"ref"`
			SHA string `json:"sha"`
		} `json:"head"`
		Base struct {
			Ref string `json:"ref"`
		} `json:"base"`
	} `json:"pull_request"`
	Changes struct {
		DefaultBranch *struct {
			From string `json:"from"`
		} `json:"default_branch"`
	} `json:"changes"`
	Member struct {
		Login string `json:"login"`
	} `json:"member"`
	Membership struct {
		User struct {
			Login string `json:"login"`
		} `json:"user"`
		Role string `json:"role"`
	} `json:"membership"`
	Organization struct {
		Login string `json:"login"`
	} `json:"organization"`
}

func (g *githubIngest) process(w http.ResponseWriter, r *http.Request, body []byte, mode string, actor uuid.UUID, actorName string) {
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
	switch event {
	case "push", "pull_request", "delete", "create", "repository", "member", "organization":
	default:
		// Organization webhooks may send every event type; acknowledge the rest.
		writeJSON(w, 200, map[string]string{"status": "ignored_event"})
		return
	}
	var p githubPayload
	if json.Unmarshal(body, &p) != nil || (event == "push" && !strings.HasPrefix(p.Ref, "refs/")) {
		writeError(w, 400, "invalid event payload")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	bundle, err := g.store.ActiveBundle(ctx)
	if err != nil {
		writeError(w, 503, "indicator store unavailable")
		return
	}
	claimed := p.Sender.Login
	if p.Pusher.Name != "" {
		claimed = p.Pusher.Name
	}
	var request *assessments.Request
	var signals []assessments.IntegrityEvent
	repo := p.Repository.FullName
	switch event {
	case "push":
		signals = g.pushSignals(ctx, p, bundle, claimed)
		branch, isBranch := strings.CutPrefix(p.Ref, "refs/heads/")
		if isBranch && !p.Deleted {
			if len(p.After) != 40 || branch == "" {
				writeError(w, 400, "immutable commit and branch required")
				return
			}
			request = &assessments.Request{AutoRemediation: g.remediation, Target: assessments.Target{Type: "git", Repository: repo, Ref: branch, Commit: p.After}}
		}
	case "pull_request":
		signals = matchPatterns(bundle, map[string][]string{"pr_title_regex": {p.PullRequest.Title}, "git_branch_regex": {p.PullRequest.Head.Ref}}, repo, "", p.PullRequest.Head.SHA, claimed)
		if p.Action == "opened" || p.Action == "synchronize" || p.Action == "reopened" {
			request = &assessments.Request{AutoRemediation: g.remediation, Target: assessments.Target{Type: "git", Repository: repo, Commit: p.PullRequest.Head.SHA, PullRequest: &assessments.PullRequest{Number: p.PullRequest.Number, BaseRef: p.PullRequest.Base.Ref, HeadRef: p.PullRequest.Head.Ref, Title: truncate(p.PullRequest.Title, 512)}}}
		}
	case "delete":
		ref := p.Ref
		severity := "high"
		signals = append(signals, assessments.IntegrityEvent{Kind: "ref_deleted", Severity: severity, Title: "GitHub " + p.RefType + " deleted", Repository: repo, Ref: ref, Actor: claimed, Details: map[string]any{"ref_type": p.RefType}})
		if p.RefType == "branch" {
			churn, err := g.store.RecentBranchCreation(ctx, repo, "refs/heads/"+ref, 15)
			if err != nil {
				writeError(w, 503, "event store unavailable")
				return
			}
			if churn {
				signals = append(signals, assessments.IntegrityEvent{Kind: "branch_churn", Severity: "high", Title: "Branch created and deleted within 15 minutes", Repository: repo, Ref: ref, Actor: claimed})
			}
		}
	case "create":
		if p.RefType == "branch" {
			signals = matchPatterns(bundle, map[string][]string{"git_branch_regex": {p.Ref}}, repo, p.Ref, "", claimed)
		}
	case "repository":
		severity := map[string]string{"deleted": "critical", "transferred": "critical", "archived": "high", "privatized": "high", "publicized": "high", "renamed": "high"}[p.Action]
		if p.Action == "edited" && p.Changes.DefaultBranch != nil {
			signals = append(signals, assessments.IntegrityEvent{Kind: "default_branch_changed", Severity: "high", Title: "Default branch changed", Repository: repo, Actor: claimed, Details: map[string]any{"from": p.Changes.DefaultBranch.From, "to": p.Repository.DefaultBranch}})
		} else if severity != "" {
			signals = append(signals, assessments.IntegrityEvent{Kind: "repository_" + p.Action, Severity: severity, Title: "Repository " + p.Action, Repository: repo, Actor: claimed})
		}
	case "member":
		if p.Action == "added" || p.Action == "edited" {
			signals = append(signals, assessments.IntegrityEvent{Kind: "collaborator_" + p.Action, Severity: "high", Title: "Repository collaborator " + p.Action, Repository: repo, Actor: claimed, Details: map[string]any{"member": p.Member.Login}})
		}
	case "organization":
		if p.Action == "member_added" || p.Action == "member_invited" {
			signals = append(signals, assessments.IntegrityEvent{Kind: "org_" + p.Action, Severity: "high", Title: "Organization " + strings.ReplaceAll(p.Action, "_", " "), Repository: p.Organization.Login, Actor: claimed, Details: map[string]any{"member": p.Membership.User.Login, "role": p.Membership.Role}})
		}
	}
	recorded, err := g.store.RecordIntegrity(ctx, delivery.String(), actor, body, mode, event, signals)
	if err != nil {
		assessmentError(w, err)
		return
	}
	if request == nil {
		writeJSON(w, 200, map[string]any{"status": statusFor(event, p), "integrity_signals": recorded})
		return
	}
	request.Trigger.Origin = "github_" + mode
	request.Trigger.Event = event
	request.Trigger.DeliveryID = delivery.String()
	request.Trigger.Actor = truncate(claimed, 100)
	a, replay, err := g.store.EnqueueEvent(ctx, *request, actor, actorName, delivery.String(), body, mode, event)
	if errors.Is(err, assessments.ErrScope) {
		// AST-004: events for undiscovered or out-of-scope repositories are
		// acknowledged, never scanned. Integrity signals above still alert.
		writeJSON(w, 200, map[string]any{"status": "ignored_out_of_scope", "integrity_signals": recorded})
		return
	}
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
}

func statusFor(event string, p githubPayload) string {
	switch {
	case event == "push" && p.Deleted:
		return "ignored_deleted_ref"
	case event == "push":
		return "ignored_non_branch_ref"
	case event == "pull_request":
		return "ignored_pull_request_action"
	}
	return "recorded"
}

func (g *githubIngest) pushSignals(ctx context.Context, p githubPayload, bundle *intelligence.Bundle, claimed string) []assessments.IntegrityEvent {
	repo := p.Repository.FullName
	branch, isBranch := strings.CutPrefix(p.Ref, "refs/heads/")
	var signals []assessments.IntegrityEvent
	if p.Forced {
		severity := "high"
		if isBranch && branch == p.Repository.DefaultBranch {
			severity = "critical"
		}
		signals = append(signals, assessments.IntegrityEvent{Kind: "force_push", Severity: severity, Title: "Force push rewrote history", Repository: repo, Ref: p.Ref, Commit: p.After, Actor: claimed, Details: map[string]any{"default_branch": branch == p.Repository.DefaultBranch}})
	}
	if p.Deleted {
		signals = append(signals, assessments.IntegrityEvent{Kind: "ref_deleted", Severity: "high", Title: "Ref deleted by push", Repository: repo, Ref: p.Ref, Actor: claimed})
	}
	removed := 0
	var messages, paths []string
	for _, c := range p.Commits {
		removed += len(c.Removed)
		messages = append(messages, c.Message)
		paths = append(paths, c.Added...)
		paths = append(paths, c.Modified...)
	}
	if removed >= g.massDeletion {
		signals = append(signals, assessments.IntegrityEvent{Kind: "mass_deletion", Severity: "high", Title: "Push removed many files", Repository: repo, Ref: p.Ref, Commit: p.After, Actor: claimed, Details: map[string]any{"removed_files": removed, "threshold": g.massDeletion}})
	}
	branches := []string{}
	if isBranch {
		branches = append(branches, branch)
	}
	return append(signals, matchPatterns(bundle, map[string][]string{"git_branch_regex": branches, "commit_message_regex": messages, "file_path_regex": paths}, repo, p.Ref, p.After, claimed)...)
}

// matchPatterns applies INT-008 operator patterns to event fields. Generic
// commit-message patterns alone are medium; branch, title and path matches
// are critical, per the campaign guidance in PRD Appendix E.
func matchPatterns(bundle *intelligence.Bundle, fields map[string][]string, repo, ref, commit, claimed string) []assessments.IntegrityEvent {
	if bundle == nil {
		return nil
	}
	var out []assessments.IntegrityEvent
	now := time.Now()
	for kind, values := range fields {
		for _, pattern := range bundle.Patterns(kind, now) {
			for _, value := range values {
				if value == "" || !pattern.MatchString(value) {
					continue
				}
				severity := "critical"
				if kind == "commit_message_regex" {
					severity = "medium"
				}
				out = append(out, assessments.IntegrityEvent{Kind: "pattern_" + pattern.ID, Severity: severity, Title: "Event matches campaign indicator " + pattern.ID, Repository: repo, Ref: ref, Commit: commit, Actor: claimed, Details: map[string]any{"indicator_id": pattern.ID, "indicator_type": kind, "bundle_version": bundle.Version, "matched_value": truncate(value, 256)}})
				break
			}
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
