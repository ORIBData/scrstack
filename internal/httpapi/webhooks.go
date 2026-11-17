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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/intelligence"
	"github.com/google/uuid"
)

// githubIngest normalizes direct and relay deliveries from GitHub and GitLab
// into one path (ING-009, ING-011). Payload content is a hint: SCRS resolves
// and fetches commits itself (TRG-003).
//
// Each connection has its own receiver, /ingest/<provider>/<connection>,
// verified with that connection's webhook secret, and its events resolve only
// to that connection's repositories. The shared receivers (/ingest/github,
// /ingest/gitlab, /webhooks/github) remain for deployments that still set
// SCRS_GITHUB_WEBHOOK_SECRET or SCRS_GITLAB_WEBHOOK_SECRET.
type githubIngest struct {
	store        *assessments.Store
	hooks        webhookStore
	secret       string
	gitlabSecret string
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
	return &githubIngest{store: store, secret: secret, gitlabSecret: os.Getenv("SCRS_GITLAB_WEBHOOK_SECRET"), remediation: remediation, relayEnabled: relay, massDeletion: threshold, slots: make(chan struct{}, 8)}
}

var deliveryID = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)

var webhookActor = uuid.NewSHA1(uuid.NameSpaceURL, []byte("scrs:github-webhook"))
var gitlabActor = uuid.NewSHA1(uuid.NameSpaceURL, []byte("scrs:gitlab-webhook"))

// verifyGitHub checks X-Hub-Signature-256 over the exact raw body.
func verifyGitHub(r *http.Request, body []byte, secret string) bool {
	header := r.Header.Get("X-Hub-Signature-256")
	supplied, err := hex.DecodeString(strings.TrimPrefix(header, "sha256="))
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	return err == nil && strings.HasPrefix(header, "sha256=") && hmac.Equal(supplied, mac.Sum(nil))
}

// sameSecret compares a supplied token with a secret in constant time.
func sameSecret(supplied, secret string) bool {
	a, b := sha256.Sum256([]byte(supplied)), sha256.Sum256([]byte(secret))
	return hmac.Equal(a[:], b[:])
}

// verify checks a delivery with the provider's mechanism.
func verify(provider string, r *http.Request, body []byte, secret string) bool {
	if provider == "gitlab" {
		return sameSecret(r.Header.Get("X-Gitlab-Token"), secret)
	}
	return verifyGitHub(r, body, secret)
}

var errNoWebhookSecret = errors.New("no webhook secret")

// secretFor returns the secret that authenticates a delivery: the named
// connection's, or the shared legacy secret on the shared receivers.
func (g *githubIngest) secretFor(ctx context.Context, provider, connection string) (string, error) {
	if connection == "" {
		secret := g.secret
		if provider == "gitlab" {
			secret = g.gitlabSecret
		}
		if len(secret) < 32 {
			return "", errNoWebhookSecret
		}
		return secret, nil
	}
	if g.hooks == nil {
		return "", errNoWebhookSecret
	}
	_, secret, err := g.hooks.WebhookSecret(ctx, provider, connection)
	if errors.Is(err, connections.ErrNotFound) {
		return "", errNoWebhookSecret
	}
	return secret, err
}

// direct authenticates with the provider's own mechanism.
func (g *githubIngest) direct(provider string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !g.acquire(w) {
			return
		}
		defer func() { <-g.slots }()
		connection := r.PathValue("connection")
		// Unsigned deliveries are refused before any secret is looked up.
		if connection != "" && r.Header.Get("X-Hub-Signature-256") == "" && r.Header.Get("X-Gitlab-Token") == "" {
			writeError(w, 401, "invalid webhook signature")
			return
		}
		lookup, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		secret, err := g.secretFor(lookup, provider, connection)
		cancel()
		switch {
		case errors.Is(err, errNoWebhookSecret) && connection == "":
			writeError(w, 503, provider+" webhook authentication not configured; give the connection a webhook secret and use /ingest/"+provider+"/<connection>")
			return
		case errors.Is(err, errNoWebhookSecret):
			// An unknown, disabled or unconfigured connection looks like a
			// bad signature, so the receiver does not reveal which exist.
			writeError(w, 401, "invalid webhook signature")
			return
		case err != nil:
			writeError(w, 503, "webhook authentication unavailable")
			return
		}
		body, ok := g.read(w, r)
		if !ok {
			return
		}
		actor, actorName := webhookActor, "github-webhook"
		if provider == "gitlab" {
			actor, actorName = gitlabActor, "gitlab-webhook"
		}
		if !verify(provider, r, body, secret) {
			writeError(w, 401, "invalid webhook signature")
			return
		}
		g.process(w, r, body, provider, "direct", actor, actorName, connection)
	})
}

// relay accepts the provider's unchanged body from automation holding an
// ingest:relay token (TRG-002). When the relay also forwards the provider's
// signature header, it is verified too, so the relay cannot alter events.
// Wrap it with Security.protect.
func (g *githubIngest) relay(provider string) http.Handler {
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
		connection := r.PathValue("connection")
		forwarded := r.Header.Get("X-Hub-Signature-256") != ""
		if provider == "gitlab" {
			forwarded = r.Header.Get("X-Gitlab-Token") != ""
		}
		// The relay token already authenticates the caller. When SCRS also
		// holds the provider secret, a forwarded signature must be valid; with
		// no secret configured it cannot be checked and is ignored.
		secret, err := g.secretFor(r.Context(), provider, connection)
		if err != nil && !errors.Is(err, errNoWebhookSecret) {
			writeError(w, 503, "webhook authentication unavailable")
			return
		}
		if forwarded && err == nil && !verify(provider, r, body, secret) {
			writeError(w, 401, "invalid forwarded provider signature")
			return
		}
		g.process(w, r, body, provider, "relay", principal.ID, principal.Name, connection)
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

// pushCommit is one commit of a push event, in the fields GitHub and GitLab
// share. Author and Committer carry a login on GitHub (`username`) and only
// a name and email on GitLab.
type pushCommit struct {
	ID        string   `json:"id"`
	Message   string   `json:"message"`
	Timestamp string   `json:"timestamp"`
	Added     []string `json:"added"`
	Removed   []string `json:"removed"`
	Modified  []string `json:"modified"`
	Author    struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Username string `json:"username"`
	} `json:"author"`
	Committer struct {
		Username string `json:"username"`
	} `json:"committer"`
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
	Commits     []pushCommit `json:"commits"`
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

func (g *githubIngest) process(w http.ResponseWriter, r *http.Request, body []byte, provider, mode string, actor uuid.UUID, actorName, connection string) {
	var delivery string
	var event string
	var p githubPayload
	if provider == "gitlab" {
		// Idempotency-Key is stable across GitLab's retries of one delivery.
		// X-Gitlab-Event-UUID is shared by recursive hooks, so it is the fallback.
		delivery = firstNonEmpty(r.Header.Get("Idempotency-Key"), r.Header.Get("X-Gitlab-Event-UUID"))
		if !deliveryID.MatchString(delivery) {
			writeError(w, 400, "Idempotency-Key or X-Gitlab-Event-UUID header required")
			return
		}
		var ok bool
		if event, p, ok = gitlabPayload(r.Header.Get("X-Gitlab-Event"), body); !ok {
			writeError(w, 400, "invalid event payload")
			return
		}
		if event == "" {
			writeJSON(w, 200, map[string]string{"status": "ignored_event"})
			return
		}
	} else {
		parsed, err := uuid.Parse(r.Header.Get("X-GitHub-Delivery"))
		if err != nil {
			writeError(w, 400, "valid delivery ID required")
			return
		}
		delivery = parsed.String()
		event = r.Header.Get("X-GitHub-Event")
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
		if json.Unmarshal(body, &p) != nil {
			writeError(w, 400, "invalid event payload")
			return
		}
	}
	if event == "push" && !strings.HasPrefix(p.Ref, "refs/") {
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
		// GitHub reports branch deletion as a separate delete event; GitLab only as a push.
		if provider == "gitlab" && isBranch && p.Deleted {
			churn, err := g.store.RecentBranchCreation(ctx, repo, p.Ref, 15)
			if err != nil {
				writeError(w, 503, "event store unavailable")
				return
			}
			if churn {
				signals = append(signals, assessments.IntegrityEvent{Kind: "branch_churn", Severity: "high", Title: "Branch created and deleted within 15 minutes", Repository: repo, Ref: branch, Actor: claimed})
			}
		}
		if isBranch && !p.Deleted {
			if len(p.After) != 40 || branch == "" {
				writeError(w, 400, "immutable commit and branch required")
				return
			}
			request = &assessments.Request{AutoRemediation: g.remediation, Target: assessments.Target{Type: "git", Provider: provider, Repository: repo, Ref: branch, Commit: p.After}}
		}
	case "pull_request":
		signals = matchPatterns(bundle, map[string][]string{"pr_title_regex": {p.PullRequest.Title}, "git_branch_regex": {p.PullRequest.Head.Ref}}, repo, "", p.PullRequest.Head.SHA, claimed)
		if p.Action == "opened" || p.Action == "synchronize" || p.Action == "reopened" {
			request = &assessments.Request{AutoRemediation: g.remediation, Target: assessments.Target{Type: "git", Provider: provider, Repository: repo, Commit: p.PullRequest.Head.SHA, PullRequest: &assessments.PullRequest{Number: p.PullRequest.Number, BaseRef: p.PullRequest.Base.Ref, HeadRef: p.PullRequest.Head.Ref, Title: truncate(p.PullRequest.Title, 512)}}}
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
	recorded, err := g.store.RecordIntegrity(ctx, delivery, actor, body, mode, storedEvent(provider, event), signals)
	if err != nil {
		assessmentError(w, err)
		return
	}
	if request == nil {
		writeJSON(w, 200, map[string]any{"status": statusFor(event, p), "integrity_signals": recorded})
		return
	}
	// A per-connection receiver only reaches that connection's repositories.
	request.Connection = connection
	request.Trigger.Origin = provider + "_" + mode
	request.Trigger.Event = event
	request.Trigger.DeliveryID = delivery
	request.Trigger.Actor = truncate(claimed, 100)
	a, replay, err := g.store.EnqueueEvent(ctx, *request, actor, actorName, delivery, body, mode, storedEvent(provider, event))
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
	signals = append(signals, g.authorSignals(ctx, p, isBranch && branch == p.Repository.DefaultBranch, claimed)...)
	return append(signals, matchPatterns(bundle, map[string][]string{"git_branch_regex": branches, "commit_message_regex": messages, "file_path_regex": paths}, repo, p.Ref, p.After, claimed)...)
}

// authorSignals records who authored a push and returns the behavioural
// signals the integrity policy asks for (INT-003). A failure to record never
// stops the push from being handled.
func (g *githubIngest) authorSignals(ctx context.Context, p githubPayload, defaultBranch bool, claimed string) []assessments.IntegrityEvent {
	if p.Deleted || len(p.Commits) == 0 || p.After == "" {
		return nil
	}
	observation := assessments.PushObservation{Repository: p.Repository.FullName, Ref: p.Ref, Commit: p.After, Pusher: claimed, DefaultBranch: defaultBranch}
	for _, c := range p.Commits {
		author := c.Author.Username
		if author == "" {
			author = c.Author.Email
		}
		at, _ := time.Parse(time.RFC3339, c.Timestamp)
		routine := strings.HasPrefix(c.Message, "Merge ") || strings.EqualFold(c.Committer.Username, "web-flow")
		observation.Commits = append(observation.Commits, assessments.AuthoredCommit{Author: author, Login: c.Author.Username, At: at, Routine: routine})
	}
	signals, err := g.store.ObservePush(ctx, observation)
	if err != nil {
		return nil
	}
	return signals
}

// matchPatterns applies INT-008 operator patterns to event fields. Generic
// commit-message patterns alone are medium; branch, title and path matches
// are critical, per the campaign guidance in PRD Appendix E. Alert sources
// use their own severity. Hunt sources are not applied: every integrity event
// raises an alert.
func matchPatterns(bundle *intelligence.Bundle, fields map[string][]string, repo, ref, commit, claimed string) []assessments.IntegrityEvent {
	if bundle == nil {
		return nil
	}
	var out []assessments.IntegrityEvent
	now := time.Now()
	for kind, values := range fields {
		for _, pattern := range bundle.Patterns(kind, now) {
			if pattern.Mode == "hunt" {
				continue
			}
			for _, value := range values {
				if value == "" || !pattern.MatchString(value) {
					continue
				}
				severity := "critical"
				if kind == "commit_message_regex" {
					severity = "medium"
				}
				if pattern.Mode == "alert" {
					severity = pattern.Severity
					if severity == "info" {
						severity = "low"
					}
				}
				key := pattern.Key()
				out = append(out, assessments.IntegrityEvent{Kind: pattern.EventKind(), Severity: severity, Title: "Event matches campaign indicator " + key, Repository: repo, Ref: ref, Commit: commit, Actor: claimed, Details: map[string]any{"indicator_id": key, "indicator_type": kind, "source": pattern.Source, "mode": pattern.Mode, "bundle_version": bundle.Version, "matched_value": truncate(value, 256)}})
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

// storedEvent names inbound events; GitHub names stay unprefixed for compatibility.
func storedEvent(provider, event string) string {
	if provider == "github" {
		return event
	}
	return provider + ":" + event
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

const zeroSHA = "0000000000000000000000000000000000000000"

// gitlabPayload maps GitLab push, tag push and merge request hooks onto the
// normalized event shape. An empty event name means "acknowledge and ignore".
// GitLab does not report force pushes, so that signal is GitHub-only.
func gitlabPayload(header string, body []byte) (string, githubPayload, bool) {
	var raw struct {
		Kind     string `json:"object_kind"`
		Ref      string `json:"ref"`
		Before   string `json:"before"`
		After    string `json:"after"`
		Username string `json:"user_username"`
		User     struct {
			Username string `json:"username"`
		} `json:"user"`
		Project struct {
			Path          string `json:"path_with_namespace"`
			DefaultBranch string `json:"default_branch"`
		} `json:"project"`
		Commits    []pushCommit `json:"commits"`
		Attributes struct {
			IID          int    `json:"iid"`
			Title        string `json:"title"`
			SourceBranch string `json:"source_branch"`
			TargetBranch string `json:"target_branch"`
			Action       string `json:"action"`
			OldRev       string `json:"oldrev"`
			LastCommit   struct {
				ID string `json:"id"`
			} `json:"last_commit"`
		} `json:"object_attributes"`
	}
	var p githubPayload
	switch header {
	case "Push Hook", "Tag Push Hook", "Merge Request Hook":
	default:
		return "", p, true
	}
	if json.Unmarshal(body, &raw) != nil || raw.Project.Path == "" {
		return "", p, false
	}
	p.Repository.FullName = raw.Project.Path
	p.Repository.DefaultBranch = raw.Project.DefaultBranch
	if raw.Kind == "merge_request" {
		a := raw.Attributes
		p.Sender.Login = raw.User.Username
		p.Action = map[string]string{"open": "opened", "reopen": "reopened"}[a.Action]
		if a.Action == "update" && a.OldRev != "" {
			p.Action = "synchronize" // new commits, not a metadata edit
		}
		if p.Action == "" {
			p.Action = a.Action
		}
		p.PullRequest.Number, p.PullRequest.Title = a.IID, a.Title
		p.PullRequest.Head.Ref, p.PullRequest.Head.SHA, p.PullRequest.Base.Ref = a.SourceBranch, a.LastCommit.ID, a.TargetBranch
		return "pull_request", p, true
	}
	p.Ref, p.After, p.Pusher.Name = raw.Ref, raw.After, raw.Username
	p.Created, p.Deleted = raw.Before == zeroSHA, raw.After == zeroSHA
	p.Commits = raw.Commits
	return "push", p, true
}
