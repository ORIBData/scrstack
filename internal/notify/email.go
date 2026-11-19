package notify

import (
	"context"
	"encoding/json"
	"fmt"
	"net/mail"
	"strings"

	"github.com/ORIBData/scrstack/internal/mailer"
)

// Email delivery. A subscription whose url is mailto:a@x.com,b@y.com gets each
// event as a message instead of an HTTP POST, through the same outbox, so
// retries, dead-lettering, redelivery, event and connection scope all apply.
// Only the summary profile may be mailed: findings and agent context do not
// leave the platform over a channel that is stored and forwarded.

const maxMailRecipients = 10

// IsMail reports whether a subscription url is an email destination.
func IsMail(raw string) bool { return strings.HasPrefix(strings.ToLower(raw), "mailto:") }

// mailRecipients parses "mailto:a@x.com,b@y.com". Query strings are refused,
// so a subscription cannot add headers or a body of its own.
func mailRecipients(raw string) ([]string, bool) {
	if !IsMail(raw) || len(raw) > 2048 || strings.ContainsAny(raw, "?\r\n") {
		return nil, false
	}
	var out []string
	for _, part := range strings.Split(raw[len("mailto:"):], ",") {
		a, err := mail.ParseAddress(strings.TrimSpace(part))
		if err != nil || a.Name != "" {
			return nil, false
		}
		out = append(out, a.Address)
	}
	return out, len(out) > 0 && len(out) <= maxMailRecipients
}

// validDestination checks a subscription's url together with its profile.
func (s *Store) validDestination(raw, profile string) bool {
	if IsMail(raw) {
		_, ok := mailRecipients(raw)
		return ok && s.MailEnabled && profile == "summary"
	}
	return s.validURL(raw)
}

// pick returns the first non-empty string at a path in decoded JSON.
func pick(v map[string]any, path ...string) string {
	var cur any = v
	for _, k := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur = m[k]
	}
	s, _ := cur.(string)
	return s
}

// renderMail builds the subject and text of an event. Unknown event types get
// a generic message; payloads are summaries, never evidence or secrets.
func renderMail(eventType string, payload []byte) (subject, text string) {
	var env struct {
		Event map[string]any `json:"event"`
		Data  map[string]any `json:"data"`
	}
	_ = json.Unmarshal(payload, &env)
	d := env.Data
	if d == nil {
		d = map[string]any{}
	}
	var b strings.Builder
	line := func(label, value string) {
		if value != "" {
			fmt.Fprintf(&b, "%-12s %s\n", label+":", value)
		}
	}
	switch {
	case strings.HasPrefix(eventType, "assessment."):
		repo := pick(d, "assessment", "repository")
		ref := pick(d, "assessment", "ref")
		subject = fmt.Sprintf("[SCRS] Assessment %s: %s", strings.TrimPrefix(eventType, "assessment."), strings.TrimSuffix(repo+"@"+ref, "@"))
		line("Repository", repo)
		line("Ref", ref)
		line("Commit", pick(d, "assessment", "commit"))
		line("Status", pick(d, "assessment", "status"))
		line("Verdict", pick(d, "assessment", "verdict"))
		line("Error", pick(d, "assessment", "error"))
		line("Assessment", pick(d, "assessment", "id"))
		line("Details", pick(d, "links", "self"))
	case strings.HasPrefix(eventType, "qa."):
		subject = fmt.Sprintf("[SCRS] QA run %s: %s", strings.TrimPrefix(eventType, "qa."), pick(d, "qa_run", "kind"))
		line("Kind", pick(d, "qa_run", "kind"))
		line("Status", pick(d, "qa_run", "status"))
		line("Ref", pick(d, "qa_run", "ref"))
		line("Commit", pick(d, "qa_run", "commit"))
		line("Error", pick(d, "qa_run", "error"))
		line("QA run", pick(d, "qa_run", "id"))
		line("Assessment", pick(d, "qa_run", "assessment_id"))
		line("Details", pick(d, "links", "self"))
	default:
		subject = "[SCRS] " + eventType
		for _, k := range []string{"title", "detail", "status", "error", "link"} {
			line(k, pick(d, k))
		}
	}
	line("Event", fmt.Sprint(env.Event["id"]))
	line("Time", fmt.Sprint(env.Event["time"]))
	b.WriteString("\nYou receive this because an SCRS webhook subscription sends this event to your address.\n")
	return subject, b.String()
}

// sendMail delivers one outbox row as email and returns a short failure reason
// ("" on success). The SMTP error is logged, never stored or returned, because
// it can name the provider account.
func (d *Dispatcher) sendMail(ctx context.Context, c claimed, sub Subscription) (int, string) {
	if d.Mail == nil || !mailer.Enabled(d.Mail) {
		return 0, "email is not configured"
	}
	to, ok := mailRecipients(sub.URL)
	if !ok || sub.Profile != "summary" {
		return 0, "subscription email destination no longer permitted"
	}
	subject, text := renderMail(c.eventType, c.payload)
	if err := d.Mail.Send(ctx, mailer.Message{To: to, Subject: subject, Text: text}); err != nil {
		if ctx.Err() != nil {
			return 0, "dispatcher stopped"
		}
		d.Logger.Warn("email delivery failed", "delivery_id", c.id, "event_type", c.eventType, "error", err)
		return 0, "email delivery failed"
	}
	return 250, ""
}
