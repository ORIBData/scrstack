package notify

import (
	"github.com/ORIBData/scrstack/internal/netguard"
	"net"
	"strings"
	"testing"
	"time"
)

func TestSignatureMatchesBodyOnly(t *testing.T) {
	body := []byte(`{"event":{"type":"ping"}}`)
	sig := Sign("whsec_test", body)
	if !Verify("whsec_test", body, sig) || Verify("whsec_other", body, sig) || Verify("whsec_test", append(body, ' '), sig) {
		t.Fatal("signature does not bind secret and exact body")
	}
}

func TestBackoffIsBoundedExponential(t *testing.T) {
	if backoff(1) != 30*time.Second || backoff(2) != time.Minute || backoff(8) != time.Hour || backoff(50) != time.Hour {
		t.Fatal("unexpected backoff schedule", backoff(1), backoff(2), backoff(8))
	}
}

func TestSubscriptionURLPolicy(t *testing.T) {
	s := &Store{PrivateHosts: map[string]bool{"n8n": true}}
	for raw, want := range map[string]bool{
		"https://hooks.example.com/scrs":     true,
		"http://n8n:5678/webhook/scrs":       true,
		"http://hooks.example.com/scrs":      false, // plain HTTP to a public host
		"https://user:pw@hooks.example.com/": false,
		"https://10.1.2.3/hook":              false, // literal private address
		"https://[::1]/hook":                 false,
		"https://169.254.169.254/latest":     false, // cloud metadata
		"ftp://hooks.example.com/":           false,
		"https://hooks.example.com/#frag":    false,
	} {
		if got := s.validURL(raw); got != want {
			t.Errorf("%s: got %v want %v", raw, got, want)
		}
	}
	for _, ip := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254", "198.18.0.1", "::1", "fd00::1", "64:ff9b::a00:1"} {
		if netguard.Public(net.ParseIP(ip)) {
			t.Errorf("%s treated as public", ip)
		}
	}
	if !netguard.Public(net.ParseIP("140.82.112.3")) {
		t.Error("public address rejected")
	}
	if !validEvents([]string{"assessment.completed", "integrity.alert"}) || validEvents([]string{"assessment.completed", "assessment.completed"}) || validEvents([]string{"made.up"}) || validEvents(nil) {
		t.Fatal("event filter validation wrong")
	}
}

func TestMailDestinationPolicyAndRendering(t *testing.T) {
	s := &Store{MailEnabled: true}
	for raw, want := range map[string]bool{
		"mailto:ops@example.com":                  true,
		"mailto:ops@example.com, sec@example.com": true,
		"mailto:":                              false,
		"mailto:ops@example.com?bcc=x@y.z":     false, // no headers or body from the url
		"mailto:Ops <ops@example.com>":         false,
		"mailto:nope":                          false,
		"mailto:ops@example.com\r\nBcc: x@y.z": false,
	} {
		if got := s.validDestination(raw, "summary"); got != want {
			t.Errorf("%q: got %v want %v", raw, got, want)
		}
	}
	if s.validDestination("mailto:ops@example.com", "full") || s.validDestination("mailto:ops@example.com", "agent") {
		t.Error("full and agent profiles must not be mailed")
	}
	if (&Store{}).validDestination("mailto:ops@example.com", "summary") {
		t.Error("email accepted while SMTP is not configured")
	}
	subject, text := renderMail("qa.failed", []byte(`{"event":{"id":"e1","time":"t"},"data":{"qa_run":{"kind":"lint","status":"failed","error":"boom"}}}`))
	if subject != "[SCRS] QA run failed: lint" || !strings.Contains(text, "boom") {
		t.Errorf("render: %q %q", subject, text)
	}
}
