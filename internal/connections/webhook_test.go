package connections

import "testing"

func TestWebhookPathsAndHookMatching(t *testing.T) {
	for provider, want := range map[string]string{"github": "/scrs/v1/ingest/github/acme", "gitlab": "/scrs/v1/ingest/gitlab/acme", "harbor": "/scrs/v1/ingest/registry/harbor/acme", "dockerhub": "/scrs/v1/ingest/registry/dockerhub/acme"} {
		if got := WebhookPath(provider, "acme"); got != want {
			t.Errorf("%s: %s", provider, got)
		}
	}
	cases := []struct {
		url, expected, name string
		want                bool
	}{
		{"https://scrs.example.com/scrs/v1/ingest/github/gh", "", "gh", true},
		{"https://scrs.example.com/scrs/v1/ingest/github/gh2", "", "gh", false},
		{"https://scrs.example.com/scrs/v1/ingest/github/gh/", "", "gh", true},
		{"https://scrs.example.com/scrs/v1/ingest/github", "", "gh", true},
		{"https://relay.example.com/hooks/scrs", "https://relay.example.com/hooks/scrs/", "gh", true},
		{"https://scrs.example.com/scrs/v1/ingest/github/gh", "https://relay.example.com/hooks/scrs", "gh", false},
	}
	for _, c := range cases {
		if got := pointsAtSCRS(c.url, c.expected, c.name); got != c.want {
			t.Errorf("%s (%q, %s) = %v", c.url, c.expected, c.name, got)
		}
	}
	for secret, ok := range map[string]bool{"short": false, "with space " + "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx": false, "0123456789abcdef0123456789abcdef": true} {
		if ValidWebhookSecret(secret) != ok {
			t.Errorf("%q", secret)
		}
	}
}
