package llm

import (
	"net/url"
	"os"
	"strings"
)

// Locality says where a provider runs, which decides what it may be sent.
const (
	// LocalityLocal is a model server the operator runs: its host is on the
	// operator's list of self-hosted servers (SCRS_LLM_PRIVATE_HOSTS). Source
	// code may be sent to it, because it does not leave the operator's network.
	LocalityLocal = "local"
	// LocalityHosted is any other provider. It receives findings and advisory
	// text. It receives source code only under SourcePolicy: the platform
	// switch is on and an administrator acknowledged that provider.
	LocalityHosted = "hosted"
)

// Local reports whether the provider is a self-hosted model server: its base
// URL (after the preset default is applied) names a host the operator listed
// in private. The list is the operator's statement of which hosts are theirs;
// a hosted provider's hostname must never be added to it.
func (p Provider) Local(private map[string]bool) bool {
	u, err := url.Parse(p.Resolve().BaseURL)
	if err != nil || u.Hostname() == "" {
		return false
	}
	return private[strings.ToLower(u.Hostname())]
}

// Locality returns LocalityLocal or LocalityHosted.
func (p Provider) Locality(private map[string]bool) string {
	if p.Local(private) {
		return LocalityLocal
	}
	return LocalityHosted
}

// EnvAllowSourceToHosted is the platform switch for sending source code to a
// hosted provider. It is off unless set to "true"; even then each provider
// needs its own acknowledgement (POST /llm/providers/{id}:allow-source).
const EnvAllowSourceToHosted = "SCRS_LLM_ALLOW_SOURCE_TO_HOSTED"

// AllowSourceToHosted reads the platform switch.
func AllowSourceToHosted() bool { return os.Getenv(EnvAllowSourceToHosted) == "true" }

// SourcePolicy decides which providers may be sent source code (code review,
// unit-test generation). A self-hosted provider always may. A hosted one may
// only when the platform switch is on and an administrator acknowledged that
// provider; findings and advisory text need neither.
type SourcePolicy struct {
	// Private is the operator's list of self-hosted hosts.
	Private map[string]bool
	// AllowHosted is the platform switch (AllowSourceToHosted).
	AllowHosted bool
}

// Check returns the provider's locality and whether it may receive source.
func (sp SourcePolicy) Check(p Provider, acknowledged bool) (locality string, ok bool) {
	locality = p.Locality(sp.Private)
	if locality == LocalityLocal {
		return locality, true
	}
	return locality, sp.AllowHosted && acknowledged
}
