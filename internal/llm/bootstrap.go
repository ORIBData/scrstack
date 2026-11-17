package llm

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Providers declared in the environment (bootstrap). SCRS_LLM_PROVIDERS lists
// provider names; each name N (upper-cased, "-" as "_") is described by
// SCRS_LLM_PROVIDER_N_KIND, _MODEL, _BASE_URL, _API_KEY, _MAX_TOKENS,
// _TEMPERATURE and _ALLOW_SOURCE. A hosted and a self-hosted provider can be
// declared side by side.

// Spec is one provider declared in the environment.
type Spec struct {
	Name     string
	Provider Provider
	Secret   Secret
	// AllowSource records the operator's acknowledgement that source code may
	// go to this provider (it still needs the platform switch).
	AllowSource bool
}

var specName = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,62}$`)

// EnvPrefix is the prefix of a provider's variables.
func EnvPrefix(name string) string {
	return "SCRS_LLM_PROVIDER_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
}

// SpecsFromEnv reads the declared providers. A provider with a bad
// declaration is reported in errs and left out; the others are returned.
// Values are never included in an error.
func SpecsFromEnv(environ []string) (specs []Spec, errs []error) {
	env := map[string]string{}
	for _, kv := range environ {
		if k, v, ok := strings.Cut(kv, "="); ok {
			env[k] = v
		}
	}
	seen := map[string]string{}
	for _, name := range strings.FieldsFunc(env["SCRS_LLM_PROVIDERS"], func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
		name = strings.ToLower(name)
		prefix := EnvPrefix(name)
		fail := func(format string, args ...any) {
			errs = append(errs, fmt.Errorf("provider %q: "+format, append([]any{name}, args...)...))
		}
		if !specName.MatchString(name) {
			fail("name is 2-63 lower-case letters, digits, hyphens or underscores")
			continue
		}
		if other, dup := seen[prefix]; dup {
			fail("uses the same variables as %q", other)
			continue
		}
		seen[prefix] = name
		get := func(field string) string { return strings.TrimSpace(env[prefix+field]) }
		spec := Spec{Name: name, Provider: Provider{Kind: get("KIND"), BaseURL: strings.TrimSuffix(get("BASE_URL"), "/"), Model: get("MODEL"), MaxTokens: 8192}, Secret: Secret{APIKey: get("API_KEY")}}
		if spec.Provider.Kind == "" || spec.Provider.Model == "" {
			fail("%sKIND and %sMODEL are required", prefix, prefix)
			continue
		}
		if v := get("MAX_TOKENS"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				fail("%sMAX_TOKENS is not a number", prefix)
				continue
			}
			spec.Provider.MaxTokens = n
		}
		if v := get("TEMPERATURE"); v != "" {
			t, err := strconv.ParseFloat(v, 64)
			if err != nil {
				fail("%sTEMPERATURE is not a number", prefix)
				continue
			}
			spec.Provider.Temperature = &t
		}
		switch strings.ToLower(get("ALLOW_SOURCE")) {
		case "", "false":
		case "true":
			spec.AllowSource = true
		default:
			fail("%sALLOW_SOURCE must be true or false", prefix)
			continue
		}
		specs = append(specs, spec)
	}
	return specs, errs
}
