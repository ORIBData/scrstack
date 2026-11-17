package llm

import (
	"strings"
	"testing"
)

func j(parts ...string) string { return strings.Join(parts, "") }

func TestSpecsFromEnvDeclaresHostedAndLocalSideBySide(t *testing.T) {
	fakeKey := j("sk", "-", "proj-", "AbCdEf0123456789")
	specs, errs := SpecsFromEnv([]string{
		"SCRS_LLM_PROVIDERS=hosted, model-host",
		"SCRS_LLM_PROVIDER_HOSTED_KIND=openai",
		"SCRS_LLM_PROVIDER_HOSTED_MODEL=gpt-test",
		"SCRS_LLM_PROVIDER_HOSTED_API_KEY=" + fakeKey,
		"SCRS_LLM_PROVIDER_HOSTED_MAX_TOKENS=16000",
		"SCRS_LLM_PROVIDER_HOSTED_TEMPERATURE=0.2",
		"SCRS_LLM_PROVIDER_MODEL_HOST_KIND=openai_compatible",
		"SCRS_LLM_PROVIDER_MODEL_HOST_BASE_URL=https://model.example.com/v1/",
		"SCRS_LLM_PROVIDER_MODEL_HOST_MODEL=qwen2.5-coder-7b",
		"SCRS_LLM_PROVIDER_MODEL_HOST_API_KEY=local-key",
		"SCRS_LLM_PROVIDER_MODEL_HOST_ALLOW_SOURCE=true",
	})
	if len(errs) != 0 || len(specs) != 2 {
		t.Fatalf("%v %v", specs, errs)
	}
	h, l := specs[0], specs[1]
	if h.Name != "hosted" || h.Provider.Kind != "openai" || h.Provider.MaxTokens != 16000 || h.Provider.Temperature == nil || *h.Provider.Temperature != 0.2 || h.Secret.APIKey != fakeKey || h.AllowSource {
		t.Fatalf("hosted %+v", h)
	}
	if l.Name != "model-host" || l.Provider.BaseURL != "https://model.example.com/v1" || l.Provider.MaxTokens != 8192 || !l.AllowSource {
		t.Fatalf("local %+v", l)
	}
	if err := Validate(h.Provider, h.Secret, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSpecsFromEnvRejectsBadDeclarationsWithoutLeakingValues(t *testing.T) {
	secret := j("hunter2", "-secret-value")
	specs, errs := SpecsFromEnv([]string{
		"SCRS_LLM_PROVIDERS=aa,BadName!,nomodel,badtokens,badallow,x_y,x-y",
		"SCRS_LLM_PROVIDER_AA_KIND=openai", "SCRS_LLM_PROVIDER_AA_MODEL=m",
		"SCRS_LLM_PROVIDER_NOMODEL_KIND=openai",
		"SCRS_LLM_PROVIDER_BADTOKENS_KIND=openai", "SCRS_LLM_PROVIDER_BADTOKENS_MODEL=m", "SCRS_LLM_PROVIDER_BADTOKENS_MAX_TOKENS=lots", "SCRS_LLM_PROVIDER_BADTOKENS_API_KEY=" + secret,
		"SCRS_LLM_PROVIDER_BADALLOW_KIND=openai", "SCRS_LLM_PROVIDER_BADALLOW_MODEL=m", "SCRS_LLM_PROVIDER_BADALLOW_ALLOW_SOURCE=maybe",
		"SCRS_LLM_PROVIDER_X_Y_KIND=openai", "SCRS_LLM_PROVIDER_X_Y_MODEL=m",
	})
	if len(specs) != 2 || specs[0].Name != "aa" || specs[1].Name != "x_y" {
		t.Fatalf("only the good ones are kept: %+v", specs)
	}
	if len(errs) != 5 {
		t.Fatalf("errors: %v", errs)
	}
	for _, err := range errs {
		if strings.Contains(err.Error(), secret) {
			t.Fatal("an error leaks a value:", err)
		}
	}
	if specs, errs := SpecsFromEnv([]string{"PATH=/bin"}); len(specs) != 0 || len(errs) != 0 {
		t.Fatal("nothing declared means nothing created")
	}
}

func TestSourcePolicy(t *testing.T) {
	private := map[string]bool{"model.internal.example": true}
	local := Provider{Kind: "openai_compatible", BaseURL: "https://model.internal.example/v1", Model: "m"}
	hosted := Provider{Kind: "openai", Model: "m"}
	for _, tc := range []struct {
		name         string
		p            Provider
		allow, ack   bool
		want         bool
		wantLocality string
	}{
		{"local needs neither", local, false, false, true, LocalityLocal},
		{"hosted, nothing", hosted, false, false, false, LocalityHosted},
		{"hosted, acknowledged but the switch is off", hosted, false, true, false, LocalityHosted},
		{"hosted, switch on but not acknowledged", hosted, true, false, false, LocalityHosted},
		{"hosted, both", hosted, true, true, true, LocalityHosted},
	} {
		locality, ok := SourcePolicy{Private: private, AllowHosted: tc.allow}.Check(tc.p, tc.ack)
		if ok != tc.want || locality != tc.wantLocality {
			t.Errorf("%s: got %v %s", tc.name, ok, locality)
		}
	}
	t.Setenv(EnvAllowSourceToHosted, "yes")
	if AllowSourceToHosted() {
		t.Fatal("only the exact value true turns it on")
	}
	t.Setenv(EnvAllowSourceToHosted, "true")
	if !AllowSourceToHosted() {
		t.Fatal("true turns it on")
	}
}
