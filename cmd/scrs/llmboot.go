package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/llm"
	"github.com/google/uuid"
)

// sealer is the part of the connection store that seals secrets.
type sealer interface {
	Seal(plain, aad []byte) ([]byte, error)
	Unseal(sealed, aad []byte) ([]byte, error)
}

// bootstrapLLMProviders creates or updates the providers declared in the
// environment (SCRS_LLM_PROVIDERS and SCRS_LLM_PROVIDER_<NAME>_*), so a hosted
// and a self-hosted provider come up with the container and need no API calls.
// A bad declaration is logged and skipped; it never stops the API. Keys are
// sealed like any provider key and never logged.
func bootstrapLLMProviders(ctx context.Context, store *assessments.Store, seals sealer, hosts map[string]bool, logger *slog.Logger) {
	specs, errs := llm.SpecsFromEnv(os.Environ())
	for _, err := range errs {
		logger.Error("LLM provider declaration ignored", "error", err.Error())
	}
	for _, spec := range specs {
		if err := llm.Validate(spec.Provider, spec.Secret, hosts); err != nil {
			logger.Error("LLM provider declaration ignored", "provider", spec.Name, "error", err.Error())
			continue
		}
		plain, _ := json.Marshal(spec.Secret)
		want := assessments.LLMProvider{Name: spec.Name, Kind: spec.Provider.Kind, BaseURL: spec.Provider.BaseURL, Model: spec.Provider.Model, MaxTokens: spec.Provider.MaxTokens, Temperature: spec.Provider.Temperature}
		seal := func(id uuid.UUID) ([]byte, error) {
			if spec.Secret.APIKey == "" {
				return []byte{}, nil
			}
			return seals.Seal(plain, assessments.LLMAAD(id))
		}
		sameKey := func(id uuid.UUID, sealed []byte) bool {
			if len(sealed) == 0 {
				return spec.Secret.APIKey == ""
			}
			opened, err := seals.Unseal(sealed, assessments.LLMAAD(id))
			var have llm.Secret
			return err == nil && json.Unmarshal(opened, &have) == nil && have.APIKey == spec.Secret.APIKey
		}
		stepCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		p, action, err := store.BootstrapLLMProvider(stepCtx, want, spec.AllowSource, seal, sameKey)
		cancel()
		switch {
		case errors.Is(err, assessments.ErrConflict):
			logger.Error("LLM provider declaration skipped: a provider with this name was created through the API; rename one of them", "provider", spec.Name)
		case err != nil:
			logger.Error("LLM provider bootstrap failed", "provider", spec.Name, "error", err.Error())
		default:
			logger.Info("LLM provider from environment", "provider", spec.Name, "action", action, "locality", spec.Provider.Locality(hosts), "model", p.Model, "source_allowed", sourceAllowed(spec.Provider, hosts, p.SourceAckAt != nil))
		}
	}
}

func sourceAllowed(p llm.Provider, hosts map[string]bool, acknowledged bool) bool {
	_, ok := llm.SourcePolicy{Private: hosts, AllowHosted: llm.AllowSourceToHosted()}.Check(p, acknowledged)
	return ok
}
