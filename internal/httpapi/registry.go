package httpapi

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
)

// registryIngest admits image pushes from registry webhooks (ING-002). Every
// caller holds an ingest:relay token: Harbor sends it from its webhook "Auth
// Header" setting; Docker Hub and GAR Pub/Sub cannot set headers and reach
// SCRS through n8n. Each pushed manifest becomes one image assessment, pinned
// to the pushed digest when the registry reports it.
type registryIngest struct {
	store        *assessments.Store
	relayEnabled bool
}

type imagePush struct {
	Locator string `json:"locator"`
	Tag     string `json:"tag,omitempty"`
	Digest  string `json:"digest,omitempty"`
}

var errRegistryProvider = errors.New("unsupported registry provider")

func (h registryIngest) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.relayEnabled {
		writeError(w, 503, "relay ingestion disabled; set SCRS_RELAY_ENABLED=true")
		return
	}
	provider := r.PathValue("provider")
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		writeError(w, 413, "webhook payload limit exceeded")
		return
	}
	pushes, err := parseRegistryEvent(provider, body)
	switch {
	case errors.Is(err, errRegistryProvider):
		writeError(w, 404, "unsupported registry provider; use harbor, dockerhub, gar or oci")
		return
	case err != nil:
		writeError(w, 400, "invalid registry event payload")
		return
	case len(pushes) == 0:
		writeJSON(w, 200, map[string]any{"status": "ignored_event", "items": []any{}})
		return
	case len(pushes) > 50:
		writeError(w, 400, "registry event lists more than 50 images")
		return
	}
	principal := r.Context().Value(principalKey{}).(connections.Token)
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	// Registries do not send a stable delivery id; the body digest is one, so
	// retried deliveries replay the same assessments.
	key := "registry:" + provider + ":" + assessments.Hash(body)[:40]
	items := make([]map[string]any, 0, len(pushes))
	queued := 0
	for i, push := range pushes {
		item := map[string]any{"locator": push.Locator, "tag": push.Tag, "digest": push.Digest}
		req := assessments.Request{Target: assessments.Target{Type: "image", Repository: push.Locator, Ref: push.Tag, Commit: push.Digest}}
		req.Trigger.Origin, req.Trigger.Event = "registry_"+provider, "push"
		req.Trigger.DeliveryID = key + ":" + strconv.Itoa(i)
		a, replay, err := h.store.EnqueueEvent(ctx, req, principal.ID, principal.Name, req.Trigger.DeliveryID, body, "relay", "registry:"+provider)
		switch {
		case errors.Is(err, assessments.ErrScope):
			item["status"] = "ignored_out_of_scope"
		case errors.Is(err, assessments.ErrInput):
			item["status"] = "invalid_reference"
		case errors.Is(err, assessments.ErrAmbiguous):
			item["status"] = "ambiguous_connection"
		case err != nil:
			// Earlier items are durable and idempotent; a retry replays them.
			assessmentError(w, err)
			return
		default:
			item["assessment_id"], item["status"] = a.ID, "queued"
			if replay {
				item["status"] = "replayed"
			} else {
				queued++
			}
		}
		items = append(items, item)
	}
	code := 200
	if queued > 0 {
		code = 202
	}
	writeJSON(w, code, map[string]any{"items": items})
}

// parseRegistryEvent extracts pushed image manifests from one provider event.
// Non-push events return no pushes.
func parseRegistryEvent(provider string, body []byte) ([]imagePush, error) {
	switch provider {
	case "harbor":
		var e struct {
			Type string `json:"type"`
			Data struct {
				Resources []struct {
					Digest      string `json:"digest"`
					Tag         string `json:"tag"`
					ResourceURL string `json:"resource_url"`
				} `json:"resources"`
				Repository struct {
					FullName string `json:"repo_full_name"`
				} `json:"repository"`
			} `json:"event_data"`
		}
		if err := json.Unmarshal(body, &e); err != nil {
			return nil, err
		}
		if e.Type != "PUSH_ARTIFACT" {
			return nil, nil
		}
		var out []imagePush
		for _, res := range e.Data.Resources {
			host, _, _ := strings.Cut(res.ResourceURL, "/")
			if host == "" || e.Data.Repository.FullName == "" {
				return nil, errors.New("harbor resource without registry host")
			}
			out = append(out, imagePush{Locator: strings.ToLower(host + "/" + e.Data.Repository.FullName), Tag: res.Tag, Digest: res.Digest})
		}
		return out, nil
	case "dockerhub":
		var e struct {
			Push struct {
				Tag string `json:"tag"`
			} `json:"push_data"`
			Repository struct {
				Name string `json:"repo_name"`
			} `json:"repository"`
		}
		if err := json.Unmarshal(body, &e); err != nil || e.Repository.Name == "" {
			return nil, errors.New("docker hub event without repository")
		}
		return []imagePush{{Locator: "docker.io/" + strings.ToLower(e.Repository.Name), Tag: e.Push.Tag}}, nil
	case "gar":
		// Accept a Pub/Sub push envelope or its decoded message data.
		var envelope struct {
			Message struct {
				Data string `json:"data"`
			} `json:"message"`
		}
		data := body
		if json.Unmarshal(body, &envelope) == nil && envelope.Message.Data != "" {
			decoded, err := base64.StdEncoding.DecodeString(envelope.Message.Data)
			if err != nil {
				return nil, err
			}
			data = decoded
		}
		var e struct {
			Action string `json:"action"`
			Digest string `json:"digest"`
			Tag    string `json:"tag"`
		}
		if err := json.Unmarshal(data, &e); err != nil {
			return nil, err
		}
		if e.Action != "INSERT" {
			return nil, nil
		}
		push := imagePush{}
		if locator, digest, ok := strings.Cut(e.Digest, "@"); ok {
			push.Locator, push.Digest = locator, digest
		}
		if i := strings.LastIndex(e.Tag, ":"); i > strings.LastIndex(e.Tag, "/") {
			if push.Locator == "" {
				push.Locator = e.Tag[:i]
			}
			push.Tag = e.Tag[i+1:]
		}
		if push.Locator == "" {
			return nil, errors.New("gar event without image")
		}
		push.Locator = strings.ToLower(push.Locator)
		return []imagePush{push}, nil
	case "oci":
		// CNCF Distribution (registry:2, Zot, Nexus and others) notifications.
		var e struct {
			Events []struct {
				Action string `json:"action"`
				Target struct {
					MediaType  string `json:"mediaType"`
					Digest     string `json:"digest"`
					Repository string `json:"repository"`
					URL        string `json:"url"`
					Tag        string `json:"tag"`
				} `json:"target"`
				Request struct {
					Host string `json:"host"`
				} `json:"request"`
			} `json:"events"`
		}
		if err := json.Unmarshal(body, &e); err != nil {
			return nil, err
		}
		var out []imagePush
		for _, ev := range e.Events {
			t := ev.Target
			if ev.Action != "push" || !(strings.Contains(t.MediaType, "manifest") || strings.Contains(t.MediaType, "image.index")) {
				continue // layer blob pushes and pulls
			}
			host := ev.Request.Host
			if u, err := url.Parse(t.URL); err == nil && u.Host != "" {
				host = u.Host
			}
			if host == "" || t.Repository == "" {
				return nil, errors.New("distribution event without registry host")
			}
			out = append(out, imagePush{Locator: strings.ToLower(host + "/" + t.Repository), Tag: t.Tag, Digest: t.Digest})
		}
		return out, nil
	}
	return nil, errRegistryProvider
}
