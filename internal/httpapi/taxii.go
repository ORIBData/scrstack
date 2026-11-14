package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/ORIBData/scrstack/internal/taxii"
	"github.com/google/uuid"
)

// Sealer encrypts TAXII credentials with SCRS_MASTER_KEY.
type Sealer interface {
	Seal(plain, aad []byte) ([]byte, error)
	Unseal(sealed, aad []byte) ([]byte, error)
}

// taxiiInput is a TAXII feed's settings with its write-only credential. On
// PATCH, nil fields are unchanged; any credential field replaces the whole
// credential.
type taxiiInput struct {
	APIRoot         *string `json:"api_root"`
	Collection      *string `json:"collection"`
	AuthType        *string `json:"auth_type"`
	AuthHeader      *string `json:"auth_header"`
	APIKey          *string `json:"api_key"`
	Username        *string `json:"username"`
	Password        *string `json:"password"`
	CertPEM         *string `json:"cert_pem"`
	KeyPEM          *string `json:"key_pem"`
	CAPEM           *string `json:"ca_pem"`
	IntervalMinutes *int    `json:"interval_minutes"`
	PageSize        *int    `json:"page_size"`
	ValidDays       *int    `json:"valid_days"`
	ResetCursor     bool    `json:"reset_cursor"`
}

// sourceView is a source with its TAXII feed state, when it has one.
type sourceView struct {
	assessments.IndicatorSource
	TAXII *assessments.TAXIIFeed `json:"taxii,omitempty"`
}

var (
	errTAXIIAdmin  = errors.New("TAXII feeds are managed with admin scope")
	errTAXIIConfig = errors.New("invalid TAXII feed")
	errNoSealer    = errors.New("credential encryption unavailable")
)

// taxiiConfigError carries a validation message for the caller.
type taxiiConfigError struct{ message string }

func (e taxiiConfigError) Error() string { return e.message }
func (e taxiiConfigError) Is(target error) bool {
	return target == errTAXIIConfig
}

func (in taxiiInput) credentialGiven() bool {
	return in.APIKey != nil || in.Username != nil || in.Password != nil || in.CertPEM != nil || in.KeyPEM != nil
}

// apply merges the input over a feed and secret, then validates the result.
func (in taxiiInput) apply(f assessments.TAXIIFeed, s taxii.Secret) (assessments.TAXIIFeed, taxii.Secret, error) {
	set := func(dst *string, src *string) {
		if src != nil {
			*dst = *src
		}
	}
	set(&f.APIRoot, in.APIRoot)
	set(&f.Collection, in.Collection)
	set(&f.AuthType, in.AuthType)
	set(&f.AuthHeader, in.AuthHeader)
	set(&f.CAPEM, in.CAPEM)
	for dst, src := range map[*int]*int{&f.IntervalMinutes: in.IntervalMinutes, &f.PageSize: in.PageSize, &f.ValidDays: in.ValidDays} {
		if src != nil {
			*dst = *src
		}
	}
	if in.credentialGiven() {
		s = taxii.Secret{}
		set(&s.APIKey, in.APIKey)
		set(&s.Username, in.Username)
		set(&s.Password, in.Password)
		set(&s.CertPEM, in.CertPEM)
		set(&s.KeyPEM, in.KeyPEM)
	}
	if f.AuthType == "api_key" && f.AuthHeader == "" {
		f.AuthHeader = "Authorization"
	}
	if f.AuthType != "api_key" {
		f.AuthHeader = ""
	}
	f.ClientCert = s.ClientCert()
	if err := taxii.Validate(clientFeed(f), s); err != nil {
		return f, s, taxiiConfigError{err.Error()}
	}
	if f.IntervalMinutes < 5 || f.IntervalMinutes > 10080 || f.ValidDays < 1 || f.ValidDays > 3650 {
		return f, s, taxiiConfigError{"interval_minutes must be 5 to 10080 and valid_days 1 to 3650"}
	}
	return f, s, nil
}

func clientFeed(f assessments.TAXIIFeed) taxii.Feed {
	return taxii.Feed{APIRoot: f.APIRoot, Collection: f.Collection, AuthType: f.AuthType, Header: f.AuthHeader, CAPEM: f.CAPEM, PageSize: f.PageSize}
}

// createTAXII stores a taxii source with its feed.
func (h sourceHandler) createTAXII(ctx context.Context, w http.ResponseWriter, principal connections.Token, record assessments.IndicatorSource, input *taxiiInput) {
	if !principal.Allows("admin") {
		sourceError(w, errTAXIIAdmin)
		return
	}
	if input == nil {
		sourceError(w, taxiiConfigError{"kind taxii needs a taxii object"})
		return
	}
	if h.secrets == nil {
		sourceError(w, errNoSealer)
		return
	}
	feed, secret, err := input.apply(assessments.TAXIIFeed{AuthType: "none", IntervalMinutes: 60, PageSize: 1000, ValidDays: 180}, taxii.Secret{})
	if err != nil {
		sourceError(w, err)
		return
	}
	plain, _ := json.Marshal(secret)
	created, stored, err := h.store.CreateTAXIISource(ctx, record, feed, principal.ID, func(id uuid.UUID) ([]byte, error) {
		return h.secrets.Seal(plain, assessments.TAXIIAAD(id))
	})
	if err != nil {
		sourceError(w, err)
		return
	}
	w.Header().Set("Location", BasePath+"/intel/indicator-sources/"+created.ID.String())
	writeJSON(w, 201, sourceView{created, &stored})
}

// taxiiItem serves /taxii, :poll and :test on a taxii source.
func (h sourceHandler) taxiiItem(ctx context.Context, w http.ResponseWriter, r *http.Request, principal connections.Token, id uuid.UUID, action string) {
	if r.Method != http.MethodGet && !principal.Allows("admin") {
		sourceError(w, errTAXIIAdmin)
		return
	}
	switch {
	case action == "taxii" && r.Method == http.MethodGet:
		feed, err := h.store.TAXIIFeedFor(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		writeJSON(w, 200, feed)
	case action == "taxii" && r.Method == http.MethodPatch:
		var input taxiiInput
		if !readSourceBody(w, r, &input) {
			return
		}
		feed, secret, err := h.feedSecret(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		feed, secret, err = input.apply(feed, secret)
		if err != nil {
			sourceError(w, err)
			return
		}
		var sealed []byte
		if input.credentialGiven() {
			plain, _ := json.Marshal(secret)
			if sealed, err = h.secrets.Seal(plain, assessments.TAXIIAAD(id)); err != nil {
				sourceError(w, err)
				return
			}
		}
		updated, err := h.store.UpdateTAXIIFeed(ctx, feed, sealed, input.ResetCursor, principal.ID)
		if err != nil {
			sourceError(w, err)
			return
		}
		writeJSON(w, 200, updated)
	case action == "poll" && r.Method == http.MethodPost:
		if err := h.store.PollTAXIINow(ctx, id); err != nil {
			sourceError(w, err)
			return
		}
		writeJSON(w, 202, map[string]bool{"queued": true})
	case action == "test" && r.Method == http.MethodPost:
		// Reads the collection resource with the stored settings, so an admin
		// can check the URL, credential and certificate before the next poll.
		feed, secret, err := h.feedSecret(ctx, id)
		if err != nil {
			sourceError(w, err)
			return
		}
		client, err := taxii.NewClient(clientFeed(feed), secret, h.taxiiHosts)
		if err != nil {
			sourceError(w, taxiiConfigError{err.Error()})
			return
		}
		checkCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		collection, err := client.Check(checkCtx)
		if err != nil {
			writeJSON(w, 502, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": collection.CanRead, "collection": collection})
	default:
		writeError(w, 405, "method not allowed")
	}
}

// feedSecret loads a feed and opens its credential.
func (h sourceHandler) feedSecret(ctx context.Context, id uuid.UUID) (assessments.TAXIIFeed, taxii.Secret, error) {
	var secret taxii.Secret
	if h.secrets == nil {
		return assessments.TAXIIFeed{}, secret, errNoSealer
	}
	feed, sealed, err := h.store.TAXIIFeedCredential(ctx, id)
	if err != nil {
		return feed, secret, err
	}
	plain, err := h.secrets.Unseal(sealed, assessments.TAXIIAAD(id))
	if err != nil {
		return feed, secret, err
	}
	if err := json.Unmarshal(plain, &secret); err != nil {
		return feed, secret, errors.New("TAXII credential invalid")
	}
	return feed, secret, nil
}
