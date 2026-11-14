package qa

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrUnknownJob means the runner has no such job (it restarted or pruned it).
var ErrUnknownJob = errors.New("runner has no such job")

// ErrRunnerBusy means the runner's queue is full; submit again later.
var ErrRunnerBusy = errors.New("runner queue full")

// Runner is the SCRS side of the runner protocol.
type Runner struct {
	URL   string
	Token string
	http  *http.Client
}

// NewRunner checks the runner URL and token. Plain http is accepted only
// when allowHTTP is set (a runner on a private compose network).
func NewRunner(raw, token, caPEM string, allowHTTP bool) (*Runner, error) {
	u, err := url.Parse(strings.TrimSuffix(raw, "/"))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("SCRS_QA_RUNNER_URL must be an absolute URL without credentials, query or fragment")
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && allowHTTP) {
		return nil, errors.New("SCRS_QA_RUNNER_URL must use https unless SCRS_QA_RUNNER_ALLOW_HTTP=true")
	}
	if len(token) < 32 {
		return nil, errors.New("SCRS_QA_RUNNER_TOKEN must be at least 32 characters")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if caPEM != "" {
		config.RootCAs = x509.NewCertPool()
		if !config.RootCAs.AppendCertsFromPEM([]byte(caPEM)) {
			return nil, errors.New("SCRS_QA_RUNNER_CA holds no PEM certificates")
		}
	}
	transport := &http.Transport{TLSClientConfig: config, Proxy: nil, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: time.Minute, MaxIdleConns: 4, IdleConnTimeout: time.Minute}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Runner{URL: u.String(), Token: token, http: client}, nil
}

func (r *Runner) do(ctx context.Context, method, p string, body io.Reader, contentType string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, r.URL+p, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+r.Token)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("runner unreachable: %w", err)
	}
	return resp, nil
}

func runnerError(resp *http.Response) error {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(data, &e)
	switch resp.StatusCode {
	case http.StatusNotFound:
		return ErrUnknownJob
	case http.StatusTooManyRequests:
		return ErrRunnerBusy
	case http.StatusUnauthorized, http.StatusForbidden:
		return errors.New("runner refused the token")
	}
	if e.Error != "" {
		return fmt.Errorf("runner returned HTTP %d: %s", resp.StatusCode, clipText(e.Error, 300))
	}
	return fmt.Errorf("runner returned HTTP %d", resp.StatusCode)
}

// Submit sends a job; resubmitting the same spec and bundle is harmless.
func (r *Runner) Submit(ctx context.Context, spec JobSpec, bundle []byte) (JobStatus, error) {
	var status JobStatus
	var body bytes.Buffer
	m := multipart.NewWriter(&body)
	encoded, _ := json.Marshal(spec)
	if err := m.WriteField("spec", string(encoded)); err != nil {
		return status, err
	}
	part, err := m.CreateFormFile("bundle", "bundle.tar.gz")
	if err != nil {
		return status, err
	}
	if _, err := part.Write(bundle); err != nil {
		return status, err
	}
	if err := m.Close(); err != nil {
		return status, err
	}
	resp, err := r.do(ctx, http.MethodPost, "/v1/jobs", &body, m.FormDataContentType())
	if err != nil {
		return status, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		return status, runnerError(resp)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&status)
	return status, err
}

// Status reads a job's state.
func (r *Runner) Status(ctx context.Context, id string) (JobStatus, error) {
	var status JobStatus
	resp, err := r.do(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(id), nil, "")
	if err != nil {
		return status, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return status, runnerError(resp)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&status)
	return status, err
}

// Report downloads a finished job's report archive and checks it against
// the digest the runner announced.
func (r *Runner) Report(ctx context.Context, id, digest string) ([]byte, error) {
	resp, err := r.do(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(id)+"/report", nil, "")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, runnerError(resp)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxReportBytes+1))
	if err != nil {
		return nil, fmt.Errorf("report download failed: %w", err)
	}
	if len(data) > MaxReportBytes {
		return nil, errors.New("report archive is over 64 MiB")
	}
	sum := sha256.Sum256(data)
	if digest != "" && hex.EncodeToString(sum[:]) != digest {
		return nil, errors.New("report archive does not match its digest")
	}
	return data, nil
}

// Delete cancels a job and removes its files.
func (r *Runner) Delete(ctx context.Context, id string) error {
	resp, err := r.do(ctx, http.MethodDelete, "/v1/jobs/"+url.PathEscape(id), nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusNotFound {
		return runnerError(resp)
	}
	return nil
}

// Info reads the runner's Karate version and load.
func (r *Runner) Info(ctx context.Context) (Info, error) {
	var info Info
	resp, err := r.do(ctx, http.MethodGet, "/v1/info", nil, "")
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, runnerError(resp)
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info)
	return info, err
}
