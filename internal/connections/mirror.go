package connections

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// MirrorInfo describes one git bundle written by Mirror.
type MirrorInfo struct {
	Refs int    `json:"refs"`
	Head string `json:"head,omitempty"`
}

// Mirror writes a git bundle (v2) holding every branch and tag of a GitHub or
// GitLab repository to w (INT-006). It speaks git's smart HTTP protocol
// directly, so the runtime image needs no git binary. The bundle restores with
// `git clone repo.bundle` and the pack checksum is verified while streaming.
func (a NativeAdapters) Mirror(ctx context.Context, c Connection, secret json.RawMessage, repository string, limit int64, w io.Writer) (MirrorInfo, error) {
	var remote, user, token string
	switch c.Provider {
	case "github":
		parts := strings.Split(repository, "/")
		if !c.Enabled || len(parts) != 2 || !providerSegment.MatchString(parts[0]) || !providerSegment.MatchString(parts[1]) || !c.Scope.matchesResource(Resource{Type: "github_repo", Locator: repository}) {
			return MirrorInfo{}, errors.New("repository is outside connection scope")
		}
		t, err := a.githubToken(ctx, c, secret, parts[0])
		if err != nil {
			return MirrorInfo{}, err
		}
		host := a.GitHubGit
		if host == "" {
			host = "https://github.com"
		}
		remote, user, token = strings.TrimSuffix(host, "/")+"/"+repository+".git", "x-access-token", t
	case "gitlab":
		cfg, t, err := parseGitLab(c, secret)
		if err != nil {
			return MirrorInfo{}, err
		}
		if !c.Enabled || !groupPath(repository) || !strings.HasPrefix(strings.ToLower(repository), strings.ToLower(cfg.Group)+"/") || !c.Scope.matchesResource(Resource{Type: "gitlab_repo", Locator: repository}) {
			return MirrorInfo{}, errors.New("repository is outside connection scope")
		}
		base := cfg.BaseURL
		if base == "" {
			base = "https://gitlab.com"
		}
		remote, user, token = strings.TrimSuffix(base, "/")+"/"+repository+".git", "oauth2", t
	default:
		return MirrorInfo{}, errors.New("provider has no git repositories")
	}
	httpClient := a.Client
	if httpClient == nil {
		httpClient = NewNativeAdapters().Client
	}
	client := *httpClient
	client.Timeout = 0 // ctx bounds the transfer
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	auth := func(r *http.Request) {
		r.SetBasicAuth(user, token)
		r.Header.Set("User-Agent", "git/2.45 (scrs-mirror)")
	}
	refs, head, err := advertisedRefs(ctx, &client, remote, auth)
	if err != nil {
		return MirrorInfo{}, err
	}
	if len(refs) == 0 {
		return MirrorInfo{}, errors.New("repository has no branches or tags")
	}
	var request bytes.Buffer
	wanted := map[string]bool{}
	for _, ref := range refs {
		if wanted[ref.sha] {
			continue
		}
		line := "want " + ref.sha
		if len(wanted) == 0 {
			line += " ofs-delta agent=scrs-mirror/1"
		}
		writePkt(&request, line+"\n")
		wanted[ref.sha] = true
	}
	request.WriteString("0000")
	writePkt(&request, "done\n")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, remote+"/git-upload-pack", &request)
	if err != nil {
		return MirrorInfo{}, errors.New("mirror request invalid")
	}
	auth(req)
	req.Header.Set("Content-Type", "application/x-git-upload-pack-request")
	req.Header.Set("Accept", "application/x-git-upload-pack-result")
	resp, err := client.Do(req)
	if err != nil {
		return MirrorInfo{}, errors.New("git fetch failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return MirrorInfo{}, fmt.Errorf("git fetch returned HTTP %d", resp.StatusCode)
	}
	body := bufio.NewReader(resp.Body)
	if line, flush, err := readPkt(body); err != nil || flush || strings.TrimSpace(line) != "NAK" {
		return MirrorInfo{}, errors.New("unexpected git fetch response")
	}
	var header bytes.Buffer
	header.WriteString("# v2 git bundle\n")
	for _, ref := range refs {
		header.WriteString(ref.sha + " " + ref.name + "\n")
	}
	if head != "" {
		header.WriteString(head + " HEAD\n")
	}
	header.WriteString("\n")
	if _, err := w.Write(header.Bytes()); err != nil {
		return MirrorInfo{}, err
	}
	if err := copyPack(w, body, limit); err != nil {
		return MirrorInfo{}, err
	}
	return MirrorInfo{Refs: len(refs), Head: head}, nil
}

// githubToken returns an installation token (GitHub App) or the stored token
// for a repository owned by the connection's organization.
func (a NativeAdapters) githubToken(ctx context.Context, c Connection, secret json.RawMessage, owner string) (string, error) {
	cfg, err := parseGitHub(c, secret)
	if err != nil || !strings.EqualFold(owner, cfg.Organization) {
		return "", errors.New("invalid GitHub configuration")
	}
	return a.accessToken(ctx, cfg)
}

type gitRef struct{ sha, name string }

// advertisedRefs reads the upload-pack ref advertisement: branches and tags
// only (pull request and merge refs are excluded), plus HEAD's commit.
func advertisedRefs(ctx context.Context, client *http.Client, remote string, auth func(*http.Request)) ([]gitRef, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, remote+"/info/refs?service=git-upload-pack", nil)
	if err != nil {
		return nil, "", errors.New("mirror request invalid")
	}
	auth(req)
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", errors.New("git ref discovery failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "application/x-git-upload-pack-advertisement" {
		return nil, "", fmt.Errorf("git ref discovery returned HTTP %d", resp.StatusCode)
	}
	r := bufio.NewReader(io.LimitReader(resp.Body, 16<<20))
	if line, _, err := readPkt(r); err != nil || line != "# service=git-upload-pack\n" {
		return nil, "", errors.New("not a git smart HTTP server")
	}
	if _, flush, err := readPkt(r); err != nil || !flush {
		return nil, "", errors.New("malformed ref advertisement")
	}
	var refs []gitRef
	head := ""
	for first := true; ; first = false {
		line, flush, err := readPkt(r)
		if err != nil {
			return nil, "", errors.New("malformed ref advertisement")
		}
		if flush {
			return refs, head, nil
		}
		line = strings.TrimSuffix(line, "\n")
		if first {
			var caps string
			line, caps, _ = strings.Cut(line, "\x00")
			if strings.Contains(" "+caps+" ", " object-format=sha256 ") {
				return nil, "", errors.New("SHA-256 repositories are not supported for mirroring")
			}
		}
		sha, name, ok := strings.Cut(line, " ")
		if !ok || len(sha) != 40 || !immutableSHA.MatchString(sha) {
			return nil, "", errors.New("malformed ref advertisement")
		}
		switch {
		case name == "HEAD":
			head = sha
		case strings.HasSuffix(name, "^{}"):
		case strings.HasPrefix(name, "refs/heads/"), strings.HasPrefix(name, "refs/tags/"):
			if len(refs) >= 20000 {
				return nil, "", errors.New("repository exceeds 20000 refs")
			}
			refs = append(refs, gitRef{sha, name})
		}
	}
}

func writePkt(b *bytes.Buffer, payload string) {
	fmt.Fprintf(b, "%04x%s", len(payload)+4, payload)
}

// readPkt reads one pkt-line; flush reports a 0000 packet.
func readPkt(r *bufio.Reader) (string, bool, error) {
	var size [4]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return "", false, err
	}
	n, err := strconv.ParseUint(string(size[:]), 16, 16)
	if err != nil {
		return "", false, err
	}
	if n == 0 {
		return "", true, nil
	}
	if n < 4 {
		return "", false, errors.New("invalid pkt-line")
	}
	payload := make([]byte, n-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", false, err
	}
	return string(payload), false, nil
}

// copyPack streams a packfile, enforcing the size limit and verifying the
// trailing SHA-1 over everything before it.
func copyPack(w io.Writer, r io.Reader, limit int64) error {
	h := sha1.New()
	buf := make([]byte, 64<<10)
	var tail []byte
	var total int64
	started := false
	for {
		n, err := r.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > limit {
				return errors.New("repository exceeds SCRS_MIRROR_MAX_BYTES")
			}
			chunk := append(tail, buf[:n]...)
			if !started && len(chunk) >= 4 {
				if string(chunk[:4]) != "PACK" {
					return errors.New("git server did not return a packfile")
				}
				started = true
			}
			if len(chunk) > sha1.Size {
				body := chunk[:len(chunk)-sha1.Size]
				h.Write(body)
				if _, werr := w.Write(body); werr != nil {
					return werr
				}
				tail = append([]byte{}, chunk[len(chunk)-sha1.Size:]...)
			} else {
				tail = chunk
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return errors.New("git pack transfer failed")
		}
	}
	if !started || len(tail) != sha1.Size || hex.EncodeToString(h.Sum(nil)) != hex.EncodeToString(tail) {
		return errors.New("git pack checksum mismatch")
	}
	_, err := w.Write(tail)
	return err
}
