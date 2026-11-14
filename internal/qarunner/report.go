package qarunner

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/ORIBData/scrstack/internal/qa"
)

// capture keeps the head and the tail of a process's output: a load run
// logs every request, and the statistics Gatling prints come last.
type capture struct {
	mu       sync.Mutex
	head     []byte
	tail     []byte
	headMax  int
	tailMax  int
	dropped  int64
	wrapping bool
}

func newCapture(head, tail int) *capture { return &capture{headMax: head, tailMax: tail} }

func (c *capture) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	if room := c.headMax - len(c.head); room > 0 && !c.wrapping {
		take := min(room, len(p))
		c.head = append(c.head, p[:take]...)
		p = p[take:]
	}
	if len(p) == 0 {
		return n, nil
	}
	c.wrapping = true
	c.tail = append(c.tail, p...)
	if over := len(c.tail) - c.tailMax; over > 0 {
		c.dropped += int64(over)
		c.tail = append([]byte(nil), c.tail[over:]...)
	}
	return n, nil
}

func (c *capture) WriteString(s string) { _, _ = c.Write([]byte(s)) }

// Bytes returns the head, a marker for any dropped middle, and the tail.
func (c *capture) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := append([]byte(nil), c.head...)
	if c.dropped > 0 {
		out = append(out, []byte("\n[... "+itoa(int(c.dropped))+" bytes of output omitted ...]\n")...)
	}
	return append(out, c.tail...)
}

// sensitiveHeader matches credential headers in Karate's request and
// response logs, in plain text, JSON strings, and XML or HTML escaping.
var sensitiveHeader = regexp.MustCompile(`(?i)(\d+ (?:>|<|&gt;|&lt;|\\u003e|\\u003c) (?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-access-token|x-csrf-token): ?)[^\r\n\\"<&]*`)

// redactor removes the job's secret values and credential headers.
type redactor struct{ values []string }

func newRedactor(vars map[string]string) redactor {
	var r redactor
	seen := map[string]bool{}
	for _, v := range vars {
		if len(v) < 4 {
			continue
		}
		escaped, _ := json.Marshal(v)
		for _, form := range []string{v, strings.Trim(string(escaped), `"`), html.EscapeString(v)} {
			if !seen[form] {
				seen[form] = true
				r.values = append(r.values, form)
			}
		}
	}
	// Longest first, so a secret containing another is replaced whole.
	sort.Slice(r.values, func(i, j int) bool { return len(r.values[i]) > len(r.values[j]) })
	return r
}

func (r redactor) apply(data []byte) []byte {
	for _, v := range r.values {
		data = bytes.ReplaceAll(data, []byte(v), []byte("[REDACTED]"))
	}
	return sensitiveHeader.ReplaceAll(data, []byte("${1}[REDACTED]"))
}

// textual lists report file types that may echo requests and responses.
var textual = map[string]bool{".html": true, ".xml": true, ".jsonl": true, ".json": true, ".js": true, ".log": true, ".txt": true, ".csv": true}

// pack writes report.tar.gz: result.json, console.log and the output tree,
// redacted. If the archive would pass the size limit, HTML pages and
// assets are left out and the result is marked truncated.
func (s *Server) pack(j *job, status qa.JobStatus, console []byte, red redactor) (string, int64, bool, error) {
	out := filepath.Join(j.dir, "out")
	type entry struct {
		path     string
		source   string
		priority int
	}
	var entries []entry
	err := filepath.WalkDir(out, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !d.Type().IsRegular() {
			return nil
		}
		rel, _ := filepath.Rel(out, p)
		rel = filepath.ToSlash(rel)
		priority := 2
		switch {
		case strings.Contains(rel, "/karate-json/") || strings.Contains(rel, "/junit-xml/"):
			priority = 0
		case strings.HasSuffix(rel, "karate-summary.html") || strings.HasPrefix(rel, "gatling/") && strings.HasSuffix(rel, "index.html"):
			priority = 1
		}
		entries = append(entries, entry{rel, p, priority})
		return nil
	})
	if err != nil {
		return "", 0, false, err
	}
	sort.Slice(entries, func(a, b int) bool { return entries[a].path < entries[b].path })
	build := func(maxPriority int, truncated bool) ([]byte, error) {
		status.Truncated = truncated
		result, _ := json.MarshalIndent(status, "", " ")
		files := []qa.File{{Path: "result.json", Data: result}, {Path: "console.log", Data: console}}
		var total int64
		for _, e := range entries {
			if e.priority > maxPriority {
				continue
			}
			data, err := os.ReadFile(e.source)
			if err != nil {
				return nil, err
			}
			if textual[strings.ToLower(filepath.Ext(e.path))] {
				data = red.apply(data)
			}
			total += int64(len(data))
			if total > 512<<20 {
				return nil, errors.New("reports exceed 512 MiB")
			}
			files = append(files, qa.File{Path: e.path, Data: data})
		}
		return qa.Pack(files)
	}
	archive, err := build(2, false)
	truncated := false
	if err != nil || len(archive) > qa.MaxReportBytes {
		truncated = true
		if archive, err = build(1, true); err == nil && len(archive) > qa.MaxReportBytes {
			archive, err = build(0, true)
		}
	}
	if err != nil {
		return "", 0, false, err
	}
	if len(archive) > qa.MaxReportBytes {
		return "", 0, false, errors.New("machine-readable reports alone exceed 64 MiB")
	}
	if err := os.WriteFile(filepath.Join(j.dir, "report.tar.gz"), archive, 0o600); err != nil {
		return "", 0, false, err
	}
	sum := sha256.Sum256(archive)
	return hex.EncodeToString(sum[:]), int64(len(archive)), truncated, nil
}
