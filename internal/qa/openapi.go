package qa

import (
	"encoding/json"
	"errors"
	"net/url"
	"path"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Operation is one documented API operation.
type Operation struct {
	Method      string   `json:"method"`
	Path        string   `json:"path"`
	OperationID string   `json:"operation_id,omitempty"`
	Summary     string   `json:"summary,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Deprecated  bool     `json:"deprecated,omitempty"`
}

// Key names an operation: "GET /users/{id}".
func (o Operation) Key() string { return o.Method + " " + o.Path }

// API is a parsed OpenAPI 3 or Swagger 2 document.
type API struct {
	Title      string      `json:"title"`
	Version    string      `json:"version"`
	BasePaths  []string    `json:"base_paths"`
	Operations []Operation `json:"operations"`
	// Document is the parsed spec, kept for prompt context.
	Document map[string]any `json:"-"`
}

// MaxSpecBytes and MaxOperations bound an OpenAPI document.
const (
	MaxSpecBytes  = 4 << 20
	MaxOperations = 2000
)

var httpMethods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// SpecNames are the file names an OpenAPI document is found by.
var SpecNames = map[string]bool{"openapi.yaml": true, "openapi.yml": true, "openapi.json": true, "swagger.yaml": true, "swagger.yml": true, "swagger.json": true}

// FindSpec returns the shallowest OpenAPI document path in a file list,
// ignoring dependencies and fixtures.
func FindSpec(paths []string) string {
	best := ""
	for _, p := range paths {
		if !SpecNames[strings.ToLower(path.Base(p))] {
			continue
		}
		skip := false
		for _, part := range strings.Split(p, "/") {
			switch part {
			case "node_modules", "vendor", "testdata", "fixtures", "third_party", ".git":
				skip = true
			}
		}
		if skip {
			continue
		}
		if best == "" || strings.Count(p, "/") < strings.Count(best, "/") || (strings.Count(p, "/") == strings.Count(best, "/") && p < best) {
			best = p
		}
	}
	return best
}

// ParseAPI reads an OpenAPI 3.x or Swagger 2.0 document in JSON or YAML.
func ParseAPI(data []byte) (API, error) {
	var api API
	if len(data) > MaxSpecBytes {
		return api, errors.New("OpenAPI document is over 4 MiB")
	}
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil || doc == nil {
		return api, errors.New("OpenAPI document is not JSON or YAML")
	}
	doc = normalize(doc).(map[string]any)
	version, _ := doc["openapi"].(string)
	swagger, _ := doc["swagger"].(string)
	if !strings.HasPrefix(version, "3.") && swagger != "2.0" {
		return api, errors.New("not an OpenAPI 3 or Swagger 2.0 document")
	}
	api.Document = doc
	if info, ok := doc["info"].(map[string]any); ok {
		api.Title, _ = info["title"].(string)
		api.Version, _ = info["version"].(string)
	}
	bases := map[string]bool{}
	if base, ok := doc["basePath"].(string); ok {
		bases[cleanBase(base)] = true
	}
	if servers, ok := doc["servers"].([]any); ok {
		for _, s := range servers {
			if m, ok := s.(map[string]any); ok {
				if raw, ok := m["url"].(string); ok {
					if u, err := url.Parse(raw); err == nil {
						bases[cleanBase(u.Path)] = true
					}
				}
			}
		}
	}
	for b := range bases {
		if b != "" {
			api.BasePaths = append(api.BasePaths, b)
		}
	}
	sort.Strings(api.BasePaths)
	paths, _ := doc["paths"].(map[string]any)
	keys := make([]string, 0, len(paths))
	for p := range paths {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	for _, p := range keys {
		item, ok := paths[p].(map[string]any)
		if !ok || !strings.HasPrefix(p, "/") {
			continue
		}
		for _, method := range httpMethods {
			op, ok := item[method].(map[string]any)
			if !ok {
				continue
			}
			if len(api.Operations) >= MaxOperations {
				return api, errors.New("OpenAPI document has over 2000 operations")
			}
			o := Operation{Method: strings.ToUpper(method), Path: p}
			o.OperationID, _ = op["operationId"].(string)
			o.Summary, _ = op["summary"].(string)
			o.Deprecated, _ = op["deprecated"].(bool)
			if tags, ok := op["tags"].([]any); ok {
				for _, t := range tags {
					if s, ok := t.(string); ok {
						o.Tags = append(o.Tags, s)
					}
				}
			}
			o.OperationID, o.Summary = clipText(o.OperationID, 128), clipText(o.Summary, 256)
			api.Operations = append(api.Operations, o)
		}
	}
	if len(api.Operations) == 0 {
		return api, errors.New("OpenAPI document has no operations")
	}
	return api, nil
}

// normalize turns YAML's map[string]any trees with any keys into JSON shapes.
func normalize(v any) any {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			t[k] = normalize(child)
		}
		return t
	case map[any]any:
		out := map[string]any{}
		for k, child := range t {
			if s, ok := k.(string); ok {
				out[s] = normalize(child)
			}
		}
		return out
	case []any:
		for i, child := range t {
			t[i] = normalize(child)
		}
	}
	return v
}

func cleanBase(p string) string {
	p = strings.TrimSuffix(path.Clean("/"+p), "/")
	if p == "/" || p == "." {
		return ""
	}
	return p
}

// OperationCoverage is one operation's test traffic.
type OperationCoverage struct {
	Operation
	Hits     int   `json:"hits"`
	Statuses []int `json:"statuses"`
}

// Coverage relates a run's HTTP traffic to the documented operations.
type Coverage struct {
	Total      int                 `json:"total"`
	Covered    int                 `json:"covered"`
	Percent    float64             `json:"percent"`
	Operations []OperationCoverage `json:"operations"`
	// Unmatched lists called paths no operation documents (first 50).
	Unmatched []string `json:"unmatched"`
}

// Cover matches calls to the target host against the operations. A call
// matches when its path, less the run's base URL path or a documented base
// path, fits an operation's template; literal segments outrank parameters,
// so /users/me matches /users/me before /users/{id}. Deprecated operations
// are listed but not counted.
func Cover(ops []Operation, basePaths []string, baseURL string, calls []Call) Coverage {
	c := Coverage{Operations: make([]OperationCoverage, len(ops)), Unmatched: []string{}}
	for i, o := range ops {
		c.Operations[i] = OperationCoverage{Operation: o, Statuses: []int{}}
	}
	host, prefixes := "", append([]string{}, basePaths...)
	if u, err := url.Parse(baseURL); err == nil {
		host = strings.ToLower(u.Host)
		if b := cleanBase(u.Path); b != "" {
			prefixes = append(prefixes, b)
		}
	}
	// Longest prefix first, then none.
	sort.Slice(prefixes, func(i, j int) bool { return len(prefixes[i]) > len(prefixes[j]) })
	prefixes = append(prefixes, "")
	unmatched := map[string]bool{}
	for _, call := range calls {
		if host != "" && call.Host != host {
			continue
		}
		best, bestScore := -1, -1
		for _, prefix := range prefixes {
			p := call.Path
			if prefix != "" {
				if p != prefix && !strings.HasPrefix(p, prefix+"/") {
					continue
				}
				p = strings.TrimPrefix(p, prefix)
				if p == "" {
					p = "/"
				}
			}
			for i, o := range ops {
				if o.Method != call.Method {
					continue
				}
				if score, ok := matchTemplate(o.Path, p); ok && score > bestScore {
					best, bestScore = i, score
				}
			}
			if best >= 0 {
				break
			}
		}
		if best < 0 {
			key := call.Method + " " + call.Path
			if !unmatched[key] && len(c.Unmatched) < 50 {
				c.Unmatched = append(c.Unmatched, key)
			}
			unmatched[key] = true
			continue
		}
		o := &c.Operations[best]
		o.Hits += call.Count
		if !containsInt(o.Statuses, call.Status) {
			o.Statuses = append(o.Statuses, call.Status)
			sort.Ints(o.Statuses)
		}
	}
	for _, o := range c.Operations {
		if o.Deprecated {
			continue
		}
		c.Total++
		if o.Hits > 0 {
			c.Covered++
		}
	}
	if c.Total > 0 {
		c.Percent = float64(int(float64(c.Covered)*10000/float64(c.Total))) / 100
	}
	return c
}

// matchTemplate matches a request path to a template; the score counts
// literal segments.
func matchTemplate(template, p string) (int, bool) {
	t := strings.Split(strings.Trim(template, "/"), "/")
	s := strings.Split(strings.Trim(p, "/"), "/")
	if len(t) != len(s) {
		return 0, false
	}
	score := 0
	for i := range t {
		if strings.HasPrefix(t[i], "{") && strings.HasSuffix(t[i], "}") {
			if s[i] == "" {
				return 0, false
			}
			continue
		}
		segment, err := url.PathUnescape(s[i])
		if err != nil {
			segment = s[i]
		}
		if t[i] != segment {
			return 0, false
		}
		score++
	}
	return score, true
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// OperationContext returns a JSON excerpt of the spec for the given
// operations: their definitions and the schemas they reference, within
// limit bytes. It is the prompt context for test generation.
func (a API) OperationContext(ops []Operation, limit int) string {
	paths, _ := a.Document["paths"].(map[string]any)
	selected := map[string]any{}
	refs := map[string]bool{}
	for _, o := range ops {
		item, _ := paths[o.Path].(map[string]any)
		op, ok := item[strings.ToLower(o.Method)]
		if !ok {
			continue
		}
		entry := map[string]any{strings.ToLower(o.Method): op}
		if params, ok := item["parameters"]; ok {
			entry["parameters"] = params
		}
		if existing, ok := selected[o.Path].(map[string]any); ok {
			for k, v := range entry {
				existing[k] = v
			}
		} else {
			selected[o.Path] = entry
		}
		collectRefs(entry, refs)
	}
	schemas := map[string]any{}
	pending := make([]string, 0, len(refs))
	for r := range refs {
		pending = append(pending, r)
	}
	for len(pending) > 0 && len(schemas) < 60 {
		ref := pending[0]
		pending = pending[1:]
		if _, done := schemas[ref]; done {
			continue
		}
		target := a.resolve(ref)
		if target == nil {
			continue
		}
		schemas[ref] = target
		more := map[string]bool{}
		collectRefs(target, more)
		for r := range more {
			if _, done := schemas[r]; !done {
				pending = append(pending, r)
			}
		}
	}
	excerpt := map[string]any{"paths": selected}
	if len(a.BasePaths) > 0 {
		excerpt["base_paths"] = a.BasePaths
	}
	if security, ok := a.Document["security"]; ok {
		excerpt["security"] = security
	}
	if len(schemas) > 0 {
		excerpt["referenced"] = schemas
	}
	data, _ := json.MarshalIndent(excerpt, "", " ")
	if len(data) > limit {
		// Without schemas, then cut: the operations matter most.
		delete(excerpt, "referenced")
		data, _ = json.MarshalIndent(excerpt, "", " ")
		if len(data) > limit {
			data = data[:limit]
		}
	}
	return string(data)
}

func collectRefs(v any, refs map[string]bool) {
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			if s, ok := child.(string); ok && k == "$ref" && strings.HasPrefix(s, "#/") {
				refs[s] = true
				continue
			}
			collectRefs(child, refs)
		}
	case []any:
		for _, child := range t {
			collectRefs(child, refs)
		}
	}
}

// resolve follows a local JSON pointer such as #/components/schemas/User.
func (a API) resolve(ref string) any {
	var node any = a.Document
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := node.(map[string]any)
		if !ok {
			return nil
		}
		node = m[part]
	}
	return node
}
