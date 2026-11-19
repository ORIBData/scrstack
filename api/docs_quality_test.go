package api

import (
	"bytes"
	"encoding/json"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"go.yaml.in/yaml/v3"
)

// The contract is what the frontend, the design files and the n8n workflows
// are built from, so a field, parameter or example that nobody explained is a
// defect. These tests keep the explanations complete as the API grows.

type contractDoc struct {
	Tags       []map[string]any          `yaml:"tags"`
	Paths      map[string]map[string]any `yaml:"paths"`
	Components struct {
		Schemas    map[string]any `yaml:"schemas"`
		Parameters map[string]any `yaml:"parameters"`
	} `yaml:"components"`
}

var httpMethods = map[string]bool{"get": true, "post": true, "put": true, "patch": true, "delete": true}

func loadContract(t *testing.T) (contractDoc, map[string]any) {
	t.Helper()
	var doc contractDoc
	if err := yaml.Unmarshal(OpenAPI, &doc); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(OpenAPI, &raw); err != nil {
		t.Fatal(err)
	}
	return doc, raw
}

func str(v any) string { s, _ := v.(string); return s }

// operations lists every operation as "METHOD /path" with its definition.
func operations(doc contractDoc) map[string]map[string]any {
	out := map[string]map[string]any{}
	for path, item := range doc.Paths {
		for method, v := range item {
			if op, ok := v.(map[string]any); ok && httpMethods[method] {
				out[strings.ToUpper(method)+" "+path] = op
			}
		}
	}
	return out
}

// Operations that stand for something the reader looks up elsewhere do not
// need a field-by-field body: provider webhook payloads, STIX and VEX
// documents, archives and CSV files.
var opaqueBodies = map[string]bool{
	"POST /uploads": true, "POST /webhooks/github": true, "POST /ingest/github": true, "POST /ingest/gitlab": true,
	"POST /ingest/github/{connection}": true, "POST /ingest/gitlab/{connection}": true,
	"POST /ingest/registry/{provider}": true, "POST /ingest/registry/{provider}/{connection}": true,
	"POST /intel/indicator-sources/{id}:import-stix": true, "POST /intel/indicator-sources/{id}:import-csv": true,
	"POST /intel/vex-documents": true, "POST /reports/frameworks": true, "POST /reports/frameworks/stig": true,
	"POST /assessments:import": true,
}

func TestOpenAPIEveryOperationIsExplained(t *testing.T) {
	doc, _ := loadContract(t)
	for _, tag := range doc.Tags {
		if len(str(tag["description"])) < 20 {
			t.Errorf("tag %v needs a description of what the module is for", tag["name"])
		}
	}
	for name, op := range operations(doc) {
		summary, description := str(op["summary"]), str(op["description"])
		switch {
		case summary == "" || len(summary) > 80:
			t.Errorf("%s: summary must be set and at most 80 characters (%d)", name, len(summary))
		case strings.HasSuffix(summary, "."):
			t.Errorf("%s: summary is a title and takes no full stop", name)
		case len(description) < 60:
			t.Errorf("%s: description must say what the call does, what comes back and when to use it (%d characters)", name, len(description))
		}
		if strings.Contains(description, "TODO") {
			t.Errorf("%s: description has a TODO", name)
		}
		for i, p := range anyList(op["parameters"]) {
			if m, ok := p.(map[string]any); ok && m["$ref"] == nil && str(m["description"]) == "" {
				t.Errorf("%s: parameter %d (%v) has no description", name, i, m["name"])
			}
		}
		responses, _ := op["responses"].(map[string]any)
		for code, r := range responses {
			if m, ok := r.(map[string]any); ok && m["$ref"] == nil && str(m["description"]) == "" {
				t.Errorf("%s: response %s has no description", name, code)
			}
		}
	}
	for name, p := range doc.Components.Parameters {
		if m, ok := p.(map[string]any); !ok || str(m["description"]) == "" {
			t.Errorf("component parameter %s has no description", name)
		}
	}
}

func anyList(v any) []any { l, _ := v.([]any); return l }

// undocumented reports every named property without a description, in a
// schema and the schemas nested inside it. A property that is only a $ref is
// explained by the schema it points to.
func undocumented(schema any, path string, report func(string)) {
	s, ok := schema.(map[string]any)
	if !ok || s["$ref"] != nil {
		return
	}
	props, _ := s["properties"].(map[string]any)
	for name, p := range props {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if pm["$ref"] == nil && str(pm["description"]) == "" {
			report(path + "." + name)
		}
		undocumented(pm, path+"."+name, report)
	}
	if items, ok := s["items"]; ok {
		undocumented(items, path+"[]", report)
	}
	for _, key := range []string{"allOf", "oneOf", "anyOf"} {
		for i, member := range anyList(s[key]) {
			undocumented(member, path, func(p string) { report(p) })
			_ = i
		}
	}
}

func TestOpenAPIEverySchemaAndFieldIsExplained(t *testing.T) {
	doc, _ := loadContract(t)
	var problems []string
	add := func(p string) { problems = append(problems, p) }
	for name, schema := range doc.Components.Schemas {
		m, ok := schema.(map[string]any)
		if !ok {
			continue
		}
		if str(m["description"]) == "" && m["$ref"] == nil {
			add("schema " + name + " has no description")
		}
		undocumented(m, "schema "+name, add)
	}
	for name, op := range operations(doc) {
		if rb, ok := op["requestBody"].(map[string]any); ok && rb["$ref"] == nil {
			for ct, media := range mediaOf(rb) {
				if opaqueBodies[name] {
					continue
				}
				undocumented(media["schema"], name+" request "+ct, add)
			}
		}
		responses, _ := op["responses"].(map[string]any)
		for code, r := range responses {
			rm, ok := r.(map[string]any)
			if !ok || rm["$ref"] != nil || opaqueBodies[name] {
				continue
			}
			for ct, media := range mediaOf(rm) {
				undocumented(media["schema"], name+" "+code+" "+ct, add)
			}
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

func mediaOf(holder map[string]any) map[string]map[string]any {
	out := map[string]map[string]any{}
	content, _ := holder["content"].(map[string]any)
	for ct, v := range content {
		if m, ok := v.(map[string]any); ok {
			out[ct] = m
		}
	}
	return out
}

func TestOpenAPIJSONRequestBodiesHaveExamples(t *testing.T) {
	doc, _ := loadContract(t)
	for name, op := range operations(doc) {
		rb, ok := op["requestBody"].(map[string]any)
		if !ok || rb["$ref"] != nil || opaqueBodies[name] {
			continue
		}
		media := mediaOf(rb)["application/json"]
		if media == nil {
			continue
		}
		if media["example"] == nil && media["examples"] == nil {
			// An example on the schema it points to also counts.
			if ref := str(mapOf(media["schema"])["$ref"]); ref != "" {
				target := mapOf(doc.Components.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")])
				if target["example"] != nil {
					continue
				}
			}
			t.Errorf("%s: the JSON request body has no example; show a body an integrator can copy", name)
		}
	}
}

func mapOf(v any) map[string]any { m, _ := v.(map[string]any); return m }

// Every example in a request or response is valid against its own schema, so
// a mock generated from the contract never shows a body the API rejects.
func TestOpenAPIMediaExamplesAreValid(t *testing.T) {
	doc, raw := loadContract(t)
	data, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("openapi.json", parsed); err != nil {
		t.Fatal(err)
	}
	escape := func(s string) string {
		return url.PathEscape(strings.NewReplacer("~", "~0", "/", "~1").Replace(s))
	}
	checked := 0
	check := func(where string, pointer string, media map[string]any) {
		var values []any
		if media["example"] != nil {
			values = append(values, media["example"])
		}
		if named, ok := media["examples"].(map[string]any); ok {
			for _, e := range named {
				if v := mapOf(e)["value"]; v != nil {
					values = append(values, v)
				}
			}
		}
		if len(values) == 0 || media["schema"] == nil {
			return
		}
		compiled, err := compiler.Compile("openapi.json#" + pointer)
		if err != nil {
			t.Errorf("%s: %v", where, err)
			return
		}
		for _, v := range values {
			encoded, _ := json.Marshal(v)
			value, err := jsonschema.UnmarshalJSON(bytes.NewReader(encoded))
			if err != nil {
				t.Errorf("%s: %v", where, err)
				continue
			}
			if err := compiled.Validate(value); err != nil {
				t.Errorf("%s: example does not match its schema: %v", where, err)
			}
			checked++
		}
	}
	for name, op := range operations(doc) {
		parts := strings.SplitN(name, " ", 2)
		base := "/paths/" + escape(parts[1]) + "/" + strings.ToLower(parts[0])
		if rb, ok := op["requestBody"].(map[string]any); ok && rb["$ref"] == nil {
			for ct, media := range mediaOf(rb) {
				check(name+" request "+ct, base+"/requestBody/content/"+escape(ct)+"/schema", media)
			}
		}
		responses, _ := op["responses"].(map[string]any)
		for code, r := range responses {
			if rm, ok := r.(map[string]any); ok && rm["$ref"] == nil {
				for ct, media := range mediaOf(rm) {
					check(name+" "+code+" "+ct, base+"/responses/"+code+"/content/"+escape(ct)+"/schema", media)
				}
			}
		}
	}
	if checked < 40 {
		t.Errorf("only %d request and response examples were checked", checked)
	}
}

// A response a designer cannot picture is a response they will guess at. Most
// JSON success responses show an example, either on the response or on the
// schema it points to. The count of those without one may only go down: when
// you add an example, lower this number; when you add an operation, give its
// response one.
const maxJSONResponsesWithoutExample = 2

func TestOpenAPIJSONResponsesHaveExamples(t *testing.T) {
	doc, _ := loadContract(t)
	var missing []string
	for name, op := range operations(doc) {
		responses, _ := op["responses"].(map[string]any)
		for code, r := range responses {
			if !strings.HasPrefix(code, "2") {
				continue
			}
			rm, ok := r.(map[string]any)
			if !ok || rm["$ref"] != nil {
				continue
			}
			media := mediaOf(rm)["application/json"]
			if media == nil || media["example"] != nil || media["examples"] != nil {
				continue
			}
			if ref := str(mapOf(media["schema"])["$ref"]); ref != "" {
				if mapOf(doc.Components.Schemas[strings.TrimPrefix(ref, "#/components/schemas/")])["example"] != nil {
					continue
				}
			}
			missing = append(missing, name+" "+code)
		}
	}
	sort.Strings(missing)
	if len(missing) > maxJSONResponsesWithoutExample {
		t.Errorf("%d JSON responses have no example (allowed %d). Add an example to the response or its schema:\n  %s",
			len(missing), maxJSONResponsesWithoutExample, strings.Join(missing, "\n  "))
	}
}

// A description with an unquoted comma or colon inside a one-line mapping is
// cut at that point and the rest becomes stray keys ("opened and closed in
// window: null"). The page then shows a truncated sentence. Real keywords only.
var schemaKeywords = map[string]bool{
	"type": true, "description": true, "properties": true, "items": true, "required": true, "enum": true, "format": true,
	"example": true, "examples": true, "default": true, "$ref": true, "additionalProperties": true, "allOf": true,
	"oneOf": true, "anyOf": true, "const": true, "minimum": true, "maximum": true, "minLength": true, "maxLength": true,
	"pattern": true, "minItems": true, "maxItems": true, "readOnly": true, "writeOnly": true, "title": true,
	"deprecated": true, "uniqueItems": true, "not": true, "exclusiveMinimum": true, "exclusiveMaximum": true,
	"multipleOf": true, "discriminator": true, "unevaluatedProperties": true, "minProperties": true, "maxProperties": true,
	"patternProperties": true, "propertyNames": true, "contentMediaType": true,
}

func strayKeys(schema any, path string, report func(string)) {
	s, ok := schema.(map[string]any)
	if !ok {
		return
	}
	for k, v := range s {
		if !schemaKeywords[k] && !strings.HasPrefix(k, "x-") {
			report(path + ": unknown key " + k)
			continue
		}
		switch k {
		case "properties", "patternProperties":
			for name, child := range mapOf(v) {
				strayKeys(child, path+"."+name, report)
			}
		case "items", "additionalProperties", "not", "propertyNames", "unevaluatedProperties":
			strayKeys(v, path+"[]", report)
		case "allOf", "oneOf", "anyOf":
			for _, child := range anyList(v) {
				strayKeys(child, path, report)
			}
		}
	}
}

func TestOpenAPIHasNoStrayKeysFromBrokenDescriptions(t *testing.T) {
	doc, _ := loadContract(t)
	var problems []string
	add := func(p string) { problems = append(problems, p) }
	for name, schema := range doc.Components.Schemas {
		strayKeys(schema, "schema "+name, add)
	}
	known := map[string]bool{"description": true, "content": true, "headers": true, "$ref": true, "required": true, "links": true}
	paramKeys := map[string]bool{"name": true, "in": true, "required": true, "description": true, "schema": true, "$ref": true, "example": true, "examples": true, "deprecated": true, "style": true, "explode": true, "allowEmptyValue": true}
	for name, op := range operations(doc) {
		for _, p := range anyList(op["parameters"]) {
			for k := range mapOf(p) {
				if !paramKeys[k] {
					add(name + ": parameter has unknown key " + k)
				}
			}
			strayKeys(mapOf(p)["schema"], name+" parameter", add)
		}
		holders := map[string]any{"requestBody": op["requestBody"]}
		for code, r := range mapOf(op["responses"]) {
			holders["response "+code] = r
		}
		for where, h := range holders {
			for k := range mapOf(h) {
				if !known[k] {
					add(name + " " + where + ": unknown key " + k)
				}
			}
			for ct, media := range mediaOf(mapOf(h)) {
				strayKeys(media["schema"], name+" "+where+" "+ct, add)
			}
		}
	}
	sort.Strings(problems)
	for _, p := range problems {
		t.Error(p)
	}
}

// The contract is published to designers and integrators, so it describes the
// API only. It never links to the source repository or points at files in it.
func TestOpenAPIDoesNotExposeTheRepository(t *testing.T) {
	text := string(OpenAPI)
	for _, forbidden := range []string{"ORIBData", "scrstack", "github.com/ORIB"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("the contract mentions %q; keep repository names and links out of it", forbidden)
		}
	}
	for _, token := range regexp.MustCompile(`[A-Za-z0-9_./-]+\.md\b`).FindAllString(text, -1) {
		t.Errorf("the contract points at the repository file %q; put the detail in the contract instead", token)
	}
	var raw map[string]any
	if err := yaml.Unmarshal(OpenAPI, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw["externalDocs"]; ok {
		t.Error("externalDocs links outside the API; remove it")
	}
	if contact, ok := mapOf(raw["info"])["contact"]; ok {
		t.Errorf("info.contact is set (%v); leave it out", contact)
	}
}
