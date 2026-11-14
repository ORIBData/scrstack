package qa

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func reportArchive(t *testing.T, status JobStatus, files ...File) []byte {
	t.Helper()
	result, _ := json.Marshal(status)
	archive, err := Pack(append([]File{{Path: "result.json", Data: result}}, files...))
	if err != nil {
		t.Fatal(err)
	}
	return archive
}

// The fixtures are real Karate 2.1.4 output: users.feature has a passing
// GET /users/1 scenario and a failing POST /users (expects 200, got 201).
func TestParseKarateEvents(t *testing.T) {
	archive := reportArchive(t, JobStatus{ID: "j", Kind: KindFunctional, State: StateFailed},
		File{Path: "reports/repo/karate-json/karate-events.jsonl", Data: fixture(t, "karate-events.jsonl")},
		File{Path: "reports/repo/junit-xml/users.users.xml", Data: fixture(t, "junit-users.xml")},
		File{Path: "console.log", Data: []byte("karate output")})
	r, err := ParseReport(archive)
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.Scenarios != 2 || r.Summary.Passed != 1 || r.Summary.Failed != 1 || r.Summary.Features != 1 || r.Summary.Karate != "2.1.4" {
		t.Fatalf("summary %+v", r.Summary)
	}
	failed := r.Scenarios[1]
	if failed.Status != "failed" || failed.Name != "create user fails on purpose" || failed.Error != "expected status: 200, actual: 201" || failed.Feature != "users/users.feature" || failed.Suite != "repo" || strings.Join(failed.Tags, ",") != "api,critical" || failed.Line != 11 {
		t.Fatalf("failed scenario %+v", failed)
	}
	want := []Call{{Method: "POST", Host: "localhost:18080", Path: "/users", Status: 201, Count: 1}, {Method: "GET", Host: "localhost:18080", Path: "/users/1", Status: 200, Count: 1}}
	if len(r.Calls) != 2 || r.Calls[0] != want[0] || r.Calls[1] != want[1] {
		t.Fatalf("calls %+v", r.Calls)
	}
}

func TestParseJUnitFallback(t *testing.T) {
	archive := reportArchive(t, JobStatus{Kind: KindFunctional},
		File{Path: "reports/generated/junit-xml/users.users.xml", Data: fixture(t, "junit-users.xml")})
	r, err := ParseReport(archive)
	if err != nil || r.Summary.Scenarios != 2 || r.Summary.Failed != 1 || r.Scenarios[1].Error != "expected status: 200, actual: 201" || r.Scenarios[0].Feature != "users/users.feature" || r.Scenarios[0].Tags[0] != "api" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, err := ParseReport(reportArchive(t, JobStatus{})[:20]); err == nil {
		t.Fatal("truncated archive accepted")
	}
}

func TestParseGatling(t *testing.T) {
	pass := ParseGatling(fixture(t, "gatling-pass.log"))
	if pass.Requests != 858 || pass.OK != 858 || pass.KO != 0 || pass.P95Millis != 15 || pass.P99Millis != 28 || pass.Throughput != 171.6 || pass.MaxMillis != 93 {
		t.Fatalf("pass %+v", pass)
	}
	if len(pass.Assertions) != 2 || !pass.Assertions[0].Passed || pass.Assertions[0].Actual != 15 {
		t.Fatalf("assertions %+v", pass.Assertions)
	}
	fail := ParseGatling(fixture(t, "gatling-fail.log"))
	if fail.Requests != 322 || fail.OK != 0 || fail.KO != 322 || len(fail.Assertions) != 2 || fail.Assertions[0].Passed || fail.Assertions[1].Actual != 100 {
		t.Fatalf("fail %+v", fail)
	}
	grouped := ParseGatling([]byte("---- Global Information ---|---Total---|-----OK----|----KO----\n> request count                       |     12,345 |     12,300 |         45\n> mean throughput (rps)               |   1,028.75 |   1,025.00 |       3.75\n"))
	if grouped.Requests != 12345 || grouped.KO != 45 || grouped.Throughput != 1028.75 {
		t.Fatalf("thousands separators %+v", grouped)
	}
	archive := reportArchive(t, JobStatus{Kind: KindPerformance, State: StateFailed}, File{Path: "console.log", Data: fixture(t, "gatling-fail.log")})
	if r, err := ParseReport(archive); err != nil || r.Perf == nil || r.Perf.KO != 322 {
		t.Fatal("perf report", r, err)
	}
}

const spec = `openapi: 3.0.3
info: {title: Users, version: "1.2"}
servers: [{url: "https://api.example.com/v1"}]
security: [{bearer: []}]
paths:
  /users:
    get: {operationId: listUsers, responses: {"200": {description: ok}}}
    post:
      operationId: createUser
      requestBody: {content: {application/json: {schema: {$ref: "#/components/schemas/NewUser"}}}}
      responses: {"201": {description: created}}
  /users/{id}:
    parameters: [{name: id, in: path, required: true, schema: {type: integer}}]
    get: {operationId: getUser, responses: {"200": {description: ok, content: {application/json: {schema: {$ref: "#/components/schemas/User"}}}}}}
    delete: {operationId: deleteUser, deprecated: true, responses: {"204": {description: gone}}}
  /users/me:
    get: {operationId: me, responses: {"200": {description: ok}}}
components:
  schemas:
    User: {type: object, properties: {id: {type: integer}, name: {type: string}, address: {$ref: "#/components/schemas/Address"}}}
    Address: {type: object, properties: {city: {type: string}}}
    NewUser: {type: object, required: [name], properties: {name: {type: string}}}
    Unused: {type: string}
`

func TestOpenAPICoverage(t *testing.T) {
	api, err := ParseAPI([]byte(spec))
	if err != nil {
		t.Fatal(err)
	}
	if len(api.Operations) != 5 || api.BasePaths[0] != "/v1" || api.Title != "Users" {
		t.Fatalf("%+v", api)
	}
	calls := []Call{
		{Method: "GET", Host: "staging.example.com", Path: "/v1/users/42", Status: 200, Count: 3},
		{Method: "GET", Host: "staging.example.com", Path: "/v1/users/42", Status: 404, Count: 1},
		{Method: "GET", Host: "staging.example.com", Path: "/v1/users/me", Status: 200, Count: 1},
		{Method: "POST", Host: "staging.example.com", Path: "/v1/orders", Status: 201, Count: 1},
		{Method: "GET", Host: "elsewhere.example.com", Path: "/v1/users", Status: 200, Count: 1},
	}
	c := Cover(api.Operations, api.BasePaths, "https://staging.example.com", calls)
	if c.Total != 4 || c.Covered != 2 || c.Percent != 50 {
		t.Fatalf("coverage %+v", c)
	}
	byKey := map[string]OperationCoverage{}
	for _, o := range c.Operations {
		byKey[o.Key()] = o
	}
	if o := byKey["GET /users/{id}"]; o.Hits != 4 || len(o.Statuses) != 2 || o.Statuses[1] != 404 {
		t.Fatalf("templated match %+v", o)
	}
	if byKey["GET /users/me"].Hits != 1 {
		t.Fatal("literal segment must win over a parameter")
	}
	if byKey["GET /users"].Hits != 0 {
		t.Fatal("another host's traffic counted")
	}
	if len(c.Unmatched) != 1 || c.Unmatched[0] != "POST /v1/orders" {
		t.Fatalf("unmatched %v", c.Unmatched)
	}
	// A base URL with a path prefix is stripped too.
	c = Cover(api.Operations, nil, "https://gw.example.com/users-api", []Call{{Method: "GET", Host: "gw.example.com", Path: "/users-api/users", Status: 200, Count: 1}})
	if c.Covered != 1 {
		t.Fatalf("base URL prefix %+v", c)
	}
	var getUser Operation
	for _, o := range api.Operations {
		if o.OperationID == "getUser" {
			getUser = o
		}
	}
	excerpt := api.OperationContext([]Operation{getUser}, 1<<20)
	if !strings.Contains(excerpt, "#/components/schemas/Address") || !strings.Contains(excerpt, `"parameters"`) || strings.Contains(excerpt, "Unused") || !strings.Contains(excerpt, "bearer") {
		t.Fatalf("operation context %s", excerpt)
	}
	if FindSpec([]string{"node_modules/x/openapi.yaml", "api/v2/openapi.json", "api/openapi.yaml", "README.md"}) != "api/openapi.yaml" {
		t.Fatal("FindSpec")
	}
	for _, bad := range []string{"swagger: '1.2'\npaths: {}", "{", "openapi: 3.1.0\npaths: {}"} {
		if _, err := ParseAPI([]byte(bad)); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
	if api, err := ParseAPI([]byte(`{"swagger":"2.0","basePath":"/api","paths":{"/ping":{"get":{}}}}`)); err != nil || api.BasePaths[0] != "/api" {
		t.Fatal("swagger 2", api, err)
	}
}

const goodFeature = `@scrs-generated
Feature: users

  Generated from GET /users/{id}.

Background:
* url baseUrl

@op=getUser
Scenario: get a user
Given path 'users', 1
And header Accept = 'application/json'
When method get
Then status 200
And match response == { id: '#number', name: '#string' }
* def body =
"""
{ "name": "Ada" }
"""

Scenario Outline: missing user <id>
Given path 'users', <id>
When method get
Then status 404
Examples:
| id |
| 0  |
`

func TestCheckFeature(t *testing.T) {
	if problems := CheckFeature("users/get_user.feature", []byte(goodFeature)); len(problems) != 0 {
		t.Fatal(problems)
	}
	for name, body := range map[string]string{
		"exec":        strings.Replace(goodFeature, "* def body =", "* def out = karate.exec('id')\n* def body =", 1),
		"java":        strings.Replace(goodFeature, "* def body =", "* def f = Java.type('java.io.File')\n* def body =", 1),
		"read":        strings.Replace(goodFeature, "* def body =", "* def secrets = read('file:/etc/passwd')\n* def body =", 1),
		"call":        strings.Replace(goodFeature, "When method get\nThen status 200", "* call other\nWhen method get\nThen status 200", 1),
		"absolute":    strings.Replace(goodFeature, "Given path 'users', 1", "Given url 'https://attacker.example'", 1),
		"url var":     strings.Replace(goodFeature, "* url baseUrl", "* url otherUrl", 1),
		"no url":      strings.Replace(goodFeature, "* url baseUrl", "* print 'x'", 1),
		"keyword":     strings.Replace(goodFeature, "When method get\nThen status 200", "* configure proxy = 'x'\nWhen method get\nThen status 200", 1),
		"expression":  strings.Replace(goodFeature, "When method get\nThen status 200", "* while(true){}\nWhen method get\nThen status 200", 1),
		"no scenario": "Feature: x\nBackground:\n* url baseUrl\n",
		"ftp in body": strings.Replace(goodFeature, `"Ada"`, `"ftp://x"`, 1),
	} {
		if len(CheckFeature("x.feature", []byte(body))) == 0 {
			t.Errorf("%s accepted", name)
		}
	}
	for _, p := range []string{"../x.feature", "/abs.feature", "x.txt", "a/b/c/d/e/f.feature"} {
		if len(CheckFeature(p, []byte(goodFeature))) == 0 {
			t.Errorf("path %s accepted", p)
		}
	}
}

func TestParseFiles(t *testing.T) {
	out := ParseFiles("Here you go\n=== FILE: users/a.feature ===\n```gherkin\nFeature: a\n```\n=== END FILE ===\n\n=== FILE: b.feature ===\nFeature: b\n=== END FILE ===")
	if len(out) != 2 || out[0].Path != "users/a.feature" || string(out[0].Data) != "Feature: a\n" || string(out[1].Data) != "Feature: b\n" {
		t.Fatalf("%+v", out)
	}
	if len(ParseFiles("no blocks")) != 0 {
		t.Fatal("phantom files")
	}
}

func TestUnitTargets(t *testing.T) {
	body := bytes.Repeat([]byte("x"), 400)
	snap := Snapshot{Paths: []string{"pkg/math.go", "pkg/math_test.go", "pkg/strings.go", "cmd/main.go", "src/app.ts", "src/app.test.ts", "src/util.ts", "web/node_modules/lib/index.js", "svc/handlers.py", "src/main/java/com/acme/Billing.java", "gen/code.go"},
		Files: map[string][]byte{"pkg/math.go": body, "pkg/strings.go": append(body, body...), "cmd/main.go": body, "src/app.ts": body, "src/util.ts": body, "web/node_modules/lib/index.js": body, "svc/handlers.py": body, "src/main/java/com/acme/Billing.java": body, "gen/code.go": append([]byte("// Code generated by x. DO NOT EDIT.\n"), body...)}}
	targets := UnitTargets(snap, "vitest", 10)
	got := map[string]string{}
	for _, tg := range targets {
		got[tg.Source] = tg.TestPath + " " + tg.Language.Framework
	}
	want := map[string]string{"pkg/strings.go": "pkg/strings_test.go go test", "src/util.ts": "src/util.test.ts vitest", "svc/handlers.py": "tests/test_handlers.py pytest", "src/main/java/com/acme/Billing.java": "src/test/java/com/acme/BillingTest.java JUnit 5"}
	if len(got) != len(want) {
		t.Fatalf("targets %v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q want %q", k, got[k], v)
		}
	}
	if targets[0].Source != "pkg/strings.go" {
		t.Fatal("larger files first", targets[0])
	}
	if JSFramework([]byte(`{"devDependencies":{"vitest":"^3"}}`)) != "vitest" || JSFramework(nil) != "jest" {
		t.Fatal("JSFramework")
	}
}

func TestSpecValidate(t *testing.T) {
	ok := JobSpec{ID: "0b7c1f43-6c55-4bb6-9d3c-2a3f0c1e4d5f", Kind: KindFunctional, BaseURL: "https://staging.example.com", Env: "staging", Threads: 4, TimeoutSeconds: 600, Suites: []Suite{{Dir: "repo", Tags: []string{"@smoke", "~@slow"}}, {Dir: "generated"}}, Variables: map[string]string{"API_TOKEN": "t"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	perf := ok
	perf.Kind, perf.Perf = KindPerformance, &Perf{Features: []string{"perf/load.feature"}, Users: 10, RampSeconds: 5, DurationSeconds: 60, P95Millis: 800, MaxErrorPercent: 1}
	if err := perf.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*JobSpec){
		"id":       func(s *JobSpec) { s.ID = "x" },
		"url":      func(s *JobSpec) { s.BaseURL = "ftp://x" },
		"tag":      func(s *JobSpec) { s.Suites[0].Tags = []string{"smoke; rm"} },
		"variable": func(s *JobSpec) { s.Variables = map[string]string{"path": "x"} },
		"suite":    func(s *JobSpec) { s.Suites = []Suite{{Dir: "../x"}} },
		"dup":      func(s *JobSpec) { s.Suites = []Suite{{Dir: "repo"}, {Dir: "repo"}} },
		"threads":  func(s *JobSpec) { s.Threads = 0 },
		"perf":     func(s *JobSpec) { s.Perf = &Perf{} },
	} {
		s := ok
		s.Suites = append([]Suite{}, ok.Suites...)
		s.Suites[0].Tags = append([]string{}, ok.Suites[0].Tags...)
		mutate(&s)
		if s.Validate() == nil {
			t.Errorf("%s accepted", name)
		}
	}
	bad := perf
	bad.Perf = &Perf{Features: []string{"../../etc/x.feature"}, Users: 1, DurationSeconds: 10, P95Millis: 1}
	if bad.Validate() == nil {
		t.Fatal("escaping perf feature accepted")
	}
}

func TestArchives(t *testing.T) {
	archive, err := Pack([]File{{Path: "repo/a.feature", Data: []byte("Feature: a")}, {Path: "repo/.karate/karate-cli.json", Data: []byte("{}")}})
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := Unpack(bytes.NewReader(archive), dir, 10, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir + "/repo/a.feature"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir + "/repo/.karate"); err == nil {
		t.Fatal(".karate directory must be dropped")
	}
	if _, err := Pack([]File{{Path: "../x"}}); err == nil {
		t.Fatal("unsafe path packed")
	}
	if err := Unpack(bytes.NewReader(archive), t.TempDir(), 1, 1<<20); err == nil {
		t.Fatal("file limit not enforced")
	}
	snapshot, _ := Pack([]File{{Path: "owner-repo-abc/karate/users.feature", Data: []byte("Feature: u")}, {Path: "owner-repo-abc/README.md", Data: []byte("x")}})
	snap, err := ReadSnapshot(snapshot, func(rel string, _ int64) bool { return Under(rel, "karate") }, 10, 1<<20)
	if err != nil || len(snap.Paths) != 2 || string(snap.Files["karate/users.feature"]) != "Feature: u" || snap.Files["README.md"] != nil {
		t.Fatalf("%+v %v", snap, err)
	}
	two, _ := Pack([]File{{Path: "a/x", Data: []byte("1")}, {Path: "b/y", Data: []byte("2")}})
	if _, err := ReadSnapshot(two, nil, 1, 1); err == nil {
		t.Fatal("multiple roots accepted")
	}
}
