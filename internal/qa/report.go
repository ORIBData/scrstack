package qa

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Scenario is one executed Karate scenario.
type Scenario struct {
	Suite          string   `json:"suite"`
	Feature        string   `json:"feature"`
	Name           string   `json:"name"`
	Line           int      `json:"line"`
	Tags           []string `json:"tags"`
	Status         string   `json:"status"`
	DurationMillis int64    `json:"duration_ms"`
	Error          string   `json:"error,omitempty"`
}

// Call is an HTTP exchange seen in the step logs, counted by method, path
// and response status.
type Call struct {
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Status int    `json:"status"`
	Count  int    `json:"count"`
}

// Summary counts a run's scenarios.
type Summary struct {
	Features       int    `json:"features"`
	Scenarios      int    `json:"scenarios"`
	Passed         int    `json:"passed"`
	Failed         int    `json:"failed"`
	Skipped        int    `json:"skipped"`
	DurationMillis int64  `json:"duration_ms"`
	Karate         string `json:"karate_version,omitempty"`
}

// Assertion is one Gatling threshold and whether it held.
type Assertion struct {
	Description string  `json:"description"`
	Passed      bool    `json:"passed"`
	Actual      float64 `json:"actual"`
}

// PerfStats are a load run's global Gatling statistics.
type PerfStats struct {
	Requests   int         `json:"requests"`
	OK         int         `json:"ok"`
	KO         int         `json:"ko"`
	MinMillis  float64     `json:"min_ms"`
	MeanMillis float64     `json:"mean_ms"`
	MaxMillis  float64     `json:"max_ms"`
	P50Millis  float64     `json:"p50_ms"`
	P75Millis  float64     `json:"p75_ms"`
	P95Millis  float64     `json:"p95_ms"`
	P99Millis  float64     `json:"p99_ms"`
	Throughput float64     `json:"throughput_rps"`
	Assertions []Assertion `json:"assertions"`
}

// Report is everything SCRS reads from a runner's report archive.
type Report struct {
	Status    JobStatus  `json:"status"`
	Summary   Summary    `json:"summary"`
	Scenarios []Scenario `json:"scenarios"`
	Calls     []Call     `json:"calls"`
	Perf      *PerfStats `json:"perf,omitempty"`
}

// Report archive limits: scenarios and distinct calls kept per run.
const (
	MaxScenarios = 10000
	maxCalls     = 5000
)

// ParseReport reads a runner report archive.
func ParseReport(archive []byte) (Report, error) {
	var r Report
	junit := map[string][][]byte{}
	events := map[string][]byte{}
	var console []byte
	haveResult := false
	err := Walk(bytes.NewReader(archive), 20000, 512<<20, func(name string, size int64, body io.Reader) error {
		read := func(limit int64) ([]byte, error) {
			if size > limit {
				return nil, errors.New(name + " is too large")
			}
			return io.ReadAll(body)
		}
		suite, rest, _ := strings.Cut(strings.TrimPrefix(name, "reports/"), "/")
		switch {
		case name == "result.json":
			data, err := read(1 << 20)
			if err != nil || json.Unmarshal(data, &r.Status) != nil {
				return errors.New("report result.json is invalid")
			}
			haveResult = true
		case name == "console.log":
			data, err := read(16 << 20)
			if err != nil {
				return err
			}
			console = data
		case strings.HasPrefix(name, "reports/") && rest == "karate-json/karate-events.jsonl":
			data, err := read(256 << 20)
			if err != nil {
				return err
			}
			events[suite] = data
		case strings.HasPrefix(name, "reports/") && strings.HasPrefix(rest, "junit-xml/") && strings.HasSuffix(rest, ".xml"):
			data, err := read(32 << 20)
			if err != nil {
				return err
			}
			junit[suite] = append(junit[suite], data)
		}
		return nil
	})
	if err != nil {
		return r, err
	}
	if !haveResult {
		return r, errors.New("report has no result.json")
	}
	calls := map[Call]int{}
	suites := map[string]bool{}
	for s := range events {
		suites[s] = true
	}
	for s := range junit {
		suites[s] = true
	}
	names := make([]string, 0, len(suites))
	for s := range suites {
		names = append(names, s)
	}
	sort.Strings(names)
	for _, suite := range names {
		var scenarios []Scenario
		var summary Summary
		if data, ok := events[suite]; ok {
			scenarios, summary, err = parseEvents(suite, data, calls)
		} else {
			scenarios, summary, err = parseJUnit(suite, junit[suite])
		}
		if err != nil {
			return r, err
		}
		r.Summary.Features += summary.Features
		r.Summary.DurationMillis += summary.DurationMillis
		if summary.Karate != "" {
			r.Summary.Karate = summary.Karate
		}
		for _, s := range scenarios {
			if len(r.Scenarios) >= MaxScenarios {
				break
			}
			r.Scenarios = append(r.Scenarios, s)
		}
	}
	for _, s := range r.Scenarios {
		r.Summary.Scenarios++
		switch s.Status {
		case "passed":
			r.Summary.Passed++
		case "failed":
			r.Summary.Failed++
		default:
			r.Summary.Skipped++
		}
	}
	for c, n := range calls {
		c.Count = n
		r.Calls = append(r.Calls, c)
	}
	sort.Slice(r.Calls, func(i, j int) bool {
		a, b := r.Calls[i], r.Calls[j]
		if a.Path != b.Path {
			return a.Path < b.Path
		}
		if a.Method != b.Method {
			return a.Method < b.Method
		}
		return a.Status < b.Status
	})
	if r.Status.Kind == KindPerformance {
		perf := ParseGatling(console)
		r.Perf = &perf
	}
	return r, nil
}

// karateEvent is one JSON Lines record of a Karate 2 run.
type karateEvent struct {
	Type string          `json:"type"`
	Data json.RawMessage `json:"data"`
}

func parseEvents(suite string, data []byte, calls map[Call]int) ([]Scenario, Summary, error) {
	var out []Scenario
	var summary Summary
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 64<<20)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var e karateEvent
		if json.Unmarshal(line, &e) != nil {
			return nil, summary, errors.New("Karate event stream is not JSON Lines")
		}
		switch e.Type {
		case "SUITE_ENTER":
			var d struct {
				Version string `json:"version"`
			}
			_ = json.Unmarshal(e.Data, &d)
			summary.Karate = d.Version
		case "SCENARIO_EXIT":
			var d struct {
				Feature     string   `json:"feature"`
				Name        string   `json:"name"`
				Line        int      `json:"line"`
				Tags        []string `json:"tags"`
				Passed      bool     `json:"passed"`
				Skipped     bool     `json:"skipped"`
				Duration    int64    `json:"durationMillis"`
				ErrorReason string   `json:"errorReason"`
				Error       string   `json:"error"`
				CallDepth   int      `json:"callDepth"`
			}
			if json.Unmarshal(e.Data, &d) != nil || d.CallDepth > 0 {
				continue
			}
			s := Scenario{Suite: suite, Feature: d.Feature, Name: clipText(d.Name, 512), Line: d.Line, Tags: normalTags(d.Tags), DurationMillis: d.Duration, Status: "passed"}
			switch {
			case d.Skipped:
				s.Status = "skipped"
			case !d.Passed:
				s.Status = "failed"
				s.Error = clipText(firstOf(d.ErrorReason, d.Error), 2000)
			}
			out = append(out, s)
		case "FEATURE_EXIT":
			summary.Features++
			collectCalls(e.Data, calls)
		case "SUITE_EXIT":
			var d struct {
				Summary struct {
					Duration int64 `json:"durationMillis"`
				} `json:"summary"`
			}
			_ = json.Unmarshal(e.Data, &d)
			summary.DurationMillis = d.Summary.Duration
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, summary, errors.New("Karate event stream unreadable")
	}
	return out, summary, nil
}

// responseLine is Karate's log line for a received response:
// "1 < 200 GET http://host/path (12 ms)".
var (
	responseLine = regexp.MustCompile(`(?m)^\d+ < (\d{3}) ([A-Z]+) (\S+)`)
	ansi         = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

// collectCalls walks a feature result for step logs, including those of
// called features, and counts the HTTP exchanges they record.
func collectCalls(raw json.RawMessage, calls map[Call]int) {
	var node any
	if json.Unmarshal(raw, &node) != nil {
		return
	}
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case map[string]any:
			for k, child := range t {
				if s, ok := child.(string); ok && k == "stepLog" {
					for _, m := range responseLine.FindAllStringSubmatch(ansi.ReplaceAllString(s, ""), -1) {
						status, _ := strconv.Atoi(m[1])
						u, err := url.Parse(m[3])
						if err != nil || u.Host == "" || len(calls) >= maxCalls {
							continue
						}
						p := u.EscapedPath()
						if p == "" {
							p = "/"
						}
						calls[Call{Method: m[2], Host: strings.ToLower(u.Host), Path: p, Status: status}]++
					}
					continue
				}
				walk(child)
			}
		case []any:
			for _, child := range t {
				walk(child)
			}
		}
	}
	walk(node)
}

type junitSuite struct {
	Name  string `xml:"name,attr"`
	Time  string `xml:"time,attr"`
	Cases []struct {
		Class      string `xml:"classname,attr"`
		Name       string `xml:"name,attr"`
		Time       string `xml:"time,attr"`
		Properties []struct {
			Name  string `xml:"name,attr"`
			Value string `xml:"value,attr"`
		} `xml:"properties>property"`
		Failure *struct {
			Message string `xml:"message,attr"`
		} `xml:"failure"`
		Error *struct {
			Message string `xml:"message,attr"`
		} `xml:"error"`
		Skipped *struct{} `xml:"skipped"`
	} `xml:"testcase"`
}

// parseJUnit reads JUnit XML when a run has no event stream.
func parseJUnit(suite string, files [][]byte) ([]Scenario, Summary, error) {
	var out []Scenario
	var summary Summary
	for _, data := range files {
		var s junitSuite
		if xml.Unmarshal(data, &s) != nil {
			return nil, summary, errors.New("JUnit report is not XML")
		}
		summary.Features++
		for _, c := range s.Cases {
			seconds, _ := strconv.ParseFloat(c.Time, 64)
			sc := Scenario{Suite: suite, Feature: strings.ReplaceAll(c.Class, ".", "/") + ".feature", Name: clipText(c.Name, 512), DurationMillis: int64(seconds * 1000), Status: "passed"}
			for _, p := range c.Properties {
				if p.Name == "tags" {
					sc.Tags = normalTags(strings.Split(p.Value, ","))
				}
			}
			switch {
			case c.Failure != nil:
				sc.Status, sc.Error = "failed", clipText(c.Failure.Message, 2000)
			case c.Error != nil:
				sc.Status, sc.Error = "failed", clipText(c.Error.Message, 2000)
			case c.Skipped != nil:
				sc.Status = "skipped"
			}
			out = append(out, sc)
		}
	}
	return out, summary, nil
}

func normalTags(tags []string) []string {
	out := []string{}
	for _, t := range tags {
		if t = strings.TrimPrefix(strings.TrimSpace(t), "@"); t != "" && len(out) < 32 {
			out = append(out, clipText(t, 128))
		}
	}
	return out
}

func clipText(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

var (
	gatlingRow       = regexp.MustCompile(`^> ([a-z0-9 ()]+?)\s+\|\s*([0-9.,]+|-)\s*\|\s*([0-9.,]+|-)\s*\|\s*([0-9.,]+|-)\s*$`)
	gatlingAssertion = regexp.MustCompile(`^(.+?) : (true|false) \(actual : ([0-9.,]+|-)\)\s*$`)
)

// ParseGatling reads the global statistics and assertion results Gatling
// prints at the end of a run; the last statistics block wins.
func ParseGatling(console []byte) PerfStats {
	var p PerfStats
	// Gatling groups thousands: "request count | 12,345 |".
	number := func(s string) float64 {
		v, _ := strconv.ParseFloat(strings.ReplaceAll(s, ",", ""), 64)
		return v
	}
	inGlobal := false
	for _, line := range strings.Split(ansi.ReplaceAllString(string(console), ""), "\n") {
		line = strings.TrimRight(line, "\r ")
		switch {
		case strings.HasPrefix(line, "---- Global Information"):
			inGlobal = true
			p = PerfStats{Assertions: p.Assertions}
			continue
		case strings.HasPrefix(line, "---- "):
			inGlobal = false
		}
		if m := gatlingAssertion.FindStringSubmatch(line); m != nil && !strings.HasPrefix(line, ">") {
			p.Assertions = append(p.Assertions, Assertion{Description: clipText(m[1], 256), Passed: m[2] == "true", Actual: number(m[3])})
			continue
		}
		if !inGlobal {
			continue
		}
		m := gatlingRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		total := number(m[2])
		switch m[1] {
		case "request count":
			p.Requests, p.OK, p.KO = int(total), int(number(m[3])), int(number(m[4]))
		case "min response time (ms)":
			p.MinMillis = total
		case "max response time (ms)":
			p.MaxMillis = total
		case "mean response time (ms)":
			p.MeanMillis = total
		case "response time 50th percentile (ms)":
			p.P50Millis = total
		case "response time 75th percentile (ms)":
			p.P75Millis = total
		case "response time 95th percentile (ms)":
			p.P95Millis = total
		case "response time 99th percentile (ms)":
			p.P99Millis = total
		case "mean throughput (rps)":
			p.Throughput = total
		}
	}
	if p.Assertions == nil {
		p.Assertions = []Assertion{}
	}
	return p
}
