package api

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Reference renders the contract as Markdown: one table per tag listing every
// operation with the scopes that may call it. docs/API_REFERENCE.md is this
// output, and a test fails when the file and the contract drift apart.
func Reference() ([]byte, error) {
	var contract struct {
		Tags []struct {
			Name        string `yaml:"name"`
			Description string `yaml:"description"`
		} `yaml:"tags"`
		Paths map[string]map[string]yaml.Node `yaml:"paths"`
	}
	if err := yaml.Unmarshal(OpenAPI, &contract); err != nil {
		return nil, err
	}
	type row struct{ method, path, access, summary string }
	byTag := map[string][]row{}
	for path, item := range contract.Paths {
		for method, node := range item {
			if !strings.Contains(" get post put patch delete ", " "+method+" ") {
				continue
			}
			var op struct {
				Tags    []string `yaml:"tags"`
				Summary string   `yaml:"summary"`
			}
			if err := node.Decode(&op); err != nil {
				return nil, err
			}
			var raw struct {
				Security *[]map[string][]string `yaml:"security"`
			}
			_ = node.Decode(&raw)
			access := "token"
			switch {
			case raw.Security == nil:
				return nil, fmt.Errorf("%s %s has no security requirement", strings.ToUpper(method), path)
			case len(*raw.Security) == 0:
				access = "public"
			default:
				scopes, anonymous := []string{}, false
				for _, requirement := range *raw.Security {
					anonymous = anonymous || len(requirement) == 0
					for _, list := range requirement {
						scopes = append(scopes, list...)
					}
				}
				if len(scopes) > 0 {
					access = "`" + strings.Join(scopes, "` or `") + "`"
				}
				if anonymous && len(scopes) > 0 {
					access = "signature or secret, or " + access
				} else if anonymous {
					access = "signature or secret"
				}
			}
			if len(op.Tags) == 0 {
				return nil, fmt.Errorf("%s %s has no tag", strings.ToUpper(method), path)
			}
			byTag[op.Tags[0]] = append(byTag[op.Tags[0]], row{strings.ToUpper(method), path, access, op.Summary})
		}
	}
	var out bytes.Buffer
	out.WriteString("# API reference by module\n\n")
	out.WriteString("<!-- Generated from api/openapi.yaml by `make api-reference`. Do not edit by hand. -->\n\n")
	out.WriteString("Every path is relative to `/scrs/v1`. A token needs **any one** of the scopes in the Access column, and `admin` satisfies every scope. ")
	out.WriteString("The contract (`GET /scrs/v1/docs`) opens with the conventions, the states to show and worked call sequences, and describes every request, response and field; this page is only the index by module. ")
	out.WriteString("See [STACK.md](STACK.md) for how the modules connect, [FRONTEND_GUIDE.md](FRONTEND_GUIDE.md) for the order to call things when building screens and [integrations/N8N.md](integrations/N8N.md) for automation.\n\n")
	for _, tag := range contract.Tags {
		rows := byTag[tag.Name]
		if len(rows) == 0 {
			continue
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].path != rows[j].path {
				return rows[i].path < rows[j].path
			}
			return rows[i].method < rows[j].method
		})
		fmt.Fprintf(&out, "## %s\n\n%s\n\n| Method | Path | Access | What it does |\n| --- | --- | --- | --- |\n", tag.Name, strings.TrimSpace(tag.Description))
		for _, r := range rows {
			fmt.Fprintf(&out, "| %s | `%s` | %s | %s |\n", r.method, r.path, r.access, strings.ReplaceAll(r.summary, "|", "\\|"))
		}
		out.WriteString("\n")
		delete(byTag, tag.Name)
	}
	for name := range byTag {
		return nil, fmt.Errorf("tag %q is used but not declared in the contract's tags", name)
	}
	return out.Bytes(), nil
}
