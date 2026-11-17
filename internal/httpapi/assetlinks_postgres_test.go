package httpapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ORIBData/scrstack/internal/assessments"
	"github.com/ORIBData/scrstack/internal/connections"
	"github.com/google/uuid"
)

// Image-to-source links (CON-012) through the API: who may set them, what
// can be linked, how a repository is named, both directions, and the source
// repository on an image's register entries.
func TestPostgresAssetLinksAPI(t *testing.T) {
	h := newHarness(t)
	put := func(c connections.Connection) {
		t.Helper()
		if _, err := h.store.Put(h.ctx, c, json.RawMessage(`{"token":"t"}`), false); err != nil {
			t.Fatal(err)
		}
	}
	put(connections.Connection{Name: "gh", Provider: "github", Config: json.RawMessage(`{"organization":"org","auth_type":"fine_grained_pat"}`), Scope: connections.Scope{Include: []string{"org/*"}}})
	put(connections.Connection{Name: "gl", Provider: "gitlab", Config: json.RawMessage(`{"group":"org"}`), Scope: connections.Scope{Include: []string{"org/*"}}})
	put(connections.Connection{Name: "hub", Provider: "dockerhub", Config: json.RawMessage(`{"namespace":"library","identifier":"bot"}`), Scope: connections.Scope{Include: []string{"docker.io/library/*"}}})
	// org/api exists on GitHub and GitLab; org/web only on GitHub.
	if _, err := h.store.Discover(h.ctx, "gh", staticInventory{{Type: "github_repo", Locator: "org/api"}, {Type: "github_repo", Locator: "org/web"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Discover(h.ctx, "gl", staticInventory{{Type: "gitlab_repo", Locator: "org/api"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.store.Discover(h.ctx, "hub", staticInventory{{Type: "container_image", Locator: "docker.io/library/api"}, {Type: "container_image", Locator: "docker.io/library/other"}}); err != nil {
		t.Fatal(err)
	}
	id := func(where string, args ...any) uuid.UUID {
		t.Helper()
		var out uuid.UUID
		if err := h.pool.QueryRow(h.ctx, "SELECT a.id FROM "+h.schema+".assets a JOIN "+h.schema+".connections c ON c.id=a.connection_id WHERE "+where, args...).Scan(&out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	image, other := id("a.locator='docker.io/library/api'"), id("a.locator='docker.io/library/other'")
	ghAPI, ghWeb, glAPI := id("c.name='gh' AND a.locator='org/api'"), id("c.name='gh' AND a.locator='org/web'"), id("c.name='gl'")
	read, write := h.issue("viewer", "read"), h.issue("engineer", "write")
	links := func(asset uuid.UUID) []assessments.AssetLink {
		t.Helper()
		var out struct {
			Items []assessments.AssetLink `json:"items"`
		}
		if err := json.Unmarshal(h.expect(h.call("GET", "/assets/"+asset.String()+"/links", read, nil, ""), 200).Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out.Items
	}
	post := func(token string, from uuid.UUID, body string, status int) assessments.AssetLink {
		t.Helper()
		var l assessments.AssetLink
		w := h.expect(h.call("POST", "/assets/"+from.String()+"/links", token, []byte(body), "application/json"), status)
		if status < 300 {
			if err := json.Unmarshal(w.Body.Bytes(), &l); err != nil {
				t.Fatal(err)
			}
		}
		return l
	}

	// Scopes, input and the ends that can be linked.
	if got := links(image); len(got) != 0 {
		t.Fatalf("no links yet: %+v", got)
	}
	post(read, image, `{"kind":"built_from","repository":"org/web"}`, 403)
	post(write, image, `{"kind":"deployed_from","repository":"org/web"}`, 400)
	post(write, image, `{"kind":"built_from"}`, 400)
	post(write, image, `{"kind":"built_from","repository":"org/web","to_asset_id":"`+ghWeb.String()+`"}`, 400)
	post(write, image, `{"kind":"built_from","repository":"org/web","provider":"svn"}`, 400)
	post(write, image, `{"kind":"built_from","repository":"org/web","extra":1}`, 400)
	post(write, image, `{"kind":"built_from","repository":"org/nowhere"}`, 404)
	post(write, uuid.New(), `{"kind":"built_from","repository":"org/web"}`, 404)
	post(write, ghWeb, `{"kind":"built_from","repository":"org/api","provider":"github"}`, 400) // a repository is not an image
	post(write, image, `{"kind":"built_from","to_asset_id":"`+other.String()+`"}`, 400)         // an image is not a source
	post(write, image, `{"kind":"built_from","to_asset_id":"`+image.String()+`"}`, 400)         // not itself
	post(write, image, `{"kind":"built_from","repository":"org/api"}`, 409)                     // on both hosts

	// Linked by repository path (any case) and by id; linking twice changes nothing.
	l := post(write, image, `{"kind":"built_from","repository":"ORG/Web"}`, 201)
	if l.Kind != "built_from" || l.Direction != "out" || l.Asset.ID != ghWeb || l.Asset.Type != "github_repo" || l.Source != "manual" {
		t.Fatalf("link: %+v", l)
	}
	post(write, image, `{"kind":"built_from","to_asset_id":"`+ghWeb.String()+`"}`, 200)
	post(write, image, `{"kind":"built_from","repository":"org/api","provider":"gitlab"}`, 201)
	if got := links(image); len(got) != 2 || got[0].Asset.ID == got[1].Asset.ID {
		t.Fatalf("image links: %+v", got)
	}
	// The repository sees the image it produced.
	back := links(ghWeb)
	if len(back) != 1 || back[0].Direction != "in" || back[0].Asset.ID != image || back[0].Asset.Locator != "docker.io/library/api" {
		t.Fatalf("repository side: %+v", back)
	}
	if got := links(ghAPI); len(got) != 0 {
		t.Fatalf("an unrelated repository: %+v", got)
	}
	h.expect(h.call("GET", "/assets/"+uuid.NewString()+"/links", read, nil, ""), 404)
	h.expect(h.call("GET", "/assets/nope/links", read, nil, ""), 404)

	// An image's register entries name the source repository, a manual link first, then by name.
	asset := image
	var assessment uuid.UUID
	if err := h.pool.QueryRow(h.ctx, "SELECT id FROM "+h.schema+".assessments LIMIT 1").Scan(&assessment); err != nil {
		// No assessment yet: create one for the image directly so a finding can reference it.
		assessment = uuid.New()
		var conn uuid.UUID
		if err := h.pool.QueryRow(h.ctx, "SELECT connection_id FROM "+h.schema+".assets WHERE id=$1", asset).Scan(&conn); err != nil {
			t.Fatal(err)
		}
		if _, err := h.pool.Exec(h.ctx, "INSERT INTO "+h.schema+".assessments(id,asset_id,connection_id,connection_revision,request,requested_by,actor_id) VALUES($1,$2,$3,1,'{}','t',$4)", assessment, asset, conn, uuid.New()); err != nil {
			t.Fatal(err)
		}
	}
	h.finding(asset, assessment, "CVE-2024-1", "high")
	register := h.expect(h.call("GET", "/register?asset_id="+asset.String(), read, nil, ""), 200).Body.String()
	if !strings.Contains(register, `"source_repository":"org/api"`) {
		t.Fatalf("register entry lacks the source repository: %s", register)
	}

	// Removing: write scope, the right pair, and a trace in the audit log.
	h.expect(h.call("DELETE", "/assets/"+image.String()+"/links/"+ghWeb.String(), read, nil, ""), 403)
	h.expect(h.call("DELETE", "/assets/"+image.String()+"/links/"+ghAPI.String(), write, nil, ""), 404)
	h.expect(h.call("DELETE", "/assets/"+image.String()+"/links/nope", write, nil, ""), 404)
	h.expect(h.call("DELETE", "/assets/"+image.String()+"/links/"+ghWeb.String()+"?kind=deployed_from", write, nil, ""), 400)
	h.expect(h.call("DELETE", "/assets/"+image.String()+"/links/"+ghWeb.String(), write, nil, ""), 204)
	h.expect(h.call("DELETE", "/assets/"+image.String()+"/links/"+ghWeb.String(), write, nil, ""), 404)
	if got := links(image); len(got) != 1 || got[0].Asset.ID != glAPI {
		t.Fatalf("after delete: %+v", got)
	}
	audit := h.expect(h.call("GET", "/audit", h.admin, nil, ""), 200).Body.String()
	if !strings.Contains(audit, "asset_link.created") || !strings.Contains(audit, "asset_link.deleted") {
		t.Fatal("links are not audited")
	}
	// A linked asset keeps its links, so it cannot be deleted out from under them.
	h.expect(h.call("DELETE", "/assets/"+glAPI.String(), h.admin, nil, ""), 409)
}
