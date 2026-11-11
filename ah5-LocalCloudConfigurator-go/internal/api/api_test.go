package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"

	"arrowhead/ah5-support-go/localcloudconfigurator/internal/catalog"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/colony"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/planner"
)

type fakeBackend struct {
	running   []string
	submitted *planner.Plan
}

func (f *fakeBackend) Status(context.Context, string) ([]string, error) { return f.running, nil }
func (f *fakeBackend) SubmitPlan(p *planner.Plan, _ string) (string, error) {
	f.submitted = p
	return "wf-1", nil
}
func (f *fakeBackend) Deployment(id string) (*colony.Deployment, error) {
	if id != "wf-1" {
		return nil, ErrNotFound
	}
	return &colony.Deployment{ID: id, State: "success"}, nil
}

func server(t *testing.T) (*httptest.Server, *fakeBackend) {
	_, f, _, _ := runtime.Caller(0)
	c, err := catalog.Load(filepath.Join(filepath.Dir(f), "..", "..", "catalogs", "gocloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{running: []string{"timemanager-rust", "translation-manager"}}
	ts := httptest.NewServer((&Server{Catalog: c, Backend: b, Token: "tok"}).Handler())
	t.Cleanup(ts.Close)
	return ts, b
}

func do(t *testing.T, method, url, token string, body any) (*http.Response, map[string]any) {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req, _ := http.NewRequest(method, url, &buf)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var m map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&m)
	return resp, m
}

func TestAuthRequired(t *testing.T) {
	ts, _ := server(t)
	for _, tok := range []string{"", "wrong"} {
		if r, _ := do(t, "GET", ts.URL+"/api/catalog", tok, nil); r.StatusCode != 401 {
			t.Fatalf("token %q: %d", tok, r.StatusCode)
		}
	}
	if r, _ := do(t, "GET", ts.URL+"/", "", nil); r.StatusCode != 200 {
		t.Fatalf("UI: %d", r.StatusCode)
	}
}

func TestStatusShowsAlternates(t *testing.T) {
	ts, _ := server(t)
	r, m := do(t, "GET", ts.URL+"/api/status", "tok", nil)
	if r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	found := false
	for _, s := range m["systems"].([]any) {
		s := s.(map[string]any)
		if s["id"] == "timemanager" {
			found = s["state"] == "alternate" && s["via"] == "timemanager-rust"
		}
	}
	if !found {
		t.Fatalf("timemanager not shown as alternate: %v", m)
	}
}

func TestDeploySubmitsPlan(t *testing.T) {
	ts, b := server(t)
	r, m := do(t, "POST", ts.URL+"/api/deployments", "tok", planner.Request{Systems: []string{"test-translation"}})
	if r.StatusCode != 202 || m["id"] != "wf-1" {
		t.Fatalf("%d %v", r.StatusCode, m)
	}
	if b.submitted == nil || len(b.submitted.Steps) != 1 || b.submitted.Steps[0].Target != "test-translation" {
		t.Fatalf("submitted %+v", b.submitted)
	}
	if r, _ := do(t, "GET", ts.URL+"/api/deployments/wf-1", "tok", nil); r.StatusCode != 200 {
		t.Fatal(r.StatusCode)
	}
	if r, _ := do(t, "GET", ts.URL+"/api/deployments/zz", "tok", nil); r.StatusCode != 404 {
		t.Fatal(r.StatusCode)
	}
}

func TestBadRequests(t *testing.T) {
	ts, _ := server(t)
	if r, _ := do(t, "POST", ts.URL+"/api/plan", "tok", map[string]any{"systems": []string{"nope"}}); r.StatusCode != 422 {
		t.Fatal(r.StatusCode)
	}
	if r, _ := do(t, "POST", ts.URL+"/api/plan", "tok", map[string]any{"cmd": "rm"}); r.StatusCode != 400 {
		t.Fatal(r.StatusCode)
	}
}
