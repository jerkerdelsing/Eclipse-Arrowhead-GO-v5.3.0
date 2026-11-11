package cloud

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func testApp(t *testing.T, role string) *App {
	t.Helper()
	s, err := OpenStore(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	spec := roleSpecs[role]
	return &App{Config: Config{Role: role, SystemName: spec.SystemName, Domain: role, Port: spec.Port, DataFile: filepath.Join(t.TempDir(), "state.json"), TokenSecret: "test-secret", Management: []string{"LocalCloudManager"}}, Store: s, client: &http.Client{Timeout: time.Second}}
}

func request(t *testing.T, a *App, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var data []byte
	if body != nil {
		var err error
		data, err = json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(data))
	r.Header.Set("Authorization", "Bearer SYSTEM//LocalCloudManager")
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestServiceRegistryRegistrationAndLookup(t *testing.T) {
	a := testApp(t, "serviceregistry")
	w := request(t, a, http.MethodPost, "/serviceregistry/system-discovery/register", map[string]any{"name": "Provider", "version": "1.0.0", "addresses": []string{"provider"}})
	if w.Code != 200 {
		t.Fatalf("register system: %d %s", w.Code, w.Body.String())
	}
	w = request(t, a, http.MethodPost, "/serviceregistry/service-discovery/register", map[string]any{"systemName": "Provider", "serviceDefinitionName": "temperature", "version": "1.0.0", "interfaces": []any{map[string]any{"templateName": "generic_http", "protocol": "HTTP", "policy": "NONE", "properties": map[string]any{"basePath": "/temperature"}}}})
	if w.Code != 200 {
		t.Fatalf("register service: %d %s", w.Code, w.Body.String())
	}
	w = request(t, a, http.MethodPost, "/serviceregistry/service-discovery/lookup", map[string]any{"serviceDefinitionNames": []string{"temperature"}})
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte("Provider|temperature|1.0.0")) {
		t.Fatalf("lookup: %d %s", w.Code, w.Body.String())
	}
}

func TestAuthorizationGrantRoundTrip(t *testing.T) {
	a := testApp(t, "authorization")
	grant := map[string]any{"consumer": "Consumer", "provider": "Provider", "serviceDefinition": "temperature", "operations": []string{"read"}}
	w := request(t, a, http.MethodPost, "/authorization/grant", grant)
	if w.Code != 201 {
		t.Fatalf("grant: %d %s", w.Code, w.Body.String())
	}
	w = request(t, a, http.MethodPost, "/authorization/verify", grant)
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"authorized":true`)) {
		t.Fatalf("verify: %d %s", w.Code, w.Body.String())
	}
}

func TestCertificateGeneration(t *testing.T) {
	cert, err := generateCertificate("TestSystem")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains([]byte(mapString(cert["certificate"])), []byte("BEGIN CERTIFICATE")) {
		t.Fatal("certificate PEM missing")
	}
}

func TestRoleSystemNamesAreUnique(t *testing.T) {
	seen := map[string]string{}
	for role, spec := range roleSpecs {
		if prior, ok := seen[spec.SystemName]; ok {
			t.Fatalf("roles %s and %s share system name %s", prior, role, spec.SystemName)
		}
		seen[spec.SystemName] = role
	}
	if len(seen) != 21 {
		t.Fatalf("got %d roles, want 21", len(seen))
	}
}

func TestLocalCloudManagerDashboard(t *testing.T) {
	a := testApp(t, "localcloudmanager")
	w := request(t, a, http.MethodGet, "/", nil)
	if w.Code != http.StatusOK || !bytes.Contains(w.Body.Bytes(), []byte("LocalCloudManager")) {
		t.Fatalf("dashboard: %d %s", w.Code, w.Body.String())
	}
}
