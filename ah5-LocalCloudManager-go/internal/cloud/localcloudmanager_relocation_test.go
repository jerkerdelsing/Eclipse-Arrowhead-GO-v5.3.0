// SPDX-License-Identifier: EPL-2.0
package cloud

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/scrypt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func consoleFixture(t *testing.T) *App {
	t.Helper()
	salt := bytes.Repeat([]byte{42}, 16)
	hash, err := scrypt.Key([]byte("test-password"), salt, 16384, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CONSOLE_PASSWORD_HASH", "scrypt:"+base64.StdEncoding.EncodeToString(salt)+":"+base64.StdEncoding.EncodeToString(hash))
	t.Setenv("CONSOLE_ALLOWED_HOSTS", "localhost,127.0.0.1")
	old := managerConsole
	managerConsole = newManagerConsoleAuth()
	t.Cleanup(func() { managerConsole = old })
	return testApp(t, "localcloudmanager")
}
func consoleRequest(a *App, method, path, body, cookie string, confirm bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if cookie != "" {
		r.Header.Set("Cookie", cookie)
	}
	if confirm {
		r.Header.Set("X-Arrowhead-Action", "confirm")
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func consoleLogin(t *testing.T, a *App) string {
	t.Helper()
	w := consoleRequest(a, "POST", "/api/session", `{"password":"test-password"}`, "", false)
	if w.Code != 204 {
		t.Fatalf("login %d %s", w.Code, w.Body.String())
	}
	return w.Result().Cookies()[0].Name + "=" + w.Result().Cookies()[0].Value
}
func TestManagerEmbeddedAssetsSurviveRelocation(t *testing.T) {
	t.Setenv("LOCALCLOUDMANAGER_UI_ROOT", filepath.Join(t.TempDir(), "absent"))
	t.Chdir(t.TempDir())
	for _, path := range []string{"/", "/ui", "/app.js", "/styles.css", "/assets/app.js", "/assets/styles.css"} {
		w := httptest.NewRecorder()
		if !serveManagerAsset(w, path) || w.Code != 200 || w.Body.Len() == 0 {
			t.Fatalf("asset %s %d", path, w.Code)
		}
	}
	if serveManagerAsset(httptest.NewRecorder(), "/../../go.mod") {
		t.Fatal("arbitrary asset path accepted")
	}
}
func TestManagerConsoleSessionAndLogout(t *testing.T) {
	a := consoleFixture(t)
	w := consoleRequest(a, "GET", "/api/overview", "", "", false)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	cookie := consoleLogin(t, a)
	w = consoleRequest(a, "GET", "/api/session", "", cookie, false)
	if !strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatal(w.Body.String())
	}
	w = consoleRequest(a, "DELETE", "/api/session", "", cookie, false)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	w = consoleRequest(a, "GET", "/api/session", "", cookie, false)
	if strings.Contains(w.Body.String(), `"authenticated":true`) {
		t.Fatal("logout failed")
	}
}
func TestManagerConsoleFailsClosedWithoutPassword(t *testing.T) {
	a := consoleFixture(t)
	managerConsole.hash = nil
	if w := consoleRequest(a, "GET", "/api/session", "", "", false); w.Code != 503 {
		t.Fatal(w.Code)
	}
}
func TestManagerRejectsUnknownHostAndNullOrigin(t *testing.T) {
	a := consoleFixture(t)
	for _, origin := range []string{"null", "http://attacker.invalid"} {
		r := httptest.NewRequest("GET", "http://localhost/api/session", nil)
		r.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	r := httptest.NewRequest("GET", "http://attacker.invalid/api/session", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestManagerRequiresMutationConfirmation(t *testing.T) {
	a := consoleFixture(t)
	cookie := consoleLogin(t, a)
	for _, op := range []struct{ method, path string }{{"POST", "/api/orchestration/rules"}, {"DELETE", "/api/orchestration/rules/1"}, {"PUT", "/api/sysmonitor/subscriptions/Provider"}, {"DELETE", "/api/sysmonitor/subscriptions/Provider"}, {"POST", "/api/plantdescriptions"}, {"POST", "/api/containers/serviceregistry/restart"}} {
		w := consoleRequest(a, op.method, op.path, `{}`, cookie, false)
		if w.Code != 428 {
			t.Fatalf("%s %s: %d", op.method, op.path, w.Code)
		}
	}
}
func TestManagerLoginLockout(t *testing.T) {
	consoleFixture(t)
	for i := 0; i < 5; i++ {
		status, _, _ := managerConsole.login("wrong")
		if status != 401 {
			t.Fatal(status)
		}
	}
	status, _, retry := managerConsole.login("test-password")
	if status != 429 || retry <= 0 {
		t.Fatalf("status%d retry%d", status, retry)
	}
}
func TestManagerLifecycleRejectsUnlistedServicesAndActions(t *testing.T) {
	t.Setenv("MANAGED_SERVICES", "serviceregistry")
	for _, pair := range [][2]string{{"database", "stop"}, {"serviceregistry", "delete"}} {
		if _, err := dockerLifecycle(pair[0], pair[1]); err == nil {
			t.Fatal("unsafe action accepted")
		}
	}
}
func TestManagerDockerUsesMockSocketAndProjectFilter(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "lcm-docker-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	socket := filepath.Join(dir, "docker.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_SOCKET", socket)
	t.Setenv("COMPOSE_PROJECT_NAME", "isolated-project")
	t.Setenv("MANAGED_SERVICES", "serviceregistry")
	seen := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Query().Get("filters"), "com.docker.compose.project=isolated-project") {
			t.Error("missing project filter")
		}
		seen <- r.URL.Path
		_ = json.NewEncoder(w).Encode([]map[string]any{{"Id": "1234567890123456", "Names": []string{"/registry"}, "Image": "isolated", "State": "running", "Status": "Up (healthy)", "Labels": map[string]string{"com.docker.compose.project": "isolated-project", "com.docker.compose.service": "serviceregistry"}}})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	rows, err := listDockerContainers()
	if err != nil || len(rows) != 1 || !rows[0].Managed || rows[0].Health != "healthy" || <-seen != "/containers/json" {
		t.Fatalf("rows%v error%v", rows, err)
	}
}
func TestManagerTelemetryDescriptor(t *testing.T) {
	a := testApp(t, "localcloudmanager")
	a.Config.Cloud = "IsolatedCloud"
	descriptor := a.monitoringRegistration()
	if descriptor["serviceDefinitionName"] != "sysMonitor" {
		t.Fatal(descriptor)
	}
	text, _ := json.Marshal(descriptor)
	for _, term := range []string{"IsolatedCloud.sysmonitor.LocalCloudManager.LocalCloudManager", "generic_amqps", "publisher-confirmed"} {
		if !bytes.Contains(text, []byte(term)) {
			t.Fatal(term)
		}
	}
}
func TestManagerLegacyLimitationsRemainExplicit(t *testing.T) {
	a := consoleFixture(t)
	cookie := consoleLogin(t, a)
	w := consoleRequest(a, "PUT", "/api/sysmonitor/subscriptions/Provider", `{"enabled":true}`, cookie, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"updated":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if len(a.Store.Data.Resources) != 0 {
		t.Fatal("legacy acknowledgement unexpectedly changed runtime state")
	}
	if a.managerIntercloud()["producer"].(map[string]any)["status"] != "unavailable" {
		t.Fatal("unexpected intercloud placeholder")
	}
}
