package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

type testEnv struct {
	t   *testing.T
	ts  *httptest.Server
	rg  *Registry
	cfg *Config
}

func newEnv(t *testing.T, over map[string]string) *testEnv {
	t.Helper()
	props := map[string]string{}
	for k, v := range defaultProps {
		props[k] = v
	}
	props["authentication.policy"] = "declared"
	props["service.address.alias"] = "address,addresses,accessAddress,accessAddresses,host,hosts"
	props["service.discovery.interface.policy"] = "extendable"
	for k, v := range over {
		props[k] = v
	}
	cfg, err := NewConfig(props)
	if err != nil {
		t.Fatal(err)
	}
	log := NewLogger(100)
	log.quiet = true
	st, err := NewStore(cfg.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	rg := NewRegistry(cfg, st, log)
	srv := NewServer(cfg, rg, log, NewAuthenticator(cfg, rg, log, nil))
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{t: t, ts: ts, rg: rg, cfg: cfg}
}

func (e *testEnv) do(method, path, who string, body any) (int, map[string]any) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		var b []byte
		if s, ok := body.(string); ok {
			b = []byte(s)
		} else {
			b, _ = json.Marshal(body)
		}
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rdr)
	if who != "" {
		req.Header.Set("Authorization", "Bearer SYSTEM//"+who)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	return resp.StatusCode, out
}

func expect(t *testing.T, got, want int, body map[string]any) {
	t.Helper()
	if got != want {
		t.Fatalf("status = %d, want %d (body %v)", got, want, body)
	}
}

func httpIface(addr string, port int) map[string]any {
	return map[string]any{
		"templateName": "generic_http", "policy": "NONE",
		"properties": map[string]any{
			"accessAddresses": []any{addr}, "accessPort": port, "basePath": "/api",
			"operations": map[string]any{"get": map[string]any{"method": "GET", "path": "/x"}},
		},
	}
}

func TestEchoAndAuth(t *testing.T) {
	e := newEnv(t, nil)
	req, _ := http.NewRequest("GET", e.ts.URL+"/serviceregistry/monitor/echo", nil)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated echo = %d", resp.StatusCode)
	}
	req.Header.Set("Authorization", "Bearer SYSTEM//Foo")
	resp, _ = http.DefaultClient.Do(req)
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(b) != "Got it!" {
		t.Fatalf("echo = %d %q", resp.StatusCode, b)
	}
}

func TestSystemAndServiceLifecycle(t *testing.T) {
	e := newEnv(t, nil)
	s, b := e.do("POST", "/serviceregistry/system-discovery/register", "Prov", map[string]any{
		"version": "1.0.0", "addresses": []string{"10.0.0.5"}, "metadata": map[string]any{"a": 1}})
	expect(t, s, 201, b)
	if b["name"] != "Prov" {
		t.Fatalf("name: %v", b)
	}
	s, b = e.do("POST", "/serviceregistry/system-discovery/register", "Prov", map[string]any{"version": "1.0.0", "addresses": []string{"10.0.0.5"}, "metadata": map[string]any{"a": 1}})
	expect(t, s, 200, b)

	reg := map[string]any{"serviceDefinitionName": "temperature", "version": "1.0.0",
		"metadata":   map[string]any{"unit": "C", "unrestrictedDiscovery": true, "range": map[string]any{"min": 1}},
		"interfaces": []any{httpIface("10.0.0.5", 8080)}}
	s, b = e.do("POST", "/serviceregistry/service-discovery/register", "Prov", reg)
	expect(t, s, 201, b)
	if b["instanceId"] != "Prov|temperature|1.0.0" {
		t.Fatalf("instance id: %v", b["instanceId"])
	}

	// lookup by another system (restricted policy => only unrestricted services)
	s, b = e.do("POST", "/serviceregistry/service-discovery/lookup", "Cons", map[string]any{"serviceDefinitionNames": []string{"temperature"}})
	expect(t, s, 200, b)
	if b["count"].(float64) != 1 {
		t.Fatalf("lookup: %v", b)
	}
	// metadata requirement
	s, b = e.do("POST", "/serviceregistry/service-discovery/lookup", "Cons", map[string]any{
		"serviceDefinitionNames":   []string{"temperature"},
		"metadataRequirementsList": []any{map[string]any{"range": map[string]any{"min": map[string]any{"op": "GREATER_THAN", "value": 5}}}}})
	expect(t, s, 200, b)
	if b["count"].(float64) != 0 {
		t.Fatalf("expected no match: %v", b)
	}

	// service without unrestrictedDiscovery is hidden from ordinary consumers, visible to sysop
	reg2 := map[string]any{"serviceDefinitionName": "hidden", "version": "1.0.0", "interfaces": []any{httpIface("10.0.0.5", 8081)}}
	s, b = e.do("POST", "/serviceregistry/service-discovery/register", "Prov", reg2)
	expect(t, s, 201, b)
	s, b = e.do("POST", "/serviceregistry/service-discovery/lookup", "Cons", map[string]any{"serviceDefinitionNames": []string{"hidden"}})
	expect(t, s, 200, b)
	if b["count"].(float64) != 0 {
		t.Fatalf("hidden visible: %v", b)
	}
	s, b = e.do("POST", "/serviceregistry/service-discovery/lookup", "Sysop", map[string]any{"serviceDefinitionNames": []string{"hidden"}})
	expect(t, s, 200, b)
	if b["count"].(float64) != 1 {
		t.Fatalf("sysop cannot see hidden: %v", b)
	}

	// verbose not allowed
	s, b = e.do("POST", "/serviceregistry/service-discovery/lookup?verbose=true", "Cons", map[string]any{"serviceDefinitionNames": []string{"hidden"}})
	expect(t, s, 403, b)

	// revoking others' services is forbidden
	s, b = e.do("DELETE", "/serviceregistry/service-discovery/revoke/Prov%7Ctemperature%7C1.0.0", "Cons", nil)
	expect(t, s, 403, b)
	s, b = e.do("DELETE", "/serviceregistry/service-discovery/revoke/Prov%7Ctemperature%7C1.0.0", "Prov", nil)
	expect(t, s, 200, b)
	s, b = e.do("DELETE", "/serviceregistry/service-discovery/revoke/Prov%7Ctemperature%7C1.0.0", "Prov", nil)
	expect(t, s, 204, b)

	// revoke system cascades instances
	s, _ = e.do("DELETE", "/serviceregistry/system-discovery/revoke", "Prov", nil)
	expect(t, s, 200, nil)
	s, b = e.do("POST", "/serviceregistry/service-discovery/lookup", "Sysop", map[string]any{"serviceDefinitionNames": []string{"hidden"}})
	expect(t, s, 200, b)
	if b["count"].(float64) != 0 {
		t.Fatalf("cascade failed: %v", b)
	}
}

func TestDeviceDiscoveryAndLocking(t *testing.T) {
	e := newEnv(t, nil)
	s, b := e.do("POST", "/serviceregistry/device-discovery/register", "Dev", map[string]any{"name": "dev1", "addresses": []string{"AA:BB:CC:DD:EE:FF", "10.1.1.1"}})
	expect(t, s, 201, b)
	s, b = e.do("POST", "/serviceregistry/system-discovery/register", "S1", map[string]any{"version": "1.0.0", "deviceName": "dev1"})
	expect(t, s, 201, b)
	s, b = e.do("POST", "/serviceregistry/device-discovery/lookup", "x", map[string]any{"deviceNames": []string{"dev1"}})
	expect(t, s, 200, b)
	if b["count"].(float64) != 1 {
		t.Fatalf("%v", b)
	}
	s, b = e.do("DELETE", "/serviceregistry/device-discovery/revoke/dev1", "Dev", nil)
	expect(t, s, 423, b)
	if b["exceptionType"] != "LOCKED" {
		t.Fatalf("%v", b)
	}
	e.do("DELETE", "/serviceregistry/system-discovery/revoke", "S1", nil)
	s, b = e.do("DELETE", "/serviceregistry/device-discovery/revoke/dev1", "Dev", nil)
	expect(t, s, 200, b)
}

func TestErrorBodies(t *testing.T) {
	e := newEnv(t, nil)
	s, b := e.do("POST", "/serviceregistry/system-discovery/register", "bad name!", map[string]any{"version": "1.0.0"})
	expect(t, s, 400, b)
	if b["exceptionType"] != "INVALID_PARAMETER" || b["origin"] != "POST /serviceregistry/system-discovery/register" || b["errorCode"].(float64) != 400 {
		t.Fatalf("%v", b)
	}
	s, b = e.do("POST", "/serviceregistry/system-discovery/lookup", "x", "{not json")
	expect(t, s, 400, b)
	s, b = e.do("POST", "/serviceregistry/service-discovery/register", "x", "")
	expect(t, s, 400, b)
}

func TestManagementCRUDAndCascades(t *testing.T) {
	e := newEnv(t, nil)
	m := "/serviceregistry/mgmt"
	s, b := e.do("POST", m+"/devices", "Sysop", map[string]any{"devices": []any{map[string]any{"name": "d1", "addresses": []string{"1.2.3.4"}}, map[string]any{"name": "d2", "addresses": []string{"1.2.3.5"}}}})
	expect(t, s, 201, b)
	s, b = e.do("POST", m+"/devices", "Sysop", map[string]any{"devices": []any{map[string]any{"name": "d1"}}})
	if s != 400 {
		t.Fatalf("duplicate device create = %d %v", s, b)
	}
	s, b = e.do("POST", m+"/devices/query", "Sysop", map[string]any{"pagination": map[string]any{"page": 0, "size": 1, "direction": "ASC", "sortField": "name"}})
	expect(t, s, 200, b)
	if len(b["entries"].([]any)) != 1 || b["count"].(float64) != 2 {
		t.Fatalf("%v", b)
	}
	s, b = e.do("POST", m+"/devices/query", "Sysop", map[string]any{"pagination": map[string]any{"size": 1}})
	expect(t, s, 400, b)

	s, b = e.do("POST", m+"/systems", "Sysop", map[string]any{"systems": []any{map[string]any{"name": "SysA", "version": "1.0.0", "addresses": []string{"1.2.3.4"}}}})
	expect(t, s, 201, b)
	s, b = e.do("POST", m+"/service-definitions", "Sysop", map[string]any{"serviceDefinitionNames": []string{"alpha"}})
	expect(t, s, 201, b)
	s, b = e.do("POST", m+"/service-instances", "Sysop", map[string]any{"instances": []any{map[string]any{
		"systemName": "SysA", "serviceDefinitionName": "alpha", "version": "1.0.0", "interfaces": []any{httpIface("1.2.3.4", 80)}}}})
	expect(t, s, 201, b)
	s, b = e.do("POST", m+"/service-instances/query", "Sysop", map[string]any{"serviceDefinitionNames": []string{"alpha"}})
	expect(t, s, 200, b)
	if b["count"].(float64) != 1 {
		t.Fatalf("%v", b)
	}
	// delete definition removes instance
	s, b = e.do("DELETE", m+"/service-definitions?names=alpha", "Sysop", nil)
	expect(t, s, 200, b)
	s, b = e.do("POST", m+"/service-instances/query", "Sysop", map[string]any{"providerNames": []string{"SysA"}})
	expect(t, s, 200, b)
	if b["count"].(float64) != 0 {
		t.Fatalf("%v", b)
	}
	// templates
	s, b = e.do("POST", m+"/interface-templates/query", "Sysop", map[string]any{})
	expect(t, s, 200, b)
	if b["count"].(float64) < 4 {
		t.Fatalf("default templates missing: %v", b)
	}
	s, b = e.do("POST", m+"/interface-templates", "Sysop", map[string]any{"interfaceTemplates": []any{map[string]any{
		"name": "custom_tmpl", "protocol": "coap",
		"propertyRequirements": []any{map[string]any{"name": "port", "mandatory": true, "validator": "PORT"}}}}})
	expect(t, s, 201, b)
	s, b = e.do("DELETE", m+"/interface-templates?names=custom_tmpl", "Sysop", nil)
	expect(t, s, 200, b)
	// remove systems / devices
	s, b = e.do("DELETE", m+"/systems?names=SysA", "Sysop", nil)
	expect(t, s, 200, b)
	s, b = e.do("DELETE", m+"/devices?names=d1,d2", "Sysop", nil)
	expect(t, s, 200, b)
	// config and logs
	s, b = e.do("GET", "/serviceregistry/general/mgmt/get-config?keys=domain.name", "Sysop", nil)
	expect(t, s, 200, b)
	if b["map"].(map[string]any)["domain.name"] == nil {
		t.Fatalf("%v", b)
	}
	s, b = e.do("POST", "/serviceregistry/general/mgmt/logs", "Sysop", map[string]any{})
	expect(t, s, 200, b)
}

func TestManagementFilter(t *testing.T) {
	e := newEnv(t, map[string]string{"enable.management.filter": "true", "management.policy": "whitelist", "management.whitelist": "Friend"})
	m := "/serviceregistry/mgmt/devices/query"
	s, b := e.do("POST", m, "Stranger", map[string]any{})
	expect(t, s, 403, b)
	s, b = e.do("POST", m, "Friend", map[string]any{})
	expect(t, s, 200, b)
	s, b = e.do("POST", m, "Sysop", map[string]any{})
	expect(t, s, 200, b)
}

func TestSelfRegistrationAndPersistence(t *testing.T) {
	file := filepath.Join(t.TempDir(), "data.json")
	e := newEnv(t, map[string]string{"data.file": file, "server.port": "8443"})
	if err := e.rg.SelfRegister(); err != nil {
		t.Fatal(err)
	}
	s, b := e.do("POST", "/serviceregistry/service-discovery/lookup", "Anyone", map[string]any{"providerNames": []string{"ServiceRegistry"}})
	expect(t, s, 200, b)
	if b["count"].(float64) != 3 { // only the unrestricted discovery services are visible
		t.Fatalf("restricted lookup count = %v", b["count"])
	}
	s, b = e.do("POST", "/serviceregistry/service-discovery/lookup", "Sysop", map[string]any{"providerNames": []string{"ServiceRegistry"}})
	if b["count"].(float64) != 5 {
		t.Fatalf("sysop lookup count = %v", b["count"])
	}
	e.rg.SelfRevoke()
	s, b = e.do("POST", "/serviceregistry/service-discovery/lookup", "Sysop", map[string]any{"providerNames": []string{"ServiceRegistry"}})
	if b["count"].(float64) != 0 {
		t.Fatalf("revoke failed: %v", b)
	}
	// reload from disk
	e.rg.SelfRegister()
	st2, err := NewStore(file)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	st2.View(func(st *state) { n = len(st.Instances) })
	if n != 5 {
		t.Fatalf("persisted instances = %d", n)
	}
}

func TestMetadataOperators(t *testing.T) {
	md := map[string]any{"a": map[string]any{"b": int64(5)}, "list": []any{"x", "y"}, "s": "Hello"}
	cases := []struct {
		req  string
		want bool
	}{
		{`{"a":{"b":5}}`, true},
		{`{"a.b":{"op":"GREATER_THAN","value":3}}`, true},
		{`{"a.b":{"op":"LESS_THAN","value":3}}`, false},
		{`{"list":{"op":"CONTAINS","value":"x"}}`, true},
		{`{"list[1]":"y"}`, true},
		{`{"s":{"op":"STARTS_WITH","value":"He"}}`, true},
		{`{"missing":"x"}`, false},
	}
	for _, c := range cases {
		var m Meta
		if err := json.Unmarshal([]byte(c.req), &m); err != nil {
			t.Fatal(err)
		}
		got, _ := isMetadataMatch(md, m)
		if got != c.want {
			t.Errorf("%s: got %v want %v", c.req, got, c.want)
		}
	}
	_ = strings.ToLower
}

func TestAuthenticatorKey(t *testing.T) {
	e := newEnv(t, map[string]string{"authentication.policy": "outsourced", "authenticator.secret.keys": "{'Foo': 'secret'}"})
	m := hmacHex("secret", "Foo")
	req, _ := http.NewRequest("GET", e.ts.URL+"/serviceregistry/monitor/echo", nil)
	req.Header.Set("Authorization", "Bearer AUTHENTICATOR-KEY//Foo//"+m)
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 200 {
		t.Fatalf("valid key rejected: %d", resp.StatusCode)
	}
	req.Header.Set("Authorization", "Bearer AUTHENTICATOR-KEY//Foo//deadbeef")
	resp, _ = http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("bad key accepted: %d", resp.StatusCode)
	}
}

func TestIdentityBootstrapLookupIsNotAuthorizationFiltered(t *testing.T) {
	e := newEnv(t, map[string]string{
		"service.discovery.policy": "restricted",
	})
	status, body := e.do(http.MethodPost, "/serviceregistry/system-discovery/register", "Authentication",
		map[string]any{"version": "1.0.0", "addresses": []string{"authentication"}, "metadata": map[string]any{}})
	expect(t, status, http.StatusCreated, body)
	status, body = e.do(http.MethodPost, "/serviceregistry/service-discovery/register", "Authentication",
		map[string]any{"serviceDefinitionName": identitySvcDef, "version": "1.0.0", "metadata": map[string]any{},
			"interfaces": []any{httpIface("authentication", 8444)}})
	expect(t, status, http.StatusCreated, body)
	e.cfg.AuthenticationPolicy = "outsourced"
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/serviceregistry/service-discovery/lookup",
		strings.NewReader(`{"serviceDefinitionNames":["identity"]}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil { t.Fatal(err) }
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK { t.Fatalf("bootstrap lookup returned %d", resp.StatusCode) }
	var result struct { Count int `json:"count"` }
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil { t.Fatal(err) }
	if result.Count != 1 { t.Fatalf("bootstrap lookup was filtered: %#v", result) }
}

func hmacHex(secret, msg string) string {
	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte(msg))
	return hex.EncodeToString(m.Sum(nil))
}
