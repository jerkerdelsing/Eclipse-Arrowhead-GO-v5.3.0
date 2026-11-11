// SPDX-License-Identifier: EPL-2.0
package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const testSuffix = "TestCloud.Arrowhead.arrowhead.eu"

type testPKI struct {
	root *x509.Certificate
	key  *rsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TestCA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	root, _ = x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return &testPKI{root, key, pool}
}
func (p *testPKI) cert(t *testing.T, name, typ string) tls.Certificate {
	t.Helper()
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if e != nil {
		t.Fatal(e)
	}
	c := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name + "." + testSuffix, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 46}, Value: typ}}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, c, p.root, &key.PublicKey, p.key)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if e != nil {
		t.Fatal(e)
	}
	pair.Leaf, _ = x509.ParseCertificate(der)
	return pair
}
func (p *testPKI) tls(cert tls.Certificate) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, RootCAs: p.pool, ClientCAs: p.pool, ClientAuth: tls.RequireAndVerifyClientCert}
}
func fixture(t *testing.T, role string) *App {
	t.Helper()
	s, e := OpenStore("")
	if e != nil {
		t.Fatal(e)
	}
	cfg := Config{Role: role, Name: "Authentication", CloudSuffix: testSuffix, IdentityTTL: 3600, TokenTTL: 600, TokenUsage: 1}
	secret := filepath.Join(t.TempDir(), "secret")
	if e = os.WriteFile(secret, []byte(strings.Repeat("x", 32)), 0600); e != nil {
		t.Fatal(e)
	}
	cfg.TokenSecretFile = secret
	a, e := New(cfg, s, nil)
	if e != nil {
		t.Fatal(e)
	}
	return a
}
func seed(t *testing.T, a *App, name string, sysop bool) {
	t.Helper()
	hash, e := bcrypt.GenerateFromPassword([]byte("test-password"), 4)
	if e != nil {
		t.Fatal(e)
	}
	if e = a.Store.Update(func(d database) error {
		bucket(d, "identities")[name] = Document{"systemName": name, "credentialHash": string(hash), "sysop": sysop, "createdBy": "test", "createdAt": now()}
		return nil
	}); e != nil {
		t.Fatal(e)
	}
}
func localRequest(t *testing.T, a *App, method, path, certName, token string, in any) (int, Document) {
	t.Helper()
	var body []byte
	if in != nil {
		body, _ = json.Marshal(in)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: certName + "." + testSuffix, Names: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 46}, Value: "sy"}}}}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert}}}
	if token != "" {
		r.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//"+token)
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	var v Document
	_ = json.Unmarshal(w.Body.Bytes(), &v)
	return w.Code, v
}
func loginLocal(t *testing.T, a *App, name string) string {
	t.Helper()
	status, v := localRequest(t, a, "POST", "/authentication/identity/login", name, "", Document{"systemName": name, "credentials": Document{"password": "test-password"}})
	if status != 200 || str(v, "token") == "" {
		t.Fatalf("login %d %v", status, v)
	}
	return str(v, "token")
}

func TestAuthenticationSessionLifecycle(t *testing.T) {
	a := fixture(t, "authentication")
	seed(t, a, "SystemA", false)
	token := loginLocal(t, a, "SystemA")
	v, _ := a.verifyIdentity(token)
	if !flag(v, "verified") {
		t.Fatal(v)
	}
	next := loginLocal(t, a, "SystemA")
	v, _ = a.verifyIdentity(token)
	if flag(v, "verified") {
		t.Fatal("old session survived login")
	}
	if next == token {
		t.Fatal("token reused")
	}
	status, _ := localRequest(t, a, "POST", "/authentication/identity/logout", "SystemA", "", Document{"systemName": "SystemA", "credentials": Document{"password": "test-password"}})
	if status != 200 {
		t.Fatal(status)
	}
	v, _ = a.verifyIdentity(next)
	if flag(v, "verified") {
		t.Fatal("logout failed")
	}
}
func TestCertificateAndTokenBinding(t *testing.T) {
	a := fixture(t, "authentication")
	seed(t, a, "SystemA", true)
	token := loginLocal(t, a, "SystemA")
	for _, tc := range []struct {
		method, path, name string
		body               any
	}{{"POST", "/authentication/identity/login", "SystemB", Document{"systemName": "SystemA", "credentials": Document{"password": "test-password"}}}, {"GET", "/authentication/identity/verify/" + token, "SystemB", nil}, {"POST", "/authentication/mgmt/identities/query", "SystemB", Document{}}} {
		status, _ := localRequest(t, a, tc.method, tc.path, tc.name, token, tc.body)
		if status != 401 {
			t.Fatalf("%s: %d", tc.path, status)
		}
	}
	r := httptest.NewRequest("GET", "/authentication/monitor/echo", nil)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestAuthenticationExpiredVerify(t *testing.T) {
	a := fixture(t, "authentication")
	seed(t, a, "SystemA", false)
	token := loginLocal(t, a, "SystemA")
	_ = a.Store.Update(func(d database) error {
		d["sessions"][digest(token)]["expirationTime"] = time.Now().Add(-time.Second).Format(time.RFC3339Nano)
		return nil
	})
	v, _ := a.verifyIdentity(token)
	if flag(v, "verified") || v["systemName"] != nil {
		t.Fatal(v)
	}
}
func TestAuthenticationChangePassword(t *testing.T) {
	a := fixture(t, "authentication")
	seed(t, a, "SystemA", false)
	token := loginLocal(t, a, "SystemA")
	status, _ := localRequest(t, a, "POST", "/authentication/identity/change", "SystemA", "", Document{"systemName": "SystemA", "credentials": Document{"password": "test-password"}, "newCredentials": Document{"password": "replacement"}})
	if status != 200 {
		t.Fatal(status)
	}
	v, _ := a.verifyIdentity(token)
	if flag(v, "verified") {
		t.Fatal("session retained")
	}
	status, _ = localRequest(t, a, "POST", "/authentication/identity/login", "SystemA", "", Document{"systemName": "SystemA", "credentials": Document{"password": "test-password"}})
	if status != 401 {
		t.Fatal(status)
	}
}
func TestIdentityManagementAtomicAndRedacted(t *testing.T) {
	a := fixture(t, "authentication")
	seed(t, a, "Sysop", true)
	token := loginLocal(t, a, "Sysop")
	req := Document{"authenticationMethod": "PASSWORD", "identities": []Document{{"systemName": "SystemA", "credentials": Document{"password": "secret-a"}}, {"systemName": "SystemB", "credentials": Document{"password": ""}}}}
	status, _ := localRequest(t, a, "POST", "/authentication/mgmt/identities", "Sysop", token, req)
	if status != 400 {
		t.Fatal(status)
	}
	_ = a.Store.View(func(d database) error {
		if d["identities"]["SystemA"] != nil {
			t.Fatal("partial batch committed")
		}
		return nil
	})
	req["identities"] = []Document{{"systemName": "SystemA", "credentials": Document{"password": "secret-a"}}}
	status, v := localRequest(t, a, "POST", "/authentication/mgmt/identities", "Sysop", token, req)
	if status != 201 {
		t.Fatal(status, v)
	}
	b, _ := json.Marshal(v)
	if bytes.Contains(b, []byte("secret-a")) || bytes.Contains(b, []byte("Hash")) {
		t.Fatal(string(b))
	}
	status, v = localRequest(t, a, "POST", "/authentication/mgmt/identities/query", "Sysop", token, Document{"namePart": "SystemA"})
	if status != 200 || number(v, "count", 0) != 1 {
		t.Fatal(status, v)
	}
}
func TestManagementRequiresPrivilege(t *testing.T) {
	a := fixture(t, "authentication")
	seed(t, a, "SystemA", false)
	token := loginLocal(t, a, "SystemA")
	status, _ := localRequest(t, a, "POST", "/authentication/mgmt/identities/query", "SystemA", token, Document{})
	if status != 403 {
		t.Fatal(status)
	}
}
func TestStorePersistenceAndRollback(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, e := OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = OpenStore(path); e == nil {
		t.Fatal("second owner allowed")
	}
	if e = s.Update(func(d database) error { bucket(d, "test")["one"] = Document{"value": "before"}; return nil }); e != nil {
		t.Fatal(e)
	}
	e = s.Update(func(d database) error { d["test"]["one"]["value"] = "after"; return bad("abort") })
	if e == nil {
		t.Fatal("expected abort")
	}
	_ = s.Close()
	s, e = OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_ = s.View(func(d database) error {
		if str(d["test"]["one"], "value") != "before" {
			t.Fatal("rollback failed")
		}
		return nil
	})
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0600 {
		t.Fatal(st.Mode())
	}
}
func TestStoreDiskFailureDoesNotPublish(t *testing.T) {
	s, _ := OpenStore("")
	s.path = filepath.Join(t.TempDir(), "missing", "state")
	if e := s.Update(func(d database) error { bucket(d, "test")["one"] = Document{}; return nil }); e == nil {
		t.Fatal("write should fail")
	}
	_ = s.View(func(d database) error {
		if len(d["test"]) != 0 {
			t.Fatal("failed write published")
		}
		return nil
	})
}
func TestStoreConcurrentTransactions(t *testing.T) {
	s, _ := OpenStore("")
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.Update(func(d database) error {
				n := number(d["counter"]["one"], "value", 0)
				bucket(d, "counter")["one"] = Document{"value": n + 1}
				return nil
			}); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	_ = s.View(func(d database) error {
		if number(d["counter"]["one"], "value", 0) != 100 {
			t.Fatal(d)
		}
		return nil
	})
}
func TestTokenReferenceRedaction(t *testing.T) {
	a := fixture(t, "consumer-authorization")
	var row Document
	e := a.Store.Update(func(d database) error {
		var e error
		row, e = a.generateToken(d, Document{"tokenVariant": "USAGE_LIMITED_TOKEN_AUTH", "provider": "Provider", "consumer": "Consumer", "targetType": "SERVICE_DEF", "target": "temperature", "usageLimit": float64(1)}, "Consumer")
		return e
	})
	if e != nil {
		t.Fatal(e)
	}
	ref, e := a.tokenReference(str(row, "token"))
	if e != nil {
		t.Fatal(e)
	}
	if str(row, "tokenType") != "USAGE_LIMITED_TOKEN" {
		t.Fatal(row)
	}
	_ = a.Store.View(func(d database) error {
		if d["tokens"][ref]["token"] != nil {
			t.Fatal("raw token persisted")
		}
		return nil
	})
}
func TestJWTAlgorithmsAndClaims(t *testing.T) {
	p := newPKI(t)
	a := fixture(t, "consumer-authorization")
	cert := p.cert(t, "ConsumerAuthorization", "sy")
	a.TLS = p.tls(cert)
	a.Config.Name = "ConsumerAuthorization"
	for _, variant := range []string{"RSA_SHA256_JSON_WEB_TOKEN_AUTH", "RSA_SHA512_JSON_WEB_TOKEN_AUTH"} {
		t.Run(variant, func(t *testing.T) {
			var row Document
			e := a.Store.Update(func(d database) error {
				var e error
				row, e = a.generateToken(d, Document{"tokenVariant": variant, "provider": "Provider", "consumer": "Consumer", "targetType": "SERVICE_DEF", "target": "temperature"}, "Consumer")
				return e
			})
			if e != nil {
				t.Fatal(e)
			}
			parts := strings.Split(str(row, "token"), ".")
			if len(parts) != 3 {
				t.Fatal(row)
			}
			b, _ := base64.RawURLEncoding.DecodeString(parts[1])
			var claims Document
			_ = json.Unmarshal(b, &claims)
			if str(claims, "csn") != "Consumer" || str(claims, "psn") != "Provider" || str(claims, "tan") != "temperature" {
				t.Fatal(claims)
			}
			if e = verifyTestJWT(cert, parts, variant); e != nil {
				t.Fatal(e)
			}
		})
	}
}
func TestKeySealing(t *testing.T) {
	a := fixture(t, "consumer-authorization")
	sealed, e := a.sealKey("Provider", "0123456789012345")
	if e != nil {
		t.Fatal(e)
	}
	raw, e := a.openKey("Provider", sealed)
	if e != nil || raw != "0123456789012345" {
		t.Fatal(e, raw)
	}
	if _, e = a.openKey("Attacker", sealed); e == nil {
		t.Fatal("AAD binding missing")
	}
	if _, e = a.openKey("Provider", sealed[:len(sealed)-4]+"AAAA"); e == nil {
		t.Fatal("tampering accepted")
	}
}
func TestMetadataOperators(t *testing.T) {
	for _, tc := range []struct {
		op          string
		left, right any
		want        bool
	}{{"EQUALS", float64(1), float64(1), true}, {"NOT_EQUALS", "a", "b", true}, {"INCLUDES_IGNORE_CASE", "AbCd", "bc", true}, {"GREATER_THAN", float64(3), float64(2), true}, {"CONTAINS", []any{"a", "b"}, "b", true}, {"IN", "a", []any{"a"}, true}, {"REGEXP", "abc", "a.*", true}, {"REGEXP", "zabc", "abc", false}, {"SIZE_EQUALS", "😀", float64(2), true}} {
		t.Run(tc.op, func(t *testing.T) {
			got, e := metaCompare(tc.left, tc.right, tc.op)
			if e != nil || got != tc.want {
				t.Fatal(got, e)
			}
		})
	}
	v := metadataValue(Document{"a": Document{"b": []any{"x"}}}, "a.b[0]")
	if v != "x" {
		t.Fatal(v)
	}
}
func TestSimpleStoreMatchmaking(t *testing.T) {
	a := fixture(t, "serviceorchestration-simple")
	_ = a.Store.Update(func(d database) error {
		bucket(d, "simpleStore")["a"] = Document{"id": "a", "consumer": "Consumer", "serviceDefinition": "temperature", "serviceInstanceId": "ProviderA|temperature|1.0.0", "priority": float64(1)}
		d["simpleStore"]["b"] = Document{"id": "b", "consumer": "Consumer", "serviceDefinition": "temperature", "serviceInstanceId": "ProviderB|temperature|1.0.0", "priority": float64(2)}
		return nil
	})
	out, e := a.simplePull(Document{"serviceRequirement": Document{"serviceDefinition": "temperature", "preferredProviders": []any{"ProviderB"}}, "orchestrationFlags": Document{"MATCHMAKING": true}}, "Consumer")
	if e != nil {
		t.Fatal(e)
	}
	rows := out["results"].([]Document)
	if len(rows) != 1 || str(rows[0], "providerName") != "ProviderB" {
		t.Fatal(out)
	}
}
func TestPaginationBounds(t *testing.T) {
	for _, p := range []Document{{"page": float64(-1)}, {"size": float64(0)}, {"size": float64(10001)}, {"direction": "garbage"}} {
		if _, e := page([]Document{}, Document{"pagination": p}, "entries"); e == nil {
			t.Fatal(p)
		}
	}
}
func TestNotifyRejectsInsecureAndURLInjection(t *testing.T) {
	for _, n := range []Document{{"protocol": "HTTP"}, {"protocol": "HTTPS", "properties": Document{"address": "evil/path", "port": "443", "method": "POST", "path": "/"}}, {"protocol": "HTTPS", "properties": Document{"address": "127.0.0.1", "port": "443", "method": "GET", "path": "/"}}} {
		if validateNotify(n) == nil {
			t.Fatal(n)
		}
	}
}
func TestRoutesAreDistinctAndAuthenticated(t *testing.T) {
	for _, role := range []string{"authentication", "consumer-authorization", "serviceorchestration-simple", "serviceorchestration-dynamic"} {
		a := fixture(t, role)
		seen := map[string]bool{}
		for _, r := range a.Routes {
			key := r.Method + " " + r.Path
			if seen[key] {
				t.Fatal(key)
			}
			seen[key] = true
			if r.Access == "" {
				t.Fatal("unguarded route")
			}
		}
	}
}
func TestBootstrapHasNoDefaultPassword(t *testing.T) {
	a := fixture(t, "authentication")
	if e := a.Bootstrap(); e != nil {
		t.Fatal(e)
	}
	_ = a.Store.View(func(d database) error {
		if len(d["identities"]) != 0 {
			t.Fatal("default identity created")
		}
		return nil
	})
}
func TestUntrustedAuthorityRejected(t *testing.T) {
	p := newPKI(t)
	wrong := p.cert(t, "Malicious", "sy")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("request reached substituted authority") }))
	srv.TLS = p.tls(wrong)
	srv.StartTLS()
	defer srv.Close()
	cert := p.cert(t, "Consumer", "sy")
	remote := NewRemote(Config{CloudSuffix: testSuffix}, p.tls(cert))
	var out Document
	if e := remote.request(context.Background(), "Authentication", srv.URL, "POST", "/identity/login", "", Document{"password": "must-not-leak"}, &out); e == nil {
		t.Fatal("substitution accepted")
	}
}
func TestUnknownConfigurationRejected(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(p, []byte(`{"disableTLS":true}`), 0600)
	if _, e := LoadConfig(p, "authentication"); e == nil {
		t.Fatal("unknown security option ignored")
	}
}
func TestMalformedBodyRejected(t *testing.T) {
	a := fixture(t, "authentication")
	for _, body := range []string{"null", "[]", "{} {}", "{"} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		if _, e := decode(httptest.NewRecorder(), r); e == nil {
			t.Fatal(body)
		}
	}
	_ = fmt.Sprint(a)
}

func TestOfferedOperationsBothForms(t *testing.T) {
	m := offeredOperations(map[string]any{"read": map[string]any{"method": "GET", "path": "/"}})
	l := offeredOperations([]any{"subscribe", 3})
	if !m["read"] || !l["subscribe"] || len(l) != 1 || len(offeredOperations("x")) != 0 {
		t.Fatal(m, l)
	}
}

func TestTranslatableInterfacesIncludeDataModelMismatch(t *testing.T) {
	requirement := Document{"operations": []any{"get-data"}, "interfaceTemplateNames": []any{"generic_https"}, "interfacePropertyRequirements": []any{map[string]any{"dataModels.get-data.output": map[string]any{"op": "EQUALS", "value": "simpleJson"}}}}
	senml := map[string]any{"templateName": "generic_https", "properties": map[string]any{"dataModels": map[string]any{"get-data": map[string]any{"output": "senml"}}}}
	native := map[string]any{"templateName": "generic_https", "properties": map[string]any{"dataModels": map[string]any{"get-data": map[string]any{"output": "simpleJson"}}}}
	noModel := map[string]any{"templateName": "generic_mqtts", "properties": map[string]any{}}
	got := translatableInterfaces(requirement, Document{"interfaces": []any{senml, native, noModel}})
	if len(got) != 1 || got[0].(map[string]any)["properties"].(map[string]any)["dataModels"].(map[string]any)["get-data"].(map[string]any)["output"] != "senml" {
		t.Fatal("same template with another data model must be translatable; native and model-less interfaces not", got)
	}
}
