// SPDX-License-Identifier: EPL-2.0
package core

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const suffix = "GoCloud.Company.arrowhead.eu"

type testPKI struct {
	root *x509.Certificate
	key  *rsa.PrivateKey
	pool *x509.CertPool
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: suffix}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(366 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	c, _ = x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &testPKI{c, key, pool}
}
func (p *testPKI) cert(t *testing.T, name, profile string) tls.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	c := &x509.Certificate{SerialNumber: n, Subject: pkix.Name{CommonName: name + "." + suffix, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 46}, Value: profile}}}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
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
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientCAs: p.pool, RootCAs: p.pool, ClientAuth: tls.RequireAndVerifyClientCert}
}

type fixture struct {
	p    *testPKI
	app  *App
	auth *httptest.Server
	dir  string
}

func newFixture(t *testing.T, role string) *fixture {
	t.Helper()
	p := newPKI(t)
	dir := t.TempDir()
	password := filepath.Join(dir, "password")
	if e := os.WriteFile(password, []byte("test-password"), 0600); e != nil {
		t.Fatal(e)
	}
	auth := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			var v Document
			_ = json.NewDecoder(r.Body).Decode(&v)
			respond(w, 200, Document{"token": "identity-" + str(v, "systemName"), "expirationTime": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)})
			return
		}
		token := strings.TrimPrefix(r.URL.Path, "/authentication/identity/verify/")
		name := strings.TrimPrefix(token, "identity-")
		respond(w, 200, Document{"verified": strings.HasPrefix(token, "identity-"), "systemName": name, "sysop": name == "Sysop"})
	}))
	auth.TLS = p.tls(p.cert(t, "Authentication", "sy"))
	auth.StartTLS()
	t.Cleanup(auth.Close)
	s, e := OpenStore("")
	if e != nil {
		t.Fatal(e)
	}
	cfg := Config{Role: role, Name: role, CloudSuffix: suffix, AuthenticationURL: auth.URL, PasswordFile: password, AuthorizationPolicy: "identity-only", TimeZone: "UTC", DefaultSubscription: "none", RetentionDays: 30}
	app, e := New(cfg, s, p.tls(p.cert(t, role, "sy")))
	if e != nil {
		t.Fatal(e)
	}
	return &fixture{p, app, auth, dir}
}
func (f *fixture) request(t *testing.T, method, path, name string, in any) (int, any) {
	t.Helper()
	var b []byte
	if in != nil {
		b, _ = json.Marshal(in)
	}
	r := httptest.NewRequest(method, path, bytes.NewReader(b))
	cert := f.p.cert(t, name, "sy").Leaf
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, f.p.root}}}
	r.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//identity-"+name)
	w := httptest.NewRecorder()
	f.app.ServeHTTP(w, r)
	var out any
	_ = json.Unmarshal(w.Body.Bytes(), &out)
	if out == nil {
		out = w.Body.String()
	}
	return w.Code, out
}
func objectResult(t *testing.T, status, want int, v any) Document {
	t.Helper()
	if status != want {
		t.Fatalf("status %d, want %d: %v", status, want, v)
	}
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("not a JSON object: %v", v)
	}
	return m
}
func TestAllSystemsConstructWithDistinctGuardedRoutes(t *testing.T) {
	if len(Systems) != 16 {
		t.Fatal(len(Systems))
	}
	for name := range Systems {
		s, _ := OpenStore("")
		a, e := New(Config{Role: name, Name: name}, s, nil)
		if e != nil {
			t.Fatal(name, e)
		}
		seen := map[string]bool{}
		for _, r := range a.Routes {
			key := r.Method + " " + r.Path
			if seen[key] || r.Access == "" {
				t.Fatal(name, r)
			}
			seen[key] = true
		}
		if len(a.Services()) < 1 {
			t.Fatal(name)
		}
	}
}
func TestBlacklistLifecycle(t *testing.T) {
	f := newFixture(t, "Blacklist")
	s, v := f.request(t, "POST", "/blacklist/mgmt/create", "Sysop", Document{"entities": []Document{{"systemName": "DeviceA", "reason": "audit", "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)}}})
	objectResult(t, s, 201, v)
	s, v = f.request(t, "GET", "/blacklist/check/DeviceA", "Consumer", nil)
	if s != 200 || v != true {
		t.Fatal(s, v)
	}
	s, _ = f.request(t, "DELETE", "/blacklist/mgmt/remove?names=DeviceA", "Sysop", nil)
	if s != 200 {
		t.Fatal(s)
	}
	s, v = f.request(t, "GET", "/blacklist/check/DeviceA", "Consumer", nil)
	if s != 200 || v != false {
		t.Fatal(s, v)
	}
}
func TestConfigurationRoundTripAndIsolation(t *testing.T) {
	f := newFixture(t, "Configuration")
	req := Document{"systemName": "Consumer", "fileName": "app.json", "contentType": "application/json", "data": base64.StdEncoding.EncodeToString([]byte(`{"x":1}`))}
	s, v := f.request(t, "PUT", "/configuration/mgmt/config/Consumer", "Sysop", req)
	objectResult(t, s, 200, v)
	s, v = f.request(t, "GET", "/configuration/config/Consumer", "Consumer", nil)
	objectResult(t, s, 200, v)
	s, _ = f.request(t, "GET", "/configuration/config/Consumer", "Other", nil)
	if s != 403 {
		t.Fatal(s)
	}
	s, v = f.request(t, "GET", "/configuration/config/raw/Consumer", "Consumer", nil)
	if s != 200 {
		t.Fatal(s, v)
	}
	req["fileName"] = "../unsafe"
	s, _ = f.request(t, "PUT", "/configuration/mgmt/config/Consumer", "Sysop", req)
	if s != 400 {
		t.Fatal(s)
	}
}
func TestSenMLHistorian(t *testing.T) {
	f := newFixture(t, "DataManager")
	pack := []Document{{"bn": "sensor/", "bt": float64(time.Now().Unix()), "n": "temperature", "v": 20.0, "u": "Cel"}}
	path := "/datamanager/data-historian/systems/Producer/services/temperature/data"
	s, v := f.request(t, "PUT", path, "Producer", pack)
	if s != 200 {
		t.Fatal(s, v)
	}
	s, v = f.request(t, "GET", path+"?count=1", "Consumer", nil)
	if s != 200 || len(v.([]any)) != 1 {
		t.Fatal(s, v)
	}
	s, _ = f.request(t, "PUT", path, "Attacker", pack)
	if s != 403 {
		t.Fatal(s)
	}
}
func TestAIGymMatchesNearestNeighbourBehavior(t *testing.T) {
	f := newFixture(t, "AIGym")
	for _, x := range []float64{1, 5} {
		s, v := f.request(t, "POST", "/aigym/samples", "Trainer", Document{"model": "model", "features": Document{"x": x}, "target": x * 2})
		objectResult(t, s, 201, v)
	}
	s, v := f.request(t, "POST", "/aigym/predict", "Consumer", Document{"model": "model", "features": Document{"x": 4.9}, "neighbours": 1})
	out := objectResult(t, s, 200, v)
	if out["value"] != float64(10) {
		t.Fatal(out)
	}
}
func TestTimeContractAndUnconfiguredTrust(t *testing.T) {
	f := newFixture(t, "TimeManager")
	s, v := f.request(t, "GET", "/timemanager/time", "Consumer", nil)
	out := objectResult(t, s, 200, v)
	for _, key := range []string{"epoch", "epochMs", "tz", "dst", "trusted", "offsetMs", "timeSource", "lastCheckTime"} {
		if _, ok := out[key]; !ok {
			t.Fatal(key)
		}
	}
	if flag(out, "trusted") {
		t.Fatal("unverified clock reported trusted")
	}
}
func TestPlantGraphValidationAndActivation(t *testing.T) {
	f := newFixture(t, "PlantDescriptionEngine")
	req := Document{"plantDescription": "Plant A", "active": true, "include": []any{}, "systems": []Document{{"systemId": "a", "systemName": "DeviceA", "ports": []any{}}}, "connections": []any{}}
	s, v := f.request(t, "POST", "/plantdescriptionengine/mgmt/plant-descriptions", "Sysop", req)
	row := objectResult(t, s, 201, v)
	id := fmt.Sprint(row["id"])
	s, _ = f.request(t, "PATCH", "/plantdescriptionengine/mgmt/plant-descriptions/"+id, "Sysop", Document{"include": []any{row["id"]}})
	if s != 400 {
		t.Fatal(s)
	}
	s, v = f.request(t, "GET", "/plantdescriptionengine/mgmt/plant-descriptions/"+id, "Sysop", nil)
	row = objectResult(t, s, 200, v)
	if len(list(row, "include")) != 0 {
		t.Fatal("failed graph mutation committed")
	}
}
func TestPlanValidationRejectsCycle(t *testing.T) {
	plan := Document{"name": "Plan", "firstActionName": "Action", "actions": []any{Document{"name": "Action", "firstStepNames": []any{"one"}, "steps": []any{Document{"name": "one", "serviceRequirement": Document{"serviceDefinition": "work"}, "nextStepNames": []any{"one"}}}}}}
	if e := validatePlan(plan); e == nil {
		t.Fatal("step cycle accepted")
	}
}
func TestChoreographerPlanSessionFlow(t *testing.T) {
	f := newFixture(t, "Choreographer")
	plan := Document{"name": "Plan", "firstActionName": "Action", "actions": []Document{{"name": "Action", "firstStepNames": []string{"one"}, "steps": []Document{{"name": "one", "serviceRequirement": Document{"serviceDefinition": "work"}, "quantity": 1, "nextStepNames": []any{}}}}}}
	s, v := f.request(t, "POST", "/choreographer/mgmt/plans", "Sysop", plan)
	objectResult(t, s, 201, v)
	s, v = f.request(t, "POST", "/choreographer/session/start", "Consumer", Document{"sessions": []Document{{"planName": "Plan", "quantity": 1}}})
	objectResult(t, s, 200, v)
	f.app.dispatchChoreography(context.Background())
	rows := f.app.rows("sessions")
	if len(rows) != 1 || str(rows[0], "status") != "ERROR" {
		t.Fatal("missing executor must not succeed", rows)
	}
}
func TestQoSAbsentMeasurementsFailClosed(t *testing.T) {
	f := newFixture(t, "DeviceQoSEvaluator")
	s, v := f.request(t, "POST", "/deviceqosevaluator/qualityevaluation/filter", "Consumer", Document{"providers": []string{"DeviceA"}, "configuration": Document{"metricNames": []string{"cpu"}, "metricWeights": []float64{1}, "threshold": 50, "timeWindow": 60}})
	out := objectResult(t, s, 200, v)
	if len(list(out, "passedProviders")) != 0 || len(list(out, "droppedProviders")) != 1 {
		t.Fatal(out)
	}
}
func TestTranslationDoesNotFabricateSuccess(t *testing.T) {
	f := newFixture(t, "TranslationManager")
	s, _ := f.request(t, "POST", "/translation/bridge/discovery", "Consumer", Document{"candidates": []any{}, "operation": "get", "interfaceTemplateNames": []string{"generic_https"}})
	if s != 400 {
		t.Fatal("empty candidate list accepted", s)
	}
	// a candidate whose data model differs, but no registry/translator: no bridge, never a fabricated success
	candidate := Document{"instanceId": "P|svc|1.0.0", "provider": Document{"name": "P"}, "serviceDefinition": Document{"name": "svc"}, "interfaces": []Document{{"templateName": "generic_https", "policy": "CERT_AUTH", "properties": Document{"dataModels": Document{"get": Document{"output": "senml"}}}}}}
	s, v := f.request(t, "POST", "/translation/bridge/discovery", "Consumer", Document{"candidates": []any{candidate}, "operation": "get", "interfaceTemplateNames": []string{"generic_https"}, "outputDataModelId": "simpleJson"})
	if s == 200 && (v.(map[string]any)["bridgeId"] != nil || len(list(v.(map[string]any), "candidates")) != 0) {
		t.Fatal("bridge fabricated", v)
	}
}
func TestMonitorSubscriptionConflictAndAtomicIntake(t *testing.T) {
	f := newFixture(t, "SysMonitor")
	s, v := f.request(t, "PUT", "/sysmonitor/management/subscriptions/DeviceA", "Sysop", Document{"observationTypes": []string{"echo"}, "enabled": true})
	objectResult(t, s, 200, v)
	_ = f.app.Store.Update(func(d database) error {
		bucket(d, "monitorProviders")["DeviceA"] = Document{"providerSystem": "DeviceA", "baseRoutingKey": "GoCloud.sysmonitor.DeviceA.DeviceA"}
		return nil
	})
	raw := Document{"sourceTime": now(), "value": Document{"status": "alive"}}
	if e := f.app.ingestObservation("GoCloud.sysmonitor.DeviceA.DeviceA.echo", raw); e != nil {
		t.Fatal(e)
	}
	if e := f.app.ingestObservation("GoCloud.sysmonitor.DeviceA.DeviceA.echo", raw); e != nil {
		t.Fatal(e)
	}
	if len(f.app.rows("observations")) != 1 || len(f.app.rows("outbox")) != 1 {
		t.Fatal("deduplication/outbox atomicity")
	}
	for _, invalid := range []Document{{"value": Document{"status": "alive"}}, {"sourceTime": now()}, {"sourceTime": now(), "value": Document{"status": "invented"}}, {"sourceTime": now(), "value": Document{"status": "alive"}, "schemaVersion": "2.0"}, {"sourceTime": now(), "value": Document{"status": "alive"}, "serviceInstance": "Other"}} {
		if e := f.app.ingestObservation("GoCloud.sysmonitor.DeviceA.DeviceA.echo", invalid); e == nil {
			t.Fatal("Invalid observation accepted", invalid)
		}
	}
	if e := f.app.ingestObservation("GoCloud.sysmonitor.Other.Other.echo", Document{"sourceTime": now(), "value": Document{}}); e == nil {
		t.Fatal("unauthorized provider accepted")
	}
}

func TestCRLRejectsRevokedExpiredAndWrongIssuer(t *testing.T) {
	p := newPKI(t)
	leaf := p.cert(t, "Consumer", "sy").Leaf
	path := filepath.Join(t.TempDir(), "revocations.pem")
	writeCRL := func(expired bool, revoked bool) {
		t.Helper()
		until := time.Now().Add(time.Hour)
		if expired {
			until = time.Now().Add(-time.Minute)
		}
		r := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Hour), NextUpdate: until}
		if revoked {
			r.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)}}
		}
		der, e := x509.CreateRevocationList(rand.Reader, r, p.root, p.key)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0600); e != nil {
			t.Fatal(e)
		}
	}
	s := tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{leaf, p.root}}}
	writeCRL(false, false)
	if e := checkPeerRevocation(path, s); e != nil {
		t.Fatal(e)
	}
	writeCRL(false, true)
	if e := checkPeerRevocation(path, s); e == nil {
		t.Fatal("Revoked certificate accepted")
	}
	writeCRL(true, false)
	if e := checkPeerRevocation(path, s); e == nil {
		t.Fatal("Stale CRL accepted")
	}
	other := newPKI(t)
	writeCRL(false, false)
	s.VerifiedChains[0][1] = other.root
	if e := checkPeerRevocation(path, s); e == nil {
		t.Fatal("Wrong issuer accepted")
	}
}

func TestRegistrationContractsHaveResolvablePaths(t *testing.T) {
	for role := range Systems {
		s, _ := OpenStore("")
		a, e := New(Config{Role: role, Name: role}, s, nil)
		if e != nil {
			t.Fatal(e)
		}
		routes := map[string]bool{}
		for _, r := range a.Routes {
			routes[r.Method+" "+r.Path] = true
		}
		for _, svc := range a.Services() {
			expectedBase := a.base()
			if svc.Definition == "plantDescriptionManagement" {
				expectedBase += "/mgmt"
			}
			if svc.BasePath != expectedBase {
				t.Fatal(role, svc)
			}
			for op, r := range svc.Operations {
				if op == "query-echo" || strings.Contains(op, "_") {
					t.Fatal(role, op)
				}
				resolvable := routes[str(r, "method")+" "+svc.BasePath+str(r, "path")]
				for route := range routes { // path parameters appended to the registered path (TestTranslation)
					if strings.HasPrefix(route, str(r, "method")+" "+svc.BasePath+str(r, "path")+"/{") {
						resolvable = true
					}
				}
				if !resolvable {
					t.Fatal(role, svc.Definition, op, "Unresolvable path")
				}
			}
		}
	}
}

func TestServiceAuthorizationFailsClosed(t *testing.T) {
	f := newFixture(t, "TimeManager")
	f.app.Config.AuthorizationPolicy = "enforce"
	status, _ := f.request(t, "GET", "/timemanager/time", "Consumer", nil)
	if status == 200 {
		t.Fatal("Missing authorization authority did not fail closed")
	}
}

func TestConfiguredHTTPSListenerRequiresTrustedClientCertificate(t *testing.T) {
	f := newFixture(t, "TimeManager")
	cert := f.p.cert(t, "TimeManager", "sy")
	config := f.app.Config
	config.Certificate = filepath.Join(f.dir, "server.pem")
	config.PrivateKey = filepath.Join(f.dir, "server.key")
	config.CA = filepath.Join(f.dir, "root.pem")
	for path, data := range map[string][]byte{config.Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}), config.PrivateKey: pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey))}), config.CA: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.p.root.Raw})} {
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	tc, e := LoadTLS(config)
	if e != nil {
		t.Fatal(e)
	}
	srv := httptest.NewUnstartedServer(f.app)
	srv.TLS = tc
	srv.StartTLS()
	defer srv.Close()
	for _, mode := range []string{"none", "untrusted", "trusted"} {
		clientTLS := &tls.Config{RootCAs: f.p.pool, MinVersion: tls.VersionTLS12}
		if mode == "trusted" {
			clientTLS.Certificates = []tls.Certificate{f.p.cert(t, "Consumer", "sy")}
		}
		if mode == "untrusted" {
			clientTLS.Certificates = []tls.Certificate{newPKI(t).cert(t, "Consumer", "sy")}
		}
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: clientTLS}, Timeout: 5 * time.Second}
		req, _ := http.NewRequest("GET", srv.URL+"/timemanager/time", nil)
		req.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//identity-Consumer")
		res, e := client.Do(req)
		if mode == "trusted" {
			if e != nil {
				t.Fatal(e)
			}
			res.Body.Close()
			if res.StatusCode != 200 {
				t.Fatal(res.StatusCode)
			}
		} else if e == nil {
			res.Body.Close()
			t.Fatal("Untrusted TLS client accepted", mode)
		}
		client.CloseIdleConnections()
	}
	if e = os.Chmod(config.PrivateKey, 0644); e != nil {
		t.Fatal(e)
	}
	if _, e = LoadTLS(config); e == nil {
		t.Fatal("World-readable TLS key accepted")
	}
}

func TestStrictConfigurationRejectsUnknownAndTrailingDocuments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	valid := `{"cloudSuffix":"GoCloud.Company.arrowhead.eu","state":"state/Test.json"}`
	for _, raw := range []string{valid + ` {}`, `{"unknown":true}`} {
		if e := os.WriteFile(path, []byte(raw), 0600); e != nil {
			t.Fatal(e)
		}
		if _, e := LoadConfig(path, "TimeManager"); e == nil {
			t.Fatal("Invalid configuration accepted", raw)
		}
	}
	if e := os.WriteFile(path, []byte(valid), 0600); e != nil {
		t.Fatal(e)
	}
	cfg, e := LoadConfig(path, "TimeManager")
	if e != nil || cfg.AuthorizationPolicy != "enforce" || cfg.DefaultSubscription != "none" {
		t.Fatal(cfg, e)
	}
}
func TestCAProfilesSignatureRevocationAndCRL(t *testing.T) {
	f := newFixture(t, "CertificateAuthority")
	caPath, keyPath := filepath.Join(f.dir, "ca.pem"), filepath.Join(f.dir, "ca.key")
	_ = os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.p.root.Raw}), 0600)
	_ = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(f.p.key)}), 0600)
	f.app.Config.CACertificate = caPath
	f.app.Config.CASigningKey = keyPath
	f.app.Config.CRLExportFile = filepath.Join(f.dir, "ca.crl")
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "DeviceA." + suffix}, ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 3, 1, 1, 0xff}}}}, key)
	req := Document{"encodedCSR": base64.StdEncoding.EncodeToString(der), "profile": "sy"}
	s, v := f.request(t, "POST", "/certificate-authority/sign", "Sysop", req)
	out := objectResult(t, s, 201, v)
	chain := list(out, "certificateChain")
	leaf, e := parseCertificate(chain[0].(string))
	if e != nil || leaf.IsCA || leaf.CheckSignatureFrom(f.p.root) != nil || profile(leaf) != "sy" {
		t.Fatal(e, leaf)
	}
	s, _ = f.request(t, "POST", "/certificate-authority/sign", "Consumer", req)
	if s != 403 {
		t.Fatal(s)
	}
	s, v = f.request(t, "POST", "/certificate-authority/mgmt/revocations", "Sysop", Document{"certificate": chain[0]})
	objectResult(t, s, 200, v)
	crlPEM, e := f.app.caCRL()
	if e != nil {
		t.Fatal(e)
	}
	block, _ := pem.Decode(crlPEM)
	crl, e := x509.ParseRevocationList(block.Bytes)
	if e != nil || crl.CheckSignatureFrom(f.p.root) != nil || len(crl.RevokedCertificateEntries) != 1 {
		t.Fatal(e, crl)
	}
	// the revocation also rewrote the exported CRL file read by brokers and the relay
	exported, e := os.ReadFile(f.app.Config.CRLExportFile)
	if e != nil {
		t.Fatal(e)
	}
	block, _ = pem.Decode(exported)
	if block == nil {
		t.Fatal("exported CRL is not PEM")
	}
	crl, e = x509.ParseRevocationList(block.Bytes)
	if e != nil || len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(leaf.SerialNumber) != 0 {
		t.Fatal("exported CRL lacks the revocation", e)
	}
}
func TestOnboardingReservedNamesAndFingerprint(t *testing.T) {
	f := newFixture(t, "Onboarding")
	s, _ := f.request(t, "PUT", "/onboarding/mgmt/enrollments/DeviceA", "Sysop", Document{"bootstrapFingerprint": strings.Repeat("a", 64), "systems": []string{"Authentication"}})
	if s != 400 {
		t.Fatal(s)
	}
	s, v := f.request(t, "PUT", "/onboarding/mgmt/enrollments/DeviceA", "Sysop", Document{"bootstrapFingerprint": strings.Repeat("a", 64), "systems": []string{"SensorA"}})
	objectResult(t, s, 200, v)
	s, _ = f.request(t, "POST", "/onboarding/certificate/name", "Consumer", Document{"commonName": "DeviceA." + suffix})
	if s != 403 {
		t.Fatal("unapproved bootstrap certificate", s)
	}
}
func TestManagementAndTokenBinding(t *testing.T) {
	f := newFixture(t, "Blacklist")
	s, _ := f.request(t, "POST", "/blacklist/mgmt/query", "Consumer", Document{})
	if s != 403 {
		t.Fatal(s)
	}
	cert := f.p.cert(t, "Consumer", "sy").Leaf
	r := httptest.NewRequest("POST", "/blacklist/mgmt/query", strings.NewReader("{}"))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, f.p.root}}}
	r.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//identity-Sysop")
	w := httptest.NewRecorder()
	f.app.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}
func TestAuthorityPinningBeforeCredentials(t *testing.T) {
	f := newFixture(t, "Blacklist")
	called := false
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	s.TLS = f.p.tls(f.p.cert(t, "Attacker", "sy"))
	s.StartTLS()
	defer s.Close()
	var out Document
	if e := f.app.Remote.request(context.Background(), "Authentication", s.URL, "POST", "/login", "", Document{"password": "not-for-attacker"}, &out); e == nil {
		t.Fatal("substituted authority accepted")
	}
	if called {
		t.Fatal("credentials reached attacker")
	}
}
func TestStateOwnershipRollbackAndConcurrentUpdates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	s, e := OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = OpenStore(path); e == nil {
		t.Fatal("second owner")
	}
	if e = s.Update(func(d database) error { bucket(d, "x")["row"] = Document{"n": 0}; return nil }); e != nil {
		t.Fatal(e)
	}
	_ = s.Update(func(d database) error { d["x"]["row"]["n"] = 100; return bad("rollback") })
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if e := s.Update(func(d database) error { d["x"]["row"]["n"] = number(d["x"]["row"], "n", 0) + 1; return nil }); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	_ = s.Close()
	s, e = OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	_ = s.View(func(d database) error {
		if number(d["x"]["row"], "n", 0) != 25 {
			t.Fatal(d)
		}
		return nil
	})
}
func TestEventDeliveryOutboxUsesPinnedSubscriber(t *testing.T) {
	f := newFixture(t, "EventHandler")
	received := make(chan Document, 1)
	callback := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var row Document
		_ = json.NewDecoder(r.Body).Decode(&row)
		received <- row
		w.WriteHeader(204)
	}))
	callback.TLS = f.p.tls(f.p.cert(t, "Consumer", "sy"))
	callback.StartTLS()
	defer callback.Close()
	s, v := f.request(t, "POST", "/eventhandler/event-subscription/subscribe", "Consumer", Document{"eventType": "Temperature", "notifyUri": callback.URL + "/notify"})
	objectResult(t, s, 201, v)
	s, v = f.request(t, "POST", "/eventhandler/event-publish/publish", "Producer", Document{"eventType": "Temperature", "payload": "value"})
	out := objectResult(t, s, 200, v)
	if number(out, "acceptedDeliveries", 0) != 1 {
		t.Fatal(out)
	}
	f.app.deliverEvents(context.Background())
	select {
	case got := <-received:
		if str(got, "sourceSystemName") != "Producer" {
			t.Fatal(got)
		}
	case <-time.After(time.Second):
		t.Fatal("no event delivered")
	}
	if len(f.app.rows("outbox")) != 0 {
		t.Fatal("delivered message not removed")
	}
}
func TestEnrollmentFingerprintIdentityIgnoresManufacturerCN(t *testing.T) {
	f := newFixture(t, "Onboarding")
	cert := f.p.cert(t, "ManufacturerId", "de").Leaf
	hash := sha256.Sum256(cert.Raw)
	_ = f.app.Store.Update(func(d database) error {
		bucket(d, "enrollments")["DeviceA"] = Document{"bootstrapFingerprint": hex.EncodeToString(hash[:]), "state": "APPROVED"}
		return nil
	})
	r := httptest.NewRequest("POST", "/onboarding/certificate/name", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, f.p.root}}}
	p, e := f.app.enrollmentIdentity(r)
	if e != nil || p.Name != "DeviceA" {
		t.Fatal(p, e)
	}
}

func TestUpstreamSystemsPinsMappedIdentity(t *testing.T) {
	f := newFixture(t, "Choreographer")
	orchestrator := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, Document{"ok": true})
	}))
	orchestrator.TLS = f.p.tls(f.p.cert(t, "DynamicServiceOrchestration", "sy"))
	orchestrator.StartTLS()
	t.Cleanup(orchestrator.Close)
	f.app.Config.Upstreams = map[string]string{"ServiceOrchestration": orchestrator.URL}
	var out Document
	if e := f.app.consume(context.Background(), "ServiceOrchestration", "GET", "/echo", nil, &out); e == nil {
		t.Fatal("upstream with a different certificate identity accepted without upstreamSystems")
	}
	f.app.Config.UpstreamSystems = map[string]string{"ServiceOrchestration": "DynamicServiceOrchestration"}
	if e := f.app.consume(context.Background(), "ServiceOrchestration", "GET", "/echo", nil, &out); e != nil || out["ok"] != true {
		t.Fatal(e, out)
	}
	path := filepath.Join(t.TempDir(), "config.json")
	_ = os.WriteFile(path, []byte(`{"cloudSuffix":"GoCloud.Company.arrowhead.eu","state":"s.json","upstreamSystems":{"ServiceOrchestration":"bad name"}}`), 0600)
	if _, e := LoadConfig(path, "Choreographer"); e == nil {
		t.Fatal("invalid upstreamSystems entry accepted")
	}
	for role, raw := range map[string]string{"TimeManager": `"clientCA":"m.pem"`, "Onboarding": `"crlExportFile":"c.crl"`} {
		_ = os.WriteFile(path, []byte(`{"cloudSuffix":"GoCloud.Company.arrowhead.eu","state":"s.json",`+raw+`}`), 0600)
		if _, e := LoadConfig(path, role); e == nil {
			t.Fatal("role-specific option accepted for", role, raw)
		}
	}
}

func TestHistorianRemoteConsumerThroughGateTunnel(t *testing.T) {
	f := newFixture(t, "DataManager")
	put := func(caller, remote string) int {
		r := httptest.NewRequest("PUT", "/datamanager/data-historian/systems/RandomDataProducer/services/fromTestCloud/data", strings.NewReader(`[{"n":"x","v":1}]`))
		cert := f.p.cert(t, caller, "sy").Leaf
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, f.p.root}}}
		r.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//identity-"+caller)
		if remote != "" {
			r.Header.Set("X-Arrowhead-Remote-Consumer", remote)
		}
		w := httptest.NewRecorder()
		f.app.ServeHTTP(w, r)
		return w.Code
	}
	if code := put("GateTunnel", "RandomDataProducer|TestCloud|Company"); code/100 != 2 {
		t.Fatal("GateTunnel refused for its remote consumer", code)
	}
	for _, c := range []struct{ caller, remote string }{{"GateTunnel", ""}, {"GateTunnel", "OtherSystem|TestCloud|Company"}, {"Consumer", "RandomDataProducer|TestCloud|Company"}} {
		if code := put(c.caller, c.remote); code != 403 {
			t.Fatal("foreign data write accepted", c, code)
		}
	}
}

func TestSysMonitorObservationCapAndDedup(t *testing.T) {
	f := newFixture(t, "SysMonitor")
	f.app.Config.MaxObservationsPerSystem = 3
	e := f.app.Store.Update(func(d database) error {
		for i := 0; i < 5; i++ {
			rec := Document{"observationId": fmt.Sprint("a", i), "providerSystem": "A", "receivedTime": fmt.Sprintf("2026-10-17T10:00:0%dZ", i)}
			if e := f.app.storeObservation(d, rec); e != nil {
				return e
			}
			delete(d["outbox"], fmt.Sprint("a", i)) // forwarded
		}
		_ = f.app.storeObservation(d, Document{"observationId": "a4", "providerSystem": "A", "receivedTime": "2026-10-17T11:00:00Z"}) // duplicate
		_ = f.app.storeObservation(d, Document{"observationId": "b0", "providerSystem": "B", "receivedTime": "2026-10-17T09:00:00Z"})
		f.app.capObservations(d, map[string]bool{"A": true})
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
	rows := f.app.rows("observations")
	ids := map[string]bool{}
	for _, r := range rows {
		ids[str(r, "observationId")] = true
	}
	if len(rows) != 4 || ids["a0"] || ids["a1"] || !ids["a2"] || !ids["a4"] || !ids["b0"] {
		t.Fatal("cap kept wrong observations", ids)
	}
}

func TestAIGymSysMonitorDataOrchestrationAndStatus(t *testing.T) {
	f := newFixture(t, "AIGym")
	orchestrator := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		respond(w, 200, Document{"results": []Document{{"providerName": "SysMonitor", "interfaces": []Document{{"templateName": "generic_mqtts", "protocol": "ssl", "properties": Document{"accessAddresses": []string{"mqtt-broker"}, "accessPort": 8883, "baseTopic": "arrowhead/GoCloud/sysmonitor/data"}}}}}})
	}))
	orchestrator.TLS = f.p.tls(f.p.cert(t, "DynamicServiceOrchestration", "sy"))
	orchestrator.StartTLS()
	t.Cleanup(orchestrator.Close)
	f.app.Config.Upstreams = map[string]string{"ServiceOrchestration": orchestrator.URL}
	f.app.Config.UpstreamSystems = map[string]string{"ServiceOrchestration": "DynamicServiceOrchestration"}
	broker, base, e := f.app.sysMonitorDataEndpoint(context.Background())
	if e != nil || broker != "ssl://mqtt-broker:8883" || base != "arrowhead/GoCloud/sysmonitor/data" {
		t.Fatal(broker, base, e)
	}
	for i := 0; i < gymObservationLimit+5; i++ {
		f.app.broker.gym.add(Document{"n": i})
	}
	obs := f.app.broker.gym.snapshot()
	if len(obs) != gymObservationLimit || obs[0]["n"] != gymObservationLimit+4 {
		t.Fatal("observation buffer not bounded/newest first", len(obs))
	}
	f.app.setRegistration(nil)
	st := f.app.aiGymStatus(Document{})
	if obj(st, "registration")["registered"] != true || obj(st, "mqtt") == nil || obj(st, "sysMonitorData") == nil || str(st, "status") != "degraded" {
		t.Fatal(st)
	}
}

func TestManagementAuthorizationPolicy(t *testing.T) {
	f := newFixture(t, "TimeManager")
	authz := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in Document
		_ = json.NewDecoder(r.Body).Decode(&in)
		respond(w, 200, str(in, "consumer") == "Consumer" && str(in, "target") == "generalManagement" && str(in, "scope") == "get-config")
	}))
	authz.TLS = f.p.tls(f.p.cert(t, "ConsumerAuthorization", "sy"))
	authz.StartTLS()
	t.Cleanup(authz.Close)
	f.app.Config.AuthorizationURL = authz.URL
	f.app.Remote = NewRemote(f.app.Config, f.app.TLS)
	if s, _ := f.request(t, "GET", "/timemanager/general/mgmt/get-config", "Consumer", nil); s != 403 {
		t.Fatal("whitelist policy: non-whitelisted caller allowed", s)
	}
	f.app.Config.ManagementPolicy = "authorization"
	if s, v := f.request(t, "GET", "/timemanager/general/mgmt/get-config", "Consumer", nil); s != 200 {
		t.Fatal("authorization policy: granted operation refused", s, v)
	}
	if s, _ := f.request(t, "POST", "/timemanager/general/mgmt/logs", "Consumer", Document{}); s != 403 {
		t.Fatal("authorization policy: ungranted operation allowed", s)
	}
}

func TestPlantRuleResolutionAndAlarms(t *testing.T) {
	plants := map[string]Document{
		"1": {"id": 1.0, "active": false, "systems": []any{map[string]any{"systemId": "historian", "systemName": "DataManager", "ports": []any{map[string]any{"portName": "store", "serviceDefinition": "dataHistorian"}}}}},
		"2": {"id": 2.0, "active": true, "include": []any{1.0}, "systems": []any{
			map[string]any{"systemId": "producer", "systemName": "RandomDataProducer", "ports": []any{map[string]any{"portName": "out", "serviceDefinition": "dataHistorian", "consumer": true}}},
			map[string]any{"systemId": "sensor", "metadata": map[string]any{"role": "sensor"}, "ports": []any{map[string]any{"portName": "out", "serviceDefinition": "dataHistorian", "consumer": true}}},
		}, "connections": []any{
			map[string]any{"consumer": map[string]any{"systemId": "producer", "portName": "out"}, "producer": map[string]any{"systemId": "historian", "portName": "store"}},
			map[string]any{"consumer": map[string]any{"systemId": "producer", "portName": "out"}, "producer": map[string]any{"systemId": "historian", "portName": "store"}, "priority": 1.0},
			map[string]any{"consumer": map[string]any{"systemId": "sensor", "portName": "out"}, "producer": map[string]any{"systemId": "historian", "portName": "store"}},
		}},
	}
	systems, connections, ok := activePlant(plants)
	if !ok || len(systems) != 3 || len(connections) != 3 {
		t.Fatal("active plant with include not resolved", len(systems), len(connections))
	}
	registered := []Document{{"name": "DataManager"}, {"name": "RandomDataProducer"}, {"name": "S1", "metadata": map[string]any{"role": "sensor"}}, {"name": "S2", "metadata": map[string]any{"role": "sensor"}}, {"name": "Extra"}}
	instances := []Document{{"instanceId": "DataManager|dataHistorian|1.0.0", "provider": map[string]any{"name": "DataManager"}, "serviceDefinition": map[string]any{"name": "dataHistorian"}}}
	snapshot := resolveSnapshot(systems, connections, registered, instances)
	// Duplicate connections collapse; ambiguous metadata consumers remain managed conservatively.
	if len(list(snapshot, "rules")) != 3 || len(list(list(snapshot, "rules")[0].(Document), "providers")) != 1 {
		t.Fatal(snapshot)
	}
	f := newFixture(t, "PlantDescriptionEngine")
	f.app.Config.AlarmIgnoredSystems = []string{"DataManager"}
	f.app.updateAlarms(context.Background(), true, systems, registered)
	causes := map[string]int{}
	for _, row := range f.app.rows("alarms") {
		if row["clearedAt"] == nil {
			causes[str(row, "cause")]++
		}
	}
	// sensor ambiguous (its candidates S1/S2 count as described, as in Java); Extra not described; DataManager ignored
	if causes[alarmMultiple] != 1 || causes[alarmNotDescribed] != 1 || causes[alarmNotRegistered] != 0 {
		t.Fatal(causes)
	}
	f.app.updateAlarms(context.Background(), false, nil, registered)
	for _, row := range f.app.rows("alarms") {
		if row["clearedAt"] == nil {
			t.Fatal("alarm not cleared without an active plant", row)
		}
	}
}

func TestChoreographerOrchestrationByProxy(t *testing.T) {
	f := newFixture(t, "Choreographer")
	var subscription atomic.Value
	orchestrator := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in Document
		_ = json.NewDecoder(r.Body).Decode(&in)
		switch {
		case strings.HasSuffix(r.URL.Path, "/push/subscribe"):
			subscription.Store(list(in, "subscriptions")[0].(map[string]any))
			respond(w, 201, Document{"entries": []Document{{"id": "sub-1"}}})
		case strings.HasSuffix(r.URL.Path, "/push/trigger"):
			sub := subscription.Load().(map[string]any)
			path := str(obj(obj(sub, "notifyInterface"), "properties"), "path")
			go func() {
				// the orchestrator posts the result to the Choreographer callback with its own identity
				time.Sleep(50 * time.Millisecond)
				f.request(t, "POST", path, "DynamicServiceOrchestration", Document{"results": []Document{{"providerName": "Provider"}}})
			}()
			respond(w, 200, Document{"jobs": []Document{{"id": "job-1"}}})
		default:
			respond(w, 404, Document{})
		}
	}))
	orchestrator.TLS = f.p.tls(f.p.cert(t, "DynamicServiceOrchestration", "sy"))
	orchestrator.StartTLS()
	t.Cleanup(orchestrator.Close)
	f.app.Config.Upstreams = map[string]string{"ServiceOrchestration": orchestrator.URL}
	f.app.Config.UpstreamSystems = map[string]string{"ServiceOrchestration": "DynamicServiceOrchestration"}
	f.app.Config.AdvertiseAddress, f.app.Config.AdvertisePort = "choreographer", 8457
	result, e := f.app.orchestrateFor(context.Background(), "ExecutorA", Document{"serviceDefinition": "temperature"}, true)
	if e != nil || len(list(result, "results")) != 1 {
		t.Fatal(result, e)
	}
	sub := subscription.Load().(map[string]any)
	if str(sub, "targetSystemName") != "ExecutorA" || !flag(obj(obj(sub, "orchestrationRequest"), "orchestrationFlags"), "ALLOW_INTERCLOUD") {
		t.Fatal("not orchestrated for the executor with inter-cloud", sub)
	}
	if s, _ := f.request(t, "POST", "/choreographer/orchestration-result/anything", "Consumer", Document{}); s != 403 {
		t.Fatal("callback accepted from a non-orchestrator", s)
	}
	if _, e := sessionNotify(Document{"notifyAddress": "x", "notifyProtocol": "HTTP", "notifyPort": 1.0}); e == nil {
		t.Fatal("plain HTTP notification accepted")
	}
	if n, e := sessionNotify(Document{"notifyAddress": "owner", "notifyPort": 9000.0, "notifyPath": "done"}); e != nil || str(n, "path") != "/done" {
		t.Fatal(n, e)
	}
}

func TestQoSDeviceGroupingAndRTT(t *testing.T) {
	systems := []Document{
		{"name": "A", "addresses": []any{map[string]any{"address": "a-host", "type": "HOSTNAME"}}, "device": map[string]any{"addresses": []any{map[string]any{"address": "10.0.0.1", "type": "IPV4"}, map[string]any{"address": "aa:bb", "type": "MAC"}}}},
		{"name": "B", "addresses": []any{map[string]any{"address": "10.0.0.1", "type": "IPV4"}}, "metadata": map[string]any{"qos": map[string]any{"deviceAugmented": true}}},
		{"name": "C", "addresses": []any{map[string]any{"address": "c-host", "type": "HOSTNAME"}}},
	}
	devices := qosDevices(systems)
	if len(devices) != 2 || devices[0].Address != "10.0.0.1" || len(devices[0].Systems) != 2 || !devices[0].Augmented || devices[1].Address != "c-host" || devices[1].Augmented {
		t.Fatal(devices)
	}
	s := qosStats([]float64{3, 1, 2, 4})
	if s["minimum"] != 1.0 || s["maximum"] != 4.0 || s["mean"] != 2.5 || s["median"] != 2.5 || s["current"] != 4.0 {
		t.Fatal(s)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	if _, ok, e := qosRTT(context.Background(), "127.0.0.1", port); ok || e != nil {
		t.Fatal("open port used as RTT probe", ok, e)
	}
	l.Close()
	if rtt, ok, e := qosRTT(context.Background(), "127.0.0.1", port); !ok || e != nil || rtt <= 0 {
		t.Fatal("refused connection not measured", rtt, ok, e)
	}
}

func TestOnboardingClientCAExemptFromCloudCRL(t *testing.T) {
	f := newFixture(t, "Onboarding")
	manufacturer := newPKI(t)
	cert := f.p.cert(t, "Onboarding", "sy")
	revoked := f.p.cert(t, "Revoked", "sy")
	crl, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: revoked.Leaf.SerialNumber, RevocationTime: time.Now()}}}, f.p.root, f.p.key)
	if e != nil {
		t.Fatal(e)
	}
	config := f.app.Config
	config.Certificate, config.PrivateKey = filepath.Join(f.dir, "s.pem"), filepath.Join(f.dir, "s.key")
	config.CA, config.ClientCA, config.CRLFile = filepath.Join(f.dir, "ca.pem"), filepath.Join(f.dir, "m.pem"), filepath.Join(f.dir, "ca.crl")
	for path, data := range map[string][]byte{
		config.Certificate: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]}),
		config.PrivateKey:  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(cert.PrivateKey.(*rsa.PrivateKey))}),
		config.CA:          pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.p.root.Raw}),
		config.ClientCA:    pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: manufacturer.root.Raw}),
		config.CRLFile:     pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crl}),
	} {
		if e := os.WriteFile(path, data, 0600); e != nil {
			t.Fatal(e)
		}
	}
	tc, e := LoadTLS(config)
	if e != nil {
		t.Fatal(e)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	srv.TLS = tc
	srv.StartTLS()
	t.Cleanup(srv.Close)
	handshake := func(client tls.Certificate) error {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: f.p.pool, Certificates: []tls.Certificate{client}}}}
		defer c.CloseIdleConnections()
		res, e := c.Get(srv.URL)
		if e == nil {
			res.Body.Close()
		}
		return e
	}
	if e := handshake(manufacturer.cert(t, "Device1", "")); e != nil {
		t.Fatal("manufacturer bootstrap certificate refused by the cloud CRL check", e)
	}
	if e := handshake(f.p.cert(t, "Device1", "de")); e != nil {
		t.Fatal("unrevoked cloud certificate refused", e)
	}
	if e := handshake(revoked); e == nil {
		t.Fatal("revoked cloud certificate accepted")
	}
}
