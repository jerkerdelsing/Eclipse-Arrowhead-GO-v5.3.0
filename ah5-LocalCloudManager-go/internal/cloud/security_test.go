package cloud

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type testPKI struct {
	root        *x509.Certificate
	key         *ecdsa.PrivateKey
	caFile, dir string
}

func makePKI(t *testing.T) *testPKI {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	root, _ = x509.ParseCertificate(der)
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return &testPKI{root: root, key: key, caFile: caFile, dir: dir}
}
func (p *testPKI) issue(t *testing.T, name, profile string) (tls.Certificate, string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	cert := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 46}, Value: profile}}}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, p.root, &key.PublicKey, p.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	cp, kp := filepath.Join(p.dir, serial.String()+".crt"), filepath.Join(p.dir, serial.String()+".key")
	if err = os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(cp, kp)
	if err != nil {
		t.Fatal(err)
	}
	pair.Leaf, _ = x509.ParseCertificate(der)
	return pair, cp, kp
}
func secureTestApp(t *testing.T, p *testPKI, role string, authURL string) *App {
	t.Helper()
	a := testApp(t, role)
	_, cp, kp := p.issue(t, a.Config.SystemName+".GoCloud.Company.arrowhead.eu", "sy")
	a.Config.Secure = true
	a.Config.Cloud = "GoCloud"
	a.Config.Organization = "Company"
	a.Config.CertFile = cp
	a.Config.KeyFile = kp
	a.Config.CAFile = p.caFile
	a.Config.AuthenticationURL = authURL
	a.Config.AuthenticationCN = "Authentication.GoCloud.Company.arrowhead.eu"
	a.Config.AuthenticationPassword = "fixture-password"
	if err := a.configureTLS(); err != nil {
		t.Fatal(err)
	}
	return a
}
func tlsTestServer(t *testing.T, p *testPKI, name string, handler http.Handler) *httptest.Server {
	t.Helper()
	pair, _, _ := p.issue(t, name, "sy")
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	s := httptest.NewUnstartedServer(handler)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
func certificateRequest(t *testing.T, p *testPKI, system, profile string) *http.Request {
	pair, _, _ := p.issue(t, system+".GoCloud.Company.arrowhead.eu", profile)
	r := httptest.NewRequest("GET", "https://localhost/echo", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{pair.Leaf}, VerifiedChains: [][]*x509.Certificate{{pair.Leaf, p.root}}}
	r.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//caller-token")
	return r
}

func TestMTLSHandshakeRefusesMissingAndForeignCertificates(t *testing.T) {
	p := makePKI(t)
	a := secureTestApp(t, p, "gatekeeper", "https://localhost:8444")
	s := httptest.NewUnstartedServer(a)
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = a.tlsConfig
	s.StartTLS()
	defer s.Close()
	pool := x509.NewCertPool()
	pool.AddCert(p.root)
	for _, mode := range []string{"none", "foreign", "valid"} {
		t.Run(mode, func(t *testing.T) {
			cfg := &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
			if mode != "none" {
				issuer := p
				if mode == "foreign" {
					issuer = makePKI(t)
				}
				pair, _, _ := issuer.issue(t, "LocalCloudManager.GoCloud.Company.arrowhead.eu", "sy")
				cfg.Certificates = []tls.Certificate{pair}
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: time.Second}
			res, err := client.Get(s.URL + "/health")
			if mode == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				res.Body.Close()
				if res.StatusCode != 200 {
					t.Fatal(res.Status)
				}
			} else {
				if err == nil {
					res.Body.Close()
					t.Fatal("untrusted client accepted")
				}
			}
		})
	}
}

func TestCertificateTokenBindingAndAuthorityPinning(t *testing.T) {
	p := makePKI(t)
	verified := true
	system := "LocalCloudManager"
	auth := tlsTestServer(t, p, "Authentication.GoCloud.Company.arrowhead.eu", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/authentication/identity/login" {
			jsonOut(w, 200, Session{Token: "own-token"})
			return
		}
		jsonOut(w, 200, map[string]any{"verified": verified, "systemName": system, "sysop": true})
	}))
	a := secureTestApp(t, p, "gatekeeper", auth.URL)
	r := certificateRequest(t, p, "LocalCloudManager", "sy")
	if got, err := a.requester(r); err != nil || got != "LocalCloudManager" {
		t.Fatalf("valid binding: %q %v", got, err)
	}
	system = "Sysop"
	if _, err := a.requester(r); err == nil {
		t.Fatal("mismatched token accepted")
	}
	system = "LocalCloudManager"
	verified = false
	if _, err := a.requester(r); err == nil {
		t.Fatal("unverified token accepted")
	}
	verified = true
	r.Header.Set("Authorization", "Bearer SYSTEM//Sysop")
	if _, err := a.requester(r); err == nil {
		t.Fatal("declared identity accepted")
	}
	r = certificateRequest(t, p, "LocalCloudManager", "on")
	if _, err := a.requester(r); err == nil {
		t.Fatal("onboarding certificate accepted as a system")
	}
	r.TLS.VerifiedChains = nil
	if _, err := a.requester(r); err == nil {
		t.Fatal("unverified TLS chain accepted")
	}
	fake := tlsTestServer(t, p, "EvilProvider.GoCloud.Company.arrowhead.eu", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { jsonOut(w, 200, Session{Token: "forged"}) }))
	substituted := secureTestApp(t, p, "gatekeeper", fake.URL)
	if _, err := substituted.ownToken(); err == nil {
		t.Fatal("substituted Authentication certificate accepted")
	}
}

func TestSecureModeFailsClosedWithoutCertificate(t *testing.T) {
	t.Setenv("ARROWHEAD_ROLE", "serviceregistry")
	t.Setenv("SERVICE_REGISTRY_URL", "https://localhost:8443")
	t.Setenv("DATA_FILE", filepath.Join(t.TempDir(), "state.json"))
	t.Setenv("TLS_SERVER_CERT", filepath.Join(t.TempDir(), "missing"))
	t.Setenv("ALLOW_INSECURE_DEVELOPMENT", "false")
	if _, err := NewFromEnv(); err == nil {
		t.Fatal("secure startup succeeded without certificate")
	}
}

func TestOutboundCleartextAndRedirectsRefused(t *testing.T) {
	p := makePKI(t)
	a := secureTestApp(t, p, "gatekeeper", "https://localhost:8444")
	if _, err := a.call("POST", "http://localhost/identity", nil, nil); err == nil {
		t.Fatal("cleartext permitted")
	}
	s := tlsTestServer(t, p, "Service.GoCloud.Company.arrowhead.eu", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "https://attacker.invalid", 302) }))
	if _, err := a.rawCall("GET", s.URL, nil, nil); err == nil {
		t.Fatal("redirect followed")
	}
}

func TestOperationScopesRejectMethodAndPathEscapes(t *testing.T) {
	parameterized := map[string]any{"put-data": map[string]any{"method": "PUT", "path": "/systems/{systemName}/services/{serviceName}/data"}}
	if !operationAllowed("PUT", "/datamanager/historian/systems/Producer/services/reading/data", "/datamanager/historian", parameterized) {
		t.Fatal("v5.2.2 parameterized historian operation rejected")
	}
	if operationAllowed("PUT", "/datamanager/historian/systems/Producer/services/reading/mgmt", "/datamanager/historian", parameterized) {
		t.Fatal("parameterized operation escaped its path")
	}
	ops := map[string]any{"put-data": map[string]any{"method": "PUT", "path": "/data"}}
	for _, tc := range []struct {
		method, path string
		allowed      bool
	}{{"PUT", "/historian/data", true}, {"PUT", "/historian/data/provider?x=1", true}, {"GET", "/historian/data", false}, {"PUT", "/historian/database", false}, {"PUT", "/historian/data/../mgmt", false}, {"PUT", "/historian/data/%2e%2e/mgmt", false}, {"PUT", "/historian/data%2fmgmt", false}, {"PUT", "//attacker/data", false}, {"PUT", "https://attacker/historian/data", false}, {"PUT", "/historian/data/%252e%252e", false}, {"PUT", "/historian/data\\mgmt", false}} {
		if got := operationAllowed(tc.method, tc.path, "/historian", ops); got != tc.allowed {
			t.Errorf("%s %s = %v", tc.method, tc.path, got)
		}
	}
}

func TestAuthorizationCloudIsolation(t *testing.T) {
	a := testApp(t, "authorization")
	a.Store.Data.Grants = []Grant{{Consumer: "Consumer", Provider: "Provider", ServiceDefinition: "temperature", Cloud: "GoCloud|Company", Operations: []string{"read"}}}
	if a.isGranted(Grant{Consumer: "Consumer", Provider: "Provider", ServiceDefinition: "temperature", Cloud: "TestCloud|Company"}) {
		t.Fatal("grant leaked across clouds")
	}
}

func TestSecureRegistryRejectsAuthorityAndProviderSubstitution(t *testing.T) {
	p := makePKI(t)
	auth := tlsTestServer(t, p, "Authentication.GoCloud.Company.arrowhead.eu", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/login") {
			jsonOut(w, 200, Session{Token: "own"})
		} else {
			jsonOut(w, 200, map[string]any{"verified": true, "systemName": "LocalCloudManager"})
		}
	}))
	a := secureTestApp(t, p, "serviceregistry", auth.URL)
	for _, body := range []map[string]any{{"systemName": "Authentication", "serviceDefinitionName": "identity"}, {"systemName": "LocalCloudManager", "serviceDefinitionName": "identity"}} {
		data, _ := json.Marshal(body)
		r := certificateRequest(t, p, "LocalCloudManager", "sy")
		r.Method = "POST"
		r.URL.Path = "/serviceregistry/service-discovery/register"
		r.Body = io.NopCloser(bytes.NewReader(data))
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("authority substitution: %d %s", w.Code, w.Body.String())
		}
	}
}
