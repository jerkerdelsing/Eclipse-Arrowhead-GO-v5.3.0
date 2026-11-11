package cloud

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type pki struct {
	root *x509.Certificate
	key  *rsa.PrivateKey
	pool *x509.CertPool
}
type Session struct {
	Token string `json:"token"`
}

func makePKI(t *testing.T) *pki {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	c := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TestCA"}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, e := x509.CreateCertificate(rand.Reader, c, c, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	c, _ = x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return &pki{c, key, pool}
}
func (p *pki) certificate(t *testing.T, cn, profile string) tls.Certificate {
	t.Helper()
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	sn, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	c := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: cn, ExtraNames: []pkix.AttributeTypeAndValue{{Type: asn1.ObjectIdentifier{2, 5, 4, 46}, Value: profile}}}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, e := x509.CreateCertificate(rand.Reader, c, p.root, &key.PublicKey, p.key)
	if e != nil {
		t.Fatal(e)
	}
	pair, e := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	if e != nil {
		t.Fatal(e)
	}
	return pair
}
func tlsTestServer(t *testing.T, p *pki, cn string, h http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(h)
	s.TLS = &tls.Config{Certificates: []tls.Certificate{p.certificate(t, cn, "sy")}, ClientCAs: p.pool, ClientAuth: tls.RequireAndVerifyClientCert}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
func testApp(t *testing.T, role string) *App {
	t.Helper()
	return &App{Config: Config{Role: role, SystemName: "GateTunnel", Cloud: "GoCloud", Organization: "Company"}, Store: &Store{Data: State{Resources: map[string]Resource{}}}}
}
func secureTestApp(t *testing.T, p *pki, role, auth string) *App {
	t.Helper()
	a := testApp(t, role)
	a.Config.Secure = true
	cert := p.certificate(t, a.commonName(a.Config.SystemName), "sy")
	a.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}, RootCAs: p.pool, ClientCAs: p.pool, ClientAuth: tls.RequireAndVerifyClientCert}
	a.ClientFor = func(name string) *http.Client {
		c := a.tlsConfig.Clone()
		c.ClientAuth = tls.NoClientCert
		c.VerifyConnection = func(cs tls.ConnectionState) error {
			if cs.PeerCertificates[0].Subject.CommonName != a.commonName(name) {
				return fmt.Errorf("unexpected peer")
			}
			return nil
		}
		return &http.Client{Transport: &http.Transport{TLSClientConfig: c}, Timeout: time.Second}
	}
	a.Token = func() (string, error) {
		b, _ := json.Marshal(map[string]any{})
		resp, e := a.ClientFor("Authentication").Post(auth+"/authentication/identity/login", "application/json", bytes.NewReader(b))
		if e != nil {
			return "", e
		}
		defer resp.Body.Close()
		var s Session
		e = json.NewDecoder(resp.Body).Decode(&s)
		return s.Token, e
	}
	a.Identity = func(r *http.Request) (string, error) {
		name := strings.SplitN(r.TLS.PeerCertificates[0].Subject.CommonName, ".", 2)[0]
		req, _ := http.NewRequest("GET", auth+"/authentication/identity/verify/other", nil)
		resp, e := a.ClientFor("Authentication").Do(req)
		if e != nil {
			return "", e
		}
		defer resp.Body.Close()
		var v map[string]any
		e = json.NewDecoder(resp.Body).Decode(&v)
		if e != nil || v["verified"] != true || v["systemName"] != name {
			return "", fmt.Errorf("invalid identity")
		}
		return name, nil
	}
	return a
}
func certificateRequest(t *testing.T, p *pki, name, profile string) *http.Request {
	pair := p.certificate(t, name+".GoCloud.Company.arrowhead.eu", profile)
	cert, _ := x509.ParseCertificate(pair.Certificate[0])
	r := httptest.NewRequest("GET", "https://127.0.0.1/", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}, VerifiedChains: [][]*x509.Certificate{{cert, p.root}}}
	return r
}
