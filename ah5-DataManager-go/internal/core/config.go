// SPDX-License-Identifier: EPL-2.0
package core

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Role                string            `json:"-"`
	Name                string            `json:"name"`
	Listen              string            `json:"listen"`
	CloudSuffix         string            `json:"cloudSuffix"`
	Certificate         string            `json:"certificate"`
	PrivateKey          string            `json:"privateKey"`
	CA                  string            `json:"ca"`
	State               string            `json:"state"`
	PasswordFile        string            `json:"passwordFile"`
	AuthenticationURL   string            `json:"authenticationURL"`
	ServiceRegistryURL  string            `json:"serviceRegistryURL"`
	AuthorizationURL    string            `json:"authorizationURL"`
	ManagementWhitelist []string          `json:"managementWhitelist"`
	Register            bool              `json:"register"`
	AdvertiseAddress    string            `json:"advertiseAddress"`
	AdvertisePort       int               `json:"advertisePort"`
	AuthorizationPolicy string            `json:"authorizationPolicy"`
	Upstreams           map[string]string `json:"upstreams"`
	// Optional system identity per logical upstream name, e.g. ServiceOrchestration -> DynamicServiceOrchestration.
	// The upstream certificate is pinned to this identity; without an entry the upstream name itself is pinned.
	UpstreamSystems     map[string]string `json:"upstreamSystems"`
	CACertificate       string            `json:"caCertificate"`
	CASigningKey        string            `json:"caSigningKey"`
	TimeZone            string            `json:"timeZone"`
	NTPServer           string            `json:"ntpServer"`
	AMQPURL             string            `json:"amqpURL"`
	MQTTURL             string            `json:"mqttURL"`
	MonitorEnabled      bool              `json:"monitorEnabled"`
	DefaultSubscription string            `json:"defaultSubscription"`
	RetentionDays       int               `json:"retentionDays"`
	FederationEnabled   bool              `json:"federationEnabled"`
	CRLFile             string            `json:"crlFile"`
	// CertificateAuthority only: PEM CRL rewritten atomically at start-up, daily and after every revocation, for
	// relying parties that read a file (brokers, relay). Empty: the CRL is only served by GET /certificate-authority/crl.
	CRLExportFile string `json:"crlExportFile"`
	// Blacklist enforcement (J12): with blacklistURL set, every requester except sysop and blacklistExclude is checked
	// with Blacklist check; an unreachable Blacklist refuses the request unless blacklistOptional is set.
	BlacklistURL      string   `json:"blacklistURL"`
	BlacklistOptional bool     `json:"blacklistOptional"`
	BlacklistExclude  []string `json:"blacklistExclude"`
	// Onboarding: extra CA bundle (device manufacturers) trusted for client certificates only, so approved bootstrap
	// certificates reach the fingerprint check. Never used to verify upstream servers.
	ClientCA string `json:"clientCA"`
	// SysMonitor: newest observations kept per monitored system (in addition to retentionDays); default 2000.
	MaxObservationsPerSystem int `json:"maxObservationsPerSystem"`
	// Management access besides sysop: "whitelist" (default: managementWhitelist only) or "authorization"
	// (managementWhitelist, else ConsumerAuthorization decides per management service and operation, as in Java).
	ManagementPolicy string `json:"managementPolicy"`
	// PlantDescriptionEngine: registered systems that never raise SYSTEM_NOT_IN_DESCRIPTION (Java default list when absent).
	AlarmIgnoredSystems []string `json:"alarmIgnoredSystems"`
	// DeviceQoSEvaluator: discover devices and measure RTT / augmented load itself (Java measurement engine).
	QoSMeasurement bool `json:"qosMeasurement"`
}

func LoadConfig(path, role string) (Config, error) {
	var c Config
	b, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("configuration must contain exactly one JSON object")
	}
	c.Role = role
	if _, ok := Systems[role]; !ok {
		return c, errors.New("Unknown support system")
	}
	if c.Name == "" {
		c.Name = role
	}
	if c.AuthorizationPolicy == "" {
		c.AuthorizationPolicy = "enforce"
	}
	if c.AuthorizationPolicy != "enforce" && c.AuthorizationPolicy != "identity-only" {
		return c, errors.New("Invalid authorizationPolicy")
	}
	if c.TimeZone == "" {
		c.TimeZone = "UTC"
	}
	if _, e := time.LoadLocation(c.TimeZone); e != nil {
		return c, e
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 30
	}
	if c.AlarmIgnoredSystems == nil {
		c.AlarmIgnoredSystems = []string{"ServiceRegistry", "DynamicServiceOrchestration", "SimpleStoreServiceOrchestration", "ConsumerAuthorization", "Authentication", "Blacklist", "DeviceQoSEvaluator", "TranslationManager", "SysMonitor", "LocalCloudManager", "PlantDescriptionEngine"}
	}
	if c.ManagementPolicy == "" {
		c.ManagementPolicy = "whitelist"
	}
	if c.ManagementPolicy != "whitelist" && c.ManagementPolicy != "authorization" {
		return c, errors.New("managementPolicy must be whitelist or authorization")
	}
	if c.MaxObservationsPerSystem == 0 {
		c.MaxObservationsPerSystem = 2000
	}
	if c.MaxObservationsPerSystem < 1 || c.MaxObservationsPerSystem > 1000000 {
		return c, errors.New("Invalid maxObservationsPerSystem")
	}
	if c.RetentionDays < 1 || c.RetentionDays > 3650 {
		return c, errors.New("Invalid retentionDays")
	}
	if c.DefaultSubscription == "" {
		c.DefaultSubscription = "none"
	}
	if c.DefaultSubscription != "none" && c.DefaultSubscription != "all" {
		return c, errors.New("defaultSubscription must be none or all")
	}
	if c.ClientCA != "" && role != "Onboarding" {
		return c, errors.New("clientCA is only valid for Onboarding")
	}
	if c.CRLExportFile != "" && role != "CertificateAuthority" {
		return c, errors.New("crlExportFile is only valid for CertificateAuthority")
	}
	for upstream, system := range c.UpstreamSystems {
		if !validName(upstream) || !validName(system) {
			return c, errors.New("Invalid upstreamSystems entry")
		}
	}
	if e := resolveListen(&c, role); e != nil {
		return c, e
	}
	if !validName(c.Name) || len(strings.Split(c.CloudSuffix, ".")) != 4 || !strings.HasSuffix(c.CloudSuffix, ".arrowhead.eu") {
		return c, errors.New("name and cloudSuffix (cloud.organization.arrowhead.eu) required")
	}
	if c.State == "" {
		return c, errors.New("durable state path required")
	}
	return c, nil
}
func readSecret(path string) (string, error) {
	st, e := os.Stat(path)
	if e != nil {
		return "", e
	}
	if st.Mode().Perm()&0077 != 0 {
		return "", errors.New("secret file must have owner-only permissions")
	}
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	v := strings.TrimRight(string(b), "\r\n")
	if v == "" {
		return "", errors.New("empty secret")
	}
	return v, nil
}
func LoadTLS(c Config) (*tls.Config, error) {
	keyInfo, e := os.Stat(c.PrivateKey)
	if e != nil {
		return nil, e
	}
	if keyInfo.Mode().Perm()&0077 != 0 {
		return nil, errors.New("TLS private key must have owner-only permissions")
	}
	cert, e := tls.LoadX509KeyPair(c.Certificate, c.PrivateKey)
	if e != nil {
		return nil, e
	}
	leaf, e := x509.ParseCertificate(cert.Certificate[0])
	if e != nil {
		return nil, e
	}
	if leaf.Subject.CommonName != c.Name+"."+c.CloudSuffix || profile(leaf) != "sy" {
		return nil, errors.New("server certificate identity/profile does not match configured system")
	}
	pem, e := os.ReadFile(c.CA)
	if e != nil {
		return nil, e
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, errors.New("no trusted CA certificates")
	}
	clientPool := pool
	clientOnly := map[string]bool{}
	if c.ClientCA != "" {
		extra, e := os.ReadFile(c.ClientCA)
		if e != nil {
			return nil, e
		}
		clientPool = x509.NewCertPool()
		clientPool.AppendCertsFromPEM(pem)
		if !clientPool.AppendCertsFromPEM(extra) {
			return nil, errors.New("no client CA certificates in clientCA")
		}
		for rest := extra; len(rest) > 0; {
			block, next := decodePEM(rest)
			if block == nil {
				break
			}
			clientOnly[string(block.Bytes)] = true
			rest = next
		}
	}
	verify := func(s tls.ConnectionState) error {
		// Certificates of a client-only CA (Onboarding: device manufacturers) are not in the cloud CA's CRL; Onboarding
		// controls them by the approved fingerprint and the enrollment state instead (2026-10-24).
		for _, chain := range s.VerifiedChains {
			if len(chain) >= 2 && clientOnly[string(chain[1].Raw)] {
				return nil
			}
		}
		return checkPeerRevocation(c.CRLFile, s)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: clientPool, RootCAs: pool, VerifyConnection: verify}, nil
}

type Remote struct {
	cfg    Config
	tls    *tls.Config
	mu     sync.Mutex
	token  string
	expiry time.Time
}

func NewRemote(c Config, t *tls.Config) *Remote { return &Remote{cfg: c, tls: t} }
func (r *Remote) client(provider string) *http.Client {
	t := &tls.Config{MinVersion: tls.VersionTLS12}
	if r.tls != nil {
		t = r.tls.Clone()
	}
	t.ClientAuth = tls.NoClientCert
	t.VerifyConnection = func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
			return errors.New("unverified authority")
		}
		c := s.PeerCertificates[0]
		if c.Subject.CommonName != provider+"."+r.cfg.CloudSuffix || profile(c) != "sy" {
			return errors.New("unexpected authority certificate")
		}
		return checkPeerRevocation(r.cfg.CRLFile, s)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: t}, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
}

// Reload configured CRLs on every TLS connection. No configured CRL means chain/time verification only.
func checkPeerRevocation(path string, s tls.ConnectionState) error {
	if path == "" {
		return nil
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		crl, e := x509.ParseRevocationList(block.Bytes)
		if e != nil {
			continue
		}
		for _, chain := range s.VerifiedChains {
			if len(chain) < 2 || crl.CheckSignatureFrom(chain[1]) != nil {
				continue
			}
			if time.Now().Before(crl.ThisUpdate) || !time.Now().Before(crl.NextUpdate) {
				return errors.New("CRL is not current")
			}
			for _, entry := range crl.RevokedCertificateEntries {
				if entry.SerialNumber.Cmp(chain[0].SerialNumber) == 0 {
					return errors.New("Certificate revoked")
				}
			}
			return nil
		}
	}
	return errors.New("No CRL matches peer issuer")
}
func (r *Remote) request(ctx context.Context, provider, base, method, path, token string, in, out any) error {
	u, e := url.Parse(base)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("explicit HTTPS authority URL required")
	}
	b, e := json.Marshal(in)
	if e != nil {
		return e
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, bytes.NewReader(b))
	if e != nil {
		return e
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//"+token)
	}
	c := r.client(provider)
	defer c.CloseIdleConnections()
	resp, e := c.Do(req)
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	body, e := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if e != nil {
		return e
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &APIError{resp.StatusCode, "Upstream " + provider + " rejected request"}
	}
	if out != nil {
		if e = json.Unmarshal(body, out); e != nil {
			return fmt.Errorf("invalid %s response: %w", provider, e)
		}
	}
	return nil
}
func (r *Remote) ownToken(ctx context.Context) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.token != "" && time.Now().Add(5*time.Second).Before(r.expiry) {
		return r.token, nil
	}
	password, e := readSecret(r.cfg.PasswordFile)
	if e != nil {
		return "", e
	}
	var v Document
	e = r.request(ctx, "Authentication", r.cfg.AuthenticationURL, "POST", "/authentication/identity/login", "", Document{"systemName": r.cfg.Name, "credentials": Document{"password": password}}, &v)
	if e != nil {
		return "", e
	}
	t, e := time.Parse(time.RFC3339Nano, str(v, "expirationTime"))
	if e != nil || str(v, "token") == "" {
		return "", errors.New("invalid login response")
	}
	r.token = str(v, "token")
	r.expiry = t
	return r.token, nil
}
func (r *Remote) Call(ctx context.Context, system, method, path string, in, out any) error {
	provider, base := "", ""
	switch system {
	case "authentication":
		provider, base = "Authentication", r.cfg.AuthenticationURL
	case "registry":
		provider, base = "ServiceRegistry", r.cfg.ServiceRegistryURL
	case "authorization":
		provider, base = "ConsumerAuthorization", r.cfg.AuthorizationURL
	case "blacklist":
		provider, base = "Blacklist", r.cfg.BlacklistURL
	default:
		return errors.New("unknown remote system")
	}
	for attempt := 0; attempt < 2; attempt++ {
		token, e := r.ownToken(ctx)
		if e != nil {
			return e
		}
		e = r.request(ctx, provider, base, method, path, token, in, out)
		var ae *APIError
		if !errors.As(e, &ae) || ae.Status != 401 {
			return e
		}
		r.mu.Lock()
		if r.token == token {
			r.token = ""
		}
		r.mu.Unlock()
	}
	return &APIError{502, "Authority rejected refreshed identity token"}
}

func (r *Remote) callAt(ctx context.Context, name, origin, method, path string, in, out any) error {
	for n := 0; n < 2; n++ {
		token, e := r.ownToken(ctx)
		if e != nil {
			return e
		}
		e = r.request(ctx, name, origin, method, path, token, in, out)
		var ae *APIError
		if !errors.As(e, &ae) || ae.Status != 401 {
			return e
		}
		r.mu.Lock()
		if r.token == token {
			r.token = ""
		}
		r.mu.Unlock()
	}
	return &APIError{502, "Rejected refreshed service identity"}
}

// localClient verifies a local-cloud system certificate (chain, `sy` profile, this cloud's CN suffix and the host
// name of the URL) without pinning a system name. Used where only an interface description is known, e.g. a
// translation bridge's target or a data model translator (the reference payloads carry no provider name).
func (r *Remote) localClient() *http.Client {
	t := &tls.Config{MinVersion: tls.VersionTLS12}
	if r.tls != nil {
		t = r.tls.Clone()
	}
	t.ClientAuth = tls.NoClientCert
	t.VerifyConnection = func(s tls.ConnectionState) error {
		if len(s.VerifiedChains) == 0 || len(s.PeerCertificates) == 0 {
			return errors.New("unverified peer")
		}
		c := s.PeerCertificates[0]
		if !strings.HasSuffix(c.Subject.CommonName, "."+r.cfg.CloudSuffix) || profile(c) != "sy" {
			return errors.New("peer is not a system of this local cloud")
		}
		return checkPeerRevocation(r.cfg.CRLFile, s)
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: t}, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect forbidden") }}
}

// callLocal sends a JSON request with this system's identity token to any local-cloud system (see localClient).
func (r *Remote) callLocal(ctx context.Context, origin, method, path string, in, out any) error {
	for attempt := 0; attempt < 2; attempt++ {
		token, e := r.ownToken(ctx)
		if e != nil {
			return e
		}
		var body io.Reader
		if in != nil {
			b, e := json.Marshal(in)
			if e != nil {
				return e
			}
			body = bytes.NewReader(b)
		}
		req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(origin, "/")+path, body)
		if e != nil {
			return e
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//"+token)
		c := r.localClient()
		resp, e := c.Do(req)
		if e != nil {
			c.CloseIdleConnections()
			return e
		}
		data, e := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
		resp.Body.Close()
		c.CloseIdleConnections()
		if e != nil {
			return e
		}
		if resp.StatusCode == 401 && attempt == 0 {
			r.mu.Lock()
			if r.token == token {
				r.token = ""
			}
			r.mu.Unlock()
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &APIError{resp.StatusCode, "Peer rejected request"}
		}
		if out != nil && len(data) > 0 {
			return json.Unmarshal(data, out)
		}
		return nil
	}
	return &APIError{502, "Peer rejected refreshed identity token"}
}

// httpsOrigin builds https://<first access address>:<port> from generic_https interface properties.
func httpsOrigin(props Document) (string, error) {
	addresses := list(props, "accessAddresses")
	port := number(props, "accessPort", 0)
	if len(addresses) == 0 || port < 1 || port > 65535 {
		return "", errors.New("interface has no access address/port")
	}
	host, _ := addresses[0].(string)
	if host == "" || strings.ContainsAny(host, "/@?#") {
		return "", errors.New("invalid access address")
	}
	return "https://" + net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// operationEndpoint returns method and path of a named operation of HTTP interface properties, or the defaults.
func operationEndpoint(props Document, operation, defMethod, defPath string) (string, string) {
	op := obj(obj(props, "operations"), operation)
	if m, p := str(op, "method"), str(op, "path"); m != "" && p != "" {
		return strings.ToUpper(m), p
	}
	return defMethod, defPath
}

// decodePEM is pem.Decode for functions with a local variable named pem.
func decodePEM(data []byte) (*pem.Block, []byte) { return pem.Decode(data) }
