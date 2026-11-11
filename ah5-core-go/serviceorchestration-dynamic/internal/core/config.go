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
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type Config struct {
	Role                  string `json:"-"`
	Name                  string `json:"name"`
	Listen                string `json:"listen"`
	CloudSuffix           string `json:"cloudSuffix"`
	Certificate           string `json:"certificate"`
	PrivateKey            string `json:"privateKey"`
	CA                    string `json:"ca"`
	State                 string `json:"state"`
	PasswordFile          string `json:"passwordFile"`
	BootstrapName         string `json:"bootstrapName"`
	BootstrapPasswordFile string `json:"bootstrapPasswordFile"`
	AuthenticationURL     string `json:"authenticationURL"`
	ServiceRegistryURL    string `json:"serviceRegistryURL"`
	AuthorizationURL      string `json:"authorizationURL"`
	// DynamicServiceOrchestration: HTTPS origin of the local Gatekeeper (certificate pinned to Gatekeeper.<cloud>);
	// empty disables inter-cloud orchestration (ALLOW_INTERCLOUD/ONLY_INTERCLOUD then return no results).
	GatekeeperURL string `json:"gatekeeperURL"`
	// Native sysMonitor telemetry: registers a sysMonitor offer and publishes echo/power/status over AMQPS.
	MonitorEnabled bool   `json:"monitorEnabled"`
	AMQPURL        string `json:"amqpURL"`
	// Management access besides sysop: "whitelist" (default: managementWhitelist only) or "authorization"
	// (managementWhitelist, else ConsumerAuthorization decides per management service and operation, as in Java).
	ManagementPolicy    string   `json:"managementPolicy"`
	IdentityTTL         int      `json:"identityTTLSeconds"`
	TokenTTL            int      `json:"tokenTTLSeconds"`
	TokenUsage          int      `json:"tokenUsageLimit"`
	TokenSecretFile     string   `json:"tokenSecretFile"`
	ManagementWhitelist []string `json:"managementWhitelist"`
	Register            bool     `json:"register"`
	AdvertiseAddress    string   `json:"advertiseAddress"`
	AdvertisePort       int      `json:"advertisePort"`
	// Revocation (J4): PEM CRL(s) of the cloud CA; client and authority certificates of that CA are checked on every
	// handshake and refused when revoked, or when no current CRL of their issuer is present (fail closed).
	CRLFile string `json:"crlFile"`
	// Blacklist enforcement (J12): with blacklistURL set, every requester except sysop and blacklistExclude is checked
	// with Blacklist check; an unreachable Blacklist refuses the request unless blacklistOptional is set.
	BlacklistURL      string   `json:"blacklistURL"`
	BlacklistOptional bool     `json:"blacklistOptional"`
	BlacklistExclude  []string `json:"blacklistExclude"`
	// MQTT API (Java mqtt.api.enabled): with mqttURL (ssl://host:port) set, the services are also served over the
	// broker and registered with a generic_mqtts interface; mqttTopicPrefix replaces the Java topic prefix of the role
	// (two orchestrators on one broker need distinct prefixes).
	MQTTURL         string `json:"mqttURL"`
	MQTTTopicPrefix string `json:"mqttTopicPrefix"`
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
	c.Role = role
	if e := resolveListen(&c, role); e != nil {
		return c, e
	}
	if c.IdentityTTL == 0 {
		c.IdentityTTL = 3600
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = 600
	}
	if c.TokenUsage == 0 {
		c.TokenUsage = 1
	}
	if c.ManagementPolicy == "" {
		c.ManagementPolicy = "whitelist"
	}
	if c.ManagementPolicy != "whitelist" && c.ManagementPolicy != "authorization" {
		return c, errors.New("managementPolicy must be whitelist or authorization")
	}
	if c.IdentityTTL < 1 || c.TokenTTL < 1 || c.TokenUsage < 1 {
		return c, errors.New("positive token limits required")
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
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, RootCAs: pool, VerifyConnection: func(s tls.ConnectionState) error { return checkPeerRevocation(c.CRLFile, s) }}, nil
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
	case "gatekeeper":
		provider, base = "Gatekeeper", r.cfg.GatekeeperURL
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

// checkPeerRevocation re-reads the configured CRL file on every TLS connection (J4; same check as ah5-support-go).
// No configured CRL means chain/time verification only.
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
