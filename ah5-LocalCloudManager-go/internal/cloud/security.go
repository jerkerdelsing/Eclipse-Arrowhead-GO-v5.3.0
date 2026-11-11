package cloud

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func (a *App) commonName(system string) string {
	return system + "." + a.Config.Cloud + "." + a.Config.Organization + ".arrowhead.eu"
}

func certificateProfile(c *x509.Certificate) string {
	for _, n := range c.Subject.Names {
		if n.Type.String() == "2.5.4.46" {
			s, _ := n.Value.(string)
			return s
		}
	}
	return ""
}

func loadTLS(certFile, keyFile, caFile string) (*tls.Config, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load service identity: %w", err)
	}
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("CA file contains no certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pool, ClientCAs: pool, ClientAuth: tls.RequireAndVerifyClientCert}, nil
}

func (a *App) configureTLS() error {
	cfg, err := loadTLS(a.Config.CertFile, a.Config.KeyFile, a.Config.CAFile)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil {
		return err
	}
	if leaf.Subject.CommonName != a.commonName(a.Config.SystemName) || certificateProfile(leaf) != "sy" {
		return errors.New("configured service certificate has the wrong Arrowhead identity or profile")
	}
	a.tlsConfig = cfg
	if a.Config.CRLFile != "" {
		cfg.VerifyConnection = func(cs tls.ConnectionState) error { return a.checkCRL(cs) }
	}
	authURL, err := url.Parse(a.Config.AuthenticationURL)
	if err != nil || authURL.Scheme != "https" || authURL.Host == "" || authURL.User != nil {
		return errors.New("AUTHENTICATION_URL must be an explicit HTTPS endpoint")
	}
	clientTLS := cfg.Clone()
	clientTLS.ClientAuth = tls.NoClientCert
	clientTLS.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 {
			return errors.New("unverified server")
		}
		if cs.ServerName == authURL.Hostname() && cs.PeerCertificates[0].Subject.CommonName != a.Config.AuthenticationCN {
			return errors.New("authentication endpoint is not the pinned Authentication identity")
		}
		if a.Config.CRLFile != "" {
			return a.checkCRL(cs)
		}
		return nil
	}
	a.client = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: clientTLS, MaxIdleConns: 32, IdleConnTimeout: 60 * time.Second}, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return errors.New("service redirects are not permitted")
	}}
	pinnedTLS := clientTLS.Clone()
	pinnedTLS.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != a.Config.AuthenticationCN || certificateProfile(cs.PeerCertificates[0]) != "sy" {
			return errors.New("server is not the pinned Authentication system")
		}
		if a.Config.CRLFile != "" {
			return a.checkCRL(cs)
		}
		return nil
	}
	a.authClient = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: pinnedTLS, MaxIdleConns: 8, IdleConnTimeout: 60 * time.Second}, CheckRedirect: a.client.CheckRedirect}
	return nil
}

// Reload the CRL on each connection, so a rotation does not need a service restart.
func (a *App) checkCRL(cs tls.ConnectionState) error {
	data, err := os.ReadFile(a.Config.CRLFile)
	if err != nil {
		return err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return errors.New("invalid CRL PEM")
	}
	crl, err := x509.ParseRevocationList(block.Bytes)
	if err != nil {
		return err
	}
	if time.Now().Before(crl.ThisUpdate) || !time.Now().Before(crl.NextUpdate) {
		return errors.New("CRL is not current")
	}
	for _, chain := range cs.VerifiedChains {
		if len(chain) < 2 || crl.CheckSignatureFrom(chain[1]) != nil {
			continue
		}
		for _, revoked := range crl.RevokedCertificateEntries {
			if revoked.SerialNumber.Cmp(chain[0].SerialNumber) == 0 {
				return errors.New("certificate is revoked")
			}
		}
		return nil
	}
	return errors.New("CRL does not verify against the peer issuer")
}

func (a *App) certificateIdentity(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return "", errors.New("verified local-cloud mutual TLS is required")
	}
	c := r.TLS.PeerCertificates[0]
	profile := certificateProfile(c)
	if profile != "sy" && profile != "op" {
		return "", errors.New("only system and operator certificates may call services")
	}
	suffix := "." + a.Config.Cloud + "." + a.Config.Organization + ".arrowhead.eu"
	if !strings.HasSuffix(c.Subject.CommonName, suffix) {
		return "", errors.New("certificate belongs to another cloud")
	}
	name := strings.TrimSuffix(c.Subject.CommonName, suffix)
	if name == "" || strings.ContainsAny(name, ".|/\\") {
		return "", errors.New("invalid Arrowhead certificate name")
	}
	return name, nil
}

func (a *App) ownToken() (string, error) {
	a.identityMu.Lock()
	defer a.identityMu.Unlock()
	if a.identityToken != "" && time.Now().Before(a.identityExpiry) {
		return a.identityToken, nil
	}
	if a.Config.AuthenticationPassword == "" {
		return "", errors.New("AUTHENTICATION_PASSWORD is required for outsourced identity")
	}
	b, err := a.rawCall(http.MethodPost, a.Config.AuthenticationURL+"/authentication/identity/login", map[string]any{"systemName": a.Config.SystemName, "credentials": map[string]string{"password": a.Config.AuthenticationPassword}}, nil)
	if err != nil {
		return "", errors.New("service identity login failed")
	}
	var session Session
	if json.Unmarshal(b, &session) != nil || session.Token == "" {
		return "", errors.New("invalid Authentication login response")
	}
	a.identityToken, a.identityExpiry = session.Token, time.Now().Add(240*time.Second)
	return session.Token, nil
}

func (a *App) secureRequester(r *http.Request) (string, error) {
	name, err := a.certificateIdentity(r)
	if err != nil {
		return "", err
	}
	const prefix = "Bearer IDENTITY-TOKEN//"
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, prefix) {
		return "", errors.New("an Arrowhead identity token is required; declared identities are disabled")
	}
	token := strings.TrimPrefix(header, prefix)
	if token == "" || len(token) > 4096 || strings.ContainsAny(token, "/?#\r\n") {
		return "", errors.New("invalid token syntax")
	}
	if a.Config.Role == "authentication" {
		a.Store.mu.RLock()
		session, ok := a.Store.Data.Sessions[token]
		a.Store.mu.RUnlock()
		if ok && session.SystemName == name && session.ExpirationTime > now() {
			return name, nil
		}
		return "", errors.New("invalid, expired or certificate-mismatched token")
	}
	// Authentication is configured explicitly, never discovered by the mutable identity service definition.
	b, err := a.call(http.MethodGet, a.Config.AuthenticationURL+"/authentication/identity/verify/"+url.PathEscape(token), nil, nil)
	if err != nil {
		return "", errors.New("identity verification failed")
	}
	var result struct {
		Verified   bool   `json:"verified"`
		SystemName string `json:"systemName"`
	}
	if json.Unmarshal(b, &result) != nil || !result.Verified || result.SystemName != name {
		return "", errors.New("invalid, expired or certificate-mismatched token")
	}
	return name, nil
}

func serviceOperations(spec ServiceSpec) map[string]any {
	if spec.Definition == "gateTunnelConnection" {
		return map[string]any{"connect-provider": map[string]any{"method": "POST", "path": "/connect_provider"}, "connect-consumer": map[string]any{"method": "POST", "path": "/connect_consumer"}, "close-sessions": map[string]any{"method": "POST", "path": "/close_sessions"}}
	}
	if spec.Definition == "gateTunnelKey" {
		return map[string]any{"public-key": map[string]any{"method": "GET", "path": "/publickey"}}
	}
	if spec.Definition == "globalServiceDiscovery" {
		return map[string]any{"query": map[string]any{"method": "POST", "path": "/init_gsd"}, "multi-query": map[string]any{"method": "POST", "path": "/init_multi_gsd"}}
	}
	if spec.Definition == "interCloudNegotiation" {
		return map[string]any{"negotiate": map[string]any{"method": "POST", "path": "/init_icn"}}
	}
	if spec.Definition == "gatekeeperManagement" {
		return map[string]any{"clouds": map[string]any{"method": "GET", "path": "/mgmt/clouds"}, "relays": map[string]any{"method": "GET", "path": "/mgmt/relays"}}
	}
	if spec.Definition == "gateTunnelManagement" {
		return map[string]any{"query-sessions": map[string]any{"method": "GET", "path": "/mgmt/sessions"}}
	}
	ops := map[string]any{}
	for _, name := range spec.Operations {
		ops[name] = map[string]any{"method": "POST", "path": "/" + name}
	}
	return ops
}
