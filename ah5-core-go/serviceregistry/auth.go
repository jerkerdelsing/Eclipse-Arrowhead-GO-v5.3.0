package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sysopName      = "Sysop"
	unknownSystem  = "<unknown>"
	identitySvcDef = "identity"
	authSvcDef     = "authorization"
	blacklistDef   = "blacklistDiscovery"
)

type ctxKey int

const (
	ctxSystemKey ctxKey = iota
	ctxSysopKey
)

// identity returns the authenticated system name and sysop flag of a request.
func identity(r *http.Request) (string, bool) {
	name, _ := r.Context().Value(ctxSystemKey).(string)
	sysop, _ := r.Context().Value(ctxSysopKey).(bool)
	if name == "" {
		name = unknownSystem
	}
	return name, sysop
}

// Authenticator implements the three authentication policies, the management filter and the
// blacklist filter.
type Authenticator struct {
	cfg    *Config
	rg     *Registry
	log    *Logger
	client *http.Client

	mu    sync.Mutex
	token string // own identity token (outsourced policy)
}

func NewAuthenticator(cfg *Config, rg *Registry, log *Logger, tlsCfg *tls.Config) *Authenticator {
	tr := &http.Transport{}
	if tlsCfg != nil {
		c := tlsCfg.Clone()
		c.ClientAuth = tls.NoClientCert
		c.RootCAs = tlsCfg.ClientCAs
		tr.TLSClientConfig = c
	}
	return &Authenticator{cfg: cfg, rg: rg, log: log, client: &http.Client{
		Timeout: time.Duration(cfg.HTTPClientTimout) * time.Millisecond, Transport: tr,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return fmt.Errorf("authority redirects are not allowed")
		}}}
}

func authorityProvider(def string) string {
	switch def {
	case identitySvcDef:
		return "Authentication"
	case authSvcDef:
		return "ConsumerAuthorization"
	case blacklistDef:
		return "Blacklist"
	}
	return ""
}

// Middleware authenticates every request except "/" and applies management and blacklist filters.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			next.ServeHTTP(w, r)
			return
		}
		origin := r.Method + " " + r.URL.Path
		m, viaMQTT := r.Context().Value(mqttPrincipalKey{}).(mqttPrincipal)
		// As in the Java framework, an outsourced registry lets the identity lookup through without a token:
		// a system must find Authentication before it can log in. The TLS client certificate is still required.
		if !viaMQTT && a.cfg.AuthenticationPolicy == "outsourced" && isIdentityLookup(r) {
			next.ServeHTTP(w, r)
			return
		}
		name, sysop := m.name, m.sysop
		if !viaMQTT {
			var err error
			if name, sysop, err = a.authenticate(r); err != nil {
				a.log.Warnf("auth", "%s -> authentication failed: %v", origin, err)
				writeError(w, err, origin)
				return
			}
		}
		if a.cfg.EnableBlacklist && !sysop {
			if err := a.checkBlacklist(name); err != nil {
				writeError(w, err, origin)
				return
			}
		}
		if a.cfg.EnableMgmtFilter && strings.Contains(r.URL.Path, "/mgmt/") {
			if err := a.checkManagement(r, name, sysop); err != nil {
				a.log.Warnf("auth", "%s by %s -> %v", origin, name, err)
				writeError(w, err, origin)
				return
			}
		}
		ctx := context.WithValue(r.Context(), ctxSystemKey, name)
		ctx = context.WithValue(ctx, ctxSysopKey, sysop)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (a *Authenticator) authenticate(r *http.Request) (string, bool, error) {
	switch a.cfg.AuthenticationPolicy {
	case "declared":
		return a.authDeclared(r)
	case "certificate":
		return a.authCertificate(r)
	default:
		return a.authOutsourced(r)
	}
}

func (a *Authenticator) authDeclared(r *http.Request) (string, bool, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false, errAuth("No authorization header has been provided")
	}
	const prefix = "Bearer SYSTEM//"
	if !strings.HasPrefix(h, prefix) {
		return "", false, errAuth("Invalid authentication method is provided")
	}
	name := strings.TrimSpace(h[len(prefix):])
	if name == "" {
		return "", false, errAuth("Invalid authentication method is provided")
	}
	return name, name == sysopName, nil
}

// dnQualifier OID 2.5.4.46
func dnQualifier(c *x509.Certificate) string {
	for _, n := range c.Subject.Names {
		if n.Type.String() == "2.5.4.46" {
			if s, ok := n.Value.(string); ok {
				return s
			}
		}
	}
	return ""
}

func (a *Authenticator) authCertificate(r *http.Request) (string, bool, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return "", false, errAuth("Client certificate is missing")
	}
	cert := r.TLS.PeerCertificates[0]
	cn := cert.Subject.CommonName
	parts := strings.Split(cn, ".")
	if len(parts) != 5 {
		return "", false, errAuth("Invalid client certificate common name: " + cn)
	}
	if a.cfg.ServerCommonName != "" {
		sp := strings.SplitN(a.cfg.ServerCommonName, ".", 2)
		if len(sp) == 2 && sp[1] != strings.Join(parts[1:], ".") {
			return "", false, errAuth("Client certificate is not from the local cloud")
		}
	}
	name := parts[0]
	switch dnQualifier(cert) {
	case "op":
		return sysopName, true, nil
	case "sy", "":
		return name, name == sysopName && dnQualifier(cert) == "op", nil
	default:
		return "", false, errAuth("Invalid client certificate type")
	}
}

func (a *Authenticator) authOutsourced(r *http.Request) (string, bool, error) {
	name, sysop, err := a.authOutsourcedHeader(r)
	if err != nil {
		return "", false, err
	}
	if err := bindToCertificate(r, name); err != nil {
		return "", false, err
	}
	return name, sysop, nil
}

// bindToCertificate requires, over TLS, that the system named by the token (or authenticator key) is the
// system named by the client certificate CN, so a stolen token cannot be used from another certificate.
func bindToCertificate(r *http.Request, name string) error {
	if r.TLS == nil {
		return nil
	}
	if len(r.TLS.PeerCertificates) == 0 {
		return errAuth("Identity token must be presented with the client certificate of the same system")
	}
	certName := strings.SplitN(r.TLS.PeerCertificates[0].Subject.CommonName, ".", 2)[0]
	if !strings.EqualFold(certName, name) {
		return errAuth("Identity token does not belong to the system of the client certificate")
	}
	return nil
}

// isIdentityLookup reports whether the request is a service lookup for exactly the identity service.
func isIdentityLookup(r *http.Request) bool {
	if r.Method != http.MethodPost || !strings.HasSuffix(strings.TrimRight(r.URL.Path, "/"), "/service-discovery/lookup") || r.Body == nil {
		return false
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body = io.NopCloser(bytes.NewReader(body))
	if err != nil {
		return false
	}
	var req struct {
		ServiceDefinitionNames []string `json:"serviceDefinitionNames"`
	}
	if json.Unmarshal(body, &req) != nil {
		return false
	}
	return len(req.ServiceDefinitionNames) == 1 && req.ServiceDefinitionNames[0] == identitySvcDef
}

func (a *Authenticator) authOutsourcedHeader(r *http.Request) (string, bool, error) {
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", false, errAuth("No authorization header has been provided")
	}
	switch {
	case strings.HasPrefix(h, "Bearer IDENTITY-TOKEN//"):
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer IDENTITY-TOKEN//"))
		return a.verifyIdentityToken(token)
	case strings.HasPrefix(h, "Bearer AUTHENTICATOR-KEY//"):
		parts := strings.Split(strings.TrimPrefix(h, "Bearer AUTHENTICATOR-KEY//"), "//")
		if len(parts) != 2 {
			return "", false, errAuth("Invalid authenticator key format")
		}
		name, hash := parts[0], parts[1]
		secret, ok := a.cfg.AuthenticatorSecretKeys[name]
		if !ok {
			return "", false, errAuth("Invalid authenticator key")
		}
		m := hmac.New(sha256.New, []byte(secret))
		m.Write([]byte(name))
		want := hex.EncodeToString(m.Sum(nil))
		if !hmac.Equal([]byte(strings.ToLower(hash)), []byte(want)) {
			return "", false, errAuth("Invalid authenticator key")
		}
		return name, name == sysopName, nil
	}
	return "", false, errAuth("Invalid authentication method is provided")
}

func (a *Authenticator) verifyIdentityToken(token string) (string, bool, error) {
	if token == "" {
		return "", false, errAuth("Empty identity token")
	}
	var out struct {
		Verified   bool   `json:"verified"`
		SystemName string `json:"systemName"`
		Sysop      bool   `json:"sysop"`
	}
	if err := a.callService(identitySvcDef, "identity-verify", nil, token, &out); err != nil {
		return "", false, errAuth("Identity verification failed: " + err.Error())
	}
	if !out.Verified {
		return "", false, errAuth("Invalid identity token")
	}
	return out.SystemName, out.Sysop, nil
}

func (a *Authenticator) checkManagement(r *http.Request, name string, sysop bool) error {
	if sysop {
		return nil
	}
	forbidden := errForbidden(name + " has no permission to access this resource")
	switch a.cfg.ManagementPolicy {
	case "sysop-only":
		return forbidden
	case "whitelist":
		if containsStr(a.cfg.ManagementWhitelist, name) {
			return nil
		}
		return forbidden
	default:
		if containsStr(a.cfg.ManagementWhitelist, name) {
			return nil
		}
		definition, op := managementTarget(r)
		if definition == "" {
			return forbidden
		}
		var ok bool
		err := a.callService(authSvcDef, "verify", map[string]any{
			"provider": "ServiceRegistry", "consumer": name, "cloud": "LOCAL",
			"targetType": "SERVICE_DEF", "target": definition, "scope": op,
		}, "", &ok)
		if err != nil {
			a.log.Warnf("auth", "authorization verify failed: %v", err)
			return forbidden
		}
		if !ok {
			return forbidden
		}
		return nil
	}
}

// Management authorization uses the v5.2.2 AuthorizationVerifyRequestDTO and the
// registered operation name, not the removed serviceDefinition/operation fields.
func managementTarget(r *http.Request) (string, string) {
	for _, sv := range selfServices() {
		if sv.def != "generalManagement" && sv.def != "serviceRegistryManagement" {
			continue
		}
		for op, definition := range sv.ops {
			if r.Method == definition[0] && r.URL.Path == sv.path+definition[1] {
				return sv.def, op
			}
		}
	}
	return "", ""
}

func (a *Authenticator) checkBlacklist(name string) error {
	// as the Java BlacklistFilter: Blacklist itself is never checked (it registers before it serves its check)
	if name == authorityProvider(blacklistDef) || containsStr(a.cfg.BlacklistExclude, name) {
		return nil
	}
	var blacklisted bool
	err := a.callService(blacklistDef, "check", nil, name, &blacklisted)
	if err != nil {
		a.log.Warnf("auth", "blacklist check failed: %v", err)
		if a.cfg.ForceBlacklist {
			return errForbidden("Blacklist check failed")
		}
		return nil
	}
	if blacklisted {
		return errForbidden(name + " is blacklisted")
	}
	return nil
}

// callService finds a provider of the given service definition in the local registry and calls
// the given operation over its generic_http(s) interface. For GET/DELETE the arg replaces a
// "{...}" placeholder in the path or is appended to it.
func (a *Authenticator) callService(def, op string, body any, arg string, out any) error {
	var url, method, path string
	var findErr error
	a.rg.store.View(func(st *state) {
		findErr = func() error {
			for _, in := range st.Instances {
				if in.Definition != def {
					continue
				}
				if expected := authorityProvider(def); expected != "" && in.System != expected {
					continue
				}
				for _, f := range in.Interfaces {
					if a.cfg.SSLEnabled && f.Template != "generic_https" {
						continue
					}
					if f.Template != "generic_http" && f.Template != "generic_https" {
						continue
					}
					addrs, _ := f.Properties["accessAddresses"].([]any)
					if len(addrs) == 0 {
						continue
					}
					host := fmt.Sprint(addrs[0])
					port := fmt.Sprint(f.Properties["accessPort"])
					if n, ok := f.Properties["accessPort"].(int64); ok {
						port = fmt.Sprint(n)
					}
					base, _ := f.Properties["basePath"].(string)
					ops, _ := f.Properties["operations"].(map[string]any)
					o, ok := ops[op].(map[string]any)
					if !ok {
						continue
					}
					scheme := "http"
					if f.Template == "generic_https" {
						scheme = "https"
					}
					method, _ = o["method"].(string)
					path, _ = o["path"].(string)
					url = fmt.Sprintf("%s://%s:%s%s%s", scheme, host, port, base, path)
					return nil
				}
			}
			return fmt.Errorf("no provider of %s/%s found", def, op)
		}()
	})
	if findErr != nil {
		return findErr
	}
	if i := strings.Index(url, "{"); i >= 0 {
		j := strings.Index(url[i:], "}")
		if j > 0 {
			url = url[:i] + arg + url[i+j+1:]
		}
	} else if arg != "" {
		url = strings.TrimRight(url, "/") + "/" + arg
	}
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	if method == "" {
		method = "POST"
	}
	req, err := http.NewRequest(strings.ToUpper(method), url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if h := a.authHeader(op, ""); h != "" {
		req.Header.Set("Authorization", h)
	}
	client := a.client
	if expected := authorityProvider(def); expected != "" && a.cfg.SSLEnabled {
		transport, ok := a.client.Transport.(*http.Transport)
		if !ok || transport.TLSClientConfig == nil {
			return fmt.Errorf("authority mutual TLS is not configured")
		}
		copyTransport := transport.Clone()
		copyTransport.TLSClientConfig = transport.TLSClientConfig.Clone()
		parts := strings.SplitN(a.cfg.ServerCommonName, ".", 2)
		if len(parts) != 2 {
			return fmt.Errorf("local cloud certificate name is invalid")
		}
		expectedCN := expected + "." + parts[1]
		copyTransport.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.VerifiedChains) == 0 || len(cs.PeerCertificates) == 0 || cs.PeerCertificates[0].Subject.CommonName != expectedCN {
				return fmt.Errorf("authority certificate must identify %s", expectedCN)
			}
			for _, n := range cs.PeerCertificates[0].Subject.Names {
				if n.Type.String() == "2.5.4.46" && n.Value == "sy" {
					return nil
				}
			}
			return fmt.Errorf("authority is not a system-profile certificate")
		}
		copyClient := *client
		copyClient.Transport = copyTransport
		client = &copyClient
		defer copyTransport.CloseIdleConnections()
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized && a.cfg.AuthenticationPolicy == "outsourced" && op != "identity-login" {
		// own token expired or replaced: log in again once and retry
		resp.Body.Close()
		rejected := req.Header.Get("Authorization")
		if h := a.authHeader(op, rejected); h != "" {
			if body != nil {
				b, _ := json.Marshal(body)
				req.Body = io.NopCloser(bytes.NewReader(b))
			}
			req.Header.Set("Authorization", h)
			if resp, err = client.Do(req); err != nil {
				return err
			}
		}
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// authHeader returns the Authorization header for an outgoing call: the registry's own identity token under
// the outsourced policy (logging in first when needed), the declared identity otherwise. Login itself is tokenless.
// When rejected is non-empty, a new login is made only if that exact token is still current. This prevents
// concurrent 401 responses from repeatedly replacing and invalidating each other's freshly issued sessions.
func (a *Authenticator) authHeader(op, rejected string) string {
	if op == "identity-login" {
		return ""
	}
	if a.cfg.AuthenticationPolicy != "outsourced" {
		return "Bearer SYSTEM//" + systemName
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current := ""
	if a.token != "" {
		current = "Bearer IDENTITY-TOKEN//" + a.token
	}
	if a.token == "" || (rejected != "" && rejected == current) {
		var out struct {
			Token string `json:"token"`
		}
		payload := map[string]any{"systemName": systemName, "credentials": map[string]string{"password": a.cfg.AuthenticatorPassword}}
		if err := a.callService(identitySvcDef, "identity-login", payload, "", &out); err != nil {
			a.log.Warnf("auth", "login to Authentication failed: %v", err)
			return ""
		}
		a.token = out.Token
	}
	return "Bearer IDENTITY-TOKEN//" + a.token
}
