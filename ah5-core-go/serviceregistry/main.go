// Arrowhead 5.2.2 ServiceRegistry core system, implemented in Go after the Java Spring reference
// implementation (eclipse-arrowhead/ah5-core-java-spring).
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

const (
	systemName     = "ServiceRegistry"
	systemVersion  = "5.2.2"
	serviceVersion = "1.0.0"
)

// selfService describes one service provided by the ServiceRegistry itself.
type selfService struct {
	def      string
	path     string
	metadata map[string]any
	ops      map[string][2]string // operation -> {method, path}
}

func selfServices() []selfService {
	unrestricted := map[string]any{metaKeyUnrestrictedDiscovery: true}
	b := basePath
	return []selfService{
		{"generalManagement", b + "/general/mgmt", nil, map[string][2]string{
			"get-log": {"POST", "/logs"}, "get-config": {"GET", "/get-config"}}},
		{"serviceRegistryManagement", b + "/mgmt", nil, map[string][2]string{
			"device-query": {"POST", "/devices/query"}, "device-create": {"POST", "/devices"},
			"device-update": {"PUT", "/devices"}, "device-remove": {"DELETE", "/devices"},
			"system-query": {"POST", "/systems/query"}, "system-create": {"POST", "/systems"},
			"system-update": {"PUT", "/systems"}, "system-remove": {"DELETE", "/systems"},
			"service-definition-query":  {"POST", "/service-definitions/query"},
			"service-definition-create": {"POST", "/service-definitions"},
			"service-definition-remove": {"DELETE", "/service-definitions"},
			"service-query":             {"POST", "/service-instances/query"},
			"service-create":            {"POST", "/service-instances"},
			"service-update":            {"PUT", "/service-instances"},
			"service-remove":            {"DELETE", "/service-instances"},
			"interface-template-query":  {"POST", "/interface-templates/query"},
			"interface-template-create": {"POST", "/interface-templates"},
			"interface-template-remove": {"DELETE", "/interface-templates"}}},
		{"deviceDiscovery", b + "/device-discovery", unrestricted, map[string][2]string{
			"register": {"POST", "/register"}, "lookup": {"POST", "/lookup"}, "revoke": {"DELETE", "/revoke/{name}"}}},
		{"systemDiscovery", b + "/system-discovery", unrestricted, map[string][2]string{
			"register": {"POST", "/register"}, "lookup": {"POST", "/lookup"}, "revoke": {"DELETE", "/revoke"}}},
		{"serviceDiscovery", b + "/service-discovery", unrestricted, map[string][2]string{
			"register": {"POST", "/register"}, "lookup": {"POST", "/lookup"}, "revoke": {"DELETE", "/revoke/{instanceId}"}}},
	}
}

func (rg *Registry) selfRequest(sv selfService) (*InstanceReq, error) {
	tmpl, policy := "generic_http", "NONE"
	if rg.cfg.SSLEnabled {
		tmpl = "generic_https"
	}
	// mutual TLS (certificate policy, or an outsourced registry requiring client certificates) is CERT_AUTH
	if rg.cfg.AuthenticationPolicy == "certificate" || (rg.cfg.SSLEnabled && rg.cfg.ClientAuthNeeded) {
		policy = "CERT_AUTH"
	}
	ops := map[string]any{}
	for k, v := range sv.ops {
		ops[k] = map[string]any{"method": v[0], "path": v[1]}
	}
	req := map[string]any{
		"systemName":            systemName,
		"serviceDefinitionName": sv.def,
		"version":               serviceVersion,
		"interfaces": []any{map[string]any{
			"templateName": tmpl,
			"policy":       policy,
			"properties": map[string]any{
				"accessAddresses": []any{rg.cfg.DomainName},
				"accessPort":      rg.cfg.ServerPort,
				"basePath":        sv.path,
				"operations":      ops,
			},
		}},
	}
	for _, extra := range rg.cfg.ExtraInterfaces {
		if extra.ServiceDefinition != sv.def {
			continue
		}
		req["interfaces"] = append(req["interfaces"].([]any), map[string]any{
			"templateName": extra.TemplateName,
			"protocol":     extra.Protocol,
			"policy":       extra.Policy,
			"properties": map[string]any{
				"accessAddresses": []any{extra.Address},
				"accessPort":      extra.Port,
				"basePath":        sv.path,
				"operations":      ops,
			},
		})
	}
	if mi := rg.mqttInterface(sv); mi != nil {
		req["interfaces"] = append(req["interfaces"].([]any), mi)
	}
	if sv.metadata != nil {
		req["metadata"] = sv.metadata
	}
	data, _ := json.Marshal(req)
	var out InstanceReq
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SelfRegister registers the ServiceRegistry system and its own services (idempotent: any previous
// registration is revoked first).
func (rg *Registry) SelfRegister() error {
	if _, err := rg.RevokeSystem(systemName); err != nil {
		return fmt.Errorf("revoke previous registration: %w", err)
	}
	if _, _, err := rg.RegisterSystem(systemName, &SystemRegisterReq{Version: systemVersion, Addresses: []string{rg.cfg.DomainName}}); err != nil {
		return fmt.Errorf("register system: %w", err)
	}
	for _, sv := range selfServices() {
		req, err := rg.selfRequest(sv)
		if err != nil {
			return err
		}
		if _, err := rg.RegisterService(req); err != nil {
			return fmt.Errorf("register service %s: %w", sv.def, err)
		}
	}
	if rg.cfg.SysMonitorEnabled {
		req, err := newSysMonitorPublisher(rg.cfg, rg).serviceRequest()
		if err != nil {
			return err
		}
		if _, err := rg.RegisterService(req); err != nil {
			return fmt.Errorf("register service sysMonitor: %w", err)
		}
	}
	rg.log.Infof("main", "%s %s registered its own services", systemName, systemVersion)
	return nil
}

// SelfRevoke removes the ServiceRegistry's own service instances.
func (rg *Registry) SelfRevoke() {
	for _, sv := range selfServices() {
		id := calcInstanceID(rg.rules.NormSystemName(systemName), rg.rules.NormServiceDef(sv.def), rg.rules.NormVersion(serviceVersion))
		if _, err := rg.RevokeService(systemName, id); err != nil {
			rg.log.Warnf("main", "revoking %s failed: %v", sv.def, err)
		}
	}
	if rg.cfg.SysMonitorEnabled {
		id := calcInstanceID(rg.rules.NormSystemName(systemName), rg.rules.NormServiceDef("sysMonitor"), rg.rules.NormVersion(serviceVersion))
		if _, err := rg.RevokeService(systemName, id); err != nil {
			rg.log.Warnf("main", "revoking sysMonitor failed: %v", err)
		}
	}
}

func buildTLS(cfg *Config) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(cfg.SSLCertFile, cfg.SSLKeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}
	tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	if cfg.SSLTrustFile != "" {
		pem, err := os.ReadFile(cfg.SSLTrustFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", cfg.SSLTrustFile)
		}
		tc.ClientCAs = pool
	}
	switch {
	case cfg.ClientAuthNeeded || cfg.AuthenticationPolicy == "certificate":
		tc.ClientAuth = tls.RequireAndVerifyClientCert
	case tc.ClientCAs != nil:
		tc.ClientAuth = tls.VerifyClientCertIfGiven
	}
	if cfg.SSLCRLFile != "" {
		// revocation (J4): client certificates of the cloud CA are checked against its CRL on every handshake
		crlFile := cfg.SSLCRLFile
		tc.VerifyConnection = func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return nil
			}
			return checkPeerRevocation(crlFile, s)
		}
	}
	return tc, nil
}

func main() {
	cfgFile := flag.String("config", "application.properties", "path of the properties file")
	// Endpoint principles: listening port = --server.port > SERVER_PORT > server.port in the file > default 8443.
	port := flag.Int("server.port", 0, "listening port; overrides SERVER_PORT and server.port in the properties file")
	flag.Parse()

	cfg, err := LoadConfig(*cfgFile)
	if err == nil && *port != 0 {
		if *port < 1 || *port > 65535 {
			err = fmt.Errorf("--server.port: listening port must be an integer in 1..65535")
		} else {
			cfg.ServerPort = *port
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "configuration error:", err)
		os.Exit(1)
	}
	log := NewLogger(cfg.LogBufferSize)
	store, err := NewStore(cfg.DataFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "store error:", err)
		os.Exit(1)
	}
	rg := NewRegistry(cfg, store, log)

	var tlsCfg *tls.Config
	if cfg.SSLEnabled {
		if tlsCfg, err = buildTLS(cfg); err != nil {
			fmt.Fprintln(os.Stderr, "TLS error:", err)
			os.Exit(1)
		}
	}
	auth := NewAuthenticator(cfg, rg, log, tlsCfg)
	srv := NewServer(cfg, rg, log, auth)

	addr := net.JoinHostPort(cfg.ServerAddress, strconv.Itoa(cfg.ServerPort))
	hs := &http.Server{Addr: addr, Handler: srv.Handler(), TLSConfig: tlsCfg, ReadHeaderTimeout: 10 * time.Second}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "listen error:", err)
		os.Exit(1)
	}
	errCh := make(chan error, 1)
	go func() {
		if cfg.SSLEnabled {
			errCh <- hs.ServeTLS(ln, "", "")
		} else {
			errCh <- hs.Serve(ln)
		}
	}()
	log.Infof("main", "ServiceRegistry %s listening on %s (ssl=%v, auth=%s)", systemVersion, addr, cfg.SSLEnabled, cfg.AuthenticationPolicy)

	if !cfg.StandaloneMode {
		if err := rg.SelfRegister(); err != nil {
			log.Errorf("main", "self registration failed: %v", err)
			_ = hs.Close()
			os.Exit(1)
		}
	}

	if cfg.MQTTEnabled {
		stopMQTT := startMQTT(cfg, srv, auth, tlsCfg)
		defer stopMQTT()
	}

	stopMonitor := make(chan struct{})
	if cfg.SysMonitorEnabled {
		go newSysMonitorPublisher(cfg, rg).run(stopMonitor)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Errorf("main", "server error: %v", err)
		}
	}
	close(stopMonitor)
	if !cfg.StandaloneMode {
		rg.SelfRevoke()
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = hs.Shutdown(sctx)
	log.Infof("main", "stopped")
}

// checkPeerRevocation re-reads the CRL file on every TLS connection (J4; same check as ah5-support-go): a revoked
// client certificate, or no current CRL of its issuer, refuses the handshake.
func checkPeerRevocation(path string, s tls.ConnectionState) error {
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
					return errors.New("certificate revoked")
				}
			}
			return nil
		}
	}
	return errors.New("no CRL matches the peer's issuer")
}
