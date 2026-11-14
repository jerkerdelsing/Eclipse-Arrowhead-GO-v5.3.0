package cloud

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type ServiceSpec struct {
	Definition string
	BasePath   string
	Operations []string
	Protocol   string
}

type RoleSpec struct {
	SystemName string
	Port       int
	Services   []ServiceSpec
}

var roleSpecs = map[string]RoleSpec{
	"serviceregistry":       {"ServiceRegistry", 8443, []ServiceSpec{{"deviceDiscovery", "/serviceregistry/device-discovery", []string{"register", "lookup", "revoke"}, "http"}, {"systemDiscovery", "/serviceregistry/system-discovery", []string{"register", "lookup", "revoke"}, "http"}, {"serviceDiscovery", "/serviceregistry/service-discovery", []string{"register", "lookup", "revoke"}, "http"}, {"serviceRegistryManagement", "/serviceregistry/mgmt", []string{"manage"}, "http"}, {"echo", "/serviceregistry/monitor", []string{"echo"}, "http"}}},
	"authentication":        {"Authentication", 8444, []ServiceSpec{{"identity", "/authentication/identity", []string{"login", "logout", "change", "verify"}, "http"}, {"authenticationManagement", "/authentication/mgmt", []string{"manage-identities", "manage-sessions"}, "http"}, {"echo", "/authentication/monitor", []string{"echo"}, "http"}}},
	"authorization":         {"ConsumerAuthorization", 8445, []ServiceSpec{{"consumerAuthorization", "/authorization", []string{"grant", "revoke", "lookup", "verify"}, "http"}, {"authorizationToken", "/authorization/token", []string{"generate", "verify", "public-key"}, "http"}, {"authorizationManagement", "/authorization/mgmt", []string{"grant", "revoke", "query", "check"}, "http"}, {"echo", "/authorization/monitor", []string{"echo"}, "http"}}},
	"orchestration-dynamic": {"DynamicServiceOrchestration", 8441, []ServiceSpec{{"serviceOrchestration", "/orchestration", []string{"pull", "push-subscribe", "push-unsubscribe"}, "http"}, {"orchestrationPushManagement", "/orchestration/mgmt/push", []string{"subscribe", "trigger", "query"}, "http"}, {"orchestrationLockManagement", "/orchestration/mgmt/lock", []string{"create", "query", "remove"}, "http"}, {"orchestrationHistoryManagement", "/orchestration/mgmt/history", []string{"query"}, "http"}, {"echo", "/orchestration/monitor", []string{"echo"}, "http"}}},
	"orchestration-simple":  {"SimpleStoreServiceOrchestration", 8456, []ServiceSpec{{"serviceOrchestration", "/orchestration", []string{"pull"}, "http"}, {"orchestrationStoreManagement", "/orchestration/mgmt/store", []string{"create", "query", "remove"}, "http"}, {"echo", "/orchestration/monitor", []string{"echo"}, "http"}}},
	"datamanager":           {"DataManager", 8461, []ServiceSpec{{"dataProxy", "/datamanager/proxy", []string{"systems", "services", "data-read", "data-write"}, "http"}, {"historian", "/datamanager/historian", []string{"systems", "services", "data-read", "data-write"}, "http"}, {"monitoringHistorian", "/datamanager/historian", []string{"store", "query"}, "http"}, {"echo", "/datamanager/monitor", []string{"echo"}, "http"}}},
	"eventhandler":          {"EventHandler", 8455, []ServiceSpec{{"eventSubscription", "/eventhandler/subscription", []string{"subscribe", "unsubscribe"}, "http"}, {"eventPublish", "/eventhandler/publish", []string{"publish"}, "http"}, {"eventHandlerManagement", "/eventhandler/mgmt", []string{"manage-subscriptions"}, "http"}, {"echo", "/eventhandler/monitor", []string{"echo"}, "http"}}},
	"onboarding":            {"Onboarding", 8476, []ServiceSpec{{"onboardingWithName", "/onboarding/certificate/name", []string{"onboard"}, "http"}, {"onboardingWithCSR", "/onboarding/certificate/csr", []string{"onboard"}, "http"}, {"onboardingWithSharedSecret", "/onboarding/sharedsecret", []string{"onboard"}, "http"}, {"echo", "/onboarding", []string{"echo"}, "http"}}},
	"blacklist":             {"Blacklist", 8464, []ServiceSpec{{"blacklisting", "/blacklist", []string{"check", "query"}, "http"}, {"blacklistManagement", "/blacklist/mgmt", []string{"create", "remove", "query"}, "http"}, {"echo", "/blacklist/monitor", []string{"echo"}, "http"}}},
	"translationmanager":    {"TranslationManager", 8465, []ServiceSpec{{"translation", "/translation", []string{"translate"}, "http"}, {"translationManagement", "/translation/mgmt", []string{"create", "remove", "query"}, "http"}, {"echo", "/translation/monitor", []string{"echo"}, "http"}}},
	"deviceqos":             {"DeviceQoSEvaluator", 8472, []ServiceSpec{{"deviceQoSEvaluation", "/device-qos", []string{"evaluate"}, "http"}, {"deviceQoSManagement", "/device-qos/mgmt", []string{"create", "remove", "query"}, "http"}, {"echo", "/device-qos/monitor", []string{"echo"}, "http"}}},
	"certificateauthority":  {"CertificateAuthority", 8477, []ServiceSpec{{"certificateAuthority", "/certificate-authority", []string{"issue-certificate", "get-ca-certificate", "verify-certificate"}, "http"}, {"certificateAuthorityManagement", "/certificate-authority/mgmt", []string{"manage-certificates", "manage-keys"}, "http"}, {"echo", "/certificate-authority/monitor", []string{"echo"}, "http"}}},
	"gatekeeper":            {"Gatekeeper", 8449, []ServiceSpec{{"globalServiceDiscovery", "/gatekeeper/init_gsd", []string{"discover"}, "http"}, {"interCloudNegotiation", "/gatekeeper/init_icn", []string{"negotiate"}, "http"}, {"gatekeeperManagement", "/gatekeeper/mgmt", []string{"manage-clouds", "manage-relays"}, "http"}, {"echo", "/gatekeeper/monitor", []string{"echo"}, "http"}}},
	"gatetunnel":            {"GateTunnel", 8453, []ServiceSpec{{"gateTunnelConnection", "/gatetunnel", []string{"connect-provider", "connect-consumer", "close-sessions"}, "http"}, {"gateTunnelKey", "/gatetunnel/publickey", []string{"get-public-key"}, "http"}, {"gateTunnelManagement", "/gatetunnel/mgmt", []string{"query-sessions"}, "http"}, {"echo", "/gatetunnel/monitor", []string{"echo"}, "http"}}},
	"sysmonitor":            {"SysMonitor", 8475, []ServiceSpec{{"sysMonitorData", "/sysmonitor/data", []string{"subscribe", "query"}, "http"}, {"sysMonitorManagement", "/sysmonitor/mgmt", []string{"subscriptions", "status"}, "http"}, {"echo", "/sysmonitor/monitor", []string{"echo"}, "http"}}},
	"aigym":                 {"AIGym", 8478, []ServiceSpec{{"aiGym", "/aigym", []string{"status", "add-sample", "predict", "observations"}, "http"}, {"echo", "/aigym/monitor", []string{"echo"}, "http"}}},
	"localcloudmanager":     {"LocalCloudManager", 8480, []ServiceSpec{{"localCloudManagement", "/api", []string{"session", "overview", "service-registry-management", "datamanager", "consumers", "intercloud", "sysmonitor", "sysmonitor-subscriptions", "plantdescriptions", "orchestration-rules", "create-orchestration-rule", "remove-orchestration-rule", "logs", "lifecycle"}, "http"}, {"monitor", "/localcloud/monitor", []string{"echo"}, "http"}}},
	"configuration":         {"Configuration", 8459, []ServiceSpec{{"configuration", "/configuration", []string{"get", "set", "query"}, "http"}, {"configurationManagement", "/configuration/mgmt", []string{"create", "update", "remove"}, "http"}, {"echo", "/configuration/monitor", []string{"echo"}, "http"}}},
	"choreographer":         {"Choreographer", 8457, []ServiceSpec{{"choreography", "/choreographer", []string{"create", "start", "stop", "status"}, "http"}, {"choreographerManagement", "/choreographer/mgmt", []string{"query", "remove"}, "http"}, {"echo", "/choreographer/monitor", []string{"echo"}, "http"}}},
	"timemanager":           {"TimeManager", 8463, []ServiceSpec{{"time", "/timemanager", []string{"current-time", "convert"}, "http"}, {"echo", "/timemanager/monitor", []string{"echo"}, "http"}}},
	"plantdescription":      {"PlantDescriptionEngine", 8432, []ServiceSpec{{"plantDescription", "/plant-description-engine", []string{"create", "get", "query", "validate"}, "http"}, {"plantDescriptionManagement", "/plant-description-engine/mgmt", []string{"update", "remove"}, "http"}, {"echo", "/plant-description-engine/monitor", []string{"echo"}, "http"}}},
}

type Config struct {
	Role, SystemName, Domain, RegistryURL, DataFile, TokenSecret   string
	Port                                                           int
	Management                                                     []string
	Secure                                                         bool
	Cloud, Organization, AuthenticationURL, AuthenticationPassword string
	CertFile, KeyFile, CAFile, CRLFile, AuthenticationCN           string
}

type App struct {
	Config         Config
	Store          *Store
	client         *http.Client
	authClient     *http.Client
	tlsConfig      *tls.Config
	identityMu     sync.Mutex
	identityToken  string
	identityExpiry time.Time
	federation     *Federation
}

func NewFromEnv() (*App, error) {
	role := strings.ToLower(env("ARROWHEAD_ROLE", "serviceregistry"))
	spec, ok := roleSpecs[role]
	if !ok {
		return nil, fmt.Errorf("unknown ARROWHEAD_ROLE %q", role)
	}
	port, err := strconv.Atoi(env("SERVER_PORT", env("PORT", strconv.Itoa(spec.Port))))
	if err != nil {
		return nil, fmt.Errorf("SERVER_PORT: %w", err)
	}
	if port < 1 || port > 65535 {
		return nil, errors.New("SERVER_PORT: listening port must be an integer in 1..65535")
	}
	cfg := Config{Role: role, SystemName: env("SYSTEM_NAME", spec.SystemName), Domain: env("DOMAIN_NAME", role), RegistryURL: strings.TrimRight(env("SERVICE_REGISTRY_URL", "http://serviceregistry:8443"), "/"), DataFile: env("DATA_FILE", "/data/state.json"), TokenSecret: env("TOKEN_SECRET", "replace-test-cloud-secret"), Port: port, Management: csv(env("MANAGEMENT_WHITELIST", "LocalCloudManager,Authentication,DynamicServiceOrchestration"))}
	cfg.Secure = env("ALLOW_INSECURE_DEVELOPMENT", "false") != "true"
	cfg.Cloud, cfg.Organization = env("LOCAL_CLOUD", "GoCloud"), env("ORGANIZATION", "Company")
	cfg.AuthenticationURL = strings.TrimRight(env("AUTHENTICATION_URL", "https://authentication:8444"), "/")
	cfg.AuthenticationPassword = os.Getenv("AUTHENTICATION_PASSWORD")
	cfg.CertFile, cfg.KeyFile = env("TLS_SERVER_CERT", "/certs/"+role+".crt"), env("TLS_SERVER_KEY", "/certs/"+role+".key")
	cfg.CAFile, cfg.CRLFile = env("TLS_CA_CERT", "/certs/ca.crt"), os.Getenv("TLS_CRL_FILE")
	cfg.AuthenticationCN = "Authentication." + cfg.Cloud + "." + cfg.Organization + ".arrowhead.eu"
	if cfg.Secure && !strings.HasPrefix(cfg.RegistryURL, "https://") {
		return nil, errors.New("secure mode requires an HTTPS SERVICE_REGISTRY_URL")
	}
	store, err := OpenStore(cfg.DataFile)
	if err != nil {
		return nil, err
	}
	app := &App{Config: cfg, Store: store, client: &http.Client{Timeout: 5 * time.Second}}
	if cfg.Secure {
		if err := app.configureTLS(); err != nil {
			return nil, err
		}
	}
	if role == "gatekeeper" || role == "gatetunnel" {
		f, err := newFederation(app)
		if err != nil {
			return nil, err
		}
		app.federation = f
	}
	if err := app.seed(); err != nil {
		return nil, err
	}
	return app, nil
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
func csv(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if strings.TrimSpace(s) != "" {
			out = append(out, strings.TrimSpace(s))
		}
	}
	return out
}

func (a *App) seed() error {
	a.Store.mu.Lock()
	defer a.Store.mu.Unlock()
	if a.Config.Role == "authentication" {
		defaults := ""
		if !a.Config.Secure {
			defaults = "LocalCloudManager=changeme,DynamicServiceOrchestration=changeme"
		}
		if a.Config.Secure && len(a.Store.Data.Identities) == 0 && os.Getenv("INITIAL_IDENTITIES") == "" {
			return errors.New("secure Authentication requires explicitly provisioned identities")
		}
		for _, item := range csv(env("INITIAL_IDENTITIES", defaults)) {
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 {
				continue
			}
			if _, ok := a.Store.Data.Identities[parts[0]]; !ok {
				a.Store.Data.Identities[parts[0]] = Identity{SystemName: parts[0], Credentials: map[string]string{"password": parts[1]}, CreatedAt: now()}
			}
		}
	}
	if a.Config.Role == "serviceregistry" {
		a.upsertLocalRegistrationLocked(roleSpecs["serviceregistry"])
	}
	return a.Store.SaveLocked()
}

func (a *App) Run() error {
	if a.Config.Secure && env("SYSMONITOR_ENABLED", "false") == "true" {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go a.monitoringLoop(ctx)
	}
	if a.federation != nil {
		if err := a.federation.Start(); err != nil {
			return err
		}
		defer a.federation.Close()
		if port := os.Getenv("HEALTH_PORT"); port != "" {
			health := &http.Server{Addr: ":" + port, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/health" {
					apiError(w, 426, "mutual TLS is required", r.URL.Path)
					return
				}
				jsonOut(w, 200, a.federation.Status())
			}), ReadHeaderTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second}
			go func() {
				if err := health.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					log.Printf("health listener failed: %v", err)
				}
			}()
			defer health.Close()
		}
	}
	if a.Config.Role != "serviceregistry" {
		go a.registrationLoop()
	}
	srv := &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", a.Config.Port), Handler: a, TLSConfig: a.tlsConfig, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	errch := make(chan error, 1)
	go func() {
		log.Printf("%s (%s) listening on %s", a.Config.SystemName, a.Config.Role, srv.Addr)
		if a.Config.Secure {
			errch <- srv.ListenAndServeTLS("", "")
		} else {
			errch <- srv.ListenAndServe()
		}
	}()
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errch:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(ctx)
	}
}

func (a *App) registrationLoop() {
	for {
		if err := a.register(); err != nil {
			log.Printf("registration pending: %v", err)
		}
		time.Sleep(20 * time.Second)
	}
}

func (a *App) register() error {
	spec := roleSpecs[a.Config.Role]
	headers := map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName}
	sys := map[string]any{"version": "5.4.0", "addresses": []string{a.Config.Domain}, "metadata": map[string]any{"implementation": "go", "role": a.Config.Role}}
	if a.federation != nil {
		if a.Config.Role == "gatekeeper" {
			sys["metadata"] = map[string]any{"role": "inter-cloud-gatekeeper", "sourceCompatibility": "4.6.2"}
		} else {
			sys["metadata"] = map[string]any{"role": "secure-inter-cloud-tunnel", "replaces": "Gateway-4.6.2"}
		}
	}
	if a.Config.Role == "localcloudmanager" && a.Config.Secure && a.tlsConfig != nil {
  certificate, err := x509.ParseCertificate(a.tlsConfig.Certificates[0].Certificate[0]); if err != nil { return err }
  publicKey, err := x509.MarshalPKIXPublicKey(certificate.PublicKey); if err != nil { return err }
  object(sys["metadata"])["x509PublicKey"] = base64.StdEncoding.EncodeToString(publicKey)
  object(sys["metadata"])["consumerInterfaceTemplates"] = "generic_https"
 }
	if _, err := a.call(http.MethodPost, a.Config.RegistryURL+"/serviceregistry/system-discovery/register", sys, headers); err != nil {
		return err
	}
	for _, ss := range spec.Services {
		protocol := ss.Protocol
		if protocol == "" {
			protocol = "http"
		}
		policy := "NONE"
		if a.Config.Secure {
			protocol, policy = "https", "CERT_AUTH"
		}
		base, version := ss.BasePath, "1.0.0"
		if a.federation != nil {
			base = "/" + a.Config.Role
			version = "5.2.2"
		}
		body := map[string]any{"systemName": a.Config.SystemName, "serviceDefinitionName": ss.Definition, "version": version, "metadata": map[string]any{"operations": ss.Operations, "implementation": "go"}, "interfaces": []any{map[string]any{"templateName": "generic_" + protocol, "protocol": strings.ToUpper(protocol), "policy": policy, "properties": map[string]any{"accessAddresses": []string{a.Config.Domain}, "accessPort": a.Config.Port, "basePath": base, "operations": serviceOperations(ss)}}}}
		if _, err := a.call(http.MethodPost, a.Config.RegistryURL+"/serviceregistry/service-discovery/register", body, headers); err != nil {
			return err
		}
	}
	if a.Config.Secure && env("SYSMONITOR_ENABLED", "false") == "true" {
		_, err := a.call(http.MethodPost, a.Config.RegistryURL+"/serviceregistry/service-discovery/register", a.monitoringRegistration(), nil)
		return err
	}
	return nil
}

func (a *App) call(method, url string, body any, headers map[string]string) ([]byte, error) {
	if a.Config.Secure {
		if !strings.HasPrefix(url, "https://") {
			return nil, errors.New("refusing cleartext service call")
		}
		token, err := a.ownToken()
		if err != nil {
			return nil, err
		}
		copyHeaders := map[string]string{}
		for k, v := range headers {
			copyHeaders[k] = v
		}
		copyHeaders["Authorization"] = "Bearer IDENTITY-TOKEN//" + token
		data, err := a.rawCall(method, url, body, copyHeaders)
		var failure *serviceCallError
		if errors.As(err, &failure) && failure.status == http.StatusUnauthorized {
			a.identityMu.Lock()
			if a.identityToken == token {
				a.identityExpiry = time.Time{}
			}
			a.identityMu.Unlock()
			refreshed, refreshErr := a.ownToken()
			if refreshErr != nil {
				return nil, refreshErr
			}
			copyHeaders["Authorization"] = "Bearer IDENTITY-TOKEN//" + refreshed
			return a.rawCall(method, url, body, copyHeaders)
		}
		return data, err
	}
	return a.rawCall(method, url, body, headers)
}

type serviceCallError struct{ status int }

func (e *serviceCallError) Error() string { return fmt.Sprintf("service returned HTTP %d", e.status) }

func (a *App) rawCall(method, url string, body any, headers map[string]string) ([]byte, error) {
	if a.Config.Secure && !strings.HasPrefix(url, "https://") {
		return nil, errors.New("cleartext service calls are disabled")
	}
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	client := a.client
	if a.authClient != nil && strings.HasPrefix(url, a.Config.AuthenticationURL+"/") {
		client = a.authClient
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if res.StatusCode/100 != 2 {
		return nil, &serviceCallError{status: res.StatusCode}
	}
	return b, nil
}

func (a *App) upsertLocalRegistrationLocked(spec RoleSpec) {
	t := now()
	sys := System{Name: spec.SystemName, Metadata: map[string]any{"implementation": "go"}, Version: "5.4.0", Addresses: []Address{{Type: "HOSTNAME", Address: a.Config.Domain}}, CreatedAt: t, UpdatedAt: t}
	a.Store.Data.Systems[sys.Name] = sys
	for _, ss := range spec.Services {
		d := Definition{Name: ss.Definition, CreatedAt: t, UpdatedAt: t}
		a.Store.Data.Definitions[d.Name] = d
		id := sys.Name + "|" + ss.Definition + "|1.0.0"
		a.Store.Data.Services[id] = Service{InstanceID: id, Provider: sys, ServiceDefinition: d, Version: "1.0.0", Metadata: map[string]any{"operations": ss.Operations, "implementation": "go"}, Interfaces: []Interface{{TemplateName: "generic_http", Protocol: "HTTP", Policy: "NONE", Properties: map[string]any{"accessAddresses": []string{a.Config.Domain}, "accessPort": a.Config.Port, "basePath": ss.BasePath}}}, CreatedAt: t, UpdatedAt: t}
	}
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if a.Config.Role == "localcloudmanager" {
		if r.Method == http.MethodGet && serveManagerAsset(w, r.URL.Path) {
			return
		}
		if a.managerAPI(w, r) {
			return
		}
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	if r.URL.Path == "/health" {
		if a.federation != nil {
			jsonOut(w, 200, a.federation.Status())
		} else {
			jsonOut(w, 200, a.runtimeConfig())
		}
		return
	}
	if a.Config.Secure {
		if _, err := a.certificateIdentity(r); err != nil {
			apiError(w, 401, err.Error(), r.URL.Path)
			return
		}
		if strings.Contains(r.URL.Path, "/mgmt/") || strings.Contains(r.URL.Path, "/management/") {
			if _, err := a.manager(r); err != nil {
				apiError(w, 403, err.Error(), r.URL.Path)
				return
			}
		}
	}
	if strings.HasSuffix(r.URL.Path, "/echo") {
		if _, err := a.requester(r); err != nil {
			apiError(w, 401, err.Error(), r.URL.Path)
			return
		}
		text(w, 200, "Got it!")
		return
	}
	switch a.Config.Role {
	case "serviceregistry":
		a.registryHTTP(w, r)
	case "authentication":
		a.authenticationHTTP(w, r)
	case "authorization":
		a.authorizationHTTP(w, r)
	case "orchestration-dynamic", "orchestration-simple":
		a.orchestrationHTTP(w, r)
	case "datamanager":
		a.dataManagerHTTP(w, r)
	case "eventhandler":
		a.eventHTTP(w, r)
	case "onboarding", "certificateauthority":
		a.certificateHTTP(w, r)
	default:
		a.supportHTTP(w, r)
	}
}

func (a *App) requester(r *http.Request) (string, error) {
	if a.Config.Secure {
		return a.secureRequester(r)
	}
	v := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if strings.HasPrefix(v, "SYSTEM//") && len(v) > 7 {
		return strings.TrimPrefix(v, "SYSTEM//"), nil
	}
	if v == "" {
		return "", errors.New("missing Arrowhead identity")
	}
	if a.Config.Role == "authentication" {
		a.Store.mu.RLock()
		defer a.Store.mu.RUnlock()
		if s, ok := a.Store.Data.Sessions[v]; ok && s.ExpirationTime > now() {
			return s.SystemName, nil
		}
	}
	b, err := a.call(http.MethodGet, env("AUTHENTICATION_URL", "http://authentication:8444")+"/authentication/identity/verify/"+v, nil, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
	if err != nil {
		return "", errors.New("invalid Arrowhead identity")
	}
	var out map[string]any
	if json.Unmarshal(b, &out) != nil {
		return "", errors.New("invalid Arrowhead identity")
	}
	n, _ := out["systemName"].(string)
	if n == "" {
		return "", errors.New("invalid Arrowhead identity")
	}
	return n, nil
}

func (a *App) manager(r *http.Request) (string, error) {
	n, e := a.requester(r)
	if e != nil {
		return "", e
	}
	for _, v := range a.Config.Management {
		if strings.EqualFold(n, v) {
			return n, nil
		}
	}
	return "", fmt.Errorf("system %s is not allowed to use management services", n)
}

func decode(r *http.Request, dst any) error {
	defer r.Body.Close()
	d := json.NewDecoder(io.LimitReader(r.Body, 4<<20))
	d.UseNumber()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func text(w http.ResponseWriter, status int, v string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, v)
}
func apiError(w http.ResponseWriter, status int, msg, origin string) {
	jsonOut(w, status, map[string]any{"errorMessage": msg, "errorCode": status, "exceptionType": http.StatusText(status), "origin": origin})
}
func randomID() string {
	b := make([]byte, 18)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func mapString(v any) string { s, _ := v.(string); return s }
func stringSlice(v any) []string {
	var out []string
	if values, ok := v.([]any); ok {
		for _, x := range values {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}
func containsFold(xs []string, s string) bool {
	if len(xs) == 0 {
		return true
	}
	for _, x := range xs {
		if strings.EqualFold(x, s) {
			return true
		}
	}
	return false
}
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func generateCertificate(name string) (map[string]any, error) {
	key, err := rsaKey()
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, DNSNames: []string{name}}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	sum := sha256.Sum256(der)
	return map[string]any{"certificate": string(cert), "privateKey": string(priv), "certificateChain": []string{string(cert)}, "fingerprint": fmt.Sprintf("%x", sum[:]), "commonName": name, "expiresAt": tmpl.NotAfter.UTC().Format(time.RFC3339)}, nil
}

func rsaKey() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }
