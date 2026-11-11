package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds the settings of the service. Property names and defaults follow
// the Java reference implementation (application.properties / Defaults classes).
type Config struct {
	props map[string]string

	ServerAddress string
	ServerPort    int
	DomainName    string

	AuthenticationPolicy string // declared | certificate | outsourced
	EnableMgmtFilter     bool
	ManagementPolicy     string // sysop-only | whitelist | authorization
	ManagementWhitelist  []string
	EnableBlacklist      bool
	ForceBlacklist       bool
	BlacklistExclude     []string

	ServiceDiscoveryPolicy          string // open | restricted
	ServiceDiscoveryDirectAccess    []string
	DiscoveryVerbose                bool
	ServiceDiscoveryInterfacePolicy string // open | extendable | restricted
	AllowSelfAddressing             bool
	AllowNonRoutableAddressing      bool
	ServiceAddressAlias             []string
	MaxPageSize                     int
	NormalizationMode               string // simple | extended

	SSLEnabled       bool
	SSLCertFile      string              // PEM certificate chain of the server
	SSLKeyFile       string              // PEM private key of the server
	SSLTrustFile     string              // PEM CA bundle used to verify client certificates
	SSLCRLFile       string              // PEM CRL of the cloud CA; client certificates are checked on every handshake (J4)
	ReservedDefs     map[string][]string // service definition -> owning systems (J9)
	ClientAuthNeeded bool
	ServerCommonName string // CN of the server certificate (used for local cloud checks)

	AuthenticatorSecretKeys map[string]string
	AuthenticatorPassword   string

	DataFile         string // JSON snapshot file, empty = memory only
	LogBufferSize    int
	LogAllReqResp    bool
	StandaloneMode   bool // do not register ServiceRegistry itself
	HTTPClientTimout int  // milliseconds

	// native sysMonitor publisher (SysMonitor-MQTT-IDD-5.2.2)
	SysMonitorEnabled       bool
	SysMonitorBrokerAddress string
	SysMonitorBrokerPort    int
	SysMonitorLocalCloud    string
	SysMonitorExchange      string
	SysMonitorInterval      int // seconds
	SysMonitorCertFile      string
	SysMonitorKeyFile       string
	SysMonitorCAFile        string
	ExtraInterfaces         []ExtraInterface

	MQTTEnabled       bool
	MQTTBrokerAddress string
	MQTTBrokerPort    int
	MQTTTopicPrefix   string
}

var defaultProps = map[string]string{
	"server.address":                     "0.0.0.0",
	"server.port":                        "8443",
	"domain.name":                        "127.0.0.1",
	"authentication.policy":              "certificate",
	"enable.management.filter":           "false",
	"management.policy":                  "sysop-only",
	"management.whitelist":               "",
	"enable.blacklist.filter":            "false",
	"force.blacklist.filter":             "true",
	"blacklist.check.exclude.list":       "ServiceRegistry",
	"service.discovery.policy":           "restricted",
	"service.discovery.direct.access":    "",
	"discovery.verbose":                  "false",
	"service.discovery.interface.policy": "restricted",
	"allow.self.addressing":              "true",
	"allow.non.routable.addressing":      "true",
	"service.address.alias":              "",
	"max.page.size":                      "1000",
	"normalization.mode":                 "extended",
	"server.ssl.enabled":                 "false",
	"server.ssl.client-auth":             "none",
	"log.all.request.and.response":       "false",
	"http.client.socket.timeout":         "30000",
	"data.file":                          "",
	"log.buffer.size":                    "5000",
	"standalone.mode":                    "false",
	"sysmonitor.enabled":                 "false",
	// MQTT API (Java mqtt.api.enabled; mqtt.topic.prefix is a Go extension)
	"mqtt.api.enabled":            "false",
	"mqtt.broker.address":         "",
	"mqtt.broker.port":            "8883",
	"mqtt.topic.prefix":           "arrowhead/serviceregistry",
	"sysmonitor.broker.address":   "amqp-broker",
	"sysmonitor.broker.port":      "5671",
	"sysmonitor.exchange":         "arrowhead",
	"sysmonitor.local.cloud":      "TestCloud",
	"sysmonitor.publish.interval": "30",
	"sysmonitor.ssl.cert-file":    "",
	"sysmonitor.ssl.key-file":     "",
	"sysmonitor.ssl.ca-file":      "",
	// JSON list of additional interfaces for the registry's own services, registered at every start-up
	"service.registry.extra.interfaces": "[]",
}

// publicConfigKeys are the keys readable through generalManagement/get-config.
var publicConfigKeys = []string{
	"server.address", "server.port", "mqtt.api.enabled", "domain.name",
	"authentication.policy", "enable.management.filter", "management.policy",
	"enable.blacklist.filter", "force.blacklist.filter", "allow.self.addressing",
	"allow.non.routable.addressing", "max.page.size", "normalization.mode",
	"service.address.alias", "service.discovery.policy", "discovery.verbose",
	"service.discovery.interface.policy",
}

func parsePropertiesFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}
		idx := strings.IndexAny(line, "=:")
		if idx < 0 {
			continue
		}
		k := strings.TrimSpace(line[:idx])
		v := strings.TrimSpace(line[idx+1:])
		out[k] = v
	}
	return out, sc.Err()
}

// envKey converts a property name to its Spring-style environment variable name.
func envKey(k string) string {
	r := strings.NewReplacer(".", "_", "-", "_")
	return strings.ToUpper(r.Replace(k))
}

// LoadConfig reads defaults, then the properties file (if any), then environment variables.
func LoadConfig(file string) (*Config, error) {
	props := map[string]string{}
	for k, v := range defaultProps {
		props[k] = v
	}
	if file != "" {
		fp, err := parsePropertiesFile(file)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		} else {
			for k, v := range fp {
				props[k] = v
			}
		}
	}
	// environment overrides, e.g. DOMAIN_NAME, SERVER_PORT, SERVICE_DISCOVERY_POLICY
	known := map[string]bool{}
	for k := range props {
		known[k] = true
	}
	for _, k := range append(append([]string{}, publicConfigKeys...), "server.ssl.key-store", "authenticator.secret.keys", "authenticator.credentials", "server.ssl.cert-file", "server.ssl.key-file", "server.ssl.trust-file", "server.common.name", "mqtt.api.enabled") {
		known[k] = true
	}
	for k := range known {
		if v, ok := os.LookupEnv(envKey(k)); ok {
			props[k] = v
		}
	}
	for _, k := range []string{"server.ssl.crl-file", "service.definition.reserved"} {
		if v, ok := os.LookupEnv(envKey(k)); ok {
			props[k] = v
		}
	}
	// Secrets as files (J7): the identity password and Authentication's secret key are read from files, so that no
	// secret is in the container environment.
	if path := os.Getenv("AUTHENTICATOR_PASSWORD_FILE"); path != "" {
		v, err := readSecretFile(path)
		if err != nil {
			return nil, err
		}
		props["authenticator.credentials"] = "{'password':'" + v + "'}"
	}
	if path := os.Getenv("AUTHENTICATOR_SECRET_KEY_FILE"); path != "" {
		v, err := readSecretFile(path)
		if err != nil {
			return nil, err
		}
		props["authenticator.secret.keys"] = "{'Authentication':'" + v + "'}"
	}
	return NewConfig(props)
}

func boolProp(p map[string]string, k string) bool {
	return strings.EqualFold(strings.TrimSpace(p[k]), "true")
}

func listProp(p map[string]string, k string) []string {
	v := strings.TrimSpace(p[k])
	v = strings.Trim(v, "\"")
	if v == "" {
		return nil
	}
	var out []string
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// mapProp parses Spring-style map literals: {'a': 'b', 'c': 'd'}.
func mapProp(p map[string]string, k string) map[string]string {
	v := strings.TrimSpace(p[k])
	v = strings.TrimPrefix(v, "{")
	v = strings.TrimSuffix(v, "}")
	out := map[string]string{}
	for _, part := range strings.Split(v, ",") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.Trim(strings.TrimSpace(kv[0]), "'\"")
		val := strings.Trim(strings.TrimSpace(kv[1]), "'\"")
		if key != "" {
			out[key] = val
		}
	}
	return out
}

// NewConfig builds a Config from raw properties and validates enumerated values.
func NewConfig(props map[string]string) (*Config, error) {
	c := &Config{props: props}
	var err error
	atoi := func(k string) (int, error) {
		n, e := strconv.Atoi(strings.TrimSpace(props[k]))
		if e != nil {
			return 0, fmt.Errorf("property %s: %w", k, e)
		}
		return n, nil
	}
	c.ServerAddress = props["server.address"]
	if c.ServerPort, err = atoi("server.port"); err != nil {
		return nil, err
	}
	if c.ServerPort < 1 || c.ServerPort > 65535 {
		return nil, fmt.Errorf("property server.port: listening port must be an integer in 1..65535")
	}
	if c.MaxPageSize, err = atoi("max.page.size"); err != nil {
		return nil, err
	}
	if c.LogBufferSize, err = atoi("log.buffer.size"); err != nil {
		return nil, err
	}
	if c.HTTPClientTimout, err = atoi("http.client.socket.timeout"); err != nil {
		return nil, err
	}
	c.DomainName = props["domain.name"]
	c.AuthenticationPolicy = strings.ToLower(strings.TrimSpace(props["authentication.policy"]))
	if c.AuthenticationPolicy != "declared" && c.AuthenticationPolicy != "certificate" && c.AuthenticationPolicy != "outsourced" {
		return nil, fmt.Errorf("unsupported authentication.policy: %q", props["authentication.policy"])
	}
	c.EnableMgmtFilter = boolProp(props, "enable.management.filter")
	c.ManagementPolicy = strings.ToLower(strings.TrimSpace(props["management.policy"]))
	switch c.ManagementPolicy {
	case "sysop-only", "whitelist", "authorization":
	default:
		return nil, fmt.Errorf("unsupported management.policy: %q", props["management.policy"])
	}
	c.ManagementWhitelist = listProp(props, "management.whitelist")
	c.EnableBlacklist = boolProp(props, "enable.blacklist.filter")
	c.ForceBlacklist = boolProp(props, "force.blacklist.filter")
	c.BlacklistExclude = listProp(props, "blacklist.check.exclude.list")
	c.ServiceDiscoveryPolicy = strings.ToLower(strings.TrimSpace(props["service.discovery.policy"]))
	if c.ServiceDiscoveryPolicy != "open" && c.ServiceDiscoveryPolicy != "restricted" {
		return nil, fmt.Errorf("unsupported service.discovery.policy: %q", props["service.discovery.policy"])
	}
	c.ServiceDiscoveryDirectAccess = listProp(props, "service.discovery.direct.access")
	c.DiscoveryVerbose = boolProp(props, "discovery.verbose")
	c.ServiceDiscoveryInterfacePolicy = strings.ToLower(strings.TrimSpace(props["service.discovery.interface.policy"]))
	switch c.ServiceDiscoveryInterfacePolicy {
	case "open", "extendable", "restricted":
	default:
		return nil, fmt.Errorf("unsupported service.discovery.interface.policy: %q", props["service.discovery.interface.policy"])
	}
	c.AllowSelfAddressing = boolProp(props, "allow.self.addressing")
	c.AllowNonRoutableAddressing = boolProp(props, "allow.non.routable.addressing")
	c.ServiceAddressAlias = listProp(props, "service.address.alias")
	c.NormalizationMode = strings.ToLower(strings.TrimSpace(props["normalization.mode"]))
	if c.NormalizationMode != "simple" && c.NormalizationMode != "extended" {
		return nil, fmt.Errorf("unsupported normalization.mode: %q", props["normalization.mode"])
	}
	c.SSLEnabled = boolProp(props, "server.ssl.enabled")
	c.SSLCertFile = props["server.ssl.cert-file"]
	c.SSLKeyFile = props["server.ssl.key-file"]
	c.SSLTrustFile = props["server.ssl.trust-file"]
	c.SSLCRLFile = props["server.ssl.crl-file"]
	reserved, err := parseReservedDefs(props["service.definition.reserved"])
	if err != nil {
		return nil, err
	}
	c.ReservedDefs = reserved
	c.ClientAuthNeeded = strings.EqualFold(strings.TrimSpace(props["server.ssl.client-auth"]), "need")
	c.ServerCommonName = props["server.common.name"]
	c.AuthenticatorSecretKeys = mapProp(props, "authenticator.secret.keys")
	creds := mapProp(props, "authenticator.credentials")
	c.AuthenticatorPassword = creds["password"]
	c.DataFile = props["data.file"]
	c.LogAllReqResp = boolProp(props, "log.all.request.and.response")
	c.StandaloneMode = boolProp(props, "standalone.mode")
	c.SysMonitorEnabled = boolProp(props, "sysmonitor.enabled")
	c.SysMonitorBrokerAddress = props["sysmonitor.broker.address"]
	c.SysMonitorLocalCloud = props["sysmonitor.local.cloud"]
	c.SysMonitorExchange = props["sysmonitor.exchange"]
	c.SysMonitorCertFile = props["sysmonitor.ssl.cert-file"]
	c.SysMonitorKeyFile = props["sysmonitor.ssl.key-file"]
	c.SysMonitorCAFile = props["sysmonitor.ssl.ca-file"]
	if c.ExtraInterfaces, err = parseExtraInterfaces(props["service.registry.extra.interfaces"]); err != nil {
		return nil, err
	}
	if c.SysMonitorBrokerPort, err = atoi("sysmonitor.broker.port"); err != nil {
		return nil, err
	}
	if c.SysMonitorInterval, err = atoi("sysmonitor.publish.interval"); err != nil {
		return nil, err
	}
	c.MQTTEnabled = boolProp(props, "mqtt.api.enabled")
	c.MQTTBrokerAddress = strings.TrimSpace(props["mqtt.broker.address"])
	c.MQTTTopicPrefix = strings.TrimSuffix(strings.TrimSpace(props["mqtt.topic.prefix"]), "/")
	if c.MQTTBrokerPort, err = atoi("mqtt.broker.port"); err != nil {
		return nil, err
	}
	if c.MQTTEnabled && (c.MQTTBrokerAddress == "" || !c.SSLEnabled || c.AuthenticationPolicy != "outsourced") {
		return nil, fmt.Errorf("mqtt.api.enabled requires mqtt.broker.address, server.ssl.enabled and authentication.policy=outsourced")
	}
	if c.AuthenticationPolicy == "certificate" && !c.SSLEnabled {
		return nil, fmt.Errorf("authentication.policy=certificate requires server.ssl.enabled=true")
	}
	return c, nil
}

// PublicConfig returns the effective value of every public key.
func (c *Config) PublicConfig() map[string]string {
	out := map[string]string{}
	for _, k := range publicConfigKeys {
		if v, ok := c.props[k]; ok {
			out[k] = v
		} else if k == "mqtt.api.enabled" {
			out[k] = "false"
		}
	}
	return out
}

// ExtraInterface is an additional ingress of one of the registry's own services (for example a private mTLS
// gateway). Base path and operations are copied from the service's native interface.
type ExtraInterface struct {
	ServiceDefinition string `json:"serviceDefinition"`
	TemplateName      string `json:"templateName"`
	Protocol          string `json:"protocol"`
	Policy            string `json:"policy"`
	Address           string `json:"address"`
	Port              int    `json:"port"`
}

func parseExtraInterfaces(raw string) ([]ExtraInterface, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var out []ExtraInterface
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, fmt.Errorf("invalid service.registry.extra.interfaces: %w", err)
	}
	for i := range out {
		e := &out[i]
		if e.ServiceDefinition == "" || e.TemplateName == "" || e.Address == "" || e.Port <= 0 {
			return nil, fmt.Errorf("invalid service.registry.extra.interfaces: serviceDefinition, templateName, address and port are mandatory")
		}
		if e.Protocol == "" {
			e.Protocol = "http"
			if strings.HasSuffix(e.TemplateName, "s") {
				e.Protocol = "https"
			}
		}
		if e.Policy == "" {
			e.Policy = "NONE"
		}
	}
	return out, nil
}

func readSecretFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading secret file: %w", err)
	}
	v := strings.TrimRight(string(b), "\r\n")
	if v == "" || strings.ContainsAny(v, "'{}") {
		return "", fmt.Errorf("secret file %s is empty or contains quotes or braces", path)
	}
	return v, nil
}

// reservedDefsDefault: core and support service definitions may only be registered by their owning systems
// (security finding J9; the same table as the Java ServiceRegistry). Shared definitions (generalManagement,
// sysMonitor) are not listed.
var reservedDefsDefault = map[string][]string{
	"serviceOrchestrationPlantManagement": {"DynamicServiceOrchestration"},
	"serviceDiscovery":                    {"ServiceRegistry"}, "systemDiscovery": {"ServiceRegistry"}, "deviceDiscovery": {"ServiceRegistry"},
	"serviceRegistryManagement": {"ServiceRegistry"},
	"identity":                  {"Authentication"}, "identityManagement": {"Authentication"},
	"authorization": {"ConsumerAuthorization"}, "authorizationManagement": {"ConsumerAuthorization"},
	"authorizationToken": {"ConsumerAuthorization"}, "authorizationTokenManagement": {"ConsumerAuthorization"},
	"serviceOrchestration":                      {"DynamicServiceOrchestration", "SimpleStoreServiceOrchestration"},
	"serviceOrchestrationHistoryManagement":     {"DynamicServiceOrchestration", "SimpleStoreServiceOrchestration"},
	"serviceOrchestrationPushManagement":        {"DynamicServiceOrchestration", "SimpleStoreServiceOrchestration"},
	"serviceOrchestrationLockManagement":        {"DynamicServiceOrchestration"},
	"serviceOrchestrationSimpleStoreManagement": {"SimpleStoreServiceOrchestration"},
	"certificateSigning":                        {"CertificateAuthority"}, "certificateValidation": {"CertificateAuthority"},
	"certificateAuthorityManagement": {"CertificateAuthority"},
	"onboarding":                     {"Onboarding"}, "onboardingManagement": {"Onboarding"},
	"blacklistDiscovery": {"Blacklist"}, "blacklistManagement": {"Blacklist"},
	"globalServiceDiscovery": {"Gatekeeper"}, "interCloudNegotiation": {"Gatekeeper"}, "gatekeeperManagement": {"Gatekeeper"},
	"gateTunnelConnection": {"GateTunnel"}, "gateTunnelKey": {"GateTunnel"}, "gateTunnelManagement": {"GateTunnel"},
	"translationBridge": {"TranslationManager"}, "translationBridgeManagement": {"TranslationManager"},
	"translationReport": {"TranslationManager"},
	"qualityEvaluation": {"DeviceQoSEvaluator"}, "deviceQualityDataManagement": {"DeviceQoSEvaluator"},
	"dataHistorian": {"DataManager"}, "dataProxy": {"DataManager"},
	"eventPublish": {"EventHandler"}, "eventSubscription": {"EventHandler"}, "eventHandlerManagement": {"EventHandler"},
	"time":          {"TimeManager"},
	"configuration": {"Configuration"}, "configurationProxy": {"Configuration"}, "configurationManagement": {"Configuration"},
	"choreographerSession": {"Choreographer"}, "choreographerExecutor": {"Choreographer"}, "choreographerManagement": {"Choreographer"},
	"plantDescriptionManagement": {"PlantDescriptionEngine"}, "plantDescriptionMonitor": {"PlantDescriptionEngine"},
	"sysMonitorData": {"SysMonitor"}, "sysMonitorHistory": {"SysMonitor"}, "sysMonitorManagement": {"SysMonitor"},
	"aiGym":                {"AIGym"},
	"localCloudManagement": {"LocalCloudManager"},
}

// parseReservedDefs merges service.definition.reserved ("<definition>:<Owner>[|<Owner>...],..."; an empty owner list
// lifts a reservation) into the default table.
func parseReservedDefs(raw string) (map[string][]string, error) {
	out := map[string][]string{}
	for k, v := range reservedDefsDefault {
		out[k] = v
	}
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		def, owners, ok := strings.Cut(entry, ":")
		def = strings.TrimSpace(def)
		if !ok || def == "" {
			return nil, fmt.Errorf("service.definition.reserved entry must be <definition>:<Owner>[|<Owner>...]: %s", entry)
		}
		names := []string{}
		for _, n := range strings.Split(owners, "|") {
			if n = strings.TrimSpace(n); n != "" {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			delete(out, def)
		} else {
			out[def] = names
		}
	}
	return out, nil
}
