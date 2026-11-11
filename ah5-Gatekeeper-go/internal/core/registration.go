// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

type Service struct {
	Definition, BasePath string
	Operations           map[string]Document
}

func (a *App) Services() []Service {
	groups := map[string]*Service{}
	for _, r := range a.Routes {
		if r.Path == "/health" || r.Access == "bridge" {
			continue
		} // Local readiness endpoint and translation bridges (created per bridge), not Arrowhead services.
		def, op := a.contractOf(r)
		s := groups[def]
		if s == nil {
			basePath := a.base()
			if def == "plantDescriptionManagement" {
				basePath += "/mgmt"
			}
			s = &Service{Definition: def, BasePath: basePath, Operations: map[string]Document{}}
			groups[def] = s
		}
		key := op
		if _, exists := s.Operations[key]; exists {
			key = strings.ToLower(r.Method) + "-" + op
		}
		opPath := strings.TrimPrefix(r.Path, s.BasePath)
		if a.Config.Role == "TestTranslation" {
			// as the reference translators: path parameters are appended to the registered path
			for strings.HasSuffix(opPath, "}") && strings.Contains(opPath, "/{") {
				opPath = opPath[:strings.LastIndex(opPath, "/{")]
			}
		}
		s.Operations[key] = Document{"method": r.Method, "path": opPath}
		// Read aliases keep the earlier Go names next to the Java ones for existing consumers.
		if def == "plantDescriptionManagement" {
			aliases := map[string]string{"query": "query-plant-descriptions", "get": "get-plant-description"}
			if alias := aliases[op]; alias != "" {
				s.Operations[alias] = s.Operations[key]
			}
		}
	}
	out := []Service{}
	for _, s := range groups {
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Definition < out[j].Definition })
	return out
}

// Published operation names are contracts, not names inferred from URL spelling.
// contractOf returns the registered service definition and operation of a route (used for registration and for
// the authorization management policy).
func (a *App) contractOf(r Route) (string, string) {
	def, op := r.Service, r.Operation
	if def == "" {
		def = Systems[a.Config.Role].Services[0]
		switch {
		case strings.Contains(r.Path, "/general/mgmt/"):
			def = "generalManagement"
		case strings.HasSuffix(r.Path, "/monitor/echo") || strings.HasSuffix(r.Path, "/echo"):
			def = "echo"
		case strings.Contains(r.Path, "/mgmt/") || strings.Contains(r.Path, "/management/"):
			for _, name := range Systems[a.Config.Role].Services {
				if strings.HasSuffix(name, "Management") {
					def = name
					break
				}
			}
		}
		if a.Config.Role == "CertificateAuthority" && (strings.Contains(r.Path, "/check") || strings.HasSuffix(r.Path, "/crl")) {
			def = "certificateValidation"
		}
		if a.Config.Role == "SysMonitor" && strings.Contains(r.Path, "/history/") {
			def = "sysMonitorHistory"
		}
		op = operationName(r)
	}
	if d, o := a.routeContract(r); d != "" {
		def, op = d, o
	}
	return def, op
}

func (a *App) routeContract(r Route) (string, string) {
	p := strings.TrimPrefix(r.Path, a.base())
	if p == "/echo" || p == "/monitor/echo" {
		return "echo", "echo"
	}
	key := r.Method + " " + p
	var def string
	var ops map[string]string
	switch a.Config.Role {
	case "CertificateAuthority":
		if strings.HasPrefix(p, "/mgmt/") {
			def = "certificateAuthorityManagement"
		} else {
			def = "certificateValidation"
		}
		if p == "/sign" {
			return "certificateSigning", "sign"
		}
		ops = map[string]string{"POST /checkCertificate": "check-certificate", "POST /checkTrustedKey": "check-trusted-key", "GET /crl": "get-crl", "GET /mgmt/certificates": "list-certificates", "GET /mgmt/keys": "list-keys", "PUT /mgmt/keys": "add-key", "DELETE /mgmt/certificates/{id}": "revoke-certificate", "DELETE /mgmt/keys/{id}": "delete-key", "POST /mgmt/revocations": "revoke-certificate-by-content"}
	case "Gatekeeper":
		if p == "/init_gsd" {
			return "globalServiceDiscovery", "query"
		}
		if p == "/init_multi_gsd" {
			return "globalServiceDiscovery", "multi-query"
		}
		if p == "/init_icn" {
			return "interCloudNegotiation", "negotiate"
		}
		def = "gatekeeperManagement"
		ops = map[string]string{"GET /mgmt/clouds": "clouds", "POST /mgmt/clouds": "add-cloud", "DELETE /mgmt/clouds/{operator}/{name}": "remove-cloud", "GET /mgmt/relays": "relays", "GET /mgmt/status": "status", "POST /mgmt/relays": "add-relay"}
	case "GateTunnel":
		if p == "/publickey" {
			return "gateTunnelKey", "public-key"
		}
		def = "gateTunnelConnection"
		if strings.HasPrefix(p, "/mgmt/") {
			def = "gateTunnelManagement"
		}
		ops = map[string]string{"POST /connect_provider": "connect-provider", "POST /connect_consumer": "connect-consumer", "POST /close_sessions": "close-sessions", "GET /mgmt/sessions": "sessions", "GET /mgmt/status": "status", "POST /mgmt/sessions/close": "close", "POST /intercloud/provider": "open-provider-session", "POST /intercloud/consumer": "open-consumer-session"}
	case "Configuration":
		def = "configurationManagement"
		ops = map[string]string{"GET /mgmt/config": "list-configurations", "PUT /mgmt/config/{systemName}": "store-configuration", "DELETE /mgmt/config/{systemName}": "remove-configuration"}
	case "Blacklist":
		def = "blacklistManagement"
		ops = map[string]string{"POST /mgmt/create": "create", "POST /mgmt/query": "query", "DELETE /mgmt/remove": "remove"}
	case "SysMonitor":
		def = "sysMonitorManagement"
		ops = map[string]string{"GET /management/status": "status", "GET /management/providers": "providers", "GET /management/subscriptions": "subscriptions", "PUT /management/subscriptions/{providerSystem}": "subscribe", "DELETE /management/subscriptions/{providerSystem}": "unsubscribe", "POST /management/reconcile": "reconcile"}
	case "TranslationManager":
		if p == "/event/report" {
			return "translationReport", "report"
		}
		def = "translationBridge"
		if strings.Contains(p, "/mgmt/") {
			def = "translationBridgeManagement"
		}
		ops = map[string]string{"POST /bridge/discovery": "discovery", "POST /bridge/negotiation": "negotiation", "DELETE /bridge/abort/{bridgeId}": "abort", "POST /bridge/mgmt/discovery": "discovery", "POST /bridge/mgmt/negotiation": "negotiation", "POST /bridge/mgmt/query": "query", "DELETE /bridge/mgmt/abort": "abort"}
	case "PlantDescriptionEngine":
		if p == "/mgmt/sync-status" {
			return "plantDescriptionManagement", "sync-status"
		}
		def = "plantDescriptionManagement"
		if strings.HasPrefix(p, "/monitor/") {
			def = "plantDescriptionMonitor"
		}
		// operation names follow the Java reference: short on the management service, qualified on the monitor
		if strings.Contains(p, "plant-descriptions") && def == "plantDescriptionManagement" {
			ops = map[string]string{"GET /mgmt/plant-descriptions": "query", "GET /mgmt/plant-descriptions/{id}": "get", "POST /mgmt/plant-descriptions": "create", "PUT /mgmt/plant-descriptions/{id}": "replace", "PATCH /mgmt/plant-descriptions/{id}": "update", "DELETE /mgmt/plant-descriptions/{id}": "remove"}
		} else if strings.Contains(p, "plant-descriptions") {
			if r.Method == "GET" && strings.HasSuffix(p, "/{id}") {
				return def, "get-plant-description"
			}
			if r.Method == "GET" {
				return def, "query-plant-descriptions"
			}
		}
	case "Onboarding":
		def = "onboarding"
		if strings.HasPrefix(p, "/mgmt/") {
			def = "onboardingManagement"
		}
		ops = map[string]string{"POST /certificate/name": "onboard-with-name", "POST /certificate/csr": "onboard-with-csr", "POST /device": "onboard-device", "POST /system": "onboard-system", "POST /device/offboard": "offboard-device", "PUT /mgmt/enrollments/{deviceName}": "approve-device", "POST /mgmt/enrollments/{deviceName}/offboard": "offboard-device", "DELETE /mgmt/enrollments/{deviceName}": "remove-enrollment"}
	case "EventHandler":
		def = "eventHandlerManagement"
		ops = map[string]string{"PUT /management/subscriptions/{subscriptionId}": "update-subscription", "DELETE /management/subscriptions/{subscriptionId}": "remove-subscription"}
	case "Choreographer":
		if p == "/session/start" {
			return "choreographerSession", "start-session"
		}
		if p == "/session/abort/{id}" {
			return "choreographerSession", "abort-session"
		}
		def = "choreographerManagement"
		ops = map[string]string{"POST /mgmt/sessions/start": "start-sessions", "DELETE /mgmt/sessions/{id}": "abort-session", "GET /mgmt/plans/{id}/check": "check-plan"}
		for _, table := range []string{"plans", "sessions", "session-steps", "worklog", "executors"} {
			singular := strings.TrimSuffix(table, "s")
			ops["GET /mgmt/"+table] = "query-" + table
			ops["GET /mgmt/"+table+"/{id}"] = "get-" + singular
			ops["POST /mgmt/"+table] = "create-" + singular
			if table != "sessions" {
				ops["DELETE /mgmt/"+table+"/{id}"] = "remove-" + singular
			}
		}
	}
	if op := ops[key]; op != "" {
		return def, op
	}
	return "", ""
}
func operationName(r Route) string {
	if strings.HasSuffix(r.Path, "/general/mgmt/logs") {
		return "get-log"
	}
	if strings.HasSuffix(r.Path, "/general/mgmt/get-config") {
		return "get-config"
	}
	p := strings.Split(strings.Trim(r.Path, "/"), "/")
	last := p[len(p)-1]
	if strings.HasPrefix(last, "{") && len(p) > 1 {
		last = p[len(p)-2]
		if r.Method == "GET" {
			return "get-" + strings.TrimSuffix(last, "s")
		}
	}
	switch r.Method {
	case "GET":
		return "query-" + last
	case "POST":
		return last
	case "PUT":
		return "update-" + last
	case "PATCH":
		return "modify-" + last
	case "DELETE":
		return "remove-" + last
	}
	return last
}
func (a *App) Register(ctx context.Context) error {
	if a.Config.AdvertiseAddress == "" || a.Config.AdvertisePort < 1 || a.Config.AdvertisePort > 65535 {
		return bad("Registration requires advertised address/port")
	}
	if e := a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/system-discovery/register", Document{"version": "5.2.2", "addresses": []string{a.Config.AdvertiseAddress}, "metadata": Document{"implementation": "Go"}}, nil); e != nil {
		return e
	}
	for _, s := range a.Services() {
		var metadata Document
		if s.Definition == "blacklistDiscovery" { // other systems' Blacklist filters look it up under restricted discovery
			metadata = Document{"unrestrictedDiscovery": true}
		}
		if a.Config.Role == "TestTranslation" {
			metadata = testTranslationMetadataFor(s.Definition, a.Config.MQTTURL != "")
		}
		props := Document{"accessAddresses": []string{a.Config.AdvertiseAddress}, "accessPort": a.Config.AdvertisePort, "basePath": s.BasePath, "operations": s.Operations}
		if s.Definition == "dataHistorian" {
			// data models of the operations, used by the TranslationManager to decide on data model translation
			props["dataModels"] = Document{"get-data": Document{"output": "senml"}, "put-data": Document{"input": "senml"}}
		}
		intf := Document{"templateName": "generic_https", "protocol": "https", "policy": "CERT_AUTH", "properties": props}
		if e := a.registerService(ctx, s.Definition, intf, metadata); e != nil {
			return e
		}
		if a.Config.Role == "TestTranslation" && s.Definition == "interfaceBridgeManagement" && a.Config.MQTTURL != "" {
			// HTTPS -> MQTT bridges: a second instance, as the interfaceBridge "to" is a single template
			if e := a.registerServiceVersion(ctx, s.Definition, "1.1.0", intf, testTranslationMQTTTargetMetadata()); e != nil {
				return e
			}
		}
	}
	if a.Config.MonitorEnabled {
		u, e := url.Parse(a.Config.AMQPURL)
		if e != nil || u.Scheme != "amqps" {
			return bad("Native monitoring requires amqps broker URL")
		}
		port := 5671
		if u.Port() != "" {
			port, e = strconv.Atoi(u.Port())
			if e != nil {
				return e
			}
		}
		cloud := strings.Split(a.Config.CloudSuffix, ".")[0]
		if e = a.registerService(ctx, "sysMonitor", Document{"templateName": "generic_amqps", "protocol": "amqps", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{u.Hostname()}, "accessPort": port, "exchange": "arrowhead", "baseRoutingKey": cloud + ".sysmonitor." + a.Config.Name + "." + a.Config.Name, "operations": []string{"echo", "power", "status"}}}, Document{"publisherMode": "native", "observationTypes": []string{"echo", "power", "status"}}); e != nil {
			return e
		}
	}
	if a.Config.Role == "SysMonitor" && a.Config.MQTTURL != "" {
		u, e := url.Parse(a.Config.MQTTURL)
		if e != nil || u.Scheme != "ssl" {
			return bad("MQTT output requires ssl URL")
		}
		port := 8883
		if u.Port() != "" {
			port, e = strconv.Atoi(u.Port())
			if e != nil {
				return e
			}
		}
		return a.registerService(ctx, "sysMonitorData", Document{"templateName": "generic_mqtts", "protocol": "ssl", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{u.Hostname()}, "accessPort": port, "baseTopic": "arrowhead/" + strings.Split(a.Config.CloudSuffix, ".")[0] + "/sysmonitor/data", "operations": []string{"subscribe"}}}, Document{"schemaVersion": "1.0"})
	}
	return nil
}
func (a *App) registerService(ctx context.Context, def string, intf, metadata Document) error {
	// as in the Java reference: the Gatekeeper and GateTunnel services are 5.2.2, everything else (sysMonitor
	// included) 1.0.0
	version := "1.0.0"
	if (a.Config.Role == "Gatekeeper" || a.Config.Role == "GateTunnel") && def != "sysMonitor" {
		version = "5.2.2"
	}
	return a.registerServiceVersion(ctx, def, version, intf, metadata)
}
func (a *App) registerServiceVersion(ctx context.Context, def, version string, intf, metadata Document) error {
	return a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/service-discovery/register", Document{"systemName": a.Config.Name, "serviceDefinitionName": def, "version": version, "metadata": metadata, "interfaces": []Document{intf}}, nil)
}
