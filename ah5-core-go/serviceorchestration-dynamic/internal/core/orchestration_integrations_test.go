// SPDX-License-Identifier: EPL-2.0
package core

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"
)

// integrationCloud is the isolated cloud with a ServiceRegistry that also lists a TranslationManager and a
// DeviceQoSEvaluator; providers is what a temperature lookup returns.
type integrationCloud struct {
	*testCloud
	mu        sync.Mutex
	providers []Document
	lookups   []Document
	calls     []string
}

func endpointOf(t *testing.T, s *httptest.Server) (string, float64) {
	u, e := url.Parse(s.URL)
	if e != nil {
		t.Fatal(e)
	}
	port, _ := strconv.Atoi(u.Port())
	return u.Hostname(), float64(port)
}

func newIntegrationCloud(t *testing.T) *integrationCloud {
	f := &integrationCloud{testCloud: isolatedCloud(t)}
	record := func(r *http.Request) Document {
		var body Document
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.calls = append(f.calls, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.Header.Get("Authorization") == "" {
			t.Errorf("%s without identity token", r.URL.Path)
		}
		return body
	}
	tm := serveTLS(t, f.pki, "TranslationManager", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := record(r)
		switch r.URL.Path {
		case "/translation/bridge/mgmt/discovery":
			if str(body, "consumer") != "Consumer" || str(body, "operation") != "read" || len(list(body, "candidates")) == 0 {
				respond(w, 400, Document{})
				return
			}
			candidates := []Document{}
			for _, raw := range list(body, "candidates") {
				c := raw.(map[string]any)
				for _, ri := range list(c, "interfaces") {
					if str(ri.(map[string]any), "templateName") == "generic_https" {
						t.Errorf("native interface sent to translation discovery: %v", c)
					}
					candidates = append(candidates, Document{"serviceInstanceId": c["instanceId"], "interfaceTemplateName": str(ri.(map[string]any), "templateName")})
				}
			}
			respond(w, 200, Document{"bridgeId": "bridge-1", "candidates": candidates})
		case "/translation/bridge/mgmt/negotiation":
			respond(w, 200, Document{"bridgeId": body["bridgeId"], "bridgeInterface": Document{"templateName": "generic_https", "protocol": "https", "policy": "TRANSLATION_BRIDGE_TOKEN_AUTH", "properties": Document{"accessAddresses": []string{"translator"}, "accessPort": 9000, "basePath": "/bridge-1", "operations": Document{"read": Document{"method": "GET", "path": "/"}}}}, "tokenUsageLimit": 10, "tokenExpiresAt": "2030-01-01T00:00:00Z"})
		default:
			respond(w, 404, Document{})
		}
	}))
	qos := serveTLS(t, f.pki, "DeviceQoSEvaluator", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := record(r)
		providers := list(body, "providers")
		switch r.URL.Path {
		case "/deviceqosevaluator/qualityevaluation/sort": // reverse order
			sorted := []any{}
			for i := len(providers) - 1; i >= 0; i-- {
				sorted = append(sorted, providers[i])
			}
			respond(w, 200, Document{"sortedProviders": sorted})
		case "/deviceqosevaluator/qualityevaluation/filter": // keep providers named in requirements.allow
			passed := []any{}
			for _, p := range providers {
				if contains(list(obj(body, "configuration"), "allow"), p.(string)) {
					passed = append(passed, p)
				}
			}
			respond(w, 200, Document{"passedProviders": passed})
		default:
			respond(w, 404, Document{})
		}
	}))
	tmHost, tmPort := endpointOf(t, tm)
	qosHost, qosPort := endpointOf(t, qos)
	registry := serveTLS(t, f.pki, "ServiceRegistry", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var lookup Document
		_ = json.NewDecoder(r.Body).Decode(&lookup)
		f.mu.Lock()
		f.lookups = append(f.lookups, lookup)
		providers := f.providers
		f.mu.Unlock()
		entries := []Document{}
		switch list(lookup, "serviceDefinitionNames")[0] {
		case "temperature":
			entries = providers
		case "translationBridgeManagement":
			entries = append(entries, Document{"instanceId": "TranslationManager|translationBridgeManagement|1.0.0", "provider": Document{"name": "TranslationManager"}, "interfaces": []Document{{"templateName": "generic_https", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{tmHost}, "accessPort": tmPort, "basePath": "/translation", "operations": Document{"discovery": Document{"method": "POST", "path": "/bridge/mgmt/discovery"}, "negotiation": Document{"method": "POST", "path": "/bridge/mgmt/negotiation"}}}}}})
		case "qualityEvaluation":
			req, _ := list(lookup, "metadataRequirementsList")[0].(map[string]any)
			if str(req, "evaluationType") == "basic-device-kpi" {
				entries = append(entries, Document{"instanceId": "DeviceQoSEvaluator|qualityEvaluation|1.0.0", "provider": Document{"name": "DeviceQoSEvaluator"}, "metadata": Document{"evaluationType": "basic-device-kpi"}, "interfaces": []Document{{"templateName": "generic_https", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{qosHost}, "accessPort": qosPort, "basePath": "/deviceqosevaluator", "operations": Document{"filter": Document{"method": "POST", "path": "/qualityevaluation/filter"}, "sort": Document{"method": "POST", "path": "/qualityevaluation/sort"}}}}}})
			}
		}
		respond(w, 200, Document{"entries": entries, "count": len(entries)})
	}))
	f.dynamic.Config.ServiceRegistryURL = registry.URL
	f.dynamic.Remote = NewRemote(f.dynamic.Config, f.dynamic.TLS)
	grants := []Document{}
	for _, p := range []string{"Provider", "Provider2", "Provider3"} {
		grants = append(grants, Document{"provider": p, "targetType": "SERVICE_DEF", "target": "temperature", "defaultPolicy": Document{"policyType": "WHITELIST", "policyList": []string{"Consumer"}}})
	}
	f.call(t, "Sysop", "ConsumerAuthorization", f.authzURL, "POST", "/consumerauthorization/authorization/mgmt/grant", Document{"list": grants})
	return f
}

func temperatureProvider(name string, interfaces ...Document) Document {
	return Document{"instanceId": name + "|temperature|1.0.0", "provider": Document{"name": name}, "serviceDefinition": Document{"name": "temperature"}, "version": "1.0.0", "metadata": Document{}, "interfaces": interfaces}
}

var (
	httpsRead = Document{"templateName": "generic_https", "protocol": "https", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{"10.0.0.1"}, "accessPort": 8080, "operations": Document{"read": Document{"method": "GET", "path": "/"}}}}
	mqttsRead = Document{"templateName": "generic_mqtts", "protocol": "mqtts", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{"broker"}, "accessPort": 8883, "operations": []string{"read"}}}
)

func (f *integrationCloud) pull(t *testing.T, body Document) Document {
	t.Helper()
	return f.call(t, "Consumer", "Orchestrator", f.dynamicURL, "POST", "/serviceorchestration/orchestration/pull", body)
}

func resultProviders(result Document) []string {
	out := []string{}
	for _, r := range list(result, "results") {
		out = append(out, str(r.(map[string]any), "providerName"))
	}
	return out
}

func TestTranslationBridgeWhenNoNativeInterface(t *testing.T) {
	f := newIntegrationCloud(t)
	f.providers = []Document{temperatureProvider("Provider", mqttsRead)}
	result := f.pull(t, Document{"serviceRequirement": Document{"serviceDefinition": "temperature", "operations": []string{"read"}, "interfaceTemplateNames": []string{"generic_https"}}, "orchestrationFlags": Document{"ALLOW_TRANSLATION": true}})
	results := list(result, "results")
	if len(results) != 1 {
		t.Fatal(result)
	}
	entry := results[0].(map[string]any)
	intf := list(entry, "interfaces")[0].(map[string]any)
	if str(intf, "policy") != "TRANSLATION_BRIDGE_TOKEN_AUTH" || str(obj(intf, "properties"), "basePath") != "/bridge-1" {
		t.Fatal(entry)
	}
	token := obj(obj(obj(entry, "authorizationTokens"), "TRANSLATION_BRIDGE_TOKEN_AUTH"), "read")
	if str(token, "token") != "bridge-1" || str(token, "tokenType") != "TRANSLATION_BRIDGE_TOKEN" || str(token, "targetType") != "SERVICE_DEF" || number(token, "usageLimit", 0) != 10 {
		t.Fatal(entry)
	}
	if w := list(result, "warnings"); len(w) != 2 || w[0] != warnAutoMatchmaking || w[1] != warnForcedInterfacePolicy {
		t.Fatal(result)
	}
	// the interface filters are applied by the orchestrator, not by the lookup
	if _, ok := f.lookups[0]["interfaceTemplateNames"]; ok {
		t.Fatal(f.lookups[0])
	}
	if !containsString(f.calls, "POST /translation/bridge/mgmt/discovery") || !containsString(f.calls, "POST /translation/bridge/mgmt/negotiation") {
		t.Fatal(f.calls)
	}
}

func TestTranslationNativeCandidateWins(t *testing.T) {
	f := newIntegrationCloud(t)
	f.providers = []Document{temperatureProvider("Provider", mqttsRead), temperatureProvider("Provider2", mqttsRead, httpsRead)}
	result := f.pull(t, Document{"serviceRequirement": Document{"serviceDefinition": "temperature", "operations": []string{"read"}, "interfaceTemplateNames": []string{"generic_https"}}, "orchestrationFlags": Document{"ALLOW_TRANSLATION": true}})
	if p := resultProviders(result); len(p) != 1 || p[0] != "Provider2" {
		t.Fatal(result)
	}
	entry := list(result, "results")[0].(map[string]any)
	if is := list(entry, "interfaces"); len(is) != 1 || str(is[0].(map[string]any), "templateName") != "generic_https" {
		t.Fatal(entry)
	}
	if len(f.calls) != 0 {
		t.Fatal("TranslationManager consulted although a native candidate exists", f.calls)
	}
}

func TestTranslationValidation(t *testing.T) {
	f := newIntegrationCloud(t)
	token, _ := f.clients["Consumer"].ownToken(t.Context())
	for _, body := range []Document{
		{"serviceRequirement": Document{"serviceDefinition": "temperature", "interfaceTemplateNames": []string{"generic_https"}}, "orchestrationFlags": Document{"ALLOW_TRANSLATION": true}},
		{"serviceRequirement": Document{"serviceDefinition": "temperature", "operations": []string{"read"}}, "orchestrationFlags": Document{"ALLOW_TRANSLATION": true}},
		{"serviceRequirement": Document{"serviceDefinition": "temperature", "operations": []string{"read"}, "interfaceTemplateNames": []string{"generic_https"}}, "orchestrationFlags": Document{"ALLOW_TRANSLATION": true, "ONLY_INTERCLOUD": true}},
		{"serviceRequirement": Document{"serviceDefinition": "temperature"}, "qualityRequirements": []Document{{"type": "basic-device-kpi", "operation": "RANK"}}},
	} {
		e := f.clients["Consumer"].request(t.Context(), "Orchestrator", f.dynamicURL, "POST", "/serviceorchestration/orchestration/pull", token, body, nil)
		if ae, ok := e.(*APIError); !ok || ae.Status != 400 {
			t.Fatal(body, e)
		}
	}
}

func TestQualityRequirementsSortAndFilter(t *testing.T) {
	f := newIntegrationCloud(t)
	f.providers = []Document{temperatureProvider("Provider", httpsRead), temperatureProvider("Provider2", httpsRead), temperatureProvider("Provider3", httpsRead)}
	sorted := f.pull(t, Document{"serviceRequirement": Document{"serviceDefinition": "temperature"}, "qualityRequirements": []Document{{"type": "basic-device-kpi", "operation": "SORT", "requirements": Document{"metricNames": []string{"cpu"}, "metricWeights": []float64{1}}}}})
	// candidates come in instance id order (Provider2, Provider3, Provider); the evaluator reverses them
	if p := resultProviders(sorted); len(p) != 3 || p[0] != "Provider" || p[1] != "Provider3" || p[2] != "Provider2" || len(list(sorted, "warnings")) != 0 {
		t.Fatal(sorted)
	}
	filtered := f.pull(t, Document{"serviceRequirement": Document{"serviceDefinition": "temperature"}, "orchestrationFlags": Document{"MATCHMAKING": true}, "qualityRequirements": []Document{
		{"type": "basic-device-kpi", "operation": "filter", "requirements": Document{"allow": []string{"Provider", "Provider2"}}},
		{"type": "basic-device-kpi", "operation": "sort"},
	}})
	// filter leaves Provider2, Provider; sort reverses them; matchmaking takes the first
	if p := resultProviders(filtered); len(p) != 1 || p[0] != "Provider" {
		t.Fatal(filtered)
	}
	// no evaluator of the requested type: the candidates stay as they are, with a warning
	unknown := f.pull(t, Document{"serviceRequirement": Document{"serviceDefinition": "temperature"}, "qualityRequirements": []Document{{"type": "other-kpi", "operation": "FILTER"}}})
	if p := resultProviders(unknown); len(p) != 3 || len(list(unknown, "warnings")) != 1 || list(unknown, "warnings")[0] != warnQoSComplianceFailure {
		t.Fatal(unknown)
	}
}

func containsString(values []string, s string) bool {
	for _, v := range values {
		if v == s {
			return true
		}
	}
	return false
}
