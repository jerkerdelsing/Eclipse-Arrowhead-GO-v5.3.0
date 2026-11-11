// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"sort"
	"strings"
)

// Integrations of DynamicServiceOrchestration with TranslationManager (ALLOW_TRANSLATION) and DeviceQoSEvaluator
// (qualityRequirements), after the Java LocalServiceOrchestration and QoSDriver. Both systems are found by a
// ServiceRegistry lookup of their service definition; no address is configured.

const (
	warnAutoMatchmaking       = "autoMatchmaking"
	warnQoSComplianceFailure  = "qosComplianceFailure"
	warnForcedInterfacePolicy = "forcedInterfaceSecurityPolicy"
)

// validateTranslation applies the Java OrchestrationFromContextValidation rules for ALLOW_TRANSLATION.
func validateTranslation(requirement, flags Document) error {
	if !flag(flags, "ALLOW_TRANSLATION") {
		return nil
	}
	if flag(flags, "ONLY_INTERCLOUD") {
		return bad("ONLY_INTERCLOUD and ALLOW_TRANSLATION flags cannot be present at the same time")
	}
	if len(list(requirement, "operations")) != 1 {
		return bad("Exactly one operation must be defined when translation is allowed")
	}
	if len(list(requirement, "interfaceTemplateNames")) == 0 {
		return bad("Interface template name(s) must be defined when translation is allowed")
	}
	return nil
}

// qosRequirements validates qualityRequirements: [{type, operation: SORT|FILTER, requirements: {...}}].
func qosRequirements(req Document) ([]Document, error) {
	out := []Document{}
	for _, raw := range list(req, "qualityRequirements") {
		q, ok := raw.(map[string]any)
		if !ok || strings.TrimSpace(str(q, "type")) == "" {
			return nil, bad("Quality requirement type is missing")
		}
		if op := strings.ToUpper(str(q, "operation")); op != "SORT" && op != "FILTER" {
			return nil, bad("Quality requirement operation must be SORT or FILTER")
		}
		if v, present := q["requirements"]; present && v != nil {
			if _, ok := v.(map[string]any); !ok {
				return nil, bad("Quality requirement requirements must be an object")
			}
		}
		out = append(out, q)
	}
	return out, nil
}

// interfaceMatches reports whether an offered interface meets the requested template names, property requirements
// and (when the ServiceRegistry did not filter them) address types.
func interfaceMatches(requirement, intf Document, checkAddressTypes bool) (bool, error) {
	if templates := list(requirement, "interfaceTemplateNames"); len(templates) > 0 && !contains(templates, str(intf, "templateName")) {
		return false, nil
	}
	if reqs := list(requirement, "interfacePropertyRequirements"); len(reqs) > 0 {
		matched := false
		for _, raw := range reqs {
			r, ok := raw.(map[string]any)
			if !ok {
				return false, bad("interfacePropertyRequirements must be objects")
			}
			m, e := metadataMatch(obj(intf, "properties"), r)
			if e != nil {
				return false, e
			}
			matched = matched || m
		}
		if !matched {
			return false, nil
		}
	}
	if types := list(requirement, "interfaceAddressTypes"); checkAddressTypes && len(types) > 0 {
		for _, a := range list(obj(intf, "properties"), "accessAddresses") {
			if s, ok := a.(string); ok && contains(types, addressType(s)) {
				return true, nil
			}
		}
		return false, nil
	}
	return true, nil
}

func addressType(address string) string {
	if ip := net.ParseIP(address); ip != nil {
		if ip.To4() != nil {
			return "IPV4"
		}
		return "IPV6"
	}
	if _, e := net.ParseMAC(address); e == nil {
		return "MAC"
	}
	return "HOSTNAME"
}

// dataModelIDs returns the interface's dataModels.<operation>.input/output identifiers (empty when absent).
func dataModelIDs(properties Document, operation string) (string, string) {
	in, _ := metadataValue(properties, "dataModels."+operation+".input").(string)
	out, _ := metadataValue(properties, "dataModels."+operation+".output").(string)
	return in, out
}

// requestedDataModelIDs extracts the dataModels.<operation>.input/output equality requirements of the requester.
func requestedDataModelIDs(requirement Document, operation string) (string, string) {
	in, out := "", ""
	for _, raw := range list(requirement, "interfacePropertyRequirements") {
		r, _ := raw.(map[string]any)
		for k, v := range r {
			value := v
			if m, ok := v.(map[string]any); ok {
				if !strings.EqualFold(str(m, "op"), "EQUALS") {
					continue
				}
				value = m["value"]
			}
			s, ok := value.(string)
			if !ok {
				continue
			}
			switch k {
			case "dataModels." + operation + ".input":
				if in == "" {
					in = s
				}
			case "dataModels." + operation + ".output":
				if out == "" {
					out = s
				}
			}
		}
	}
	return in, out
}

// translatableInterfaces returns the interfaces of a non-native candidate that a bridge could translate to: the
// interfaces that do not match the template or property requirements (e.g. another template, or the accepted
// template with another data model) and whose data models agree with the requested ones (Java
// assortInterfacesAndMarkIfNonNative). An interface matching template and properties is never translatable.
func translatableInterfaces(requirement, row Document) []any {
	operation, _ := list(requirement, "operations")[0].(string)
	wantIn, wantOut := requestedDataModelIDs(requirement, operation)
	out := []any{}
	for _, raw := range list(row, "interfaces") {
		intf, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if native, e := interfaceMatches(requirement, intf, false); e != nil || native {
			continue
		}
		in, o := dataModelIDs(obj(intf, "properties"), operation)
		if (wantIn != "") != (in != "") || (wantOut != "") != (o != "") {
			continue
		}
		out = append(out, intf)
	}
	return out
}

// discoveredEndpoint is an HTTP operation of a provider found in the ServiceRegistry.
type discoveredEndpoint struct {
	provider, base, method, path string
}

// discover looks up one CERT_AUTH/NONE generic_https instance of definition (optionally with metadata requirements)
// and resolves operation into an endpoint; nil when no instance offers it.
func (a *App) discover(ctx context.Context, definition, operation string, metadata Document) (*discoveredEndpoint, error) {
	lookup := Document{"serviceDefinitionNames": []string{definition}, "interfaceTemplateNames": []string{"generic_https"}, "policies": []string{"CERT_AUTH", "NONE"}}
	if metadata != nil {
		lookup["metadataRequirementsList"] = []Document{metadata}
	}
	var found Document
	if e := a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/service-discovery/lookup", lookup, &found); e != nil {
		return nil, e
	}
	entries := list(found, "entries")
	sort.SliceStable(entries, func(i, j int) bool {
		x, _ := entries[i].(map[string]any)
		y, _ := entries[j].(map[string]any)
		return str(x, "instanceId") < str(y, "instanceId")
	})
	for _, raw := range entries {
		row, _ := raw.(map[string]any)
		provider := str(obj(row, "provider"), "name")
		for _, ri := range list(row, "interfaces") {
			intf, _ := ri.(map[string]any)
			props := obj(intf, "properties")
			op := obj(obj(props, "operations"), operation)
			addresses := list(props, "accessAddresses")
			port := number(props, "accessPort", 0)
			if str(intf, "templateName") != "generic_https" || op == nil || len(addresses) == 0 || port < 1 || port > 65535 || !validName(provider) {
				continue
			}
			host, _ := addresses[0].(string)
			if host == "" {
				continue
			}
			base := (&url.URL{Scheme: "https", Host: net.JoinHostPort(host, fmt.Sprint(port))}).String() + str(props, "basePath")
			return &discoveredEndpoint{provider: provider, base: base, method: str(op, "method"), path: str(op, "path")}, nil
		}
	}
	return nil, nil
}

// consume calls a discovered endpoint with this system's identity token; path parameters {name} are filled from
// params (path templates are the convention of all three implementations).
func (a *App) consume(ctx context.Context, ep *discoveredEndpoint, params map[string]string, in, out any) error {
	path := ep.path
	for k, v := range params {
		path = strings.ReplaceAll(path, "{"+k+"}", url.PathEscape(v))
	}
	r := a.Remote
	for attempt := 0; attempt < 2; attempt++ {
		token, e := r.ownToken(ctx)
		if e != nil {
			return e
		}
		e = r.request(ctx, ep.provider, ep.base, ep.method, path, token, in, out)
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
	return &APIError{502, "Provider rejected refreshed identity token"}
}

// qosCompliance evaluates the candidates with a DeviceQoSEvaluator per requirement (Java QoSDriver): FILTER keeps
// the passed providers, SORT reorders them. An evaluator that cannot be found or fails adds qosComplianceFailure
// and leaves the candidates as they are.
func (a *App) qosCompliance(ctx context.Context, candidates []Document, requirements []Document, warnings map[string]bool) []Document {
	for _, q := range requirements {
		operation := strings.ToLower(str(q, "operation"))
		ep, e := a.discover(ctx, "qualityEvaluation", operation, Document{"evaluationType": str(q, "type")})
		if e != nil || ep == nil {
			log.Printf("no quality evaluator for type %q: %v", str(q, "type"), e)
			warnings[warnQoSComplianceFailure] = true
			continue
		}
		providers := []string{}
		for _, c := range candidates {
			providers = append(providers, str(obj(c, "provider"), "name"))
		}
		configuration := obj(q, "requirements")
		if configuration == nil {
			configuration = Document{}
		}
		var result Document
		if e := a.consume(ctx, ep, nil, Document{"providers": providers, "configuration": configuration}, &result); e != nil {
			log.Printf("quality evaluation %s by %s failed: %v", operation, ep.provider, e)
			warnings[warnQoSComplianceFailure] = true
			continue
		}
		key := "passedProviders"
		if operation == "sort" {
			key = "sortedProviders"
		}
		names, ok := result[key].([]any)
		if !ok {
			warnings[warnQoSComplianceFailure] = true
			continue
		}
		next := []Document{}
		for _, n := range names {
			for _, c := range candidates {
				if name, _ := n.(string); name == str(obj(c, "provider"), "name") {
					next = append(next, c)
					break
				}
			}
		}
		candidates = next
	}
	return candidates
}

// translationDiscovery asks TranslationManager for bridges to the non-native candidates (only their translatable
// interfaces are sent). It returns the bridge id and the candidates, in the given order, that a bridge can reach,
// each with the interface the bridge will translate to.
func (a *App) translationDiscovery(ctx context.Context, requirement Document, consumer string, candidates []Document) (string, []Document, error) {
	ep, e := a.discover(ctx, "translationBridgeManagement", "discovery", nil)
	if e != nil {
		return "", nil, e
	}
	if ep == nil {
		return "", nil, &APIError{503, "No TranslationManager is registered"}
	}
	operation, _ := list(requirement, "operations")[0].(string)
	sent := []Document{}
	for _, c := range candidates {
		instance := Document{}
		for k, v := range c {
			instance[k] = v
		}
		instance["interfaces"] = translatableInterfaces(requirement, c)
		sent = append(sent, instance)
	}
	in, out := requestedDataModelIDs(requirement, operation)
	request := Document{"candidates": sent, "consumer": consumer, "operation": operation, "interfaceTemplateNames": list(requirement, "interfaceTemplateNames"), "flags": Document{"CONSUMER_BLACKLIST_CHECK": false, "CANDIDATES_BLACKLIST_CHECK": false, "CANDIDATES_AUTH_CHECK": false, "TRANSLATORS_BLACKLIST_CHECK": a.Config.BlacklistURL != "", "TRANSLATORS_AUTH_CHECK": true}}
	if in != "" {
		request["inputDataModelId"] = in
	}
	if out != "" {
		request["outputDataModelId"] = out
	}
	var response Document
	if e := a.consume(ctx, ep, nil, request, &response); e != nil {
		return "", nil, e
	}
	discovered := list(response, "candidates")
	if len(discovered) == 0 {
		return "", nil, nil
	}
	bridgeID := str(response, "bridgeId")
	if bridgeID == "" {
		return "", nil, fmt.Errorf("no bridgeId has been provided by TranslationManager")
	}
	reachable := []Document{}
	for i, c := range sent {
		var chosen any
		for _, ri := range list(c, "interfaces") {
			intf, _ := ri.(map[string]any)
			for _, rd := range discovered {
				d, _ := rd.(map[string]any)
				if str(d, "serviceInstanceId") == str(c, "instanceId") && str(d, "interfaceTemplateName") == str(intf, "templateName") {
					chosen = intf
					break
				}
			}
			if chosen != nil {
				break
			}
		}
		if chosen != nil {
			row := Document{}
			for k, v := range candidates[i] {
				row[k] = v
			}
			row["interfaces"] = []any{chosen}
			reachable = append(reachable, row)
		}
	}
	return bridgeID, reachable, nil
}

// buildTranslationBridge negotiates the bridge to the chosen candidate. The result interface is the bridge's; its
// token (the bridge id) has the token type of the bridge interface policy.
func (a *App) buildTranslationBridge(ctx context.Context, bridgeID, operation string, candidate Document) ([]Document, Document, error) {
	ep, e := a.discover(ctx, "translationBridgeManagement", "negotiation", nil)
	if e != nil {
		return nil, nil, e
	}
	if ep == nil {
		return nil, nil, &APIError{503, "No TranslationManager is registered"}
	}
	var response Document
	if e := a.consume(ctx, ep, nil, Document{"bridgeId": bridgeID, "targetInstanceId": str(candidate, "instanceId")}, &response); e != nil {
		return nil, nil, e
	}
	intf := obj(response, "bridgeInterface")
	if str(response, "bridgeId") != bridgeID || intf == nil {
		return nil, nil, fmt.Errorf("invalid TranslationManager negotiation response")
	}
	policy := str(intf, "policy")
	// AuthorizationTokenType.fromServiceInterfacePolicy: NONE and CERT_AUTH have no token type (null)
	tokenType, ok := map[string]any{"NONE": nil, "CERT_AUTH": nil, "BASE64_SELF_CONTAINED_TOKEN_AUTH": "SELF_CONTAINED_TOKEN", "RSA_SHA256_JSON_WEB_TOKEN_AUTH": "SELF_CONTAINED_TOKEN", "RSA_SHA512_JSON_WEB_TOKEN_AUTH": "SELF_CONTAINED_TOKEN", "TIME_LIMITED_TOKEN_AUTH": "TIME_LIMITED_TOKEN", "USAGE_LIMITED_TOKEN_AUTH": "USAGE_LIMITED_TOKEN", "TRANSLATION_BRIDGE_TOKEN_AUTH": "TRANSLATION_BRIDGE_TOKEN"}[policy]
	if !ok {
		return nil, nil, fmt.Errorf("translation bridge interface policy %q is not a service interface policy", policy)
	}
	tokens := Document{policy: Document{operation: Document{"tokenType": tokenType, "targetType": "SERVICE_DEF", "token": bridgeID, "usageLimit": response["tokenUsageLimit"], "expiresAt": response["tokenExpiresAt"]}}}
	return []Document{intf}, tokens, nil
}
