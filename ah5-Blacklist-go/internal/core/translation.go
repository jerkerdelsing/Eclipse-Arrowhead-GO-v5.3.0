// SPDX-License-Identifier: EPL-2.0
package core

// TranslationManager (2026-10-24): port of the Java TranslatorBridgeEngine, CoreSystemsDriver,
// InterfaceTranslatorDriver and DataModelTranslatorFactoryDriver of ah5-support-java-spring/TranslationManager.
//
// Discovery: candidates are normalized per requested operation (interfaces whose data models already match the
// consumer's and whose template the consumer accepts need no translation and are dropped); blacklisted and
// unauthorized candidates are removed; interface translators (interfaceBridgeManagement, metadata
// interfaceBridge.from/to) are looked up in the ServiceRegistry and asked which targets they can reach
// (check-targets); data model translators (dataModelTranslation, metadata dataModelIds containing [from, to]) or,
// failing that, data model translator factories (dataModelTranslatorFactoryControl check) are selected. Negotiation:
// a factory initializes a translator if needed, a token for the target is generated for token policies, and the
// interface translator initializes the bridge (initialize-bridge) whose interface must use
// TRANSLATION_BRIDGE_TOKEN_AUTH. Abort tells active bridges to abort (abort-bridge); the interface translator reports
// usage, closing and errors (translationReport). Bridge statuses and transitions are the Java ones.
//
// Go profile: translators are called over mutual TLS with this system's identity token (TOKEN_AUTH policies on
// interfaceBridgeManagement are not used); custom translator configuration (Java: TODO) is not sent.

import (
	"context"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	bridgePolicy             = "TRANSLATION_BRIDGE_TOKEN_AUTH"
	translationDiscoveryAge  = 8 * time.Hour
	interfaceBridgeMgmt      = "interfaceBridgeManagement"
	dataModelTranslation     = "dataModelTranslation"
	dataModelTranslatorCtl   = "dataModelTranslatorFactoryControl"
	translationTemplateHTTPS = "generic_https"
)

var dataModelIDPattern = regexp.MustCompile(`^([a-z]|[a-z][0-9A-Za-z]+)$`)

// bridgeTransitions are the valid TranslationBridgeStatus transitions of the reference.
var bridgeTransitions = map[string][]string{
	"NEW":         {"DISCOVERED", "ABORTED", "CLOSED", "ERROR"},
	"DISCOVERED":  {"PENDING", "ABORTED", "CLOSED", "ERROR"},
	"PENDING":     {"INITIALIZED", "ABORTED", "CLOSED", "ERROR"},
	"INITIALIZED": {"USED", "ABORTED", "CLOSED", "ERROR"},
	"USED":        {"USED", "ABORTED", "CLOSED", "ERROR"},
}

func bridgeTransition(from, to string) bool {
	for _, s := range bridgeTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}
func bridgeActive(s string) bool { return s == "INITIALIZED" || s == "USED" }
func bridgeEnded(s string) bool  { return s == "ABORTED" || s == "CLOSED" || s == "ERROR" }

// translationRequest is a validated discovery request.
type translationRequest struct {
	candidates              []Document
	consumer, createdBy     string
	operation               string
	templates               []string
	inputModel, outputModel string
	flags                   map[string]bool
	serviceDefinition       string
}

func normalizeDataModel(v any) (string, error) {
	s, _ := v.(string)
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if !dataModelIDPattern.MatchString(s) || len(s) > 63 {
		return "", bad("The specified data model identifier does not match the naming convention: " + s)
	}
	return s, nil
}

func (a *App) parseDiscovery(req Document, consumer, createdBy string, flags map[string]bool) (*translationRequest, error) {
	t := &translationRequest{consumer: consumer, createdBy: createdBy, flags: flags, operation: strings.TrimSpace(str(req, "operation"))}
	if t.operation == "" {
		return nil, bad("operation is missing")
	}
	for _, v := range list(req, "interfaceTemplateNames") {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			t.templates = append(t.templates, strings.TrimSpace(s))
		}
	}
	if len(t.templates) == 0 {
		return nil, bad("interfaceTemplateNames list is missing")
	}
	var e error
	if t.inputModel, e = normalizeDataModel(req["inputDataModelId"]); e != nil {
		return nil, e
	}
	if t.outputModel, e = normalizeDataModel(req["outputDataModelId"]); e != nil {
		return nil, e
	}
	for _, v := range list(req, "candidates") {
		c, ok := v.(map[string]any)
		if !ok || str(c, "instanceId") == "" {
			return nil, bad("Invalid candidate")
		}
		def := str(obj(c, "serviceDefinition"), "name")
		if t.serviceDefinition == "" {
			t.serviceDefinition = def
		} else if def != t.serviceDefinition {
			return nil, bad("All candidates must provide the same service definition")
		}
		t.candidates = append(t.candidates, c)
	}
	if len(t.candidates) == 0 {
		return nil, bad("candidates list is missing")
	}
	return t, nil
}

// operationDataModels returns the input/output data models an interface declares for the operation.
func operationDataModels(props Document, operation string) (string, string, bool) {
	dm := obj(obj(props, "dataModels"), operation)
	in, e1 := normalizeDataModel(dm["input"])
	out, e2 := normalizeDataModel(dm["output"])
	return in, out, e1 == nil && e2 == nil
}

// normalizeCandidate keeps the interfaces that need and allow translation (Java getNormalizedInterfaceIfAppropriate).
func (t *translationRequest) normalizeCandidate(c Document) Document {
	good := []any{}
	for _, v := range list(c, "interfaces") {
		intf, ok := v.(map[string]any)
		if !ok {
			continue
		}
		props := obj(intf, "properties")
		in, out, ok := operationDataModels(props, t.operation)
		if !ok {
			continue
		}
		if in == t.inputModel && out == t.outputModel && contains(stringsToAny(t.templates), str(intf, "templateName")) {
			continue // no translation needed
		}
		if (t.inputModel == "") != (in == "") || (t.outputModel == "") != (out == "") {
			continue // the data model specification of the two sides cannot be bridged
		}
		normalized := Document{}
		for k, val := range props {
			if k != "dataModels" {
				normalized[k] = val
			}
		}
		normalized["dataModels"] = Document{t.operation: Document{"input": nilIfEmpty(in), "output": nilIfEmpty(out)}}
		good = append(good, Document{"templateName": intf["templateName"], "protocol": intf["protocol"], "policy": intf["policy"], "properties": normalized})
	}
	return Document{"instanceId": c["instanceId"], "provider": str(obj(c, "provider"), "name"), "serviceDefinition": str(obj(c, "serviceDefinition"), "name"), "interfaces": good}
}

func interfaceTemplates(c Document) []string {
	out := []string{}
	for _, v := range list(c, "interfaces") {
		if i, ok := v.(map[string]any); ok {
			out = append(out, str(i, "templateName"))
		}
	}
	return out
}

// authorizedProviders keeps the providers whose service (and operation, if given) the consumer may use.
func (a *App) authorizedProviders(ctx context.Context, providers []string, consumer, definition, operation string) ([]string, error) {
	if len(providers) == 0 {
		return providers, nil
	}
	checks := []Document{}
	for _, p := range providers {
		check := Document{"provider": p, "consumer": consumer, "cloud": "LOCAL", "targetType": "SERVICE_DEF", "target": definition}
		if operation != "" {
			check["scope"] = operation
		}
		checks = append(checks, check)
	}
	var answer Document
	if e := a.Remote.Call(ctx, "authorization", "POST", "/consumerauthorization/authorization/mgmt/check", Document{"list": checks}, &answer); e != nil {
		return nil, e
	}
	denied := map[string]bool{}
	for _, v := range list(answer, "entries") {
		if row, ok := v.(map[string]any); ok && !flag(row, "granted") {
			denied[str(row, "provider")] = true
		}
	}
	out := []string{}
	for _, p := range providers {
		if !denied[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// notBlacklisted keeps the systems Blacklist does not list (no Blacklist configured: all).
func (a *App) notBlacklisted(ctx context.Context, names []string) []string {
	out := []string{}
	for _, n := range names {
		if a.checkBlacklist(ctx, n) == nil {
			out = append(out, n)
		}
	}
	return out
}

func filterByProvider(rows []Document, allowed []string, key func(Document) string) []Document {
	keep := map[string]bool{}
	for _, a := range allowed {
		keep[a] = true
	}
	out := []Document{}
	for _, r := range rows {
		if keep[key(r)] {
			out = append(out, r)
		}
	}
	return out
}

func (a *App) lookup(ctx context.Context, req Document) ([]Document, error) {
	var found Document
	if e := a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/service-discovery/lookup", req, &found); e != nil {
		return nil, e
	}
	return listOf(found, "entries"), nil
}

func providerName(d Document) string { return str(obj(d, "provider"), "name") }

func firstInterface(d Document) Document {
	if l := list(d, "interfaces"); len(l) > 0 {
		if i, ok := l[0].(map[string]any); ok {
			return i
		}
	}
	return Document{}
}

// discover runs a translation discovery and stores the bridge; it returns the bridge id ("" when no translation is
// possible) and the candidates (target instance, interface template for the consumer).
func (a *App) discover(ctx context.Context, t *translationRequest) (string, []Document, error) {
	if t.flags["CONSUMER_BLACKLIST_CHECK"] {
		if e := a.checkBlacklist(ctx, t.consumer); e != nil {
			return "", nil, e
		}
	}
	candidates := []Document{}
	for _, c := range t.candidates {
		if n := t.normalizeCandidate(c); len(list(n, "interfaces")) > 0 {
			candidates = append(candidates, n)
		}
	}
	byProvider := func(d Document) string { return str(d, "provider") }
	if len(candidates) > 0 && t.flags["CANDIDATES_BLACKLIST_CHECK"] {
		names := []string{}
		for _, c := range candidates {
			names = append(names, str(c, "provider"))
		}
		candidates = filterByProvider(candidates, a.notBlacklisted(ctx, names), byProvider)
	}
	if len(candidates) > 0 && t.flags["CANDIDATES_AUTH_CHECK"] {
		names := []string{}
		for _, c := range candidates {
			names = append(names, str(c, "provider"))
		}
		allowed, e := a.authorizedProviders(ctx, names, t.consumer, t.serviceDefinition, t.operation)
		if e != nil {
			return "", nil, e
		}
		candidates = filterByProvider(candidates, allowed, byProvider)
	}
	if len(candidates) == 0 {
		return "", []Document{}, nil
	}
	translators, e := a.interfaceTranslators(ctx, t, candidates)
	if e != nil || len(translators) == 0 {
		return "", []Document{}, e
	}
	// target instance -> interface translators that can reach it
	reachable := map[string][]Document{}
	for _, it := range translators {
		to := str(obj(obj(it, "metadata"), "interfaceBridge"), "to")
		related := []Document{}
		for _, c := range candidates {
			if contains(stringsToAny(interfaceTemplates(c)), to) {
				related = append(related, c)
			}
		}
		for _, target := range a.checkTargets(ctx, it, t.operation, related) {
			id := str(target, "instanceId")
			reachable[id] = append(reachable[id], it)
		}
	}
	models := []Document{}
	for _, c := range candidates {
		if m := a.discoveryModel(t, c, reachable[str(c, "instanceId")]); m != nil {
			models = append(models, m)
		}
	}
	if len(models) > 0 && (t.inputModel != "" || t.outputModel != "") {
		if models, e = a.addDataModelTranslators(ctx, t, models); e != nil {
			return "", nil, e
		}
	}
	if len(models) == 0 {
		return "", []Document{}, nil
	}
	id := uuid()
	row := Document{"bridgeId": id, "status": "DISCOVERED", "createdBy": t.createdBy, "consumer": t.consumer, "createdAt": now(), "updatedAt": now(), "alivesAt": nil, "usageReportCount": 0, "message": nil, "discoveries": models}
	if e = a.Store.Update(func(d database) error { bucket(d, "bridges")[id] = row; return nil }); e != nil {
		return "", nil, e
	}
	out := []Document{}
	for _, m := range models {
		// Java DTOConverter: the candidate carries the target (provider-side) interface template
		out = append(out, Document{"serviceInstanceId": m["targetInstanceId"], "interfaceTemplateName": m["toInterfaceTemplate"]})
	}
	return id, out, nil
}

// interfaceTranslators looks up interface translators accepting one of the consumer's templates and producing one
// of a target's templates, then applies the blacklist and authorization (TranslationManager -> translator) checks.
func (a *App) interfaceTranslators(ctx context.Context, t *translationRequest, targets []Document) ([]Document, error) {
	requirements := []Document{}
	seen := map[string]bool{}
	for _, c := range targets {
		tpl := interfaceTemplates(c)
		key := strings.Join(tpl, ",")
		if seen[key] {
			continue
		}
		seen[key] = true
		requirements = append(requirements, Document{
			"interfaceBridge.from": Document{"op": "CONTAINS_ANY", "value": t.templates},
			"interfaceBridge.to":   Document{"op": "IN", "value": tpl},
		})
	}
	found, e := a.lookup(ctx, Document{"serviceDefinitionNames": []string{interfaceBridgeMgmt}, "interfaceTemplateNames": []string{translationTemplateHTTPS}, "metadataRequirementsList": requirements})
	if e != nil {
		return nil, e
	}
	translators := []Document{}
	for _, it := range found {
		if strings.HasSuffix(str(firstInterface(it), "policy"), "TOKEN_AUTH") {
			continue // Go profile: translators are called with mutual TLS and the identity token only
		}
		translators = append(translators, it)
	}
	names := func() []string {
		n := []string{}
		for _, it := range translators {
			n = append(n, providerName(it))
		}
		return n
	}
	if len(translators) > 0 && t.flags["TRANSLATORS_BLACKLIST_CHECK"] {
		translators = filterByProvider(translators, a.notBlacklisted(ctx, names()), providerName)
	}
	if len(translators) > 0 && t.flags["TRANSLATORS_AUTH_CHECK"] {
		allowed, e := a.authorizedProviders(ctx, names(), a.Config.Name, interfaceBridgeMgmt, "")
		if e != nil {
			return nil, e
		}
		translators = filterByProvider(translators, allowed, providerName)
	}
	return translators, nil
}

// checkTargets asks an interface translator which of the targets it can reach (an error removes the translator).
func (a *App) checkTargets(ctx context.Context, translator Document, operation string, targets []Document) []Document {
	if len(targets) == 0 {
		return nil
	}
	props := obj(firstInterface(translator), "properties")
	origin, e := httpsOrigin(props)
	if e != nil {
		return nil
	}
	method, path := operationEndpoint(props, "check-targets", "POST", "/check-targets")
	payload := []Document{}
	for _, c := range targets {
		payload = append(payload, Document{"instanceId": c["instanceId"], "interfaces": c["interfaces"]})
	}
	var response Document
	if e = a.Remote.callAt(ctx, providerName(translator), origin, method, str(props, "basePath")+path, Document{"targetOperation": operation, "targets": payload}, &response); e != nil {
		return nil
	}
	return listOf(response, "targets")
}

// discoveryModel selects an interface translator for a target and fills the model (Java createDiscoveryModels).
func (a *App) discoveryModel(t *translationRequest, c Document, translators []Document) Document {
	for _, it := range translators { // default matchmaking: the first acceptable translator
		bridge := obj(obj(it, "metadata"), "interfaceBridge")
		to := str(bridge, "to")
		from := ""
		for _, tpl := range t.templates {
			if contains(list(bridge, "from"), tpl) {
				from = tpl
				break
			}
		}
		var target Document
		for _, v := range list(c, "interfaces") {
			if i, ok := v.(map[string]any); ok && str(i, "templateName") == to {
				target = i
				break
			}
		}
		if from == "" || target == nil {
			continue
		}
		props := obj(target, "properties")
		in, out, _ := operationDataModels(props, t.operation)
		itf := firstInterface(it)
		return Document{
			"targetInstanceId": c["instanceId"], "provider": c["provider"], "serviceDefinition": c["serviceDefinition"], "operation": t.operation, "consumer": t.consumer,
			"inputDataModelIdRequirement": nilIfEmpty(t.inputModel), "outputDataModelIdRequirement": nilIfEmpty(t.outputModel),
			"fromInterfaceTemplate": from, "toInterfaceTemplate": to,
			"interfaceTranslator": providerName(it), "interfaceTranslatorPolicy": itf["policy"], "interfaceTranslatorProperties": itf["properties"],
			"targetPolicy": target["policy"], "targetProperties": props,
			"targetInputDataModelId": nilIfEmpty(in), "targetOutputDataModelId": nilIfEmpty(out),
		}
	}
	return nil
}

// addDataModelTranslators selects data model translators (or factories) for the models that need them and drops the
// models without one (Java collectAppropriateDataModelTranslators/extendDiscoveryModels).
func (a *App) addDataModelTranslators(ctx context.Context, t *translationRequest, models []Document) ([]Document, error) {
	requirements := []Document{}
	for _, m := range models {
		for _, dir := range [][2]string{{str(m, "inputDataModelIdRequirement"), str(m, "targetInputDataModelId")}, {str(m, "targetOutputDataModelId"), str(m, "outputDataModelIdRequirement")}} {
			if dir[0] != "" && dir[1] != "" && dir[0] != dir[1] {
				requirements = append(requirements, Document{"dataModelIds": Document{"op": "CONTAINS", "value": []string{dir[0], dir[1]}}})
			}
		}
	}
	var translators []Document
	if len(requirements) > 0 {
		var e error
		if translators, e = a.lookup(ctx, Document{"serviceDefinitionNames": []string{dataModelTranslation}, "interfaceTemplateNames": []string{translationTemplateHTTPS}, "policies": []string{"CERT_AUTH", "NONE"}, "metadataRequirementsList": requirements}); e != nil {
			return nil, e
		}
		if len(translators) > 0 && t.flags["TRANSLATORS_BLACKLIST_CHECK"] {
			names := []string{}
			for _, d := range translators {
				names = append(names, providerName(d))
			}
			translators = filterByProvider(translators, a.notBlacklisted(ctx, names), providerName)
		}
	}
	out := []Document{}
	for _, m := range models {
		keep := true
		for _, side := range []struct {
			prefix   string
			from, to string
		}{{"input", str(m, "inputDataModelIdRequirement"), str(m, "targetInputDataModelId")}, {"output", str(m, "targetOutputDataModelId"), str(m, "outputDataModelIdRequirement")}} {
			if side.from == "" || side.to == "" || side.from == side.to {
				continue // no data model translation on this side
			}
			selected, factory, e := a.selectDataModelTranslator(ctx, t, m, translators, side.from, side.to)
			if e != nil {
				return nil, e
			}
			if selected == nil {
				keep = false
				break
			}
			m[side.prefix+"DataModelTranslator"] = providerName(selected)
			m[side.prefix+"DataModelTranslatorProperties"] = obj(firstInterface(selected), "properties")
			m[side.prefix+"DataModelTranslatorFactory"] = factory
		}
		if keep {
			out = append(out, m)
		}
	}
	return out, nil
}

func (a *App) selectDataModelTranslator(ctx context.Context, t *translationRequest, m Document, translators []Document, from, to string) (Document, bool, error) {
	related := []Document{}
	for _, d := range translators {
		for _, pair := range list(obj(d, "metadata"), "dataModelIds") {
			if p, ok := pair.([]any); ok && len(p) == 2 && p[0] == from && p[1] == to {
				related = append(related, d)
				break
			}
		}
	}
	if len(related) > 0 && t.flags["TRANSLATORS_AUTH_CHECK"] {
		names := []string{}
		for _, d := range related {
			names = append(names, providerName(d))
		}
		// the interface translator is the consumer of the data model translator
		allowed, e := a.authorizedProviders(ctx, names, str(m, "interfaceTranslator"), dataModelTranslation, "")
		if e != nil {
			return nil, false, e
		}
		related = filterByProvider(related, allowed, providerName)
	}
	if len(related) > 0 {
		return related[0], false, nil
	}
	factories, e := a.lookup(ctx, Document{"serviceDefinitionNames": []string{dataModelTranslatorCtl}, "interfaceTemplateNames": []string{translationTemplateHTTPS}, "policies": []string{"CERT_AUTH", "NONE"}})
	if e != nil {
		return nil, false, nil
	}
	for _, f := range factories {
		props := obj(firstInterface(f), "properties")
		origin, e := httpsOrigin(props)
		if e != nil {
			continue
		}
		method, path := operationEndpoint(props, "check", "GET", "/check")
		var supported bool
		if a.Remote.callAt(ctx, providerName(f), origin, method, str(props, "basePath")+path, Document{"fromModelId": from, "toModelId": to}, &supported) == nil && supported {
			return f, true, nil
		}
	}
	return nil, false, nil
}

// negotiate initializes the bridge for the selected target (Java doNegotiation).
func (a *App) negotiate(ctx context.Context, bridgeID, targetInstance, requester string, management bool) (Document, error) {
	var model Document
	e := a.Store.Update(func(d database) error {
		row := d["bridges"][bridgeID]
		if row == nil {
			return bad("Invalid bridge id: " + bridgeID)
		}
		if !management && str(row, "createdBy") != requester {
			return forbidden()
		}
		if !bridgeTransition(str(row, "status"), "PENDING") {
			return bad("Bridge is not in a negotiable state")
		}
		for _, v := range list(row, "discoveries") {
			if m, ok := v.(map[string]any); ok && str(m, "targetInstanceId") == targetInstance {
				model = m
			}
		}
		if model == nil {
			return bad("Target instance is not a candidate of the bridge: " + targetInstance)
		}
		row["status"], row["updatedAt"] = "PENDING", now()
		delete(row, "discoveries")
		for _, k := range []string{"targetInstanceId", "provider", "serviceDefinition", "operation", "interfaceTranslator"} {
			row[k] = model[k]
		}
		row["interfaceTranslatorData"] = Document{"fromInterfaceTemplate": model["fromInterfaceTemplate"], "toInterfaceTemplate": model["toInterfaceTemplate"], "token": nil, "interfaceProperties": model["interfaceTranslatorProperties"], "configurationSettings": nil}
		return nil
	})
	if e != nil {
		return nil, e
	}
	fail := func(e error) (Document, error) {
		_ = a.Store.Update(func(d database) error {
			if row := d["bridges"][bridgeID]; row != nil && bridgeTransition(str(row, "status"), "ERROR") {
				row["status"], row["message"], row["updatedAt"] = "ERROR", e.Error(), now()
			}
			return nil
		})
		return nil, e
	}
	descriptors := Document{}
	for _, side := range []struct{ prefix, from, to string }{
		{"input", str(model, "inputDataModelIdRequirement"), str(model, "targetInputDataModelId")},
		{"output", str(model, "targetOutputDataModelId"), str(model, "outputDataModelIdRequirement")},
	} {
		name := str(model, side.prefix+"DataModelTranslator")
		if name == "" {
			continue
		}
		props := obj(model, side.prefix+"DataModelTranslatorProperties")
		if flag(model, side.prefix+"DataModelTranslatorFactory") {
			origin, e := httpsOrigin(props)
			if e != nil {
				return fail(e)
			}
			method, path := operationEndpoint(props, "initialize", "POST", "/initialize-translator")
			var init Document
			if e = a.Remote.callAt(ctx, name, origin, method, str(props, "basePath")+path, Document{"fromModelId": side.from, "toModelId": side.to}, &init); e != nil {
				return fail(&APIError{502, "Data model translator factory failed: " + e.Error()})
			}
			if !validName(str(init, "dataModelTranslatorName")) || len(obj(init, "interfaceProperties")) == 0 {
				return fail(&APIError{502, "Data model translator factory returned invalid data"})
			}
			name, props = str(init, "dataModelTranslatorName"), obj(init, "interfaceProperties")
		}
		descriptors[side.prefix] = Document{"fromModelId": side.from, "toModelId": side.to, "interfaceProperties": props, "configurationSettings": nil}
		descriptors[side.prefix+"Name"] = name
	}
	var targetToken Document
	if policy := str(model, "targetPolicy"); strings.HasSuffix(policy, "TOKEN_AUTH") {
		provider := strings.SplitN(str(model, "targetInstanceId"), "|", 2)[0]
		var tokens Document
		if e := a.Remote.Call(ctx, "authorization", "POST", "/consumerauthorization/authorization/mgmt/token/generate", Document{"list": []Document{{"tokenVariant": policy, "targetType": "SERVICE_DEF", "consumer": model["interfaceTranslator"], "provider": provider, "target": model["serviceDefinition"], "scope": model["operation"]}}}, &tokens); e != nil {
			return fail(&APIError{502, "Token generation for the target failed: " + e.Error()})
		}
		if entries := listOf(tokens, "entries"); len(entries) > 0 {
			targetToken = entries[0]
		}
	}
	_ = a.Store.Update(func(d database) error {
		if row := d["bridges"][bridgeID]; row != nil {
			row["inputDataModelTranslator"], row["inputDataModelTranslatorData"] = nilIfEmpty(str(descriptors, "inputName")), descriptors["input"]
			row["outputDataModelTranslator"], row["outputDataModelTranslatorData"] = nilIfEmpty(str(descriptors, "outputName")), descriptors["output"]
		}
		return nil
	})
	itProps := obj(model, "interfaceTranslatorProperties")
	origin, e := httpsOrigin(itProps)
	if e != nil {
		return fail(e)
	}
	method, path := operationEndpoint(itProps, "initialize-bridge", "POST", "/initialize-bridge")
	payload := Document{
		"bridgeId": bridgeID, "inputInterface": model["fromInterfaceTemplate"],
		"inputDataModelTranslator": descriptors["input"], "resultDataModelTranslator": descriptors["output"],
		"inputDataModelRequirement": model["inputDataModelIdRequirement"], "resultDataModelRequirement": model["outputDataModelIdRequirement"],
		"targetInterface": model["toInterfaceTemplate"], "targetInterfaceProperties": model["targetProperties"],
		"operation": model["operation"], "authorizationToken": nilIfEmpty(str(targetToken, "token")), "interfaceTranslatorSettings": nil,
	}
	var bridgeInterface Document
	if e = a.Remote.callAt(ctx, str(model, "interfaceTranslator"), origin, method, str(itProps, "basePath")+path, payload, &bridgeInterface); e != nil {
		return fail(&APIError{502, "Bridge initialization failed: " + e.Error()})
	}
	if strings.ToUpper(strings.TrimSpace(str(bridgeInterface, "policy"))) != bridgePolicy {
		a.abortTranslatorBridge(ctx, bridgeID, str(model, "interfaceTranslator"), itProps)
		return fail(&APIError{502, "Interface provider returns with invalid data"})
	}
	ended := false
	e = a.Store.Update(func(d database) error {
		row := d["bridges"][bridgeID]
		if row == nil || str(row, "status") != "PENDING" {
			ended = true
			return nil
		}
		row["status"], row["updatedAt"] = "INITIALIZED", now()
		return nil
	})
	if e == nil && ended {
		a.abortTranslatorBridge(ctx, bridgeID, str(model, "interfaceTranslator"), itProps)
		return nil, bad("Bridge is already in an end state")
	}
	return Document{"bridgeId": bridgeID, "bridgeInterface": bridgeInterface, "tokenExpiresAt": targetToken["expiresAt"], "tokenUsageLimit": targetToken["usageLimit"]}, e
}

func (a *App) abortTranslatorBridge(ctx context.Context, bridgeID, translator string, props Document) {
	origin, e := httpsOrigin(props)
	if e != nil {
		return
	}
	method, path := operationEndpoint(props, "abort-bridge", "DELETE", "/abort-bridge")
	_ = a.Remote.callAt(ctx, translator, origin, method, str(props, "basePath")+path+"/"+url.PathEscape(bridgeID), nil, nil)
}

// abortBridges aborts bridges (Java doAbort): true when aborted now or already ended, false for unknown or
// non-abortable bridges; requester "" means management (no creator check).
func (a *App) abortBridges(ctx context.Context, ids []string, requester string) (Document, error) {
	result := Document{}
	for _, id := range ids {
		var row Document
		var from string
		aborted := false
		e := a.Store.Update(func(d database) error {
			row = d["bridges"][id]
			if row == nil {
				return nil
			}
			if requester != "" && str(row, "createdBy") != requester {
				return &APIError{403, "No permission to abort bridge: " + id}
			}
			from = str(row, "status")
			if bridgeTransition(from, "ABORTED") {
				row["status"], row["updatedAt"] = "ABORTED", now()
				aborted = true
			}
			row = copyDB(database{"x": {"r": row}})["x"]["r"]
			return nil
		})
		if e != nil {
			return nil, e
		}
		switch {
		case row == nil:
			result[id] = false
		case aborted:
			result[id] = true
			if bridgeActive(from) {
				data := obj(row, "interfaceTranslatorData")
				a.abortTranslatorBridge(ctx, id, str(row, "interfaceTranslator"), obj(data, "interfaceProperties"))
			}
		default:
			result[id] = bridgeEnded(from)
		}
	}
	return result, nil
}

var reportStates = map[string]string{"USED": "USED", "INTERNAL_CLOSED": "CLOSED", "INTERNAL_ERROR": "ERROR", "EXTERNAL_ERROR": "ERROR"}

// report handles an interface translator's bridge event (Java handleTranslationReport).
func (a *App) report(requester string, req Document) error {
	to := reportStates[strings.ToUpper(strings.TrimSpace(str(req, "state")))]
	if to == "" {
		return bad("Invalid state")
	}
	timestamp := str(req, "timestamp")
	if _, e := time.Parse(time.RFC3339Nano, timestamp); e != nil {
		return bad("Invalid timestamp")
	}
	return a.Store.Update(func(d database) error {
		row := d["bridges"][str(req, "bridgeId")]
		if row == nil || str(row, "interfaceTranslator") == "" {
			return bad("Invalid bridge id: " + str(req, "bridgeId"))
		}
		if str(row, "interfaceTranslator") != requester {
			return &APIError{403, "Requester has no permission to report about the specified translation bridge"}
		}
		if !bridgeActive(str(row, "status")) || !bridgeTransition(str(row, "status"), to) {
			return bad("Invalid reporting case")
		}
		row["status"], row["alivesAt"], row["updatedAt"] = to, timestamp, now()
		if to == "USED" {
			row["usageReportCount"] = number(row, "usageReportCount", 0) + 1
		}
		if m := str(req, "errorMessage"); m != "" {
			row["message"] = m
		}
		return nil
	})
}

// cleanBridgeDiscoveries closes bridges still in discovery after 8 hours (Java CleanerJob).
func (a *App) cleanBridgeDiscoveries() {
	threshold := time.Now().Add(-translationDiscoveryAge)
	_ = a.Store.Update(func(d database) error {
		for _, row := range d["bridges"] {
			if row["discoveries"] == nil {
				continue
			}
			if t, e := time.Parse(time.RFC3339Nano, str(row, "createdAt")); e != nil || !t.Before(threshold) {
				continue
			}
			if s := str(row, "status"); !bridgeEnded(s) && !bridgeActive(s) {
				row["status"], row["message"], row["updatedAt"] = "CLOSED", "Closed by TranslationManager because of inactivity", now()
			}
			delete(row, "discoveries")
		}
		return nil
	})
}

func (a *App) runTranslationCleaner(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		a.cleanBridgeDiscoveries()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// bridgeQueryEntry is the TranslationQueryResponseDTO view of a bridge.
func bridgeQueryEntry(row Document) Document {
	out := Document{}
	for _, k := range []string{"bridgeId", "status", "usageReportCount", "alivesAt", "message", "consumer", "provider", "serviceDefinition", "operation", "interfaceTranslator", "interfaceTranslatorData", "inputDataModelTranslator", "inputDataModelTranslatorData", "outputDataModelTranslator", "outputDataModelTranslatorData", "createdBy", "createdAt", "updatedAt"} {
		out[k] = row[k]
	}
	return out
}

func timeWithin(value, from, to string) bool {
	t, e := time.Parse(time.RFC3339Nano, value)
	if from != "" {
		f, e2 := time.Parse(time.RFC3339Nano, from)
		if e != nil || e2 != nil || t.Before(f) {
			return false
		}
	}
	if to != "" {
		u, e2 := time.Parse(time.RFC3339Nano, to)
		if e != nil || e2 != nil || t.After(u) {
			return false
		}
	}
	return true
}

func (a *App) translationRoutes() {
	b := "/translation"
	flagsFrom := func(req Document, management bool) map[string]bool {
		if !management {
			// consumer API: the requester is already checked by the Blacklist filter; the rest follows the configuration
			enforce := a.Config.AuthorizationPolicy == "enforce"
			blacklist := a.Config.BlacklistURL != ""
			return map[string]bool{"CANDIDATES_BLACKLIST_CHECK": blacklist, "TRANSLATORS_BLACKLIST_CHECK": blacklist, "CANDIDATES_AUTH_CHECK": enforce, "TRANSLATORS_AUTH_CHECK": enforce}
		}
		flags := map[string]bool{}
		for k, v := range obj(req, "flags") {
			flags[strings.ToUpper(k)] = v == true
		}
		return flags
	}
	discovery := func(management bool) endpoint {
		return func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			req, e := decode(w, r)
			if e != nil {
				return nil, 0, e
			}
			consumer := caller(r).Name
			if management {
				if consumer = str(req, "consumer"); !validName(consumer) {
					return nil, 0, bad("consumer is missing or invalid")
				}
			}
			t, e := a.parseDiscovery(req, consumer, caller(r).Name, flagsFrom(req, management))
			if e != nil {
				return nil, 0, e
			}
			id, candidates, e := a.discover(r.Context(), t)
			if e != nil {
				return nil, 0, e
			}
			return Document{"bridgeId": nilIfEmpty(id), "candidates": candidates}, 200, nil
		}
	}
	a.serviceRoute("POST", b+"/bridge/discovery", "translationBridge", "discovery", discovery(false))
	a.route("POST", b+"/bridge/mgmt/discovery", "management", discovery(true))
	a.serviceRoute("POST", b+"/bridge/negotiation", "translationBridge", "negotiation", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		target := obj(req, "target")
		if str(target, "instanceId") == "" {
			return nil, 0, bad("target is missing")
		}
		id := str(req, "bridgeId")
		if id == "" {
			// discovery not done yet: discover for this one target first (Java negotiationOperation)
			t, e := a.parseDiscovery(Document{"candidates": []any{target}, "operation": req["operation"], "interfaceTemplateNames": []any{req["interfaceTemplateName"]}, "inputDataModelId": req["inputDataModelId"], "outputDataModelId": req["outputDataModelId"]}, caller(r).Name, caller(r).Name, flagsFrom(req, false))
			if e != nil {
				return nil, 0, e
			}
			if id, _, e = a.discover(r.Context(), t); e != nil {
				return nil, 0, e
			}
			if id == "" {
				return Document{"bridgeId": nil, "bridgeInterface": nil, "tokenExpiresAt": nil, "tokenUsageLimit": nil}, 200, nil
			}
		}
		v, e := a.negotiate(r.Context(), id, str(target, "instanceId"), caller(r).Name, false)
		return v, 200, e
	})
	a.route("POST", b+"/bridge/mgmt/negotiation", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if str(req, "bridgeId") == "" || str(req, "targetInstanceId") == "" {
			return nil, 0, bad("bridgeId and targetInstanceId are required")
		}
		v, e := a.negotiate(r.Context(), str(req, "bridgeId"), str(req, "targetInstanceId"), caller(r).Name, true)
		return v, 200, e
	})
	a.serviceRoute("DELETE", b+"/bridge/abort/{bridgeId}", "translationBridge", "abort", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		result, e := a.abortBridges(r.Context(), []string{r.PathValue("bridgeId")}, caller(r).Name)
		if e != nil {
			return nil, 0, e
		}
		return result[r.PathValue("bridgeId")] == true, 200, nil
	})
	a.route("DELETE", b+"/bridge/mgmt/abort", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		ids, e := queryNames(r, "ids")
		if e != nil || len(ids) == 0 {
			return nil, 0, bad("ids are required")
		}
		result, e := a.abortBridges(r.Context(), ids, "")
		return Document{"results": result}, 200, e
	})
	a.route("POST", b+"/bridge/mgmt/query", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decodeOptional(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		for _, row := range a.rows("bridges") {
			dmts := []string{str(row, "inputDataModelTranslator"), str(row, "outputDataModelTranslator")}
			usage := number(row, "usageReportCount", 0)
			if !selected(req, "bridgeIds", str(row, "bridgeId")) || !selected(req, "creators", str(row, "createdBy")) || !selected(req, "statuses", str(row, "status")) ||
				!selected(req, "consumers", str(row, "consumer")) || !selected(req, "providers", str(row, "provider")) || !selected(req, "serviceDefinitions", str(row, "serviceDefinition")) ||
				!selected(req, "interfaceTranslators", str(row, "interfaceTranslator")) ||
				(len(list(req, "dataModelTranslators")) > 0 && !contains(list(req, "dataModelTranslators"), dmts[0]) && !contains(list(req, "dataModelTranslators"), dmts[1])) ||
				!timeWithin(str(row, "createdAt"), str(req, "creationFrom"), str(req, "creationTo")) ||
				((str(req, "alivesFrom") != "" || str(req, "alivesTo") != "") && !timeWithin(str(row, "alivesAt"), str(req, "alivesFrom"), str(req, "alivesTo"))) ||
				(req["minUsage"] != nil && usage < number(req, "minUsage", 0)) || (req["maxUsage"] != nil && usage > number(req, "maxUsage", 0)) {
				continue
			}
			rows = append(rows, bridgeQueryEntry(row))
		}
		sort.Slice(rows, func(i, j int) bool { return str(rows[i], "createdAt") < str(rows[j], "createdAt") })
		v, e := page(rows, req, "entries")
		return v, 200, e
	})
	a.serviceRoute("POST", b+"/event/report", "translationReport", "report", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		return nil, 200, a.report(caller(r).Name, req)
	})
}
