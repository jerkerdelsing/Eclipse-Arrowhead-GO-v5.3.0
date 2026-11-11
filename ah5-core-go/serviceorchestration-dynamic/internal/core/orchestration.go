// SPDX-License-Identifier: EPL-2.0
package core

import (
	"fmt"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func instanceParts(id string) (provider, service, version string, e error) {
	p := strings.Split(id, "|")
	if len(p) != 3 || !validName(p[0]) || p[1] == "" || p[2] == "" {
		return "", "", "", bad("serviceInstanceId must be provider|serviceDefinition|version")
	}
	return p[0], p[1], p[2], nil
}

// newJob records a job already IN_PROGRESS (a pull starts at once), so a pull costs two state writes, not three.
func (a *App) newJob(owner, target, typ, definition, sub string) (Document, error) {
	at := now()
	j := Document{"id": uuid(), "status": "IN_PROGRESS", "type": typ, "requesterSystem": owner, "targetSystem": target, "serviceDefinition": definition, "subscriptionId": sub, "message": nil, "createdAt": at, "startedAt": at, "finishedAt": nil}
	e := a.Store.Update(func(d database) error {
		pruneJobs(d, time.Now())
		bucket(d, "jobs")[str(j, "id")] = j
		return nil
	})
	return j, e
}

// Job history retention: every pull adds a job and the whole state is copied and rewritten per transaction, so an
// unbounded history makes each pull slower and larger (2026-10-23: 21k jobs, 9 MB state, DSO OOM-killed at 192m).
const (
	jobRetention = 24 * time.Hour
	maxJobs      = 1000
)

// pruneJobs drops finished (DONE/ERROR) jobs older than jobRetention, then the oldest finished jobs beyond maxJobs.
// Unfinished jobs are always kept.
func pruneJobs(d database, at time.Time) {
	jobs := d["jobs"]
	finished := []Document{}
	for id, j := range jobs {
		if s := str(j, "status"); s != "DONE" && s != "ERROR" {
			continue
		}
		if t, e := time.Parse(time.RFC3339Nano, str(j, "createdAt")); e == nil && at.Sub(t) > jobRetention {
			delete(jobs, id)
			continue
		}
		finished = append(finished, j)
	}
	if excess := len(jobs) - maxJobs; excess > 0 {
		sort.Slice(finished, func(i, k int) bool { return str(finished[i], "createdAt") < str(finished[k], "createdAt") })
		for i := 0; i < excess && i < len(finished); i++ {
			delete(jobs, str(finished[i], "id"))
		}
	}
}
func (a *App) jobStatus(id, status, message string) error {
	return a.Store.Update(func(d database) error {
		j := d["jobs"][id]
		if j == nil {
			return &APIError{404, "Job not found"}
		}
		j["status"] = status
		j["message"] = message
		if status == "IN_PROGRESS" {
			j["startedAt"] = now()
		} else if status == "DONE" || status == "ERROR" {
			j["finishedAt"] = now()
		}
		return nil
	})
}
func (a *App) orchestrate(r *http.Request, req Document, consumer, jobID string) (Document, error) {
	if a.Config.Role == "serviceorchestration-simple" {
		return a.simplePull(req, consumer)
	}
	return a.dynamicPull(r, req, consumer, jobID)
}
func (a *App) simplePull(req Document, consumer string) (Document, error) {
	requirement := obj(req, "serviceRequirement")
	flags := obj(req, "orchestrationFlags")
	preferred := list(requirement, "preferredProviders")
	if flag(flags, "ONLY_PREFERRED") && len(preferred) == 0 {
		return nil, bad("ONLY_PREFERRED requires preferredProviders")
	}
	warnings := []string{}
	for k, v := range requirement {
		if k != "serviceDefinition" && k != "preferredProviders" && v != nil {
			warnings = append(warnings, "ignoredFields: "+k)
		}
	}
	for k, v := range flags {
		if k != "MATCHMAKING" && k != "ONLY_PREFERRED" && v == true {
			warnings = append(warnings, "ignoredFlags: "+k)
		}
	}
	rows := []Document{}
	e := a.Store.View(func(d database) error {
		for _, row := range d["simpleStore"] {
			if str(row, "consumer") == consumer && (str(requirement, "serviceDefinition") == "" || str(requirement, "serviceDefinition") == str(row, "serviceDefinition")) {
				rows = append(rows, row)
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	sort.Slice(rows, func(i, j int) bool {
		pi, _, _, _ := instanceParts(str(rows[i], "serviceInstanceId"))
		pj, _, _, _ := instanceParts(str(rows[j], "serviceInstanceId"))
		ip, jp := contains(preferred, pi), contains(preferred, pj)
		if ip != jp {
			return ip
		}
		a, b := number(rows[i], "priority", 0), number(rows[j], "priority", 0)
		if a == b {
			return str(rows[i], "id") < str(rows[j], "id")
		}
		return a < b
	})
	results := []Document{}
	seen := map[string]bool{}
	for _, row := range rows {
		p, s, v, e := instanceParts(str(row, "serviceInstanceId"))
		if e != nil {
			return nil, e
		}
		if flag(flags, "ONLY_PREFERRED") && !contains(preferred, p) {
			continue
		}
		if flag(flags, "MATCHMAKING") && seen[s] {
			continue
		}
		seen[s] = true
		results = append(results, Document{"serviceInstanceId": row["serviceInstanceId"], "cloudIdentitifer": "LOCAL", "providerName": p, "serviceDefinitition": s, "version": v, "aliveUntil": nil, "exclusiveUntil": nil, "metadata": nil, "interfaces": nil, "authorizationTokens": nil})
	}
	sort.Strings(warnings)
	return Document{"results": results, "warnings": warnings}, nil
}

// dynamicPull: local orchestration, and inter-cloud orchestration through the local Gatekeeper for ONLY_INTERCLOUD,
// or for ALLOW_INTERCLOUD when no local provider is found (as the Java DynamicServiceOrchestration extension).
func (a *App) dynamicPull(r *http.Request, req Document, consumer, jobID string) (Document, error) {
	requirement := obj(req, "serviceRequirement")
	if e := require(requirement, "serviceDefinition"); e != nil {
		return nil, e
	}
	flags := obj(req, "orchestrationFlags")
	if e := validateTranslation(requirement, flags); e != nil {
		return nil, e
	}
	ranks, managed, e := a.plantRanks(consumer, str(requirement, "serviceDefinition"))
	if e != nil {
		return nil, e
	}
	if managed && flag(flags, "ONLY_INTERCLOUD") {
		return Document{"results": []Document{}, "warnings": []string{}}, nil
	}
	if !managed && flag(flags, "ONLY_INTERCLOUD") {
		return a.interCloudPull(r, requirement, consumer), nil
	}
	local, e := a.localPull(r, req, consumer, jobID, ranks, managed)
	if found, _ := local["results"].([]Document); e != nil || managed || !flag(flags, "ALLOW_INTERCLOUD") || len(found) > 0 {
		return local, e
	}
	return a.interCloudPull(r, requirement, consumer), nil
}

// interCloudPull: globalServiceDiscovery query, then interCloudNegotiation negotiate per candidate; each provider
// cloud returns only providers its ConsumerAuthorization grants to this consumer. The result's interface is the
// local GateTunnel session. Matchmaking is implied: the first negotiated provider is returned.
func (a *App) interCloudPull(r *http.Request, requirement Document, consumer string) Document {
	warnings := []string{"interCloud", "autoMatchmaking"}
	results := []Document{}
	if a.Config.GatekeeperURL == "" {
		return Document{"results": results, "warnings": append(warnings, "interCloudDisabled")}
	}
	query := Document{"serviceDefinition": str(requirement, "serviceDefinition")}
	for _, k := range []string{"operations", "versions", "interfaceTemplateNames", "securityPolicies", "preferredProviders"} {
		if v := list(requirement, k); len(v) > 0 {
			query[k] = v
		}
	}
	var gsd Document
	if e := a.Remote.Call(r.Context(), "gatekeeper", "POST", "/gatekeeper/init_gsd", Document{"serviceRequirement": query, "consumerSystem": consumer}, &gsd); e != nil {
		log.Printf("inter-cloud global service discovery failed: %v", e)
		return Document{"results": results, "warnings": append(warnings, "interCloudFailed")}
	}
	for _, raw := range list(gsd, "results") {
		candidate, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		negotiate := Document{"targetCloud": candidate["cloud"], "providerName": candidate["providerName"], "serviceDefinition": query["serviceDefinition"], "consumerSystem": consumer}
		if ops, ok := query["operations"]; ok {
			negotiate["operations"] = ops
		}
		var icn Document
		if e := a.Remote.Call(r.Context(), "gatekeeper", "POST", "/gatekeeper/init_icn", negotiate, &icn); e != nil {
			log.Printf("inter-cloud negotiation with %v failed: %v", candidate["cloud"], e)
			continue
		}
		if !flag(icn, "negotiated") {
			log.Printf("inter-cloud negotiation with %v refused: %v", candidate["cloud"], icn["reason"])
			continue
		}
		intf := obj(icn, "interface")
		if intf == nil {
			continue
		}
		provider, def, version := str(icn, "providerName"), str(icn, "serviceDefinition"), str(icn, "version")
		metadata := obj(icn, "metadata")
		if metadata == nil {
			metadata = Document{}
		}
		results = append(results, Document{"serviceInstanceId": provider + "|" + def + "|" + version, "cloudIdentitifer": str(icn, "providerCloud"), "providerName": provider, "serviceDefinitition": def, "version": version, "aliveUntil": nil, "exclusiveUntil": nil, "metadata": metadata, "interfaces": []Document{intf}, "authorizationTokens": nil})
		break
	}
	sort.Strings(warnings)
	return Document{"results": results, "warnings": warnings}
}

func (a *App) localPull(r *http.Request, req Document, consumer, jobID string, ranks map[string]int, managed bool) (Document, error) {
	requirement := obj(req, "serviceRequirement")
	flags := obj(req, "orchestrationFlags")
	for k, v := range flags {
		if _, ok := v.(bool); !ok {
			return nil, bad("Orchestration flags must be boolean")
		}
		switch k {
		case "ALLOW_INTERCLOUD", "ONLY_INTERCLOUD", "ALLOW_TRANSLATION", "MATCHMAKING", "ONLY_PREFERRED", "ONLY_EXCLUSIVE":
		default:
			return nil, bad("Unknown orchestration flag")
		}
	}
	quality, e := qosRequirements(req)
	if e != nil {
		return nil, e
	}
	// With translation allowed the interface filters are applied here, so that non-matching interfaces remain
	// available for a translation bridge (Java serviceDiscovery withoutInterface).
	translation := flag(flags, "ALLOW_TRANSLATION")
	warnings := map[string]bool{}
	preferred := list(requirement, "preferredProviders")
	if flag(flags, "ONLY_PREFERRED") && len(preferred) == 0 {
		return nil, bad("ONLY_PREFERRED requires preferredProviders")
	}
	lookup := Document{"serviceDefinitionNames": []string{str(requirement, "serviceDefinition")}, "versions": requirement["versions"], "alivesAt": requirement["alivesAt"], "metadataRequirementsList": requirement["metadataRequirements"], "addressTypes": requirement["interfaceAddressTypes"], "interfaceTemplateNames": requirement["interfaceTemplateNames"], "interfacePropertyRequirementsList": requirement["interfacePropertyRequirements"], "policies": requirement["securityPolicies"]}
	if translation {
		for _, k := range []string{"addressTypes", "interfaceTemplateNames", "interfacePropertyRequirementsList"} {
			delete(lookup, k)
		}
	}
	var discovery Document
	if e := a.Remote.Call(r.Context(), "registry", "POST", "/serviceregistry/service-discovery/lookup", lookup, &discovery); e != nil {
		return nil, e
	}
	instances := []Document{}
	checks := []Document{}
	// Requested operations are authorization scopes: a provider qualifies only if every requested operation is
	// granted (scoped policy, else the default policy). Without operations the all-scopes check applies.
	scopes := []string{""}
	if operations := list(requirement, "operations"); len(operations) > 0 {
		scopes = scopes[:0]
		for _, op := range operations {
			name, ok := op.(string)
			if !ok || name == "" {
				return nil, bad("operations must be non-empty strings")
			}
			scopes = append(scopes, name)
		}
	}
	for _, v := range list(discovery, "entries") {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("invalid discovery entry")
		}
		if _, ok := ranks[str(row, "instanceId")]; managed && !ok {
			continue
		}
		provider := str(obj(row, "provider"), "name")
		if flag(flags, "ONLY_PREFERRED") && !contains(preferred, provider) {
			continue
		}
		instances = append(instances, row)
		for _, scope := range scopes {
			check := Document{"provider": provider, "consumer": consumer, "cloud": "LOCAL", "targetType": "SERVICE_DEF", "target": str(requirement, "serviceDefinition")}
			if scope != "" {
				check["scope"] = scope
			}
			checks = append(checks, check)
		}
	}
	if len(instances) == 0 {
		return Document{"results": []Document{}, "warnings": []string{}}, nil
	}
	var authorization Document
	if e := a.Remote.Call(r.Context(), "authorization", "POST", "/consumerauthorization/authorization/mgmt/check", Document{"list": checks}, &authorization); e != nil {
		return nil, e
	}
	answers := list(authorization, "entries")
	if len(answers) != len(checks) {
		return nil, fmt.Errorf("authorization response count mismatch")
	}
	allowed := []Document{}
	for i, row := range instances {
		granted := true
		for j := range scopes {
			answer, ok := answers[i*len(scopes)+j].(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid authorization answer")
			}
			if str(answer, "consumer") != consumer || str(answer, "provider") != str(obj(row, "provider"), "name") {
				return nil, fmt.Errorf("authorization answer identity mismatch")
			}
			granted = granted && flag(answer, "granted")
		}
		if granted {
			allowed = append(allowed, row)
		}
	}
	sort.Slice(allowed, func(i, j int) bool {
		if managed {
			pi, pj := ranks[str(allowed[i], "instanceId")], ranks[str(allowed[j], "instanceId")]
			if pi != pj {
				return pi < pj
			}
			return str(allowed[i], "instanceId") < str(allowed[j], "instanceId")
		}
		ip, jp := contains(preferred, str(obj(allowed[i], "provider"), "name")), contains(preferred, str(obj(allowed[j], "provider"), "name"))
		if ip != jp {
			return ip
		}
		return str(allowed[i], "instanceId") < str(allowed[j], "instanceId")
	})
	// Translation: native candidates win; only without any is a bridge discovered to the translatable ones.
	bridgeID := ""
	if translation {
		native := []Document{}
		translatable := []Document{}
		for _, row := range allowed {
			isNative := false
			for _, raw := range list(row, "interfaces") {
				intf, _ := raw.(map[string]any)
				m, e := interfaceMatches(requirement, intf, true)
				if e != nil {
					return nil, e
				}
				isNative = isNative || m
			}
			if isNative {
				native = append(native, row)
			} else if len(translatableInterfaces(requirement, row)) > 0 && !a.lockedByOther(str(row, "instanceId"), consumer) {
				translatable = append(translatable, row)
			}
		}
		if len(native) > 0 {
			allowed = native
		} else if len(translatable) == 0 {
			allowed = nil
		} else {
			if bridgeID, allowed, e = a.translationDiscovery(r.Context(), requirement, consumer, translatable); e != nil {
				return nil, e
			}
			if !flag(flags, "MATCHMAKING") {
				warnings[warnAutoMatchmaking] = true
			}
		}
	}
	if len(quality) > 0 && len(allowed) > 0 {
		allowed = a.qosCompliance(r.Context(), allowed, quality, warnings)
		// plant rule priorities still decide the order of the QoS-compliant candidates
		if managed {
			sort.SliceStable(allowed, func(i, j int) bool {
				return ranks[str(allowed[i], "instanceId")] < ranks[str(allowed[j], "instanceId")]
			})
		}
	}
	results := []Document{}
	duration := number(req, "exclusivityDuration", 0)
	if duration < 0 || duration > 86400 {
		return nil, bad("exclusivityDuration must be 0–86400 seconds")
	}
	for _, row := range allowed {
		id := str(row, "instanceId")
		allowedDuration, _ := strconv.Atoi(str(obj(row, "metadata"), "allowExclusivity"))
		lockDuration := duration
		if flag(flags, "ONLY_EXCLUSIVE") && lockDuration == 0 {
			lockDuration = allowedDuration
		}
		if lockDuration > allowedDuration {
			lockDuration = allowedDuration
		}
		if lockDuration < 0 {
			lockDuration = 0
		}
		var locked bool
		_ = a.Store.View(func(d database) error {
			for _, lock := range d["locks"] {
				if str(lock, "serviceInstanceId") == id && str(lock, "owner") != consumer && !expired(str(lock, "expiresAt")) {
					locked = true
				}
			}
			return nil
		})
		if locked {
			continue
		}
		if flag(flags, "ONLY_EXCLUSIVE") && lockDuration == 0 {
			continue
		}
		interfaces := []Document{}
		tokens := Document{}
		if bridgeID != "" {
			operation, _ := list(requirement, "operations")[0].(string)
			if interfaces, tokens, e = a.buildTranslationBridge(r.Context(), bridgeID, operation, row); e != nil {
				return nil, e
			}
			warnings[warnForcedInterfacePolicy] = true
		}
		for _, raw := range list(row, "interfaces") {
			if bridgeID != "" {
				break
			}
			intf, ok := raw.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("invalid interface")
			}
			if m, e := interfaceMatches(requirement, intf, translation); e != nil {
				return nil, e
			} else if translation && !m {
				continue
			}
			operationsMatch := true
			offered := offeredOperations(obj(intf, "properties")["operations"])
			for _, op := range list(requirement, "operations") {
				name, ok := op.(string)
				if !ok || !offered[name] {
					operationsMatch = false
				}
			}
			if !operationsMatch {
				continue
			}
			policy := str(intf, "policy")
			if policy == "NONE" || policy == "CERT_AUTH" {
				interfaces = append(interfaces, intf)
				continue
			}
			operations := list(requirement, "operations")
			if len(operations) == 0 {
				operations = []any{""}
			}
			requests := []Document{}
			for _, op := range operations {
				requests = append(requests, Document{"tokenVariant": policy, "targetType": "SERVICE_DEF", "consumer": consumer, "provider": str(obj(row, "provider"), "name"), "target": str(requirement, "serviceDefinition"), "scope": op})
			}
			var response Document
			if e := a.Remote.Call(r.Context(), "authorization", "POST", "/consumerauthorization/authorization/mgmt/token/generate", Document{"list": requests}, &response); e != nil {
				return nil, e
			}
			items := list(response, "entries")
			if len(items) != len(operations) {
				return nil, fmt.Errorf("token response count mismatch")
			}
			scopes := Document{}
			for i, v := range items {
				row, ok := v.(map[string]any)
				if !ok {
					return nil, fmt.Errorf("invalid token response")
				}
				scope := fmt.Sprint(operations[i])
				if scope == "" {
					scope = str(requirement, "serviceDefinition")
				}
				scopes[scope] = Document{"tokenType": row["tokenType"], "targetType": row["targetType"], "token": row["token"], "usageLimit": row["usageLimit"], "expiresAt": row["expiresAt"]}
			}
			tokens[policy] = scopes
			interfaces = append(interfaces, intf)
		}
		if len(interfaces) == 0 {
			continue
		}
		result := Document{"serviceInstanceId": id, "cloudIdentitifer": "LOCAL", "providerName": str(obj(row, "provider"), "name"), "serviceDefinitition": str(requirement, "serviceDefinition"), "version": row["version"], "aliveUntil": row["expiresAt"], "exclusiveUntil": nil, "metadata": row["metadata"], "interfaces": interfaces, "authorizationTokens": tokens}
		if lockDuration > 0 {
			result["exclusiveUntil"] = time.Now().UTC().Add(time.Duration(lockDuration) * time.Second).Format(time.RFC3339Nano)
		}
		results = append(results, result)
		if flag(flags, "MATCHMAKING") || bridgeID != "" {
			break
		}
	}
	// Acquire all result locks atomically, rechecking after network operations to prevent double allocation.
	e = a.Store.Update(func(d database) error {
		for _, result := range results {
			for _, lock := range d["locks"] {
				if str(lock, "serviceInstanceId") == str(result, "serviceInstanceId") && str(lock, "owner") != consumer && !expired(str(lock, "expiresAt")) {
					return &APIError{409, "Service became exclusive during orchestration; retry"}
				}
			}
			if result["exclusiveUntil"] != nil {
				id := nextLockID(d)
				bucket(d, "locks")[id] = Document{"id": number(d["sequence"]["lock"], "value", 0), "orchestrationJobId": jobID, "serviceInstanceId": result["serviceInstanceId"], "owner": consumer, "expiresAt": result["exclusiveUntil"], "temporary": false}
			}
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	out := []string{}
	for w := range warnings {
		out = append(out, w)
	}
	sort.Strings(out)
	return Document{"results": results, "warnings": out}, nil
}

// lockedByOther reports whether another consumer holds an unexpired lock on the service instance.
func (a *App) lockedByOther(id, consumer string) bool {
	locked := false
	_ = a.Store.View(func(d database) error {
		for _, lock := range d["locks"] {
			if str(lock, "serviceInstanceId") == id && str(lock, "owner") != consumer && !expired(str(lock, "expiresAt")) {
				locked = true
			}
		}
		return nil
	})
	return locked
}
func nextLockID(d database) string {
	row := bucket(d, "sequence")["lock"]
	n := number(row, "value", 0) + 1
	d["sequence"]["lock"] = Document{"value": float64(n)}
	return fmt.Sprint(n)
}
func (a *App) orchestrationRoutes() {
	base := "/serviceorchestration/orchestration"
	a.route("POST", base+"/pull", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decodeOptional(w, r)
		if e != nil {
			return nil, 0, e
		}
		p := caller(r)
		j, e := a.newJob(p.Name, p.Name, "PULL", str(obj(req, "serviceRequirement"), "serviceDefinition"), "")
		if e != nil {
			return nil, 0, e
		}
		result, e := a.orchestrate(r, req, p.Name, str(j, "id"))
		requirement := obj(req, "serviceRequirement")
		resultCount := 0
		if result != nil {
			resultCount = len(list(result, "results"))
		}
		log.Printf("orchestration pull requester=%s requirement=%v flags=%v results=%d error=%t", p.Name, requirement, obj(req, "orchestrationFlags"), resultCount, e != nil)
		status, message := "DONE", "Orchestration completed"
		if e != nil {
			status, message = "ERROR", "Orchestration failed"
		}
		if writeErr := a.jobStatus(str(j, "id"), status, message); writeErr != nil {
			return nil, 0, writeErr
		}
		return result, 200, e
	})
	a.route("POST", base+"/mgmt/history/query", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decodeOptional(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		e = a.Store.View(func(d database) error {
			for _, j := range d["jobs"] {
				if !selected(req, "ids", str(j, "id")) || !selected(req, "statuses", str(j, "status")) || !selected(req, "requesterSystems", str(j, "requesterSystem")) || !selected(req, "targetSystems", str(j, "targetSystem")) || !selected(req, "serviceDefinitions", str(j, "serviceDefinition")) || !selected(req, "subscriptionIds", str(j, "subscriptionId")) {
					continue
				}
				if str(req, "type") != "" && str(req, "type") != str(j, "type") {
					continue
				}
				rows = append(rows, j)
			}
			return nil
		})
		if e != nil {
			return nil, 0, e
		}
		out, e := page(rows, req, "entries")
		return out, 200, e
	})
	if a.Config.Role == "serviceorchestration-simple" {
		a.simpleStoreRoutes(base)
	} else {
		a.lockRoutes(base)
		a.plantRuleRoutes()
	}
	a.subscriptionRoutes(base)
}

// offeredOperations accepts both interface property forms: a map of operation -> {method, path} (HTTP templates)
// and a string set of operation names (MQTT/AMQP templates such as generic_mqtts and generic_amqps).
func offeredOperations(v any) map[string]bool {
	out := map[string]bool{}
	switch ops := v.(type) {
	case map[string]any:
		for name, op := range ops {
			if op != nil {
				out[name] = true
			}
		}
	case []any:
		for _, op := range ops {
			if name, ok := op.(string); ok {
				out[name] = true
			}
		}
	}
	return out
}
