package cloud

import (
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"strings"
)

var editorLocalName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,62}$`)
var editorScope = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,100}$`)

func localEditorPolicy(p map[string]any) bool {
	return (mapString(p["cloud"]) == "" || p["cloud"] == "LOCAL") && (mapString(p["level"]) == "" || p["level"] == "MGMT")
}
func cleanEditorPolicy(p map[string]any) map[string]any {
	s := object(p["scopedPolicies"])
	if s == nil {
		s = map[string]any{}
	}
	return map[string]any{"provider": p["provider"], "targetType": p["targetType"], "target": p["target"], "cloud": "LOCAL", "description": mapString(p["description"]), "defaultPolicy": p["defaultPolicy"], "scopedPolicies": s}
}
func validateEditorPolicy(p map[string]any, systems, services []any) (map[string]any, error) {
	if !localEditorPolicy(p) {
		return nil, errors.New("Only local management policies can be edited")
	}
	provider, target, kind := mapString(p["provider"]), mapString(p["target"]), mapString(p["targetType"])
	if !editorLocalName.MatchString(provider) || !editorLocalName.MatchString(target) || (kind != "SERVICE_DEF" && kind != "EVENT_TYPE") {
		return nil, errors.New("Invalid local policy target")
	}
	found := false
	for _, v := range systems {
		if object(v)["name"] == provider {
			found = true
		}
	}
	if !found {
		return nil, errors.New("Provider is not registered in this local cloud")
	}
	if kind == "SERVICE_DEF" {
		found = false
		for _, v := range services {
			s := object(v)
			if object(s["provider"])["name"] == provider && object(s["serviceDefinition"])["name"] == target {
				found = true
			}
		}
		if !found {
			return nil, errors.New("Service is not registered for this provider")
		}
	}
	validate := func(v any) error {
		p := object(v)
		kind := mapString(p["policyType"])
		if kind != "ALL" && kind != "WHITELIST" && kind != "BLACKLIST" {
			return errors.New("Invalid policy type")
		}
		if p["policyList"] != nil {
			a, ok := p["policyList"].([]any)
			if !ok || len(a) > 500 {
				return errors.New("Invalid local policy list")
			}
			for _, n := range a {
				if !editorLocalName.MatchString(mapString(n)) {
					return errors.New("Policy lists require local system names")
				}
			}
		}
		return nil
	}
	if err := validate(p["defaultPolicy"]); err != nil {
		return nil, err
	}
	scoped := object(p["scopedPolicies"])
	if p["scopedPolicies"] != nil && scoped == nil {
		return nil, errors.New("Invalid operation scopes")
	}
	if len(scoped) > 100 {
		return nil, errors.New("Too many operation scopes")
	}
	for k, v := range scoped {
		if !editorScope.MatchString(k) {
			return nil, errors.New("Invalid operation scope")
		}
		if err := validate(v); err != nil {
			return nil, err
		}
	}
	if len(mapString(p["description"])) > 1000 {
		return nil, errors.New("Description is too long")
	}
	return cleanEditorPolicy(p), nil
}
func (a *App) editorPolicyCall(method, path string, body any) (map[string]any, error) {
	base := env("AUTHORIZATION_URL", "http://consumerauthorization:8445")
	prefix := env("AUTHORIZATION_MGMT_PATH", "/consumerauthorization/mgmt")
	if a.Config.Secure && env("AUTHORIZATION_MGMT_PATH", "") == "" {
		prefix = "/consumerauthorization/authorization/mgmt"
	}
	return a.managerJSON(method, strings.TrimRight(base, "/")+prefix+path, body)
}
func (a *App) editorPoliciesHTTP(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/orchestration/policies") {
		return false
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/orchestration/policies")
	if id != "" {
		if !strings.HasPrefix(id, "/") {
			jsonOut(w, 404, map[string]any{"error": "Not found"})
			return true
		}
		id = strings.TrimPrefix(id, "/")
	}
	fail := func(status int, e error) { jsonOut(w, status, map[string]any{"error": e.Error()}) }
	if r.Method != http.MethodGet && r.Method != http.MethodPost && r.Method != http.MethodDelete {
		fail(405, errors.New("Method not allowed"))
		return true
	}
	if r.Method != http.MethodGet && !confirmed(r) {
		fail(428, errors.New("Missing action confirmation header"))
		return true
	}
	result, err := a.editorPolicyCall(http.MethodPost, "/query", map[string]any{"pagination": map[string]any{"page": 0, "size": 1000}})
	if err != nil {
		fail(502, err)
		return true
	}
	rows := []any{}
	readOnly := []any{}
	for _, raw := range entries(result) {
		p := object(raw)
		if localEditorPolicy(p) {
			rows = append(rows, p)
		} else if mapString(p["cloud"]) == "" || p["cloud"] == "LOCAL" {
			readOnly = append(readOnly, p)
		}
	}
	if r.Method == http.MethodGet && id == "" {
		jsonOut(w, 200, map[string]any{"entries": rows, "readOnlyEntries": readOnly, "collectedAt": now()})
		return true
	}
	var body map[string]any
	if err = decode(r, &body); err != nil {
		fail(400, err)
		return true
	}
	expected := object(body["expected"])
	var policy map[string]any
	if r.Method == http.MethodDelete {
		for _, v := range rows {
			if object(v)["instanceId"] == id {
				policy = object(v)
			}
		}
		if policy == nil {
			fail(404, errors.New("Local management policy not found"))
			return true
		}
		if expected == nil {
			fail(428, errors.New("Expected policy snapshot required"))
			return true
		}
	} else {
		if id != "" {
			fail(405, errors.New("Method not allowed"))
			return true
		}
		systems, e := a.registryQuery("systems")
		if e != nil {
			fail(502, e)
			return true
		}
		services, e := a.registryQuery("service-instances")
		if e != nil {
			fail(502, e)
			return true
		}
		policy, err = validateEditorPolicy(object(body["policy"]), entries(systems), entries(services))
		if err != nil {
			fail(400, err)
			return true
		}
	}
	matches := []map[string]any{}
	for _, v := range rows {
		p := object(v)
		if p["provider"] == policy["provider"] && p["targetType"] == policy["targetType"] && p["target"] == policy["target"] {
			matches = append(matches, p)
		}
	}
	var old map[string]any
	if len(matches) > 1 && r.Method != http.MethodDelete {
		fail(409, errors.New("Multiple policies share this target"))
		return true
	}
	if len(matches) == 1 {
		old = matches[0]
	}
	if r.Method == http.MethodDelete {
		old = policy
	}
	if (expected == nil && old != nil) || (expected != nil && (old == nil || old["instanceId"] != expected["instanceId"] || !reflect.DeepEqual(cleanEditorPolicy(old), cleanEditorPolicy(expected)))) {
		fail(409, errors.New("Policy changed; reload before saving"))
		return true
	}
	revoke := func(id string) error {
		_, e := a.editorPolicyCall(http.MethodDelete, "/revoke?instanceIds="+url.QueryEscape(id), nil)
		return e
	}
	if r.Method == http.MethodDelete {
		if err = revoke(id); err != nil {
			fail(502, err)
		} else {
			jsonOut(w, 200, map[string]any{"removed": true, "id": id})
		}
		return true
	}
	granted, err := a.editorPolicyCall(http.MethodPost, "/grant", map[string]any{"list": []any{policy}})
	if err != nil {
		fail(502, err)
		return true
	}
	created := granted
	if list := entries(granted); len(list) > 0 {
		created = object(list[0])
	}
	newID := mapString(created["instanceId"])
	if newID == "" {
		fail(502, errors.New("Authority did not return a policy identifier; reload before retrying"))
		return true
	}
	if old != nil && old["instanceId"] != newID {
		if err = revoke(mapString(old["instanceId"])); err != nil {
			_ = revoke(newID)
			fail(502, errors.New("Policy replacement could not finish; reload before retrying"))
			return true
		}
	}
	status := 201
	if old != nil {
		status = 200
	}
	jsonOut(w, status, created)
	return true
}

func (a *App) editorRulePriorityHTTP(w http.ResponseWriter, r *http.Request) bool {
	if !confirmed(r) {
		jsonOut(w, 428, map[string]any{"error": "Missing action confirmation header"})
		return true
	}
	var body map[string]any
	if err := decode(r, &body); err != nil {
		jsonOut(w, 400, map[string]any{"error": err.Error()})
		return true
	}
	priority, ok := number(body["priority"])
	if !ok || priority < 1 || priority > 2147483647 || priority != float64(int(priority)) {
		jsonOut(w, 400, map[string]any{"error": "Use a positive integer priority"})
		return true
	}
	expected := object(body["expected"])
	if expected == nil {
		jsonOut(w, 428, map[string]any{"error": "Expected rule snapshot required"})
		return true
	}
	current, err := a.managerRules()
	if err != nil {
		a.managerResult(w, r, 502, nil, err)
		return true
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/orchestration/rules/")
	var old map[string]any
	for _, raw := range anySlice(current["rules"]) {
		row := object(raw)
		if mapString(row["id"]) == id {
			old = row
		}
	}
	if old == nil || old["consumer"] != expected["consumer"] || old["serviceInstanceId"] != expected["serviceInstanceId"] || old["priority"] != expected["priority"] {
		jsonOut(w, 409, map[string]any{"error": "The rule changed; reload before saving"})
		return true
	}
	var changes any = map[string]any{id: priority}
	if !a.Config.Secure {
		changes = map[string]any{"candidates": []any{map[string]any{"id": id, "priority": priority}}}
	}
	result, err := a.managerJSON(http.MethodPut, env("SIMPLE_ORCHESTRATION_URL", "http://serviceorchestration-simple:8456")+"/serviceorchestration/orchestration/mgmt/simple-store/modify-priorities", changes)
	a.managerResult(w, r, 200, result, err)
	return true
}
