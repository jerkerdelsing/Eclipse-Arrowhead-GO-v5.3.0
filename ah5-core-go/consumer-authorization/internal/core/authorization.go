// SPDX-License-Identifier: EPL-2.0
// Policy precedence follows AuthorizationPolicyEngine in the EPL-2.0 Java reference.
package core

import (
	"net/http"
	"reflect"
	"regexp"
	"strings"
)

// Keep policy identifiers distinct from the permissive generic name check,
// which is also used for non-system identifiers elsewhere in the runtime.
var policySystemNameRE = regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`)
var policyTargetNameRE = regexp.MustCompile(`^[a-z][A-Za-z0-9]{0,62}$`)
var policyScopeRE = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)

func validPolicySystemName(name string) bool { return policySystemNameRE.MatchString(name) }
func validPolicyTargetName(name string) bool { return policyTargetNameRE.MatchString(name) }
func validPolicyScope(name string) bool      { return len(name) <= 63 && policyScopeRE.MatchString(name) }

func normalizeTarget(d Document) error {
	if str(d, "cloud") == "" {
		d["cloud"] = "LOCAL"
	}
	d["targetType"] = strings.ToUpper(strings.TrimSpace(str(d, "targetType")))
	if str(d, "targetType") != "SERVICE_DEF" && str(d, "targetType") != "EVENT_TYPE" {
		return bad("targetType must be SERVICE_DEF or EVENT_TYPE")
	}
	if !validName(str(d, "provider")) || !validName(str(d, "consumer")) || strings.ContainsAny(str(d, "target")+str(d, "scope"), "|\r\n") {
		return bad("Invalid authorization identity, target or scope")
	}
	return require(d, "provider", "consumer", "target")
}
func validatePolicy(p Document) error {
	if p == nil {
		return bad("Policy is required")
	}
	switch str(p, "policyType") {
	case "ALL":
	case "BLACKLIST", "WHITELIST":
		if list(p, "policyList") == nil {
			return bad("policyList required")
		}
		for _, v := range list(p, "policyList") {
			s, ok := v.(string)
			if !ok || !validPolicySystemName(s) {
				return bad("Invalid policyList identity")
			}
		}
	case "SYS_METADATA":
		if obj(p, "policyMetadataRequirement") == nil {
			return bad("policyMetadataRequirement required")
		}
	default:
		return bad("Invalid policyType")
	}
	return nil
}
func policyID(level string, d Document) string {
	prefix := "PR"
	if level == "MGMT" {
		prefix = "MGMT"
	}
	return strings.Join([]string{prefix, str(d, "cloud"), str(d, "provider"), str(d, "targetType"), str(d, "target")}, "|")
}
func (a *App) evaluatePolicy(r *http.Request, p Document, consumer string) (bool, error) {
	switch str(p, "policyType") {
	case "ALL":
		return true, nil
	case "WHITELIST":
		return contains(list(p, "policyList"), consumer), nil
	case "BLACKLIST":
		return !contains(list(p, "policyList"), consumer), nil
	case "SYS_METADATA":
		var v Document
		e := a.Remote.Call(r.Context(), "registry", "POST", "/serviceregistry/system-discovery/lookup", Document{"systemNames": []string{consumer}}, &v)
		if e != nil {
			return false, e
		}
		entries := list(v, "entries")
		if len(entries) == 0 {
			return false, nil
		}
		row, ok := entries[0].(map[string]any)
		if !ok {
			return false, nil
		}
		return metadataMatch(obj(row, "metadata"), obj(p, "policyMetadataRequirement"))
	}
	return false, nil
}
func (a *App) granted(r *http.Request, req Document) (bool, error) {
	if e := normalizeTarget(req); e != nil {
		return false, e
	}
	var row Document
	e := a.Store.View(func(d database) error {
		for _, level := range []string{"MGMT", "PROVIDER"} {
			if p := d["policies"][policyID(level, req)]; p != nil {
				row = p
				break
			}
		}
		return nil
	})
	if e != nil || row == nil {
		return false, e
	}
	policies := []Document{}
	scoped := obj(row, "scopedPolicies")
	scope := str(req, "scope")
	if scope == "" {
		if p := obj(row, "defaultPolicy"); p != nil {
			policies = append(policies, p)
		}
		for _, v := range scoped {
			policies = append(policies, v.(map[string]any))
		}
	} else {
		p := obj(scoped, scope)
		if p == nil {
			p = obj(row, "defaultPolicy")
		}
		if p != nil {
			policies = append(policies, p)
		}
	}
	if len(policies) == 0 {
		return false, nil
	}
	for _, p := range policies {
		ok, e := a.evaluatePolicy(r, p, str(req, "consumer"))
		if e != nil || !ok {
			return false, e
		}
	}
	return true, nil
}
func grantRow(d database, req Document, level, creator string) (Document, bool, error) {
	if str(req, "cloud") == "" {
		req["cloud"] = "LOCAL"
	}
	if e := require(req, "provider", "targetType", "target"); e != nil {
		return nil, false, e
	}
	if !validPolicySystemName(str(req, "provider")) || !validPolicyTargetName(str(req, "target")) {
		return nil, false, bad("Invalid provider or target")
	}
	if str(req, "targetType") != "SERVICE_DEF" && str(req, "targetType") != "EVENT_TYPE" {
		return nil, false, bad("Invalid targetType")
	}
	if e := validatePolicy(obj(req, "defaultPolicy")); e != nil {
		return nil, false, e
	}
	for scope, v := range obj(req, "scopedPolicies") {
		p, ok := v.(map[string]any)
		if !ok || !validPolicyScope(scope) {
			return nil, false, bad("Invalid scoped policy")
		}
		if e := validatePolicy(p); e != nil {
			return nil, false, e
		}
	}
	id := policyID(level, req)
	existing := bucket(d, "policies")[id]
	created := existing == nil
	if existing != nil && level == "PROVIDER" && (!reflect.DeepEqual(existing["defaultPolicy"], req["defaultPolicy"]) || !reflect.DeepEqual(existing["scopedPolicies"], req["scopedPolicies"])) {
		return nil, false, bad("Existing provider policy details differ; revoke first")
	}
	row := Document{"instanceId": id, "level": level, "cloud": req["cloud"], "provider": req["provider"], "targetType": req["targetType"], "target": req["target"], "description": req["description"], "defaultPolicy": req["defaultPolicy"], "scopedPolicies": req["scopedPolicies"], "createdBy": creator, "createdAt": now()}
	if existing != nil {
		row["createdBy"] = existing["createdBy"]
		row["createdAt"] = existing["createdAt"]
	}
	bucket(d, "policies")[id] = row
	return row, created, nil
}
func (a *App) authorizationRoutes() {
	base := "/consumerauthorization/authorization"
	a.route("POST", base+"/grant", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		req["provider"] = caller(r).Name
		var row Document
		var created bool
		e = a.Store.Update(func(d database) error { row, created, e = grantRow(d, req, "PROVIDER", caller(r).Name); return e })
		status := 200
		if created {
			status = 201
		}
		return row, status, e
	})
	a.route("POST", base+"/mgmt/grant", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		if len(list(req, "list")) == 0 {
			return nil, 0, bad("list is required")
		}
		e = a.Store.Update(func(d database) error {
			for _, v := range list(req, "list") {
				p, ok := v.(map[string]any)
				if !ok {
					return bad("Invalid grant")
				}
				row, _, e := grantRow(d, p, "MGMT", caller(r).Name)
				if e != nil {
					return e
				}
				rows = append(rows, row)
			}
			return nil
		})
		return Document{"entries": rows, "count": len(rows)}, 201, e
	})
	a.route("DELETE", base+"/revoke/{instanceId}", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		id := r.PathValue("instanceId")
		e := a.Store.Update(func(d database) error {
			p := d["policies"][id]
			if p != nil && (str(p, "provider") != caller(r).Name || str(p, "level") != "PROVIDER") {
				return forbidden()
			}
			delete(bucket(d, "policies"), id)
			return nil
		})
		return nil, 200, e
	})
	a.route("DELETE", base+"/mgmt/revoke", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		ids, e := queryNames(r, "instanceIds")
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for _, id := range ids {
				delete(bucket(d, "policies"), id)
			}
			return nil
		})
		return nil, 200, e
	})
	for _, path := range []string{"/lookup", "/mgmt/query"} {
		p := path
		access := "identity"
		if strings.Contains(p, "mgmt") {
			access = "management"
		}
		a.route("POST", base+p, access, func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			req, e := decode(w, r)
			if e != nil {
				return nil, 0, e
			}
			rows := []Document{}
			e = a.Store.View(func(d database) error {
				for _, row := range d["policies"] {
					if p == "/lookup" && (str(row, "provider") != caller(r).Name || str(row, "level") != "PROVIDER") {
						continue
					}
					if !selected(req, "providers", str(row, "provider")) || !selected(req, "instanceIds", str(row, "instanceId")) || !selected(req, "cloudIdentifiers", str(row, "cloud")) || !selected(req, "targetNames", str(row, "target")) {
						continue
					}
					if s := str(req, "level"); s != "" && s != str(row, "level") {
						continue
					}
					if s := str(req, "targetType"); s != "" && s != str(row, "targetType") {
						continue
					}
					rows = append(rows, row)
				}
				return nil
			})
			if e != nil {
				return nil, 0, e
			}
			out, e := page(rows, req, "entries")
			return out, 200, e
		})
	}
	a.route("POST", base+"/verify", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if str(req, "provider") == "" {
			req["provider"] = caller(r).Name
		}
		if str(req, "consumer") == "" {
			req["consumer"] = caller(r).Name
		}
		if str(req, "provider") != caller(r).Name && str(req, "consumer") != caller(r).Name {
			return nil, 0, forbidden()
		}
		ok, e := a.granted(r, req)
		return ok, 200, e
	})
	a.route("POST", base+"/mgmt/check", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		if len(list(req, "list")) == 0 {
			return nil, 0, bad("list is required")
		}
		for _, v := range list(req, "list") {
			row, ok := v.(map[string]any)
			if !ok {
				return nil, 0, bad("Invalid check")
			}
			yes, e := a.granted(r, row)
			if e != nil {
				return nil, 0, e
			}
			row["granted"] = yes
			rows = append(rows, row)
		}
		return Document{"entries": rows, "count": len(rows)}, 200, nil
	})
	a.tokenRoutes()
}
