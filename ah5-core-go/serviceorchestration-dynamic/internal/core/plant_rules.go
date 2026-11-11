// SPDX-License-Identifier: EPL-2.0
package core

import (
	"math"
	"net/http"
	"sort"
	"strings"
)

const plantRulesPath = "/serviceorchestration/mgmt/plant-rules"

func normalizePlantRules(in Document) (Document, error) {
	raw, ok := in["rules"].([]any)
	if !ok || len(raw) > 10000 {
		return nil, bad("rules must be an array of at most 10000 scopes")
	}
	scopes := map[string]bool{}
	rules := []any{}
	for _, v := range raw {
		row, ok := v.(map[string]any)
		if !ok || !validName(str(row, "consumer")) || !validName(str(row, "serviceDefinition")) {
			return nil, bad("Invalid consumer/serviceDefinition")
		}
		key := str(row, "consumer") + "|" + str(row, "serviceDefinition")
		if scopes[key] {
			return nil, bad("Duplicate plant scope")
		}
		scopes[key] = true
		ps, ok := row["providers"].([]any)
		if !ok || len(ps) > 1000 {
			return nil, bad("providers must be an array of at most 1000 entries")
		}
		ids := map[string]bool{}
		providers := []any{}
		for _, p := range ps {
			provider, ok := p.(map[string]any)
			if !ok {
				return nil, bad("Invalid provider")
			}
			id := str(provider, "serviceInstanceId")
			priority, ok := provider["priority"].(float64)
			if strings.TrimSpace(id) == "" || len(id) > 255 || ids[id] || !ok || math.Trunc(priority) != priority || priority < 0 || priority > 2147483647 {
				return nil, bad("Unique provider IDs and nonnegative integer priorities required")
			}
			ids[id] = true
			providers = append(providers, Document{"serviceInstanceId": id, "priority": priority})
		}
		sort.Slice(providers, func(i, j int) bool {
			a, b := providers[i].(Document), providers[j].(Document)
			if a["priority"] != b["priority"] {
				return a["priority"].(float64) < b["priority"].(float64)
			}
			return str(a, "serviceInstanceId") < str(b, "serviceInstanceId")
		})
		rules = append(rules, Document{"consumer": row["consumer"], "serviceDefinition": row["serviceDefinition"], "providers": providers})
	}
	sort.Slice(rules, func(i, j int) bool {
		a, b := rules[i].(Document), rules[j].(Document)
		return str(a, "consumer")+"|"+str(a, "serviceDefinition") < str(b, "consumer")+"|"+str(b, "serviceDefinition")
	})
	return Document{"rules": rules}, nil
}
func (a *App) plantSnapshot() (Document, error) {
	result := Document{"rules": []any{}}
	e := a.Store.View(func(d database) error {
		if row := d["plantRules"]["active"]; row != nil {
			result = row
		}
		return nil
	})
	return result, e
}
func (a *App) plantRanks(consumer, definition string) (map[string]int, bool, error) {
	snapshot, e := a.plantSnapshot()
	if e != nil {
		return nil, false, e
	}
	for _, v := range list(snapshot, "rules") {
		row := v.(map[string]any)
		if str(row, "consumer") == consumer && str(row, "serviceDefinition") == definition {
			ranks := map[string]int{}
			for _, p := range list(row, "providers") {
				r := p.(map[string]any)
				ranks[str(r, "serviceInstanceId")] = number(r, "priority", 0)
			}
			return ranks, true, nil
		}
	}
	return nil, false, nil
}
func (a *App) plantRuleRoutes() {
	a.route("POST", plantRulesPath+"/query", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		p := caller(r)
		if !p.Sysop && p.Name != "PlantDescriptionEngine" && p.Name != "LocalCloudManager" {
			return nil, 0, forbidden()
		}
		v, e := a.plantSnapshot()
		return v, 200, e
	})
	a.route("PUT", plantRulesPath+"/replace", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		p := caller(r)
		if !p.Sysop && p.Name != "PlantDescriptionEngine" {
			return nil, 0, forbidden()
		}
		in, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		snapshot, e := normalizePlantRules(in)
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error { bucket(d, "plantRules")["active"] = snapshot; return nil })
		return snapshot, 200, e
	})
}
