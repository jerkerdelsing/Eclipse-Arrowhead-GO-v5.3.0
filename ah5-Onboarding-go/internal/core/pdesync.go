// SPDX-License-Identifier: EPL-2.0
package core

// PlantDescriptionEngine synchronization (2026-10-17), as the Java PlantSynchronizer/RuleResolver/AlarmDetector:
// the active plant (with its includes) is matched against the registered systems; every connection becomes a
// DSO scope with ranked providers; snapshots are atomically
// reconciled with them; alarms for unregistered, ambiguous, undescribed and unmonitored/stale systems are raised and
// cleared. Runs every 30 s and within ~2 s of a plant description change.

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	pdeDefaultPriority = 1
	pdeStaleAfter      = 5 * time.Minute
	alarmNotRegistered = "SYSTEM_NOT_REGISTERED"
	alarmMultiple      = "MULTIPLE_MATCHES"
	alarmNotDescribed  = "SYSTEM_NOT_IN_DESCRIPTION"
	alarmNotMonitored  = "NOT_MONITORED"
	alarmStale         = "NO_RECENT_OBSERVATION"
)

// activePlant returns the systems (active plant and includes) and the connections of the active plant.
func activePlant(plants map[string]Document) (systems, connections []Document, ok bool) {
	var active Document
	var activeID string
	for id, p := range plants {
		if flag(p, "active") {
			active, activeID = p, id
		}
	}
	if active == nil {
		return nil, nil, false
	}
	seen := map[string]bool{}
	var visit func(id string, p Document)
	visit = func(id string, p Document) {
		if p == nil || seen[id] {
			return
		}
		seen[id] = true
		for _, v := range list(p, "include") {
			if n, ok := v.(float64); ok {
				key := strconv.FormatInt(int64(n), 10)
				visit(key, plants[key])
			}
		}
		for _, v := range list(p, "systems") {
			if s, ok := v.(map[string]any); ok {
				systems = append(systems, s)
			}
		}
		for _, v := range list(p, "connections") {
			if c, ok := v.(map[string]any); ok {
				connections = append(connections, c)
			}
		}
	}
	visit(activeID, active)
	return systems, connections, true
}

// metadataSubset: every required key exists in actual with the same (string) value.
func metadataSubset(required, actual Document) bool {
	for k, v := range required {
		got, ok := actual[k]
		if !ok || fmt.Sprint(got) != fmt.Sprint(v) {
			return false
		}
	}
	return true
}

// matchSystems: a plant system matches a registered system when the names agree (if named) and its metadata is a subset.
func matchSystems(systems []Document, registered []Document) map[string][]Document {
	out := map[string][]Document{}
	for _, s := range systems {
		matches := []Document{}
		for _, r := range registered {
			if name := str(s, "systemName"); name != "" && name != str(r, "name") {
				continue
			}
			if metadataSubset(obj(s, "metadata"), obj(r, "metadata")) {
				matches = append(matches, r)
			}
		}
		out[str(s, "systemId")] = matches
	}
	return out
}

func findPort(systems []Document, ref Document) Document {
	for _, s := range systems {
		if str(s, "systemId") != str(ref, "systemId") {
			continue
		}
		for _, v := range list(s, "ports") {
			if p, ok := v.(map[string]any); ok && str(p, "portName") == str(ref, "portName") {
				return p
			}
		}
	}
	return nil
}

func offersInterface(inst Document, iface string) bool {
	if iface == "" {
		return true
	}
	for _, v := range list(inst, "interfaces") {
		if i, ok := v.(map[string]any); ok && strings.EqualFold(str(i, "templateName"), iface) {
			return true
		}
	}
	return false
}

func (a *App) runPlantSync(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	last, lastRun := "", time.Time{}
	for {
		var plants map[string]Document
		_ = a.Store.ViewTables(func(d database) error { plants = d["plants"]; return nil }, "plants")
		b, _ := json.Marshal(plants)
		sum := fmt.Sprintf("%x", sha256.Sum256(b))
		if sum != last || time.Since(lastRun) >= 30*time.Second {
			last, lastRun = sum, time.Now()
			a.syncPlant(ctx, plants)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (a *App) syncPlant(ctx context.Context, plants map[string]Document) {
	state := Document{"time": now()}
	defer func() {
		_ = a.Store.Update(func(d database) error { bucket(d, "pdeSync")["state"] = state; return nil })
	}()
	systems, connections, active := activePlant(plants)
	var registered []Document
	var systemList Document
	if e := a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/mgmt/systems/query", Document{"pagination": Document{"page": 0, "size": 1000}}, &systemList); e != nil {
		state["ok"], state["detail"] = false, "registry not available: "+e.Error()
		return
	}
	if _, ok := systemList["entries"].([]any); !ok || number(systemList, "count", 0) > len(list(systemList, "entries")) {
		state["ok"], state["detail"] = false, "registry system query incomplete"
		return
	}
	for _, v := range list(systemList, "entries") {
		if r, ok := v.(map[string]any); ok {
			registered = append(registered, r)
		}
	}
	a.updateAlarms(ctx, active, systems, registered)
	desired := Document{"rules": []any{}}
	if active {
		definitions := map[string]bool{}
		for _, s := range systems {
			for _, v := range list(s, "ports") {
				if p, ok := v.(map[string]any); ok && !flag(p, "consumer") && str(p, "serviceDefinition") != "" {
					definitions[str(p, "serviceDefinition")] = true
				}
			}
		}
		names := []string{}
		for d := range definitions {
			names = append(names, d)
		}
		sort.Strings(names)
		var instances []Document
		if len(names) > 0 {
			var found Document
			if e := a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/mgmt/service-instances/query", Document{"pagination": Document{"page": 0, "size": 1000}, "serviceDefinitionNames": names}, &found); e != nil {
				state["ok"], state["detail"] = false, "registry not available: "+e.Error()
				return
			}
			if _, ok := found["entries"].([]any); !ok || number(found, "count", 0) > len(list(found, "entries")) {
				state["ok"], state["detail"] = false, "registry service query incomplete"
				return
			}
			for _, v := range list(found, "entries") {
				if r, ok := v.(map[string]any); ok {
					instances = append(instances, r)
				}
			}
		}
		desired = resolveSnapshot(systems, connections, registered, instances)
	}
	removed, created, e := a.reconcileRules(ctx, desired)
	if e != nil {
		state["ok"], state["detail"] = false, "DSO not available: "+e.Error()
		return
	}
	state["ok"], state["rules"], state["removed"], state["created"] = true, len(list(desired, "rules")), removed, created
	state["detail"] = "no active plant description"
	if active {
		state["detail"] = "active plant in force"
	}
}

// reconcileRules atomically replaces the DSO snapshot only after a successful query.
func (a *App) reconcileRules(ctx context.Context, desired Document) (int, int, error) {
	var current Document
	if e := a.consume(ctx, "DynamicServiceOrchestration", "POST", "/serviceorchestration/mgmt/plant-rules/query", nil, &current); e != nil {
		return 0, 0, e
	}
	if _, ok := current["rules"].([]any); !ok {
		return 0, 0, fmt.Errorf("DSO returned an invalid snapshot")
	}
	if reflect.DeepEqual(current, desired) {
		return 0, 0, nil
	}
	var ack Document
	if e := a.consume(ctx, "DynamicServiceOrchestration", "PUT", "/serviceorchestration/mgmt/plant-rules/replace", desired, &ack); e != nil {
		return 0, 0, e
	}
	if !reflect.DeepEqual(ack, desired) {
		return 0, 0, fmt.Errorf("DSO did not acknowledge the desired snapshot")
	}
	return len(list(current, "rules")), len(list(desired, "rules")), nil
}

func resolveSnapshot(systems, connections, registered, instances []Document) Document {
	matched := matchSystems(systems, registered)
	scopes := map[string]map[string]int{}
	for _, c := range connections {
		cr, pr := obj(c, "consumer"), obj(c, "producer")
		cp, pp := findPort(systems, cr), findPort(systems, pr)
		if cp == nil || pp == nil {
			continue
		}
		names := map[string]bool{}
		for _, s := range systems {
			if str(s, "systemId") == str(cr, "systemId") && str(s, "systemName") != "" {
				names[str(s, "systemName")] = true
			}
		}
		for _, r := range matched[str(cr, "systemId")] {
			names[str(r, "name")] = true
		}
		def := str(pp, "serviceDefinition")
		if def == "" {
			def = str(cp, "serviceDefinition")
		}
		for name := range names {
			key := name + "|" + def
			if scopes[key] == nil {
				scopes[key] = map[string]int{}
			}
			producers := matched[str(pr, "systemId")]
			if len(producers) != 1 {
				continue
			}
			iface := str(pp, "serviceInterface")
			if iface == "" {
				iface = str(cp, "serviceInterface")
			}
			priority := int(number(c, "priority", pdeDefaultPriority))
			for _, inst := range instances {
				if str(obj(inst, "provider"), "name") != str(producers[0], "name") || str(obj(inst, "serviceDefinition"), "name") != def || !metadataSubset(obj(pp, "metadata"), obj(inst, "metadata")) || !offersInterface(inst, iface) {
					continue
				}
				id := str(inst, "instanceId")
				if old, ok := scopes[key][id]; !ok || priority < old {
					scopes[key][id] = priority
				}
			}
		}
	}
	keys := []string{}
	for key := range scopes {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rules := []any{}
	for _, key := range keys {
		parts := strings.SplitN(key, "|", 2)
		providers := []any{}
		ids := []string{}
		for id := range scopes[key] {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			if scopes[key][ids[i]] != scopes[key][ids[j]] {
				return scopes[key][ids[i]] < scopes[key][ids[j]]
			}
			return ids[i] < ids[j]
		})
		for _, id := range ids {
			providers = append(providers, Document{"serviceInstanceId": id, "priority": float64(scopes[key][id])})
		}
		rules = append(rules, Document{"consumer": parts[0], "serviceDefinition": parts[1], "providers": providers})
	}
	return Document{"rules": rules}
}

// updateAlarms raises the detected alarms and clears open alarms whose cause is gone. Monitoring alarms are left
// unchanged when the monitoring history cannot be read.
func (a *App) updateAlarms(ctx context.Context, active bool, systems, registered []Document) {
	type detected struct{ systemID, name, cause, description string }
	found := []detected{}
	causes := map[string]bool{alarmNotRegistered: true, alarmMultiple: true, alarmNotDescribed: true}
	if active {
		var observations map[string]string
		var history Document
		if a.Config.Upstreams["SysMonitor"] != "" && a.consume(ctx, "SysMonitor", "GET", "/sysmonitor/history/systems", nil, &history) == nil {
			observations = map[string]string{}
			for _, v := range list(history, "systems") {
				if m, ok := v.(map[string]any); ok && str(m, "systemName") != "" && str(m, "lastObservationTime") != "" {
					observations[str(m, "systemName")] = str(m, "lastObservationTime")
				}
			}
			causes[alarmNotMonitored], causes[alarmStale] = true, true
		}
		described := map[string]bool{}
		matched := matchSystems(systems, registered)
		for _, s := range systems {
			id := str(s, "systemId")
			matches := matched[id]
			for _, m := range matches {
				described[str(m, "name")] = true
			}
			switch {
			case len(matches) == 0:
				found = append(found, detected{id, str(s, "systemName"), alarmNotRegistered, "System '" + id + "' is in the plant description but not registered"})
			case len(matches) > 1:
				found = append(found, detected{id, str(s, "systemName"), alarmMultiple, fmt.Sprintf("System '%s' matches %d registered systems", id, len(matches))})
			case observations != nil:
				name := str(matches[0], "name")
				if last, ok := observations[name]; !ok {
					found = append(found, detected{id, name, alarmNotMonitored, "System '" + name + "' has published no sysMonitor observations"})
				} else if t, e := time.Parse(time.RFC3339Nano, last); e != nil || time.Since(t) > pdeStaleAfter {
					found = append(found, detected{id, name, alarmStale, "System '" + name + "' has published no sysMonitor observation since " + last})
				}
			}
		}
		for _, r := range registered {
			if name := str(r, "name"); !described[name] && !contains(stringsToAny(a.Config.AlarmIgnoredSystems), name) {
				found = append(found, detected{"", name, alarmNotDescribed, "System '" + name + "' is registered but not in the active plant description"})
			}
		}
	}
	_ = a.Store.Update(func(d database) error {
		key := func(systemID, name, cause string) string { return systemID + "|" + name + "|" + cause }
		want := map[string]detected{}
		for _, f := range found {
			want[key(f.systemID, f.name, f.cause)] = f
		}
		open := map[string]bool{}
		for _, row := range d["alarms"] {
			if row["clearedAt"] != nil || !causes[str(row, "cause")] {
				continue
			}
			k := key(str(row, "systemId"), str(row, "systemName"), str(row, "cause"))
			if _, still := want[k]; still {
				open[k] = true
			} else {
				row["clearedAt"], row["updatedAt"] = now(), now()
			}
		}
		for k, f := range want {
			if open[k] {
				continue
			}
			id, n := nextID(d, "alarms")
			bucket(d, "alarms")[id] = Document{"id": n, "systemId": nilIfEmpty(f.systemID), "systemName": f.name, "acknowledged": false, "severity": "ERROR", "cause": f.cause, "description": f.description, "raisedAt": now(), "updatedAt": now(), "clearedAt": nil, "acknowledgedAt": nil}
		}
		return nil
	})
}

func stringsToAny(xs []string) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

func nilIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
