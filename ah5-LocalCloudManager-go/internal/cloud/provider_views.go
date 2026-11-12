// SPDX-License-Identifier: EPL-2.0
package cloud

// Console views that read the v5.2.2 Go providers of this distribution (2026-11-11). The requests follow the providers'
// own contracts:
//   - ServiceRegistry: mgmt/service-instances/query needs at least one of instanceIds, providerNames or
//     serviceDefinitionNames; the registered systems' names are used as providerNames.
//   - DataManager: the dataHistorian service lists systems and their services and returns SenML records per service
//     (GET /datamanager/data-historian/systems/{system}/services/{service}/data?count=N); there is no aggregate
//     historian endpoint.
//   - SysMonitor: the sysMonitorHistory service lists the observed systems and returns their latest observations and
//     history (GET /sysmonitor/history/systems[/{system}/latest|observations]).

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// managerDataMaxStreams bounds the provider calls of one DataManager view (one call per system/service pair).
const managerDataMaxStreams = 64

func (a *App) registryQuery(resource string) (map[string]any, error) {
	body := map[string]any{}
	if resource == "service-instances" {
		systems, err := a.registryQuery("systems")
		if err != nil {
			return nil, err
		}
		names := registeredSystemNames(systems)
		if len(names) == 0 {
			return map[string]any{"entries": []any{}, "count": 0}, nil
		}
		body["providerNames"] = names
	}
	return a.managerJSON(http.MethodPost, a.Config.RegistryURL+"/serviceregistry/mgmt/"+resource+"/query", body)
}

// registeredSystemNames returns the sorted, distinct names of a systems query result.
func registeredSystemNames(payload map[string]any) []string {
	seen := map[string]bool{}
	names := []string{}
	for _, raw := range entries(payload) {
		if name := mapString(object(raw)["name"]); name != "" && !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// managerAny calls a provider and decodes any JSON document (DataManager returns SenML packs as arrays).
func (a *App) managerAny(method, endpoint string) (any, error) {
	b, err := a.call(method, endpoint, nil, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func stringList(v any) []string {
	out := []string{}
	for _, raw := range anySlice(v) {
		if s := mapString(raw); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (a *App) managerData(r *http.Request) (map[string]any, error) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 {
		limit = 240
	}
	if limit > 1000 {
		limit = 1000
	}
	base := strings.TrimRight(env("DATAMANAGER_URL", "http://datamanager:8461"), "/") + "/datamanager/data-historian"
	listed, err := a.managerAny(http.MethodGet, base+"/systems")
	if err != nil {
		return nil, err
	}
	flat, problems, streams := []any{}, []any{}, 0
	for _, system := range stringList(object(listed)["systems"]) {
		services, err := a.managerAny(http.MethodGet, base+"/systems/"+url.PathEscape(system)+"/services")
		if err != nil {
			problems = append(problems, system+": "+err.Error())
			continue
		}
		for _, service := range stringList(object(services)["services"]) {
			if streams >= managerDataMaxStreams {
				break
			}
			streams++
			records, err := a.managerAny(http.MethodGet, base+"/systems/"+url.PathEscape(system)+"/services/"+url.PathEscape(service)+"/data?count="+strconv.Itoa(limit))
			if err != nil {
				problems = append(problems, system+"/"+service+": "+err.Error())
				continue
			}
			flat = append(flat, senmlEntries(system, service, anySlice(records))...)
		}
	}
	sort.SliceStable(flat, func(i, j int) bool {
		ti, _ := number(object(flat[i])["time"])
		tj, _ := number(object(flat[j])["time"])
		return ti < tj
	})
	if len(flat) > limit {
		flat = flat[len(flat)-limit:]
	}
	return map[string]any{"collectedAt": now(), "count": len(flat), "latest": []any{}, "entries": reverseAny(flat), "series": dataSeries(flat), "errors": problems}, nil
}

// senmlEntries flattens stored SenML records (RFC 8428: base name/time apply to the records that follow them) into the
// console's data entries.
func senmlEntries(system, service string, records []any) []any {
	out := []any{}
	baseName, baseTime := "", 0.0
	for _, raw := range records {
		record := object(raw)
		if record == nil {
			continue
		}
		if bn, ok := record["bn"].(string); ok {
			baseName = bn
		}
		if bt, ok := number(record["bt"]); ok {
			baseTime = bt
		}
		name := baseName + mapString(record["n"])
		if name == "" {
			continue
		}
		entry := map[string]any{"system": system, "service": service, "name": name, "unit": record["u"],
			"value": map[string]any{"v": record["v"], "vs": record["vs"], "vb": record["vb"]}}
		if t, ok := number(record["t"]); ok || baseTime != 0 {
			entry["time"] = baseTime + t
		} else {
			entry["time"] = nil
		}
		out = append(out, entry)
	}
	return out
}

func (a *App) managerSysMonitor(r *http.Request) (map[string]any, error) {
	base := strings.TrimRight(env("SYSMONITOR_URL", "http://sysmonitor:8475"), "/") + "/sysmonitor/history"
	payload, err := a.managerJSON(http.MethodGet, base+"/systems", nil)
	if err != nil {
		return nil, err
	}
	type row struct {
		name  string
		count float64
		last  any
	}
	rows := []row{}
	stored := 0.0
	for _, raw := range anySlice(payload["systems"]) {
		s := object(raw)
		count, _ := number(s["observationCount"])
		stored += count
		if name := mapString(s["systemName"]); name != "" {
			rows = append(rows, row{name, count, s["lastObservationTime"]})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	selected := r.URL.Query().Get("system")
	if selected == "" && len(rows) > 0 {
		selected = rows[0].name
	}
	systems := []any{}
	for _, s := range rows {
		latest := map[string]any{}
		if doc, err := a.managerJSON(http.MethodGet, base+"/systems/"+url.PathEscape(s.name)+"/latest", nil); err == nil {
			for typ, obs := range object(doc["latest"]) {
				latest[typ] = observationView(object(obs))
			}
		} else if failure := (*serviceCallError)(nil); !errors.As(err, &failure) || failure.status != http.StatusNotFound {
			return nil, err
		}
		systems = append(systems, map[string]any{"systemName": s.name, "observationCount": int(s.count), "lastObservationTime": s.last, "latest": latest})
	}
	observations := []any{}
	if selected != "" {
		doc, err := a.managerJSON(http.MethodGet, base+"/systems/"+url.PathEscape(selected)+"/observations?count=200", nil)
		if err != nil {
			return nil, err
		}
		for _, raw := range anySlice(doc["observations"]) {
			observations = append(observations, observationView(object(raw)))
		}
	}
	return map[string]any{"collectedAt": now(), "retentionDays": payload["retentionDays"], "storedObservations": int(stored), "systems": systems, "selectedSystem": selected, "observations": observations}, nil
}

func observationView(item map[string]any) map[string]any {
	typ := mapString(item["observationType"])
	if typ == "" {
		typ = "status"
	}
	source := mapString(item["sourceTime"])
	if source == "" {
		source = mapString(item["receivedTime"])
	}
	return map[string]any{"observationType": typ, "sourceTime": source, "value": item["value"], "unit": item["unit"], "quality": item["quality"]}
}
