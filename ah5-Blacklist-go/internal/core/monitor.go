// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// monitorLookup returns the subscriptions and orchestrated offers (small tables) for intake validation.
func (a *App) monitorLookup() (subs, offers map[string]Document) {
	_ = a.Store.ViewTables(func(d database) error {
		subs, offers = d["monitorSubscriptions"], d["monitorProviders"]
		return nil
	}, "monitorSubscriptions", "monitorProviders")
	return subs, offers
}
func (a *App) ingestObservation(routing string, input Document) error {
	subs, offers := a.monitorLookup()
	record, e := a.prepareObservation(routing, input, subs, offers)
	if e != nil {
		return e
	}
	return a.Store.UpdateTables(func(d database) error { return a.storeObservation(d, record) }, "observations", "outbox")
}

// prepareObservation validates one AMQP observation against its routing key, the orchestrated offer and the
// subscription, and returns the normalized record (no state change).
func (a *App) prepareObservation(routing string, input Document, subs, offers map[string]Document) (Document, error) {
	parts := strings.Split(routing, ".")
	if len(parts) != 5 || parts[0] != strings.Split(a.Config.CloudSuffix, ".")[0] || parts[1] != "sysmonitor" || !validName(parts[2]) || parts[3] == "" || parts[4] == "" {
		return nil, bad("Invalid monitoring routing key")
	}
	provider, typ := parts[2], parts[4]
	sub, offer := subs[provider], offers[provider]
	if offer == nil || str(offer, "baseRoutingKey") != strings.Join(parts[:4], ".") {
		return nil, forbidden()
	}
	if sub == nil {
		if a.Config.DefaultSubscription != "all" {
			return nil, forbidden()
		}
	} else if !flag(sub, "enabled") || !contains(list(sub, "observationTypes"), "*") && !contains(list(sub, "observationTypes"), typ) {
		return nil, forbidden()
	}
	id := str(input, "observationId")
	if id == "" {
		b, e := json.Marshal(input)
		if e != nil {
			return nil, e
		}
		id = digest(routing + "\x00" + string(b))
	}
	source := str(input, "sourceTime")
	if _, e := time.Parse(time.RFC3339Nano, source); e != nil || !strings.HasSuffix(source, "Z") {
		return nil, bad("Invalid sourceTime")
	}
	if version := str(input, "schemaVersion"); version != "" && strings.Split(version, ".")[0] != "1" {
		return nil, bad("Unsupported schemaVersion")
	}
	if _, exists := input["value"]; !exists {
		return nil, bad("Observation value required")
	}
	value := obj(input, "value")
	if typ == "echo" && !contains([]any{"alive", "degraded", "failed"}, str(value, "status")) {
		return nil, bad("Invalid echo status")
	}
	if typ == "power" && !contains([]any{"line", "battery", "harvesting"}, str(value, "supplyType")) {
		return nil, bad("Invalid power supply")
	}
	if instance := str(input, "serviceInstance"); instance != "" && instance != parts[3] {
		return nil, bad("Service instance/routing mismatch")
	}
	if s := str(input, "providerSystem"); s != "" && s != provider {
		return nil, forbidden()
	}
	if s := str(input, "observationType"); s != "" && s != typ {
		return nil, bad("Observation type/routing mismatch")
	}
	quality := input["quality"]
	if quality == nil {
		quality = "good"
	}
	metadata := input["metadata"]
	if metadata == nil {
		metadata = Document{}
	}
	input = Document{"schemaVersion": "1.0", "observationId": id, "providerSystem": provider, "serviceInstance": parts[3], "observationType": typ, "sourceTime": source, "receivedTime": now(), "publishedTime": nil, "value": input["value"], "unit": input["unit"], "quality": quality, "metadata": metadata, "pipeline": Document{"sysMonitor": a.Config.Name, "revision": 1}}
	return input, nil
}

// storeObservation adds a prepared record inside a store transaction (duplicates are ignored: at-least-once intake)
// and keeps at most maxObservationsPerSystem observations of its provider, dropping the oldest.
func (a *App) storeObservation(d database, record Document) error {
	id := str(record, "observationId")
	if d["observations"][id] != nil {
		return nil
	}
	if len(d["outbox"]) >= 10000 {
		return &APIError{503, "Observation outbox full"}
	}
	bucket(d, "observations")[id] = record
	// the job refers to the stored observation (kept until forwarded) instead of holding a second copy of it
	bucket(d, "outbox")[id] = Document{"id": id, "kind": "observation", "createdAt": now(), "attempts": 0}
	return nil
}

// capObservations enforces maxObservationsPerSystem for the given providers (oldest receivedTime first).
func (a *App) capObservations(d database, providers map[string]bool) {
	limit := a.Config.MaxObservationsPerSystem
	if limit < 1 {
		return
	}
	per := map[string][]string{}
	for key, row := range d["observations"] {
		if p := str(row, "providerSystem"); providers == nil || providers[p] {
			per[p] = append(per[p], key)
		}
	}
	for _, keys := range per {
		if len(keys) <= limit {
			continue
		}
		sort.Slice(keys, func(i, j int) bool {
			return str(d["observations"][keys[i]], "receivedTime") < str(d["observations"][keys[j]], "receivedTime")
		})
		for _, key := range keys[:len(keys)-limit] {
			if d["outbox"][key] == nil {
				delete(d["observations"], key)
			}
		}
	}
}
func (a *App) reconcileMonitor(ctx context.Context) error {
	var response Document
	e := a.consume(ctx, "ServiceOrchestration", "POST", "/serviceorchestration/orchestration/pull", Document{"serviceRequirement": Document{"serviceDefinition": "sysMonitor", "interfaceTemplateNames": []string{"generic_amqps"}}}, &response)
	if e != nil {
		return e
	}
	offers := map[string]Document{}
	for _, v := range list(response, "results") {
		row, ok := v.(map[string]any)
		if !ok {
			continue
		}
		provider := str(row, "providerName")
		if !validName(provider) {
			continue
		}
		for _, iv := range list(row, "interfaces") {
			intf, ok := iv.(map[string]any)
			if !ok || str(intf, "templateName") != "generic_amqps" {
				continue
			}
			p := obj(intf, "properties")
			base := str(p, "baseRoutingKey")
			parts := strings.Split(base, ".")
			if len(parts) != 4 || parts[1] != "sysmonitor" || parts[2] != provider {
				continue
			}
			offers[provider] = Document{"providerSystem": provider, "serviceInstanceId": row["serviceInstanceId"], "baseRoutingKey": base, "exchange": p["exchange"], "observationTypes": p["operations"], "broker": p["accessAddresses"], "port": p["accessPort"], "orchestratedAt": now()}
		}
	}
	return a.Store.Update(func(d database) error { d["monitorProviders"] = offers; return nil })
}
func (a *App) monitorRoutes() {
	b := "/sysmonitor"
	for _, resource := range []string{"status", "providers", "subscriptions"} {
		res := resource
		a.route("GET", b+"/management/"+res, "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			if res == "status" {
				return a.monitorStatus(), 200, nil
			}
			table := "monitorProviders"
			if res == "subscriptions" {
				table = "monitorSubscriptions"
			}
			return Document{"defaultSubscription": a.Config.DefaultSubscription, "list": a.rows(table)}, 200, nil
		})
	}
	a.route("PUT", b+"/management/subscriptions/{providerSystem}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		provider := r.PathValue("providerSystem")
		if !validName(provider) {
			return nil, 0, bad("Invalid providerSystem")
		}
		types := list(req, "observationTypes")
		if len(types) == 0 {
			return nil, 0, bad("observationTypes required")
		}
		for _, v := range types {
			s, ok := v.(string)
			if !ok || s == "" || strings.ContainsAny(s, ".#/+") || s == "*" && len(types) != 1 {
				return nil, 0, bad("Invalid observationTypes")
			}
		}
		revision, check, e := revisionHeader(r)
		if e != nil {
			return nil, 0, e
		}
		var row Document
		e = a.Store.Update(func(d database) error {
			previous := d["monitorSubscriptions"][provider]
			n := number(previous, "revision", 0)
			if check && (previous == nil || revision != n) {
				return &APIError{409, "Subscription revision conflict"}
			}
			enabled := true
			if req["enabled"] != nil {
				v, ok := req["enabled"].(bool)
				if !ok {
					return bad("enabled must be boolean")
				}
				enabled = v
			}
			row = Document{"providerSystem": provider, "observationTypes": types, "enabled": enabled, "revision": n + 1, "updatedAt": now(), "updatedBy": caller(r).Name}
			bucket(d, "monitorSubscriptions")[provider] = row
			return nil
		})
		if e == nil {
			w.Header().Set("ETag", fmt.Sprint(row["revision"]))
		}
		return row, 200, e
	})
	a.route("DELETE", b+"/management/subscriptions/{providerSystem}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		_, e := removeRow(a, "monitorSubscriptions", r.PathValue("providerSystem"))
		return nil, 204, e
	})
	a.route("POST", b+"/management/reconcile", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		if e := a.reconcileMonitor(r.Context()); e != nil {
			return nil, 0, e
		}
		return Document{"jobId": uuid()}, 202, nil
	})
	a.serviceRoute("GET", b+"/history/systems", "sysMonitorHistory", "list-systems", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		groups := map[string]Document{}
		a.Store.Select("observations", func(row Document) bool {
			name := str(row, "providerSystem")
			g := groups[name]
			if g == nil {
				g = Document{"systemName": name, "observationCount": 0, "firstObservationTime": row["sourceTime"], "lastObservationTime": row["sourceTime"]}
				groups[name] = g
			}
			g["observationCount"] = number(g, "observationCount", 0) + 1
			if str(row, "sourceTime") < str(g, "firstObservationTime") {
				g["firstObservationTime"] = row["sourceTime"]
			}
			if str(row, "sourceTime") > str(g, "lastObservationTime") {
				g["lastObservationTime"] = row["sourceTime"]
			}
			return false
		})
		rows := []Document{}
		for _, row := range groups {
			rows = append(rows, row)
		}
		return Document{"systems": rows, "retentionDays": a.Config.RetentionDays}, 200, nil
	})
	for _, resource := range []string{"latest", "observations"} {
		res := resource
		op := "query"
		if res == "latest" {
			op = "latest"
		}
		a.serviceRoute("GET", b+"/history/systems/{systemName}/"+res, "sysMonitorHistory", op, func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			name := r.PathValue("systemName")
			n, e := parseCount(r, 100)
			if e != nil {
				return nil, 0, e
			}
			rows := []Document{}
			from, to := "", ""
			for key, p := range map[string]*string{"from": &from, "to": &to} {
				if s := r.URL.Query().Get(key); s != "" {
					if v, e := strconv.ParseFloat(s, 64); e == nil {
						*p = time.UnixMilli(int64(v * 1000)).UTC().Format(time.RFC3339Nano)
					} else {
						if _, e = time.Parse(time.RFC3339Nano, s); e != nil {
							return nil, 0, bad("Invalid " + key)
						}
						*p = s
					}
				}
			}
			types := []string{}
			for _, s := range r.URL.Query()["type"] {
				types = append(types, strings.Split(s, ",")...)
			}
			rows = a.Store.Select("observations", func(row Document) bool {
				if str(row, "providerSystem") != name || !timeRange(str(row, "sourceTime"), from, to) {
					return false
				}
				if len(types) > 0 {
					found := false
					for _, typ := range types {
						if typ == str(row, "observationType") {
							found = true
						}
					}
					if !found {
						return false
					}
				}
				return true
			})
			sort.Slice(rows, func(i, j int) bool { return str(rows[i], "sourceTime") > str(rows[j], "sourceTime") })
			if res == "latest" {
				latest := Document{}
				for _, row := range rows {
					typ := str(row, "observationType")
					if latest[typ] == nil {
						latest[typ] = row
					}
				}
				if len(latest) == 0 {
					return nil, 0, &APIError{404, "No stored observations"}
				}
				return Document{"systemName": name, "latest": latest}, 200, nil
			}
			if len(rows) > n {
				rows = rows[:n]
			}
			return Document{"systemName": name, "count": len(rows), "observations": rows}, 200, nil
		})
	}
}
func (a *App) monitorStatus() Document {
	status := "degraded"
	if a.broker.amqpConnected.Load() && a.broker.mqttConnected.Load() && len(a.rows("monitorProviders")) > 0 {
		status = "running"
	}
	return Document{"system": "SysMonitor", "implementation": "Go", "status": status, "version": "5.2.2", "defaultSubscription": a.Config.DefaultSubscription, "providers": a.rows("monitorProviders"), "subscriptions": a.rows("monitorSubscriptions"), "storage": Document{"stored": a.Store.Count("observations"), "pending": a.Store.Count("outbox"), "retentionDays": a.Config.RetentionDays}, "amqp": Document{"connected": a.broker.amqpConnected.Load()}, "mqtt": Document{"connected": a.broker.mqttConnected.Load()}}
}
