// SPDX-License-Identifier: EPL-2.0
package core

import (
	"fmt"
	"math"
	"net/http"
	"strconv"
)

func validatePlant(d database, id string, row Document) error {
	if e := require(row, "plantDescription"); e != nil {
		return e
	}
	systems := map[string]Document{}
	ports := map[string]bool{}
	var visit func(string, map[string]bool) error
	visit = func(key string, stack map[string]bool) error {
		if stack[key] {
			return bad("Cyclic plant inclusion")
		}
		plant := row
		if key != id {
			plant = d["plants"][key]
			if plant == nil {
				return bad("Included plant does not exist")
			}
		}
		stack[key] = true
		defer delete(stack, key)
		for _, v := range list(plant, "include") {
			n, ok := v.(float64)
			if !ok {
				return bad("include requires numeric IDs")
			}
			if e := visit(strconv.FormatInt(int64(n), 10), stack); e != nil {
				return e
			}
		}
		for _, v := range list(plant, "systems") {
			system, ok := v.(map[string]any)
			if !ok || str(system, "systemId") == "" {
				return bad("Invalid plant system")
			}
			name := str(system, "systemId")
			if systems[name] != nil {
				return bad("Duplicate included systemId")
			}
			systems[name] = system
			for _, p := range list(system, "ports") {
				port, ok := p.(map[string]any)
				if !ok || str(port, "portName") == "" {
					return bad("Invalid port")
				}
				key := name + "|" + str(port, "portName")
				if ports[key] {
					return bad("Duplicate port")
				}
				ports[key] = true
			}
		}
		return nil
	}
	if e := visit(id, map[string]bool{}); e != nil {
		return e
	}
	for _, v := range list(row, "connections") {
		connection, ok := v.(map[string]any)
		if !ok {
			return bad("Invalid connection")
		}
		if v, exists := connection["priority"]; exists && v != nil {
			p, ok := v.(float64)
			if !ok || p < 0 || p > 2147483647 || math.Trunc(p) != p {
				return bad("Nonnegative integer priority required")
			}
		}
		for _, side := range []string{"consumer", "producer"} {
			endpoint := obj(connection, side)
			if !ports[str(endpoint, "systemId")+"|"+str(endpoint, "portName")] {
				return bad("Connection references an unknown system port")
			}
		}
	}
	return nil
}
func (a *App) plantRoutes() {
	b := "/plantdescriptionengine"
	a.route("GET", b+"/mgmt/sync-status", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		var state Document
		e := a.Store.ViewTables(func(d database) error { state = d["pdeSync"]["state"]; return nil }, "pdeSync")
		if state == nil {
			state = Document{"ok": false, "detail": "not synchronized yet"}
		}
		return state, 200, e
	})
	for _, part := range []string{"mgmt", "monitor"} {
		p := part
		access := "management"
		if p == "monitor" {
			access = "identity"
		}
		base := b + "/" + p + "/plant-descriptions"
		a.route("GET", base, access, func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			if p == "monitor" {
				if e := a.authorize(r, "plantDescriptionMonitor", "query-plant-descriptions"); e != nil {
					return nil, 0, e
				}
			}
			rows := []Document{}
			for _, row := range a.rows("plants") {
				if s := r.URL.Query().Get("active"); s != "" && fmt.Sprint(row["active"]) != s {
					continue
				}
				if p == "monitor" {
					row = a.monitorPlant(r, row)
				}
				rows = append(rows, row)
			}
			v, e := page(rows, queryDoc(r), "entries")
			return v, 200, e
		})
		a.route("GET", base+"/{id}", access, func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			if p == "monitor" {
				if e := a.authorize(r, "plantDescriptionMonitor", "get-plant-description"); e != nil {
					return nil, 0, e
				}
			}
			row, e := a.row("plants", r.PathValue("id"))
			if e == nil && p == "monitor" {
				row = a.monitorPlant(r, row)
			}
			return row, 200, e
		})
		if p == "mgmt" {
			for _, method := range []string{"POST", "PUT", "PATCH"} {
				m := method
				path := base
				if m != "POST" {
					path += "/{id}"
				}
				a.route(m, path, "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
					req, e := decode(w, r)
					if e != nil {
						return nil, 0, e
					}
					var row Document
					e = a.Store.Update(func(d database) error {
						id := r.PathValue("id")
						if m == "POST" {
							key, n := nextID(d, "plants")
							id = key
							row = Document{"id": n, "createdAt": now(), "active": false}
						} else {
							row = d["plants"][id]
							if row == nil {
								return &APIError{404, "Plant not found"}
							}
						}
						if m == "PUT" {
							row = Document{"id": row["id"], "createdAt": row["createdAt"], "active": false}
						}
						for _, k := range []string{"plantDescription", "active", "include", "systems", "connections"} {
							if v, ok := req[k]; ok {
								row[k] = v
							}
						}
						if e := validatePlant(d, id, row); e != nil {
							return e
						}
						if flag(row, "active") {
							for _, other := range d["plants"] {
								other["active"] = false
							}
						}
						row["updatedAt"] = now()
						bucket(d, "plants")[id] = row
						return nil
					})
					status := 200
					if m == "POST" {
						status = 201
					}
					return row, status, e
				})
			}
			a.route("DELETE", base+"/{id}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
				e := a.Store.Update(func(d database) error {
					id := r.PathValue("id")
					for _, row := range d["plants"] {
						for _, v := range list(row, "include") {
							if fmt.Sprint(v) == id {
								return &APIError{409, "Plant is included by another description"}
							}
						}
					}
					if d["plants"][id] == nil {
						return &APIError{404, "Plant not found"}
					}
					delete(d["plants"], id)
					return nil
				})
				return nil, 200, e
			})
		}
	}
	a.serviceRoute("GET", b+"/monitor/alarms", "plantDescriptionMonitor", "query-alarms", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		rows := []Document{}
		for _, row := range a.rows("alarms") {
			matches := true
			for query, key := range map[string]string{"system_name": "systemName", "severity": "severity", "acknowledged": "acknowledged"} {
				if s := r.URL.Query().Get(query); s != "" && fmt.Sprint(row[key]) != s {
					matches = false
				}
			}
			if matches {
				rows = append(rows, row)
			}
		}
		v, e := page(rows, queryDoc(r), "entries")
		return v, 200, e
	})
	a.serviceRoute("GET", b+"/monitor/alarms/{id}", "plantDescriptionMonitor", "get-alarm", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		v, e := a.row("alarms", r.PathValue("id"))
		return v, 200, e
	})
	a.serviceRoute("PATCH", b+"/monitor/alarms/{id}", "plantDescriptionMonitor", "acknowledge-alarm", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		b, ok := req["acknowledged"].(bool)
		if !ok {
			return nil, 0, bad("acknowledged must be boolean")
		}
		var row Document
		e = a.Store.Update(func(d database) error {
			row = d["alarms"][r.PathValue("id")]
			if row == nil {
				return &APIError{404, "Alarm not found"}
			}
			row["acknowledged"] = b
			row["updatedAt"] = now()
			if b {
				row["acknowledgedAt"] = now()
			} else {
				row["acknowledgedAt"] = nil
			}
			return nil
		})
		return row, 200, e
	})
}
func (a *App) monitorPlant(r *http.Request, row Document) Document {
	systems := []Document{}
	for _, v := range list(row, "systems") {
		system, ok := v.(map[string]any)
		if !ok {
			continue
		}
		name := str(system, "systemName")
		system["registeredSystemName"] = name
		var observation Document
		e := a.consume(r.Context(), "SysMonitor", "GET", "/sysmonitor/history/systems/"+name+"/latest", nil, &observation)
		if e != nil {
			system["monitoring"] = Document{"status": "unknown", "reason": "Monitoring history unavailable"}
		} else {
			system["monitoring"] = observation["latest"]
			system["lastObservationTime"] = now()
		}
		systems = append(systems, system)
	}
	row["systems"] = systems
	return row
}
func (a *App) raiseAlarm(systemID, name, cause, description string) error {
	return a.Store.Update(func(d database) error {
		for _, row := range d["alarms"] {
			if str(row, "systemId") == systemID && str(row, "cause") == cause && row["clearedAt"] == nil {
				return nil
			}
		}
		id, n := nextID(d, "alarms")
		bucket(d, "alarms")[id] = Document{"id": n, "systemId": systemID, "systemName": name, "acknowledged": false, "severity": "ERROR", "cause": cause, "description": description, "raisedAt": now(), "updatedAt": now(), "clearedAt": nil, "acknowledgedAt": nil}
		return nil
	})
}
