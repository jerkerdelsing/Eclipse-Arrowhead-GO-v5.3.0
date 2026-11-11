// SPDX-License-Identifier: EPL-2.0
package core

import (
	"encoding/base64"
	"math"
	"mime"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (a *App) blacklistRoutes() {
	a.serviceRoute("GET", "/blacklist/check/{systemName}", "blacklistDiscovery", "check", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		row, _ := a.row("blacklist", r.PathValue("systemName"))
		return active(row), 200, nil
	})
	a.serviceRoute("GET", "/blacklist/lookup", "blacklistDiscovery", "lookup", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		rows := []Document{}
		for _, row := range a.rows("blacklist") {
			if active(row) {
				rows = append(rows, row)
			}
		}
		return Document{"entries": rows, "count": len(rows)}, 200, nil
	})
	a.route("POST", "/blacklist/mgmt/create", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if len(list(req, "entities")) == 0 {
			return nil, 0, bad("entities required")
		}
		rows := []Document{}
		e = a.Store.Update(func(d database) error {
			for _, v := range list(req, "entities") {
				item, ok := v.(map[string]any)
				if !ok || !validName(str(item, "systemName")) {
					return bad("Invalid systemName")
				}
				if s := str(item, "expiresAt"); s != "" && expired(s) {
					return bad("expiresAt must be in the future")
				}
				row := Document{"systemName": item["systemName"], "reason": item["reason"], "expiresAt": item["expiresAt"], "createdBy": caller(r).Name, "createdAt": now(), "updatedAt": now(), "revokedBy": nil, "active": true}
				bucket(d, "blacklist")[str(item, "systemName")] = row
				rows = append(rows, row)
			}
			return nil
		})
		return Document{"entries": rows, "count": len(rows)}, 201, e
	})
	a.route("DELETE", "/blacklist/mgmt/remove", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		names, e := queryNames(r, "names")
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for _, name := range names {
				if row := d["blacklist"][name]; row != nil {
					row["active"] = false
					row["revokedBy"] = caller(r).Name
					row["updatedAt"] = now()
				}
			}
			return nil
		})
		return nil, 200, e
	})
	a.route("POST", "/blacklist/mgmt/query", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decodeOptional(w, r)
		if e != nil {
			return nil, 0, e
		}
		mode := str(req, "mode")
		if mode != "" && mode != "ALL" && mode != "ACTIVE" && mode != "INACTIVE" {
			return nil, 0, bad("Invalid mode")
		}
		rows := []Document{}
		for _, row := range a.rows("blacklist") {
			isActive := active(row)
			if mode == "ACTIVE" && !isActive || mode == "INACTIVE" && isActive {
				continue
			}
			if !selected(req, "systemNames", str(row, "systemName")) || !selected(req, "issuers", str(row, "createdBy")) || !selected(req, "revokers", str(row, "revokedBy")) || !strings.Contains(str(row, "reason"), str(req, "reason")) {
				continue
			}
			row["active"] = isActive
			rows = append(rows, row)
		}
		out, e := page(rows, req, "entries")
		return out, 200, e
	})
}
func (a *App) configurationRoutes() {
	get := func(raw bool) endpoint {
		return func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			name := r.PathValue("systemName")
			if name != caller(r).Name && !caller(r).Sysop {
				return nil, 0, forbidden()
			}
			row, e := a.row("configuration", name)
			if e != nil {
				return nil, 0, e
			}
			if raw {
				b, e := base64.StdEncoding.DecodeString(str(row, "data"))
				return binaryResponse{b, str(row, "contentType")}, 200, e
			}
			return row, 200, nil
		}
	}
	for _, prefix := range []string{"/configuration", "/configuration/proxy"} {
		def := "configuration"
		if strings.HasSuffix(prefix, "/proxy") {
			def = "configurationProxy"
		}
		a.serviceRoute("GET", prefix+"/config/{systemName}", def, "get-configuration", get(false))
	}
	a.serviceRoute("GET", "/configuration/config/raw/{systemName}", "configuration", "get-raw-configuration", get(true))
	save := func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		name := str(req, "systemName")
		if !validName(name) {
			return nil, 0, bad("Invalid systemName")
		}
		if r.PathValue("systemName") != "" && r.PathValue("systemName") != name {
			return nil, 0, bad("Path and body system names differ")
		}
		if strings.Contains(r.URL.Path, "/proxy/") && name != caller(r).Name && !caller(r).Sysop {
			return nil, 0, forbidden()
		}
		if e = require(req, "fileName", "contentType", "data"); e != nil {
			return nil, 0, e
		}
		if strings.ContainsAny(str(req, "fileName"), "/\\\r\n") || len(str(req, "fileName")) > 255 {
			return nil, 0, bad("Invalid fileName")
		}
		if _, _, e = mime.ParseMediaType(str(req, "contentType")); e != nil {
			return nil, 0, bad("Invalid contentType")
		}
		content, e := base64.StdEncoding.Strict().DecodeString(str(req, "data"))
		if e != nil {
			return nil, 0, bad("data must be base64")
		}
		var row Document
		e = a.Store.Update(func(d database) error {
			row = bucket(d, "configuration")[name]
			if row == nil {
				_, id := nextID(d, "configuration")
				row = Document{"id": id, "createdAt": now()}
			}
			for _, k := range []string{"systemName", "fileName", "contentType", "data"} {
				row[k] = req[k]
			}
			row["size"] = len(content)
			row["updatedAt"] = now()
			d["configuration"][name] = row
			return nil
		})
		return row, 200, e
	}
	a.route("PUT", "/configuration/mgmt/config/{systemName}", "management", save)
	a.serviceRoute("PUT", "/configuration/proxy/save-config", "configurationProxy", "store-configuration", save)
	a.route("GET", "/configuration/mgmt/config", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		rows := a.rows("configuration")
		sort.Slice(rows, func(i, j int) bool { return str(rows[i], "systemName") < str(rows[j], "systemName") })
		return Document{"count": len(rows), "data": rows}, 200, nil
	})
	a.route("DELETE", "/configuration/mgmt/config/{systemName}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		row, e := removeRow(a, "configuration", r.PathValue("systemName"))
		return row, 200, e
	})
}
func (a *App) timeRoutes() {
	a.serviceRoute("GET", "/timemanager/time", "time", "get-time", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		zone := a.Config.TimeZone
		if zone == "" {
			zone = "UTC"
		}
		loc, e := time.LoadLocation(zone)
		if e != nil {
			return nil, 0, e
		}
		t := time.Now()
		trust := a.timeTrust(r)
		return Document{"epoch": t.Unix(), "epochMs": t.UnixMilli(), "tz": zone, "dst": t.In(loc).IsDST(), "trusted": trust["trusted"], "offsetMs": trust["offsetMs"], "timeSource": trust["server"], "lastCheckTime": trust["checkedAt"]}, 200, nil
	})
}
func (a *App) aiRoutes() {
	a.route("GET", "/health", "certificate", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return Document{"status": "up", "system": "AIGym", "time": now()}, 200, nil
	})
	a.serviceRoute("POST", "/aigym/samples", "aiGym", "add-sample", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if e = features(obj(req, "features")); e != nil {
			return nil, 0, e
		}
		target, ok := req["target"].(float64)
		if !ok || math.IsNaN(target) || math.IsInf(target, 0) {
			return nil, 0, bad("Numeric target required")
		}
		model := strings.TrimSpace(str(req, "model"))
		if model == "" {
			model = "default"
		}
		row := Document{"id": uuid(), "model": model, "features": req["features"], "target": target, "createdAt": now()}
		e = a.Store.Update(func(d database) error { bucket(d, "samples")[str(row, "id")] = row; return nil })
		return row, 201, e
	})
	a.serviceRoute("POST", "/aigym/predict", "aiGym", "predict", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		f := obj(req, "features")
		if e = features(f); e != nil {
			return nil, 0, e
		}
		model := strings.TrimSpace(str(req, "model"))
		if model == "" {
			model = "default"
		}
		rows := []Document{}
		for _, s := range a.rows("samples") {
			if str(s, "model") == model {
				rows = append(rows, s)
			}
		}
		if len(rows) == 0 {
			return nil, 0, bad("Model has no training samples")
		}
		sort.Slice(rows, func(i, j int) bool {
			return distance(obj(rows[i], "features"), f) < distance(obj(rows[j], "features"), f)
		})
		k := number(req, "neighbours", 3)
		if k < 1 {
			k = 1
		}
		if k > len(rows) {
			k = len(rows)
		}
		value := 0.0
		for _, s := range rows[:k] {
			value += s["target"].(float64)
		}
		prediction := Document{"model": model, "value": value / float64(k), "neighbours": k, "trainingSamples": len(rows), "createdAt": now()}
		e = a.Store.Update(func(d database) error { bucket(d, "aiObservations")[uuid()] = prediction; return nil })
		return prediction, 200, e
	})
	// latest authorized sysMonitorData observations (Java AIGym contract); predictions stay in the state as aiObservations
	a.serviceRoute("GET", "/aigym/observations", "aiGym", "observations", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		return a.broker.gym.snapshot(), 200, nil
	})
	a.serviceRoute("GET", "/aigym/status", "aiGym", "status", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		inventory := Document{}
		for _, s := range a.rows("samples") {
			model := str(s, "model")
			inventory[model] = number(inventory, model, 0) + 1
		}
		return a.aiGymStatus(inventory), 200, nil
	})
}
func features(f Document) error {
	if len(f) == 0 {
		return bad("Numeric features required")
	}
	for _, v := range f {
		n, ok := v.(float64)
		if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
			return bad("Invalid numeric feature")
		}
	}
	return nil
}
func distance(a, b Document) float64 {
	keys := map[string]bool{}
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	sum := 0.0
	for k := range keys {
		x, _ := a[k].(float64)
		y, _ := b[k].(float64)
		sum += (x - y) * (x - y)
	}
	return math.Sqrt(sum)
}
func parseCount(r *http.Request, def int) (int, error) {
	v := r.URL.Query().Get("count")
	if v == "" {
		return def, nil
	}
	n, e := strconv.Atoi(v)
	if e != nil || n < 1 || n > 1000 {
		return 0, bad("count must be 1–1000")
	}
	return n, nil
}
