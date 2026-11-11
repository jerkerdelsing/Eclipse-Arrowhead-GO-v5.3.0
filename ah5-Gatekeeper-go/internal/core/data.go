// SPDX-License-Identifier: EPL-2.0
package core

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (a *App) dataRoutes() {
	for _, area := range []string{"data-historian", "data-proxy"} {
		kind := area
		def := "dataHistorian"
		if kind == "data-proxy" {
			def = "dataProxy"
		}
		base := "/datamanager/" + kind
		a.serviceRoute("GET", base+"/systems", def, "list-systems", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			set := map[string]bool{}
			for _, row := range a.rows("senml") {
				set[str(row, "system")] = true
			}
			if kind == "data-proxy" {
				var v Document
				e := a.Remote.Call(r.Context(), "registry", "POST", "/serviceregistry/system-discovery/lookup", Document{}, &v)
				if e != nil {
					return nil, 0, e
				}
				for _, x := range list(v, "entries") {
					if row, ok := x.(map[string]any); ok {
						set[str(row, "name")] = true
					}
				}
			}
			names := []string{}
			for name := range set {
				names = append(names, name)
			}
			sort.Strings(names)
			return Document{"systems": names}, 200, nil
		})
		a.serviceRoute("GET", base+"/systems/{systemName}/services", def, "list-services", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			set := map[string]bool{}
			for _, row := range a.rows("senml") {
				if str(row, "system") == r.PathValue("systemName") {
					set[str(row, "service")] = true
				}
			}
			if kind == "data-proxy" {
				var v Document
				e := a.Remote.Call(r.Context(), "registry", "POST", "/serviceregistry/service-discovery/lookup", Document{"providerNames": []string{r.PathValue("systemName")}}, &v)
				if e != nil {
					return nil, 0, e
				}
				for _, x := range list(v, "entries") {
					if row, ok := x.(map[string]any); ok {
						set[str(obj(row, "serviceDefinition"), "name")] = true
					}
				}
			}
			names := []string{}
			for name := range set {
				names = append(names, name)
			}
			sort.Strings(names)
			return Document{"services": names}, 200, nil
		})
		for _, method := range []string{"GET", "PUT"} {
			m := method
			operation := "get-data"
			if m == "PUT" {
				operation = "put-data"
			}
			op := operation
			a.serviceRoute(m, base+"/systems/{systemName}/services/{serviceName}/data", def, op, func(w http.ResponseWriter, r *http.Request) (any, int, error) {
				system, service := r.PathValue("systemName"), r.PathValue("serviceName")
				if !validName(system) || service == "" {
					return nil, 0, bad("Invalid system/service")
				}
				if kind == "data-proxy" {
					return a.proxyData(w, r, system, service, op)
				}
				if m == "PUT" {
					if system != caller(r).Name && !caller(r).Sysop && !remoteOwner(r, system) {
						return nil, 0, forbidden()
					}
					v, e := decodeAny(w, r)
					if e != nil {
						return nil, 0, e
					}
					records, ok := v.([]any)
					if !ok || len(records) > 1000 {
						return nil, 0, bad("A SenML pack of at most 1000 records is required")
					}
					e = a.Store.Update(func(d database) error {
						baseTime := float64(time.Now().UnixMilli()) / 1000
						baseName := ""
						for _, x := range records {
							record, ok := x.(map[string]any)
							if !ok {
								return bad("Invalid SenML record")
							}
							if bt, ok := record["bt"].(float64); ok {
								baseTime = bt
							}
							if bn, ok := record["bn"].(string); ok {
								baseName = bn
							}
							t, _ := record["t"].(float64)
							epoch := baseTime + t
							if epoch < 0 {
								return bad("Invalid SenML time")
							}
							id := uuid()
							bucket(d, "senml")[id] = Document{"id": id, "system": system, "service": service, "signal": baseName + str(record, "n"), "epoch": epoch, "record": record, "receivedAt": now()}
						}
						return nil
					})
					return nil, 200, e
				}
				n, e := parseCount(r, 100)
				if e != nil {
					return nil, 0, e
				}
				from, to := -1.0, 1e20
				for key, p := range map[string]*float64{"from": &from, "to": &to} {
					if s := r.URL.Query().Get(key); s != "" {
						value, e := strconv.ParseFloat(s, 64)
						if e != nil {
							return nil, 0, bad("Invalid " + key)
						}
						*p = value
					}
				}
				signals := map[string]bool{}
				for _, v := range r.URL.Query()["signals"] {
					for _, name := range strings.Split(v, ",") {
						signals[name] = true
					}
				}
				rows := []Document{}
				for _, row := range a.rows("senml") {
					if str(row, "system") != system || str(row, "service") != service {
						continue
					}
					epoch, _ := row["epoch"].(float64)
					if epoch < from || epoch > to {
						continue
					}
					if len(signals) > 0 && !signals[str(row, "signal")] {
						continue
					}
					rows = append(rows, row)
				}
				sort.Slice(rows, func(i, j int) bool { return rows[i]["epoch"].(float64) > rows[j]["epoch"].(float64) })
				if len(rows) > n {
					rows = rows[:n]
				}
				out := []Document{}
				for _, row := range rows {
					out = append(out, obj(row, "record"))
				}
				return out, 200, nil
			})
		}
	}
}
func (a *App) proxyData(w http.ResponseWriter, r *http.Request, system, service, operation string) (any, int, error) {
	var discovery Document
	e := a.Remote.Call(r.Context(), "registry", "POST", "/serviceregistry/service-discovery/lookup", Document{"providerNames": []string{system}, "serviceDefinitionNames": []string{service}, "interfaceTemplateNames": []string{"generic_https"}}, &discovery)
	if e != nil {
		return nil, 0, e
	}
	for _, v := range list(discovery, "entries") {
		row, ok := v.(map[string]any)
		if !ok || str(obj(row, "provider"), "name") != system {
			continue
		}
		for _, v := range list(row, "interfaces") {
			intf, ok := v.(map[string]any)
			if !ok {
				continue
			}
			props := obj(intf, "properties")
			op := obj(obj(props, "operations"), operation)
			if str(op, "method") != r.Method {
				continue
			}
			addresses := list(props, "accessAddresses")
			if len(addresses) == 0 {
				continue
			}
			host, ok := addresses[0].(string)
			if !ok {
				continue
			}
			origin := url.URL{Scheme: "https", Host: host + ":" + strconv.Itoa(number(props, "accessPort", 443))}
			path := str(props, "basePath") + str(op, "path")
			if !strings.HasPrefix(path, "/") {
				continue
			}
			var in, out any
			if r.Method == "PUT" {
				in, e = decodeAny(w, r)
				if e != nil {
					return nil, 0, e
				}
			}
			e = a.Remote.callAt(r.Context(), system, origin.String(), r.Method, path, in, &out)
			return out, 200, e
		}
	}
	return nil, 0, &APIError{404, "No matching HTTPS data operation"}
}

// remoteOwner: the local GateTunnel forwards an inter-cloud request of a negotiated session and names the remote
// consumer ("<system>|<cloud>|<organization>"); that consumer may store its own data. The header is only trusted
// from the mTLS-verified GateTunnel identity.
func remoteOwner(r *http.Request, system string) bool {
	if caller(r).Name != "GateTunnel" {
		return false
	}
	consumer, cloud, ok := strings.Cut(r.Header.Get("X-Arrowhead-Remote-Consumer"), "|")
	return ok && consumer == system && cloud != ""
}
