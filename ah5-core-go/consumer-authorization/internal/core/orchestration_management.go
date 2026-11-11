// SPDX-License-Identifier: EPL-2.0
package core

import (
	"fmt"
	"net/http"
	"time"
)

func validatePriorities(d database) error {
	seen := map[string]bool{}
	for _, row := range d["simpleStore"] {
		key := fmt.Sprintf("%s|%s|%d", str(row, "consumer"), str(row, "serviceDefinition"), number(row, "priority", 0))
		if seen[key] {
			return bad("Duplicate priority for consumer and service definition")
		}
		seen[key] = true
	}
	return nil
}
func (a *App) simpleStoreRoutes(base string) {
	base += "/mgmt/simple-store"
	a.route("POST", base+"/create", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if len(list(req, "candidates")) == 0 {
			return nil, 0, bad("candidates required")
		}
		rows := []Document{}
		e = a.Store.Update(func(d database) error {
			for _, v := range list(req, "candidates") {
				row, ok := v.(map[string]any)
				if !ok || !validName(str(row, "consumer")) {
					return bad("Invalid consumer")
				}
				_, service, _, e := instanceParts(str(row, "serviceInstanceId"))
				if e != nil {
					return e
				}
				priority, ok := row["priority"].(float64)
				if !ok || priority < 1 || priority != float64(int(priority)) {
					return bad("priority must be a positive integer")
				}
				created := Document{"id": uuid(), "consumer": row["consumer"], "serviceDefinition": service, "serviceInstanceId": row["serviceInstanceId"], "priority": priority, "createdBy": caller(r).Name, "updatedBy": nil, "createdAt": now(), "updatedAt": nil}
				bucket(d, "simpleStore")[str(created, "id")] = created
				rows = append(rows, created)
			}
			return validatePriorities(d)
		})
		return Document{"entries": rows, "count": len(rows)}, 200, e
	})
	a.route("PUT", base+"/modify-priorities", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		e = a.Store.Update(func(d database) error {
			for id, v := range req {
				priority, ok := v.(float64)
				if !ok || priority < 1 || priority != float64(int(priority)) {
					return bad("priority must be a positive integer")
				}
				row := d["simpleStore"][id]
				if row == nil {
					return &APIError{404, "Store entry not found"}
				}
				row["priority"] = priority
				row["updatedBy"] = caller(r).Name
				row["updatedAt"] = now()
				rows = append(rows, row)
			}
			return validatePriorities(d)
		})
		return Document{"entries": rows, "count": len(rows)}, 200, e
	})
	a.route("DELETE", base+"/remove", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		ids, e := queryNames(r, "uuids")
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for _, id := range ids {
				delete(bucket(d, "simpleStore"), id)
			}
			return nil
		})
		return nil, 200, e
	})
	a.route("POST", base+"/query", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		e = a.Store.View(func(d database) error {
			for _, row := range d["simpleStore"] {
				if !selected(req, "ids", str(row, "id")) || !selected(req, "consumerNames", str(row, "consumer")) || !selected(req, "serviceDefinitions", str(row, "serviceDefinition")) || !selected(req, "serviceInstanceIds", str(row, "serviceInstanceId")) {
					continue
				}
				n := number(row, "priority", 0)
				if req["minPriority"] != nil && n < number(req, "minPriority", 0) {
					continue
				}
				if req["maxPriority"] != nil && n > number(req, "maxPriority", 0) {
					continue
				}
				if s := str(req, "createdBy"); s != "" && s != str(row, "createdBy") {
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
func (a *App) lockRoutes(base string) {
	base += "/mgmt/lock"
	a.route("POST", base+"/create", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if len(list(req, "locks")) == 0 {
			return nil, 0, bad("locks required")
		}
		rows := []Document{}
		e = a.Store.Update(func(d database) error {
			for _, v := range list(req, "locks") {
				lock, ok := v.(map[string]any)
				if !ok || !validName(str(lock, "owner")) {
					return bad("Invalid lock owner")
				}
				if _, _, _, e := instanceParts(str(lock, "serviceInstanceId")); e != nil {
					return e
				}
				if expired(str(lock, "expiresAt")) {
					return bad("Lock expiresAt must be in the future")
				}
				for _, existing := range d["locks"] {
					if str(existing, "serviceInstanceId") == str(lock, "serviceInstanceId") && !expired(str(existing, "expiresAt")) {
						return &APIError{409, "Service instance is already locked"}
					}
				}
				id := nextLockID(d)
				row := Document{"id": number(d["sequence"]["lock"], "value", 0), "orchestrationJobId": nil, "serviceInstanceId": lock["serviceInstanceId"], "owner": lock["owner"], "expiresAt": lock["expiresAt"], "temporary": false}
				bucket(d, "locks")[id] = row
				rows = append(rows, row)
			}
			return nil
		})
		return Document{"entries": rows, "count": len(rows)}, 200, e
	})
	a.route("POST", base+"/query", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decodeOptional(w, r)
		if e != nil {
			return nil, 0, e
		}
		for _, k := range []string{"expiresBefore", "expiresAfter"} {
			if str(req, k) != "" {
				if _, e := time.Parse(time.RFC3339Nano, str(req, k)); e != nil {
					return nil, 0, bad("Invalid " + k)
				}
			}
		}
		rows := []Document{}
		e = a.Store.View(func(d database) error {
			for _, row := range d["locks"] {
				if expired(str(row, "expiresAt")) || !selected(req, "orchestrationJobIds", str(row, "orchestrationJobId")) || !selected(req, "serviceInstanceIds", str(row, "serviceInstanceId")) || !selected(req, "owners", str(row, "owner")) {
					continue
				}
				if len(list(req, "ids")) > 0 {
					found := false
					for _, id := range list(req, "ids") {
						if id == row["id"] {
							found = true
						}
					}
					if !found {
						continue
					}
				}
				if !timeRange(str(row, "expiresAt"), str(req, "expiresAfter"), str(req, "expiresBefore")) {
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
	a.route("DELETE", base+"/remove/{owner}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		ids, e := queryNames(r, "instanceIds")
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for key, row := range d["locks"] {
				if str(row, "owner") == r.PathValue("owner") {
					for _, id := range ids {
						if id == str(row, "serviceInstanceId") {
							delete(d["locks"], key)
						}
					}
				}
			}
			return nil
		})
		return nil, 200, e
	})
}
