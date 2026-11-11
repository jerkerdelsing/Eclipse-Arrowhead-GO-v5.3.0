// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func validCallback(raw string) bool {
	u, e := url.Parse(raw)
	return e == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Fragment == ""
}
func validateSubscription(req Document) error {
	if e := require(req, "eventType", "notifyUri"); e != nil {
		return e
	}
	if !validCallback(str(req, "notifyUri")) {
		return bad("notifyUri must be an absolute HTTPS endpoint without credentials or fragment")
	}
	for _, k := range []string{"startsAt", "expiresAt"} {
		if s := str(req, k); s != "" {
			if _, e := time.Parse(time.RFC3339Nano, s); e != nil {
				return bad("Invalid " + k)
			}
		}
	}
	if str(req, "expiresAt") != "" && expired(str(req, "expiresAt")) {
		return bad("Subscription already expired")
	}
	return nil
}
func (a *App) eventRoutes() {
	a.serviceRoute("POST", "/eventhandler/event-subscription/subscribe", "eventSubscription", "subscribe", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if e = validateSubscription(req); e != nil {
			return nil, 0, e
		}
		var row Document
		e = a.Store.Update(func(d database) error {
			key, id := nextID(d, "eventSubscriptions")
			row = Document{"id": id, "subscriberSystemName": caller(r).Name, "eventType": req["eventType"], "notifyUri": req["notifyUri"], "matchMetadata": flag(req, "matchMetadata"), "metadataFilter": req["metadataFilter"], "startsAt": req["startsAt"], "expiresAt": req["expiresAt"], "createdAt": now(), "updatedAt": now()}
			bucket(d, "eventSubscriptions")[key] = row
			return nil
		})
		return row, 201, e
	})
	a.serviceRoute("DELETE", "/eventhandler/event-subscription/unsubscribe/{subscriptionId}", "eventSubscription", "unsubscribe", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		e := a.Store.Update(func(d database) error {
			row := d["eventSubscriptions"][r.PathValue("subscriptionId")]
			if row == nil {
				return nil
			}
			if str(row, "subscriberSystemName") != caller(r).Name {
				return forbidden()
			}
			delete(d["eventSubscriptions"], r.PathValue("subscriptionId"))
			return nil
		})
		return nil, 200, e
	})
	a.route("GET", "/eventhandler/management/subscriptions", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		v, e := page(a.rows("eventSubscriptions"), queryDoc(r), "entries")
		return v, 200, e
	})
	a.route("PUT", "/eventhandler/management/subscriptions/{subscriptionId}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if e = validateSubscription(req); e != nil {
			return nil, 0, e
		}
		var row Document
		e = a.Store.Update(func(d database) error {
			row = d["eventSubscriptions"][r.PathValue("subscriptionId")]
			if row == nil {
				return &APIError{404, "Subscription not found"}
			}
			for _, k := range []string{"eventType", "notifyUri", "matchMetadata", "metadataFilter", "startsAt", "expiresAt"} {
				row[k] = req[k]
			}
			row["updatedAt"] = now()
			return nil
		})
		return row, 200, e
	})
	a.route("DELETE", "/eventhandler/management/subscriptions/{subscriptionId}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		_, e := removeRow(a, "eventSubscriptions", r.PathValue("subscriptionId"))
		return nil, 200, e
	})
	a.serviceRoute("POST", "/eventhandler/event-publish/publish", "eventPublish", "publish", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if e = require(req, "eventType"); e != nil {
			return nil, 0, e
		}
		if _, ok := req["payload"].(string); !ok {
			return nil, 0, bad("payload must be a string")
		}
		notification := Document{"eventType": req["eventType"], "payload": req["payload"], "metadata": req["metadata"], "timestamp": now(), "sourceSystemName": caller(r).Name}
		matched := []Document{}
		for _, s := range a.rows("eventSubscriptions") {
			if str(s, "eventType") != str(req, "eventType") || str(s, "expiresAt") != "" && expired(str(s, "expiresAt")) {
				continue
			}
			if start := str(s, "startsAt"); start != "" {
				t, _ := time.Parse(time.RFC3339Nano, start)
				if t.After(time.Now()) {
					continue
				}
			}
			if flag(s, "matchMetadata") {
				yes, e := metadataMatch(obj(req, "metadata"), obj(s, "metadataFilter"))
				if e != nil {
					return nil, 0, e
				}
				if !yes {
					continue
				}
			}
			matched = append(matched, s)
		}
		jobs := []Document{}
		for _, s := range matched {
			if a.Config.AuthorizationPolicy != "identity-only" {
				var result Document
				e = a.Remote.Call(r.Context(), "authorization", "POST", "/consumerauthorization/authorization/mgmt/check", Document{"list": []Document{{"provider": caller(r).Name, "consumer": s["subscriberSystemName"], "cloud": "LOCAL", "targetType": "EVENT_TYPE", "target": req["eventType"]}}}, &result)
				if e != nil {
					return nil, 0, e
				}
				entries := list(result, "entries")
				if len(entries) != 1 {
					return nil, 0, &APIError{502, "Invalid event authorization response"}
				}
				answer, ok := entries[0].(map[string]any)
				if !ok || !flag(answer, "granted") {
					continue
				}
			}
			jobs = append(jobs, Document{"id": uuid(), "kind": "event", "provider": s["subscriberSystemName"], "uri": s["notifyUri"], "payload": notification, "attempts": 0, "createdAt": now(), "state": "PENDING"})
		}
		e = a.Store.Update(func(d database) error {
			if len(d["outbox"])+len(jobs) > 10000 {
				return &APIError{503, "Delivery queue is full"}
			}
			for _, job := range jobs {
				bucket(d, "outbox")[str(job, "id")] = job
			}
			return nil
		})
		return Document{"matchedSubscriptions": len(matched), "acceptedDeliveries": len(jobs)}, 200, e
	})
}
func (a *App) deliverEvents(ctx context.Context) {
	processed := 0
	for _, job := range a.rows("outbox") {
		if str(job, "kind") != "event" || str(job, "state") != "PENDING" {
			continue
		}
		if processed >= 20 {
			return
		}
		processed++
		id := str(job, "id")
		u, e := url.Parse(str(job, "uri"))
		if e == nil && validCallback(u.String()) {
			origin := *u
			origin.Path = ""
			origin.RawQuery = ""
			e = a.Remote.callAt(ctx, str(job, "provider"), origin.String(), "POST", u.RequestURI(), job["payload"], nil)
		} else {
			e = bad("Invalid callback")
		}
		_ = a.Store.Update(func(d database) error {
			row := d["outbox"][id]
			if row == nil {
				return nil
			}
			if e == nil {
				delete(d["outbox"], id)
			} else {
				n := number(row, "attempts", 0) + 1
				row["attempts"] = n
				if n >= 3 {
					row["state"] = "ERROR"
				}
			}
			return nil
		})
	}
}
func revisionHeader(r *http.Request) (int, bool, error) {
	s := strings.Trim(r.Header.Get("If-Match"), "\"")
	if s == "" {
		return 0, false, nil
	}
	n, e := strconv.Atoi(s)
	if e != nil || n < 1 {
		return 0, false, bad("Invalid If-Match revision")
	}
	return n, true, nil
}
