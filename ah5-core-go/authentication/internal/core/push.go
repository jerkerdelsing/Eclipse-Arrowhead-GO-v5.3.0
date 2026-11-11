// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

func validateNotify(d Document) error {
	if strings.ToUpper(str(d, "protocol")) != "HTTPS" {
		return bad("This secure profile supports only HTTPS notification callbacks")
	}
	p := obj(d, "properties")
	if e := require(p, "address", "port", "method", "path"); e != nil {
		return e
	}
	if str(p, "method") != "POST" && str(p, "method") != "PUT" {
		return bad("Callback method must be POST or PUT")
	}
	if !strings.HasPrefix(str(p, "path"), "/") || strings.HasPrefix(str(p, "path"), "//") || strings.ContainsAny(str(p, "path"), "?#") {
		return bad("Invalid callback path")
	}
	if _, e := net.LookupPort("tcp", str(p, "port")); e != nil {
		return bad("Invalid callback port")
	}
	if strings.ContainsAny(str(p, "address"), "/@?#") {
		return bad("Invalid callback address")
	}
	return nil
}

// subscribe stores a push subscription. notifyRecipient is the identity the result callback is pinned to: the
// target for own and sysop-made subscriptions, else the subscribing system (orchestration by proxy, e.g. the
// Choreographer for an executor), which supplied the notify interface.
func (a *App) subscribe(d database, req Document, owner string, management, sysop bool) (Document, bool, error) {
	target := str(req, "targetSystemName")
	if target == "" {
		target = owner
	}
	if !validName(target) {
		return nil, false, bad("Invalid targetSystemName")
	}
	if !management && target != owner {
		return nil, false, forbidden()
	}
	if e := validateNotify(obj(req, "notifyInterface")); e != nil {
		return nil, false, e
	}
	duration := number(req, "duration", 3600)
	if duration < 1 || duration > 86400*365 {
		return nil, false, bad("Subscription duration must be 1–31536000 seconds")
	}
	orch := obj(req, "orchestrationRequest")
	definition := str(obj(orch, "serviceRequirement"), "serviceDefinition")
	if a.Config.Role == "serviceorchestration-dynamic" && definition == "" {
		return nil, false, bad("serviceDefinition required")
	}
	id := uuid()
	created := now()
	override := false
	for _, existing := range d["subscriptions"] {
		if str(existing, "ownerSystemName") == owner && str(existing, "targetSystemName") == target && str(obj(obj(existing, "orchestrationRequest"), "serviceRequirement"), "serviceDefinition") == definition {
			id = str(existing, "id")
			created = str(existing, "createdAt")
			override = true
			break
		}
	}
	recipient := target
	if management && !sysop && target != owner {
		recipient = owner
	}
	row := Document{"id": id, "ownerSystemName": owner, "targetSystemName": target, "notifyRecipient": recipient, "orchestrationRequest": orch, "notifyInterface": req["notifyInterface"], "expiredAt": time.Now().UTC().Add(time.Duration(duration) * time.Second).Format(time.RFC3339Nano), "createdAt": created}
	bucket(d, "subscriptions")[id] = row
	return row, override, nil
}
func (a *App) queuePush(owner string, subscriptions []Document) ([]Document, error) {
	jobs := []Document{}
	e := a.Store.Update(func(d database) error {
		pruneJobs(d, time.Now())
		for _, sub := range subscriptions {
			id := str(sub, "id")
			current := d["subscriptions"][id]
			if current == nil || expired(str(current, "expiredAt")) {
				return bad("Subscription expired or removed")
			}
			j := Document{"id": uuid(), "status": "PENDING", "type": "PUSH", "requesterSystem": owner, "targetSystem": sub["targetSystemName"], "serviceDefinition": str(obj(obj(sub, "orchestrationRequest"), "serviceRequirement"), "serviceDefinition"), "subscriptionId": id, "message": nil, "createdAt": now(), "startedAt": nil, "finishedAt": nil}
			bucket(d, "jobs")[str(j, "id")] = j
			jobs = append(jobs, j)
		}
		return nil
	})
	return jobs, e
}
func (a *App) subscriptionRoutes(base string) {
	a.route("POST", base+"/subscribe", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		var row Document
		var override bool
		e = a.Store.Update(func(d database) error {
			row, override, e = a.subscribe(d, req, caller(r).Name, false, caller(r).Sysop)
			return e
		})
		if e != nil {
			return nil, 0, e
		}
		if r.URL.Query().Get("trigger") == "true" {
			if _, e = a.queuePush(caller(r).Name, []Document{row}); e != nil {
				return nil, 0, e
			}
		}
		status := 201
		if override {
			status = 200
		}
		return textResponse(str(row, "id")), status, nil
	})
	a.route("DELETE", base+"/unsubscribe/{id}", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		found := false
		e := a.Store.Update(func(d database) error {
			row := d["subscriptions"][r.PathValue("id")]
			if row == nil {
				return nil
			}
			if str(row, "ownerSystemName") != caller(r).Name {
				return forbidden()
			}
			delete(d["subscriptions"], r.PathValue("id"))
			found = true
			return nil
		})
		status := 200
		if !found {
			status = 204
		}
		return nil, status, e
	})
	mgmt := base + "/mgmt/push"
	a.route("POST", mgmt+"/subscribe", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if len(list(req, "subscriptions")) == 0 {
			return nil, 0, bad("subscriptions required")
		}
		rows := []Document{}
		e = a.Store.Update(func(d database) error {
			for _, v := range list(req, "subscriptions") {
				req, ok := v.(map[string]any)
				if !ok {
					return bad("Invalid subscription")
				}
				row, _, e := a.subscribe(d, req, caller(r).Name, true, caller(r).Sysop)
				if e != nil {
					return e
				}
				rows = append(rows, row)
			}
			return nil
		})
		return Document{"entries": rows, "count": len(rows)}, 200, e
	})
	a.route("POST", mgmt+"/query", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decodeOptional(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		e = a.Store.View(func(d database) error {
			for _, row := range d["subscriptions"] {
				if expired(str(row, "expiredAt")) || !selected(req, "ownerSystems", str(row, "ownerSystemName")) || !selected(req, "targetSystems", str(row, "targetSystemName")) || !selected(req, "serviceDefinitions", str(obj(obj(row, "orchestrationRequest"), "serviceRequirement"), "serviceDefinition")) {
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
	a.route("DELETE", mgmt+"/unsubscribe", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		ids, e := queryNames(r, "ids")
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for _, id := range ids {
				delete(bucket(d, "subscriptions"), id)
			}
			return nil
		})
		return nil, 200, e
	})
	a.route("POST", mgmt+"/trigger", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if len(list(req, "targetSystems")) == 0 && len(list(req, "subscriptionIds")) == 0 {
			return nil, 0, bad("targetSystems or subscriptionIds required")
		}
		subscriptions := []Document{}
		e = a.Store.View(func(d database) error {
			for _, s := range d["subscriptions"] {
				if !expired(str(s, "expiredAt")) && selected(req, "targetSystems", str(s, "targetSystemName")) && selected(req, "subscriptionIds", str(s, "id")) {
					subscriptions = append(subscriptions, s)
				}
			}
			return nil
		})
		if e != nil {
			return nil, 0, e
		}
		jobs, e := a.queuePush(caller(r).Name, subscriptions)
		return Document{"jobs": jobs}, 200, e
	})
}

// RunWorker executes persisted push jobs. At-most-once callback attempts: interrupted jobs
// are marked ERROR on restart, never silently delivered a second time.
func (a *App) RunWorker(ctx context.Context) error {
	if !strings.HasPrefix(a.Config.Role, "serviceorchestration-") {
		return nil
	}
	if e := a.Store.Update(func(d database) error {
		for _, j := range d["jobs"] {
			if str(j, "status") == "IN_PROGRESS" {
				j["status"] = "ERROR"
				j["message"] = "Interrupted by process restart; delivery status unknown"
				j["finishedAt"] = now()
			}
		}
		return nil
	}); e != nil {
		return e
	}
	a.background.Add(1)
	go func() {
		defer a.background.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if ctx.Err() != nil {
					return
				}
				a.processPush(ctx)
			}
		}
	}()
	return nil
}
func (a *App) processPush(ctx context.Context) {
	var job, sub Document
	e := a.Store.Update(func(d database) error {
		for _, j := range d["jobs"] {
			if str(j, "status") == "PENDING" && str(j, "type") == "PUSH" {
				job = j
				sub = d["subscriptions"][str(j, "subscriptionId")]
				j["status"] = "IN_PROGRESS"
				j["startedAt"] = now()
				break
			}
		}
		return nil
	})
	if e != nil || job == nil {
		return
	}
	if sub == nil || expired(str(sub, "expiredAt")) {
		_ = a.jobStatus(str(job, "id"), "ERROR", "Subscription expired or removed")
		return
	}
	req, _ := http.NewRequestWithContext(ctx, "POST", "https://orchestration.local", nil)
	result, e := a.orchestrate(req, obj(sub, "orchestrationRequest"), str(sub, "targetSystemName"), str(job, "id"))
	if e == nil {
		notify := obj(sub, "notifyInterface")
		p := obj(notify, "properties")
		if e = validateNotify(notify); e == nil {
			token, tokenErr := a.Remote.ownToken(ctx)
			e = tokenErr
			if e == nil {
				base := url.URL{Scheme: "https", Host: net.JoinHostPort(str(p, "address"), str(p, "port"))}
				recipient := str(sub, "notifyRecipient")
				if recipient == "" {
					recipient = str(sub, "targetSystemName") // subscriptions stored before notifyRecipient
				}
				e = a.Remote.request(ctx, recipient, base.String(), str(p, "method"), str(p, "path"), token, result, nil)
			}
		}
	}
	status, message := "DONE", "Push delivered"
	if e != nil {
		status, message = "ERROR", fmt.Sprintf("Push failed: %T", e)
	}
	_ = a.jobStatus(str(job, "id"), status, message)
}
