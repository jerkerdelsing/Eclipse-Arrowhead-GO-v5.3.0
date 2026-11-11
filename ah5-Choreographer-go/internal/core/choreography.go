// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func validatePlan(plan Document) error {
	if e := require(plan, "name", "firstActionName"); e != nil {
		return e
	}
	actions := map[string]Document{}
	for _, v := range list(plan, "actions") {
		a, ok := v.(map[string]any)
		if !ok || str(a, "name") == "" || actions[str(a, "name")] != nil {
			return bad("Invalid or duplicate action")
		}
		actions[str(a, "name")] = a
		steps := map[string]Document{}
		for _, v := range list(a, "steps") {
			s, ok := v.(map[string]any)
			if !ok || str(s, "name") == "" || steps[str(s, "name")] != nil || str(obj(s, "serviceRequirement"), "serviceDefinition") == "" {
				return bad("Invalid or duplicate step")
			}
			steps[str(s, "name")] = s
		}
		visited, stack := map[string]bool{}, map[string]bool{}
		var visit func(string) error
		visit = func(n string) error {
			if stack[n] {
				return bad("Step cycle")
			}
			if visited[n] {
				return nil
			}
			s := steps[n]
			if s == nil {
				return bad("Unknown step")
			}
			stack[n] = true
			for _, x := range list(s, "nextStepNames") {
				next, ok := x.(string)
				if !ok {
					return bad("Invalid nextStepNames")
				}
				if e := visit(next); e != nil {
					return e
				}
			}
			delete(stack, n)
			visited[n] = true
			return nil
		}
		for _, x := range list(a, "firstStepNames") {
			n, ok := x.(string)
			if !ok {
				return bad("Invalid firstStepNames")
			}
			if e := visit(n); e != nil {
				return e
			}
		}
		if len(visited) != len(steps) || len(steps) == 0 {
			return bad("All steps must be reachable from firstStepNames")
		}
	}
	seen := map[string]bool{}
	name := str(plan, "firstActionName")
	for name != "" {
		if seen[name] || actions[name] == nil {
			return bad("Unknown or cyclic action")
		}
		seen[name] = true
		name = str(actions[name], "nextActionName")
	}
	if len(seen) != len(actions) {
		return bad("All actions must be reachable")
	}
	return nil
}
func executorMatches(row Document, definition string) bool {
	for _, v := range list(row, "serviceDefinitions") {
		if d, ok := v.(map[string]any); ok && str(d, "serviceDefinitionName") == definition {
			return true
		}
	}
	return false
}
func (a *App) choreographyRoutes() {
	b := "/choreographer"
	for _, table := range []string{"plans", "sessions", "session-steps", "worklog", "executors"} {
		t := table
		a.route("GET", b+"/mgmt/"+t, "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			rows := []Document{}
			for _, row := range a.rows(t) {
				matches := true
				for _, k := range []string{"planId", "sessionId", "status", "planName", "actionName", "stepName"} {
					if s := r.URL.Query().Get(k); s != "" && fmt.Sprint(row[k]) != s {
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
	}
	for _, table := range []string{"plans", "executors"} {
		t := table
		a.route("GET", b+"/mgmt/"+t+"/{id}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			row, e := a.row(t, r.PathValue("id"))
			return row, 200, e
		})
		a.route("DELETE", b+"/mgmt/"+t+"/{id}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			_, e := removeRow(a, t, r.PathValue("id"))
			return nil, 200, e
		})
	}
	a.route("POST", b+"/mgmt/plans", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if e = validatePlan(req); e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for _, p := range d["plans"] {
				if str(p, "name") == str(req, "name") {
					return &APIError{409, "Plan name exists"}
				}
			}
			key, id := nextID(d, "plans")
			req["id"] = id
			req["createdAt"] = now()
			req["updatedAt"] = now()
			bucket(d, "plans")[key] = req
			return nil
		})
		return req, 201, e
	})
	a.route("GET", b+"/mgmt/plans/{id}/check", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		p, e := a.row("plans", r.PathValue("id"))
		if e != nil {
			return nil, 0, e
		}
		messages := []string{}
		if e = validatePlan(p); e != nil {
			messages = append(messages, e.Error())
		}
		for _, av := range list(p, "actions") {
			action := av.(map[string]any)
			for _, sv := range list(action, "steps") {
				step := sv.(map[string]any)
				found := false
				for _, executor := range a.rows("executors") {
					if executorMatches(executor, str(obj(step, "serviceRequirement"), "serviceDefinition")) {
						found = true
					}
				}
				if !found {
					messages = append(messages, "Executor not found for "+str(step, "name"))
				}
			}
		}
		return Document{"planId": p["id"], "errorMessages": messages, "needInterCloud": false}, 200, nil
	})
	saveExecutor := func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		name := caller(r).Name
		if strings.Contains(r.URL.Path, "/mgmt/") {
			name = str(req, "systemName")
		}
		if !validName(name) || require(req, "address", "basePath", "serviceDefinitionName") != nil || number(req, "port", 0) < 1 || number(req, "port", 0) > 65535 || !strings.HasPrefix(str(req, "basePath"), "/") {
			return nil, 0, bad("Invalid executor endpoint")
		}
		var row Document
		e = a.Store.Update(func(d database) error {
			key, id := nextID(d, "executors")
			for k, existing := range d["executors"] {
				if str(existing, "name") == name {
					key = k
					id = existing["id"].(float64)
				}
			}
			row = Document{"id": id, "name": name, "address": req["address"], "port": req["port"], "basePath": req["basePath"], "serviceDefinitions": []Document{{"serviceDefinitionName": req["serviceDefinitionName"], "minVersion": req["minVersion"], "maxVersion": req["maxVersion"]}}, "createdAt": now(), "updatedAt": now()}
			bucket(d, "executors")[key] = row
			return nil
		})
		return row, 201, e
	}
	a.route("POST", b+"/mgmt/executors", "management", saveExecutor)
	a.serviceRoute("POST", b+"/executor/register", "choreographerExecutor", "register", saveExecutor)
	a.serviceRoute("DELETE", b+"/executor/unregister", "choreographerExecutor", "unregister", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		e := a.Store.Update(func(d database) error {
			for k, row := range d["executors"] {
				if str(row, "name") == caller(r).Name {
					delete(d["executors"], k)
				}
			}
			return nil
		})
		return nil, 200, e
	})
	for _, path := range []string{"/session/start", "/mgmt/sessions/start"} {
		p := path
		access := "identity"
		if strings.Contains(p, "mgmt") {
			access = "management"
		}
		a.route("POST", b+p, access, func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			if access == "identity" {
				if e := a.authorize(r, "choreographerSession", "start-session"); e != nil {
					return nil, 0, e
				}
			}
			req, e := decode(w, r)
			if e != nil {
				return nil, 0, e
			}
			if len(list(req, "sessions")) == 0 {
				return nil, 0, bad("sessions required")
			}
			rows := []Document{}
			e = a.Store.Update(func(d database) error {
				for _, v := range list(req, "sessions") {
					s, ok := v.(map[string]any)
					if !ok {
						return bad("Invalid session")
					}
					notify, e := sessionNotify(s)
					if e != nil {
						return e
					}
					var plan Document
					for _, p := range d["plans"] {
						if p["id"] == s["planId"] || str(p, "name") == str(s, "planName") {
							plan = p
							break
						}
					}
					if plan == nil {
						return &APIError{404, "Plan not found"}
					}
					quantity := number(s, "quantity", 1)
					if quantity < 1 || quantity > 1000 {
						return bad("quantity must be 1–1000")
					}
					id, n := nextID(d, "sessions")
					session := Document{"id": n, "planId": plan["id"], "planName": plan["name"], "status": "RUNNING", "quantityDone": 0, "quantityGoal": quantity, "executionNumber": 1, "owner": caller(r).Name, "currentAction": plan["firstActionName"], "allowInterCloud": flag(s, "allowInterCloud"), "notify": notify, "startedAt": now(), "updatedAt": now()}
					bucket(d, "sessions")[id] = session
					instantiateSteps(d, plan, session)
					rows = append(rows, Document{"planId": plan["id"], "sessionId": n, "quantity": quantity, "status": "RUNNING", "errorMessages": []string{}, "needInterCloud": flag(s, "allowInterCloud")})
				}
				return nil
			})
			return Document{"entries": rows}, 200, e
		})
	}
	for _, path := range []string{"/session/abort/{id}", "/mgmt/sessions/{id}"} {
		p := path
		access := "identity"
		if strings.Contains(p, "mgmt") {
			access = "management"
		}
		a.route("DELETE", b+p, access, func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			e := a.Store.Update(func(d database) error {
				s := d["sessions"][r.PathValue("id")]
				if s == nil {
					return &APIError{404, "Session not found"}
				}
				if access == "identity" && str(s, "owner") != caller(r).Name {
					return forbidden()
				}
				s["status"] = "ABORTED"
				s["updatedAt"] = now()
				for _, step := range d["session-steps"] {
					if fmt.Sprint(step["sessionId"]) == r.PathValue("id") && str(step, "status") == "EXECUTING" {
						step["status"] = "ABORTED"
						step["updatedAt"] = now()
					}
				}
				return nil
			})
			if e == nil {
				id, by := r.PathValue("id"), caller(r).Name
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					a.abortExecutors(ctx, id)
					a.notifySession(ctx, id, "Aborted by "+by)
				}()
			}
			return nil, 200, e
		})
	}
	a.serviceRoute("POST", b+"/executor/notify-step-done", "choreographerExecutor", "notify-step-done", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			key := fmt.Sprint(req["sessionStepId"])
			step := d["session-steps"][key]
			if step == nil || step["sessionId"] != req["sessionId"] {
				return bad("Unknown session step")
			}
			if str(step, "executorName") != caller(r).Name {
				return forbidden()
			}
			if str(step, "status") != "EXECUTING" {
				return &APIError{409, "Step is not executing"}
			}
			s := d["sessions"][fmt.Sprint(step["sessionId"])]
			if s == nil || str(s, "status") != "RUNNING" {
				return &APIError{409, "Session is not running"}
			}
			if str(req, "status") == "DONE" {
				step["status"] = "DONE"
			} else if str(req, "status") == "ERROR" {
				step["status"] = "ERROR"
				s["status"] = "ERROR"
			} else {
				return bad("Expected DONE or ERROR")
			}
			step["message"] = req["message"]
			step["updatedAt"] = now()
			return nil
		})
		if e == nil && str(req, "status") == "ERROR" {
			a.notifySession(r.Context(), req["sessionId"], "Step failed: "+str(req, "message"))
		}
		return nil, 200, e
	})
	a.orchestrationResultRoute(b)
}
func instantiateSteps(d database, plan, session Document) {
	for _, av := range list(plan, "actions") {
		action := av.(map[string]any)
		for _, sv := range list(action, "steps") {
			step := sv.(map[string]any)
			key, id := nextID(d, "session-steps")
			bucket(d, "session-steps")[key] = Document{"id": id, "sessionId": session["id"], "stepId": id, "planName": plan["name"], "actionName": action["name"], "stepName": step["name"], "executorName": nil, "status": "PENDING", "executionNumber": session["executionNumber"], "specification": step, "startedAt": nil, "updatedAt": now()}
		}
	}
}
func (a *App) dispatchChoreography(ctx context.Context) {
	for _, session := range a.rows("sessions") {
		if str(session, "status") != "RUNNING" {
			continue
		}
		var eligible []Document
		var pending bool
		for _, step := range a.rows("session-steps") {
			if step["sessionId"] != session["id"] || step["executionNumber"] != session["executionNumber"] || str(step, "actionName") != str(session, "currentAction") {
				continue
			}
			if str(step, "status") != "DONE" {
				pending = true
			}
			if str(step, "status") != "PENDING" {
				continue
			}
			ready := true
			for _, pre := range a.rows("session-steps") {
				if pre["sessionId"] == session["id"] && pre["executionNumber"] == session["executionNumber"] && str(pre, "actionName") == str(step, "actionName") && contains(list(obj(pre, "specification"), "nextStepNames"), str(step, "stepName")) && str(pre, "status") != "DONE" {
					ready = false
				}
			}
			if ready {
				eligible = append(eligible, step)
			}
		}
		if !pending {
			done := false
			_ = a.Store.Update(func(d database) error {
				s := d["sessions"][fmt.Sprint(session["id"])]
				if str(s, "status") != "RUNNING" {
					return nil
				}
				plan := d["plans"][fmt.Sprint(s["planId"])]
				if plan == nil {
					s["status"] = "ERROR"
					return nil
				}
				next := ""
				for _, av := range list(plan, "actions") {
					action := av.(map[string]any)
					if str(action, "name") == str(s, "currentAction") {
						next = str(action, "nextActionName")
					}
				}
				if next != "" {
					s["currentAction"] = next
				} else {
					n := number(s, "quantityDone", 0) + 1
					s["quantityDone"] = n
					if n >= number(s, "quantityGoal", 1) {
						s["status"] = "DONE"
						done = true
					} else {
						s["executionNumber"] = number(s, "executionNumber", 1) + 1
						s["currentAction"] = plan["firstActionName"]
						instantiateSteps(d, plan, s)
					}
				}
				s["updatedAt"] = now()
				return nil
			})
			if done {
				a.notifySession(ctx, session["id"], "Session finished")
			}
			continue
		}
		for _, step := range eligible {
			var executor Document
			spec := obj(step, "specification")
			for _, e := range a.rows("executors") {
				if executorMatches(e, str(obj(spec, "serviceRequirement"), "serviceDefinition")) {
					executor = e
					break
				}
			}
			if executor == nil {
				a.choreographyFailure(step, "Executor unavailable")
				continue
			}
			// orchestration by proxy: the orchestrator orchestrates for the executor (its authorization and tokens)
			orch, e := a.orchestrateFor(ctx, str(executor, "name"), obj(spec, "serviceRequirement"), flag(session, "allowInterCloud"))
			if e != nil || len(list(orch, "results")) == 0 {
				a.choreographyFailure(step, "Orchestration unavailable")
				continue
			}
			e = a.Store.Update(func(d database) error {
				s := d["session-steps"][fmt.Sprint(step["id"])]
				if s == nil || str(d["sessions"][fmt.Sprint(session["id"])], "status") != "RUNNING" {
					return forbidden()
				}
				s["status"] = "EXECUTING"
				s["executorName"] = executor["name"]
				s["startedAt"] = now()
				return nil
			})
			if e != nil {
				continue
			}
			origin := "https://" + net.JoinHostPort(str(executor, "address"), strconv.Itoa(number(executor, "port", 443)))
			e = a.Remote.callAt(ctx, str(executor, "name"), origin, "POST", str(executor, "basePath")+"/start", Document{"sessionId": session["id"], "sessionStepId": step["id"], "preconditionOrchestrationResults": []any{}, "mainOrchestrationResult": list(orch, "results")[0], "quantity": number(spec, "quantity", 1), "staticParameters": spec["staticParameters"]}, nil)
			if e != nil {
				a.choreographyFailure(step, "Executor start rejected")
			}
		}
	}
}
func (a *App) choreographyFailure(step Document, message string) {
	_ = a.Store.Update(func(d database) error {
		if s := d["session-steps"][fmt.Sprint(step["id"])]; s != nil {
			s["status"] = "ERROR"
			s["message"] = message
		}
		if s := d["sessions"][fmt.Sprint(step["sessionId"])]; s != nil {
			s["status"] = "ERROR"
		}
		key, id := nextID(d, "worklog")
		bucket(d, "worklog")[key] = Document{"id": id, "entryDate": now(), "sessionId": step["sessionId"], "planName": step["planName"], "actionName": step["actionName"], "stepName": step["stepName"], "message": message}
		return nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	a.notifySession(ctx, step["sessionId"], message)
}
