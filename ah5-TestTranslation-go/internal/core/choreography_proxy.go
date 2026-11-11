// SPDX-License-Identifier: EPL-2.0
package core

// Choreographer additions (2026-10-17), as the Java Choreographer:
//   - orchestration by proxy: DynamicServiceOrchestration orchestrates for the executor (authorization and tokens
//     are evaluated for the executor) through a push subscription whose result is posted to
//     /choreographer/orchestration-result/{correlationId};
//   - inter-cloud sessions (allowInterCloud adds ALLOW_INTERCLOUD to that orchestration);
//   - abort propagation to the executors of executing steps;
//   - session notifications to the owner's HTTPS notify endpoint (certificate pinned to the session owner).

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const choreographyOrchestrationTimeout = 30 * time.Second

type orchestrationBroker struct {
	mu      sync.Mutex
	pending map[string]chan Document
	locks   map[string]*sync.Mutex
}

func (b *orchestrationBroker) open() (string, chan Document) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pending == nil {
		b.pending = map[string]chan Document{}
	}
	id := uuid()
	ch := make(chan Document, 1)
	b.pending[id] = ch
	return id, ch
}

func (b *orchestrationBroker) close(id string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pending, id)
}

func (b *orchestrationBroker) complete(id string, result Document) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	ch := b.pending[id]
	if ch == nil {
		return false
	}
	select {
	case ch <- result:
	default:
	}
	return true
}

// lock serializes orchestrations of one (executor, service definition): the orchestrator keeps one subscription per
// (owner, target, definition), so a new subscription replaces the previous one.
func (b *orchestrationBroker) lock(key string) *sync.Mutex {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.locks == nil {
		b.locks = map[string]*sync.Mutex{}
	}
	if b.locks[key] == nil {
		b.locks[key] = &sync.Mutex{}
	}
	return b.locks[key]
}

// orchestrateFor asks the orchestrator to orchestrate requirement for executor and waits for the pushed result.
func (a *App) orchestrateFor(ctx context.Context, executor string, requirement Document, allowInterCloud bool) (Document, error) {
	b := &a.broker.orchestration
	l := b.lock(executor + "|" + str(requirement, "serviceDefinition"))
	l.Lock()
	defer l.Unlock()
	correlation, ch := b.open()
	defer b.close(correlation)
	request := Document{"serviceRequirement": requirement, "orchestrationFlags": Document{"MATCHMAKING": true, "ALLOW_INTERCLOUD": allowInterCloud}}
	notify := Document{"protocol": "HTTPS", "properties": Document{"address": a.Config.AdvertiseAddress, "port": strconv.Itoa(a.Config.AdvertisePort), "method": "POST", "path": "/choreographer/orchestration-result/" + correlation}}
	var subscribed Document
	if e := a.consume(ctx, "ServiceOrchestration", "POST", "/serviceorchestration/orchestration/mgmt/push/subscribe", Document{"subscriptions": []Document{{"targetSystemName": executor, "duration": int(choreographyOrchestrationTimeout/time.Second) + 60, "orchestrationRequest": request, "notifyInterface": notify}}}, &subscribed); e != nil {
		return nil, e
	}
	entries := list(subscribed, "entries")
	if len(entries) == 0 {
		return nil, fmt.Errorf("push orchestration subscription was not created")
	}
	id := str(entries[0].(map[string]any), "id")
	if e := a.consume(ctx, "ServiceOrchestration", "POST", "/serviceorchestration/orchestration/mgmt/push/trigger", Document{"subscriptionIds": []string{id}}, nil); e != nil {
		return nil, e
	}
	select {
	case result := <-ch:
		return result, nil
	case <-time.After(choreographyOrchestrationTimeout):
		return nil, fmt.Errorf("no orchestration result for %s within %s", executor, choreographyOrchestrationTimeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// orchestrationResultRoute receives pushed orchestration results; only the orchestrator identity may post them.
func (a *App) orchestrationResultRoute(b string) {
	a.route("POST", b+"/orchestration-result/{correlationId}", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		orchestrator := a.Config.UpstreamSystems["ServiceOrchestration"]
		if orchestrator == "" {
			orchestrator = "ServiceOrchestration"
		}
		if caller(r).Name != orchestrator {
			return nil, 0, forbidden()
		}
		result, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if !a.broker.orchestration.complete(r.PathValue("correlationId"), result) {
			return nil, 0, &APIError{404, "Unknown or expired correlation"}
		}
		return nil, 200, nil
	})
}

// abortExecutors tells the executors of the session's executing steps to abort (best effort).
func (a *App) abortExecutors(ctx context.Context, sessionID any) {
	executors := map[string]Document{}
	for _, e := range a.rows("executors") {
		executors[str(e, "name")] = e
	}
	for _, step := range a.rows("session-steps") {
		if fmt.Sprint(step["sessionId"]) != fmt.Sprint(sessionID) || str(step, "status") != "ABORTED" || step["abortSentAt"] != nil {
			continue
		}
		ex := executors[str(step, "executorName")]
		if ex == nil {
			continue
		}
		origin := "https://" + net.JoinHostPort(str(ex, "address"), strconv.Itoa(number(ex, "port", 443)))
		if e := a.Remote.callAt(ctx, str(ex, "name"), origin, "POST", str(ex, "basePath")+"/abort", Document{"sessionId": step["sessionId"], "sessionStepId": step["id"]}, nil); e != nil {
			a.recordLog("WARN", "Executor abort failed: "+str(ex, "name"))
		}
		_ = a.Store.Update(func(d database) error {
			if s := d["session-steps"][fmt.Sprint(step["id"])]; s != nil {
				s["abortSentAt"] = now()
			}
			return nil
		})
	}
}

// notifySession posts a session notification to the owner's notify endpoint, if the session has one. Failures are
// logged only: notifications must not affect the plan execution.
func (a *App) notifySession(ctx context.Context, sessionID any, message string) {
	s, _ := a.row("sessions", fmt.Sprint(sessionID))
	notify := obj(s, "notify")
	if s == nil || notify == nil {
		return
	}
	payload := Document{"sessionId": s["id"], "planId": s["planId"], "planName": s["planName"], "timestamp": now(), "status": s["status"], "message": message, "details": nil}
	origin := "https://" + net.JoinHostPort(str(notify, "address"), strconv.Itoa(number(notify, "port", 443)))
	if e := a.Remote.callAt(ctx, str(s, "owner"), origin, "POST", str(notify, "path"), payload, nil); e != nil {
		a.recordLog("WARN", "Session notification failed")
	}
}

// sessionNotify validates the optional notify endpoint of a session start request (HTTPS only).
func sessionNotify(s Document) (Document, error) {
	address := str(s, "notifyAddress")
	if address == "" {
		return nil, nil
	}
	if p := str(s, "notifyProtocol"); p != "" && p != "HTTPS" && p != "https" {
		return nil, bad("Only HTTPS session notifications are supported")
	}
	port := number(s, "notifyPort", 0)
	if port < 1 || port > 65535 {
		return nil, bad("notifyPort must be 1–65535")
	}
	path := str(s, "notifyPath")
	if path == "" || path[0] != '/' {
		path = "/" + path
	}
	return Document{"address": address, "port": port, "path": path}, nil
}
