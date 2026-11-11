package cloud

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Session bookkeeping contract of the deployed Python GateTunnel. As in that
// implementation these control records are distinct from live relay listeners.
func (f *Federation) controlSessions() []any {
	f.app.Store.mu.RLock()
	defer f.app.Store.mu.RUnlock()
	out := []any{}
	for _, id := range sortedKeys(f.app.Store.Data.Resources) {
		v := f.app.Store.Data.Resources[id]
		if v.Kind == "gatetunnel-control" {
			out = append(out, v.Payload)
		}
	}
	return out
}
func (f *Federation) tunnelControlHTTP(w http.ResponseWriter, r *http.Request, owner, path string) bool {
	if path == "/gatetunnel/publickey" && r.Method == "GET" {
		if !containsExact([]string{"Gatekeeper", "ServiceOrchestration", "DynamicServiceOrchestration", "SimpleStoreServiceOrchestration", "LocalCloudManager", "Sysop"}, owner) {
			apiError(w, 403, "not a GateTunnel client", path)
			return true
		}
		cert, err := x509.ParseCertificate(f.app.tlsConfig.Certificates[0].Certificate[0])
		if err != nil {
			apiError(w, 500, "invalid server identity", path)
			return true
		}
		der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			apiError(w, 500, "invalid public key", path)
			return true
		}
		jsonOut(w, 200, map[string]any{"algorithm": "RSA", "format": "X.509", "publicKey": base64.StdEncoding.EncodeToString(der)})
		return true
	}
	if !containsExact([]string{"/gatetunnel/connect_provider", "/gatetunnel/connect_consumer", "/gatetunnel/close_sessions", "/gatetunnel/mgmt/sessions/close"}, path) {
		return false
	}
	if r.Method != "POST" {
		apiError(w, 405, "method not allowed", path)
		return true
	}
	if !containsExact([]string{"Gatekeeper", "ServiceOrchestration", "DynamicServiceOrchestration", "SimpleStoreServiceOrchestration", "LocalCloudManager", "Sysop"}, owner) {
		apiError(w, 403, "not a GateTunnel client", path)
		return true
	}
	if strings.Contains(path, "/mgmt/") && !containsExact([]string{"LocalCloudManager", "Sysop"}, owner) {
		apiError(w, 403, "management denied", path)
		return true
	}
	var raw any
	if err := decode(r, &raw); err != nil {
		apiError(w, 400, err.Error(), path)
		return true
	}
	payload := object(raw)
	store := f.app.Store
	store.mu.Lock()
	defer store.mu.Unlock()
	original := store.Data.Resources
	updated := make(map[string]Resource, len(original))
	for k, v := range original {
		updated[k] = v
	}
	store.Data.Resources = updated
	rollback := true
	defer func() {
		if rollback {
			store.Data.Resources = original
		}
	}()
	respond := func(code int, value any) {
		if err := store.SaveLocked(); err != nil {
			apiError(w, 500, "session persistence failed", path)
			return
		}
		rollback = false
		jsonOut(w, code, value)
	}
	if path == "/gatetunnel/connect_provider" {
		for _, field := range []string{"consumer", "provider", "consumerCloud", "providerCloud", "relay", "serviceDefinition"} {
			if payload[field] == nil || payload[field] == "" {
				apiError(w, 400, field+" is required", path)
				return true
			}
		}
		used := map[int]bool{}
		for _, v := range updated {
			if v.Kind == "gatetunnel-control" && v.Payload["state"] != "CLOSED" {
				p, _ := number(v.Payload["tunnelPort"])
				used[int(p)] = true
			}
		}
		min, _ := strconv.Atoi(env("MIN_TUNNEL_PORT", "8000"))
		max, _ := strconv.Atoi(env("MAX_TUNNEL_PORT", "8099"))
		port := 0
		for p := min; p <= max; p++ {
			if !used[p] {
				port = p
				break
			}
		}
		if port == 0 {
			apiError(w, 503, "no control session ports available", path)
			return true
		}
		id := randomID()
		queue := mapString(payload["queueId"])
		if queue == "" {
			queue = "gatetunnel." + randomID()
		}
		for _, v := range updated {
			if v.Kind == "gatetunnel-control" && v.Payload["queueId"] == queue {
				apiError(w, 409, "queueId already exists", path)
				return true
			}
		}
		peer := mapString(payload["peerName"])
		if peer == "" {
			peer = "GateTunnel-" + randomID()
		}
		session := map[string]any{"sessionId": id, "queueId": queue, "peerName": peer, "serviceDefinition": payload["serviceDefinition"], "tunnelPort": port, "state": "PROVIDER_READY", "consumer": payload["consumer"], "provider": payload["provider"], "consumerCloud": payload["consumerCloud"], "providerCloud": payload["providerCloud"], "relay": payload["relay"], "sessionStartedAt": float64(time.Now().UnixMilli()) / 1000}
		updated[id] = Resource{ID: id, Kind: "gatetunnel-control", Owner: owner, Payload: session, CreatedAt: now(), UpdatedAt: now()}
		respond(201, map[string]any{"sessionId": id, "queueId": queue, "peerName": peer, "serverPort": port, "state": "PROVIDER_READY"})
		return true
	}
	if path == "/gatetunnel/connect_consumer" {
		queue := mapString(payload["queueId"])
		if queue == "" {
			apiError(w, 400, "queueId is required", path)
			return true
		}
		for id, v := range updated {
			if v.Kind != "gatetunnel-control" || v.Payload["queueId"] != queue || v.Payload["state"] == "CLOSED" {
				continue
			}
			copyPayload := map[string]any{}
			for k, x := range v.Payload {
				copyPayload[k] = x
			}
			copyPayload["state"] = "ACTIVE"
			v.Payload = copyPayload
			v.UpdatedAt = now()
			updated[id] = v
			respond(201, map[string]any{"sessionId": id, "serverPort": copyPayload["tunnelPort"], "state": "ACTIVE"})
			return true
		}
		apiError(w, 404, "control session not found", path)
		return true
	}
	closeRecord := func(sessionID string, port int) bool {
		for id, v := range updated {
			if v.Kind != "gatetunnel-control" || v.Payload["state"] == "CLOSED" {
				continue
			}
			p, _ := number(v.Payload["tunnelPort"])
			if (sessionID != "" && id != sessionID) || (sessionID == "" && int(p) != port) {
				continue
			}
			copyPayload := map[string]any{}
			for k, x := range v.Payload {
				copyPayload[k] = x
			}
			copyPayload["state"] = "CLOSED"
			v.Payload = copyPayload
			v.UpdatedAt = now()
			updated[id] = v
			return true
		}
		return false
	}
	if path == "/gatetunnel/mgmt/sessions/close" {
		p, _ := number(payload["tunnelPort"])
		id := mapString(payload["sessionId"])
		// Relay listeners are explicitly closable by management as well.
		if id != "" {
			f.mu.Lock()
			s, ok := f.consumers[id]
			if ok {
				if s.Server != nil {
					_ = s.Server.Close()
				}
				delete(f.consumers, id)
			}
			_, provider := f.providers[id]
			delete(f.providers, id)
			f.mu.Unlock()
			if ok || provider {
				rollback = false
				jsonOut(w, 200, map[string]any{"closed": true})
				return true
			}
		}
		if !closeRecord(id, int(p)) {
			apiError(w, 404, "active session not found", path)
			return true
		}
		respond(200, map[string]any{"closed": true})
		return true
	}
	ports, ok := raw.([]any)
	if !ok {
		ports, _ = payload["ports"].([]any)
	}
	failures := []any{}
	seen := map[int]bool{}
	for _, value := range ports {
		p, valid := number(value)
		if !valid || p < 1 || p > 65535 {
			apiError(w, 400, fmt.Sprintf("invalid port %v", value), path)
			return true
		}
		port := int(p)
		if seen[port] {
			continue
		}
		seen[port] = true
		if !closeRecord("", port) {
			failures = append(failures, map[string]any{"port": port, "error": "Active session not found"})
		}
	}
	respond(200, failures)
	return true
}
