package cloud

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (a *App) supportHTTP(w http.ResponseWriter, r *http.Request) {
	owner, err := a.requester(r)
	if err != nil {
		apiError(w, 401, err.Error(), r.URL.Path)
		return
	}
	switch a.Config.Role {
	case "blacklist":
		a.blacklistHTTP(w, r, owner)
	case "translationmanager":
		a.translationHTTP(w, r, owner)
	case "deviceqos":
		a.deviceQoSHTTP(w, r, owner)
	case "gatekeeper":
		a.gatekeeperHTTP(w, r, owner)
	case "gatetunnel":
		a.gateTunnelHTTP(w, r, owner)
	case "sysmonitor":
		a.sysMonitorHTTP(w, r, owner)
	case "aigym":
		a.aiGymHTTP(w, r, owner)
	case "localcloudmanager":
		a.localCloudHTTP(w, r)
	case "configuration", "choreographer", "plantdescription":
		a.documentSupportHTTP(w, r, owner, a.Config.Role)
	case "timemanager":
		a.timeManagerHTTP(w, r)
	default:
		apiError(w, 404, "No such support-system operation", r.URL.Path)
	}
}

func (a *App) documentSupportHTTP(w http.ResponseWriter, r *http.Request, owner, kind string) {
	switch r.Method {
	case http.MethodPost, http.MethodPut:
		a.createResourceOwned(w, r, kind, owner)
	case http.MethodGet:
		a.queryResources(w, kind)
	case http.MethodDelete:
		id := qString(r, "id")
		if id == "" {
			id = keyFromPath(r.URL.Path)
		}
		a.Store.mu.Lock()
		delete(a.Store.Data.Resources, id)
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		apiError(w, http.StatusMethodNotAllowed, "method not allowed", r.URL.Path)
	}
}

func (a *App) timeManagerHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		apiError(w, http.StatusMethodNotAllowed, "method not allowed", r.URL.Path)
		return
	}
	jsonOut(w, http.StatusOK, map[string]any{"utc": now(), "unixMillis": time.Now().UTC().UnixMilli(), "timezone": "UTC"})
}

func (a *App) blacklistHTTP(w http.ResponseWriter, r *http.Request, owner string) {
	switch {
	case r.Method == http.MethodPost && (strings.HasSuffix(r.URL.Path, "/check") || r.URL.Path == "/blacklist"):
		var req map[string]any
		if err := decode(r, &req); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		target := mapString(req["systemName"])
		if target == "" {
			target = mapString(req["name"])
		}
		a.Store.mu.RLock()
		listed := false
		for _, v := range a.Store.Data.Resources {
			if v.Kind == "blacklist-entry" && strings.EqualFold(mapString(v.Payload["systemName"]), target) {
				listed = true
				break
			}
		}
		a.Store.mu.RUnlock()
		jsonOut(w, 200, map[string]any{"systemName": target, "blacklisted": listed})
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/mgmt"):
		if _, err := a.manager(r); err != nil {
			apiError(w, 403, err.Error(), r.URL.Path)
			return
		}
		a.createResourceOwned(w, r, "blacklist-entry", owner)
	case r.Method == http.MethodGet || strings.HasSuffix(r.URL.Path, "/query"):
		a.queryResources(w, "blacklist-entry")
	default:
		apiError(w, 404, "No such Blacklist operation", r.URL.Path)
	}
}

func (a *App) translationHTTP(w http.ResponseWriter, r *http.Request, owner string) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/translation/translate":
		var req map[string]any
		if err := decode(r, &req); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		payload := req["payload"]
		if payload == nil {
			payload = req["data"]
		}
		jsonOut(w, 200, map[string]any{"sourceFormat": req["sourceFormat"], "targetFormat": req["targetFormat"], "payload": payload, "translated": true})
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/mgmt"):
		if _, err := a.manager(r); err != nil {
			apiError(w, 403, err.Error(), r.URL.Path)
			return
		}
		a.createResourceOwned(w, r, "translation-template", owner)
	case r.Method == http.MethodGet || strings.HasSuffix(r.URL.Path, "/query"):
		a.queryResources(w, "translation-template")
	default:
		apiError(w, 404, "No such TranslationManager operation", r.URL.Path)
	}
}

func (a *App) deviceQoSHTTP(w http.ResponseWriter, r *http.Request, owner string) {
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/evaluate"):
		var req map[string]any
		if err := decode(r, &req); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		metrics, _ := req["metrics"].(map[string]any)
		score, count := 0.0, 0.0
		for _, v := range metrics {
			if n, ok := number(v); ok {
				score += n
				count++
			}
		}
		if count > 0 {
			score /= count
		}
		jsonOut(w, 200, map[string]any{"deviceName": req["deviceName"], "score": score, "qualified": count > 0, "evaluatedAt": now()})
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/mgmt"):
		if _, err := a.manager(r); err != nil {
			apiError(w, 403, err.Error(), r.URL.Path)
			return
		}
		a.createResourceOwned(w, r, "device-qos-policy", owner)
	case r.Method == http.MethodGet || strings.HasSuffix(r.URL.Path, "/query"):
		a.queryResources(w, "device-qos-policy")
	default:
		apiError(w, 404, "No such DeviceQoSEvaluator operation", r.URL.Path)
	}
}

func (a *App) gatekeeperHTTP(w http.ResponseWriter, r *http.Request, owner string) {
	if a.federation != nil {
		a.federation.GatekeeperHTTP(w, r, owner)
		return
	}
	switch {
	case r.Method == http.MethodPost && (r.URL.Path == "/gatekeeper/init_gsd" || r.URL.Path == "/gatekeeper/init_multi_gsd"):
		jsonOut(w, 200, unavailable("no trusted remote-cloud transport is configured"))
	case r.Method == http.MethodPost && r.URL.Path == "/gatekeeper/init_icn":
		jsonOut(w, 200, map[string]any{"negotiated": false, "reason": "no trusted remote-cloud transport is configured"})
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/mgmt"):
		if _, err := a.manager(r); err != nil {
			apiError(w, 403, err.Error(), r.URL.Path)
			return
		}
		a.createResourceOwned(w, r, "gatekeeper-peer", owner)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/mgmt"):
		a.queryResources(w, "gatekeeper-peer")
	default:
		apiError(w, 404, "No such Gatekeeper operation", r.URL.Path)
	}
}

func (a *App) gateTunnelHTTP(w http.ResponseWriter, r *http.Request, owner string) {
	if a.federation != nil {
		a.federation.TunnelHTTP(w, r, owner)
		return
	}
	p := strings.Replace(r.URL.Path, "/gateway/", "/gatetunnel/", 1)
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(p, "/publickey"):
		sum := sha256.Sum256([]byte(a.Config.TokenSecret))
		text(w, 200, base64.StdEncoding.EncodeToString(sum[:]))
	case r.Method == http.MethodPost && (strings.HasSuffix(p, "/connect_provider") || strings.HasSuffix(p, "/connect_consumer") || strings.HasSuffix(p, "/connect-provider") || strings.HasSuffix(p, "/connect-consumer")):
		a.createResourceOwned(w, r, "gate-tunnel-session", owner)
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/close_sessions"):
		var req map[string]any
		_ = decode(r, &req)
		id := mapString(req["id"])
		a.Store.mu.Lock()
		if id != "" {
			delete(a.Store.Data.Resources, id)
		}
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		jsonOut(w, 200, map[string]any{"closed": id})
	case r.Method == http.MethodGet && strings.Contains(p, "/mgmt"):
		a.queryResources(w, "gate-tunnel-session")
	default:
		apiError(w, 404, "No such GateTunnel operation", r.URL.Path)
	}
}

func (a *App) sysMonitorHTTP(w http.ResponseWriter, r *http.Request, owner string) {
	switch {
	case r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "subscribe") || strings.Contains(r.URL.Path, "subscriptions")):
		a.createResourceOwned(w, r, "sysmonitor-subscription", owner)
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "data"):
		var payload map[string]any
		if err := decode(r, &payload); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		payload["receivedAt"] = now()
		payload["sourceSystemName"] = owner
		a.Store.mu.Lock()
		a.Store.Data.Records = append(a.Store.Data.Records, payload)
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		jsonOut(w, 201, payload)
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "data"):
		a.Store.mu.RLock()
		out := append([]map[string]any(nil), a.Store.Data.Records...)
		a.Store.mu.RUnlock()
		jsonOut(w, 200, listResponse(out))
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "status"):
		jsonOut(w, 200, fmtStatus(a.Config.SystemName))
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "subscriptions"):
		a.queryResources(w, "sysmonitor-subscription")
	default:
		apiError(w, 404, "No such SysMonitor operation", r.URL.Path)
	}
}

func (a *App) aiGymHTTP(w http.ResponseWriter, r *http.Request, owner string) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/aigym/status":
		jsonOut(w, 200, fmtStatus(a.Config.SystemName))
	case r.Method == http.MethodPost && r.URL.Path == "/aigym/samples":
		a.createResourceOwned(w, r, "ai-sample", owner)
	case r.Method == http.MethodPost && r.URL.Path == "/aigym/predict":
		var req map[string]any
		if err := decode(r, &req); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		features, _ := req["features"].(map[string]any)
		model := mapString(req["model"])
		k := 3
		if n, ok := number(req["neighbours"]); ok {
			k = int(n)
		}
		a.Store.mu.RLock()
		samples := []Resource{}
		for _, s := range a.Store.Data.Resources {
			if s.Kind == "ai-sample" && (model == "" || mapString(s.Payload["model"]) == model) {
				samples = append(samples, s)
			}
		}
		a.Store.mu.RUnlock()
		prediction, ok := nearest(samples, features, k)
		if !ok {
			apiError(w, 404, "no compatible training samples", r.URL.Path)
			return
		}
		jsonOut(w, 200, map[string]any{"model": model, "prediction": prediction, "neighbours": k})
	case r.Method == http.MethodGet && r.URL.Path == "/aigym/observations":
		a.Store.mu.RLock()
		out := append([]map[string]any(nil), a.Store.Data.Records...)
		a.Store.mu.RUnlock()
		jsonOut(w, 200, listResponse(out))
	default:
		apiError(w, 404, "No such AIGym operation", r.URL.Path)
	}
}

func (a *App) localCloudHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/status"):
		jsonOut(w, 200, fmtStatus(a.Config.SystemName))
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/systems"):
		b, err := a.call(http.MethodPost, a.Config.RegistryURL+"/serviceregistry/mgmt/systems/query", map[string]any{}, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
		if err != nil {
			apiError(w, 502, err.Error(), r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/services"):
		b, err := a.call(http.MethodPost, a.Config.RegistryURL+"/serviceregistry/mgmt/service-instances/query", map[string]any{}, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
		if err != nil {
			apiError(w, 502, err.Error(), r.URL.Path)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	default:
		apiError(w, 404, "No such LocalCloudManager operation", r.URL.Path)
	}
}

func serviceNames() string {
	names := []string{}
	for _, s := range roleSpecs {
		names = append(names, s.SystemName)
	}
	return fmt.Sprintf("%v", names)
}
