package cloud

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"
)

func (a *App) authenticationHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/authentication/identity/login":
		var req struct {
			SystemName  string            `json:"systemName"`
			Credentials map[string]string `json:"credentials"`
		}
		if err := decode(r, &req); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		if a.Config.Secure {
			name, err := a.certificateIdentity(r)
			if err != nil || name != req.SystemName {
				apiError(w, 401, "login identity must match the client certificate", r.URL.Path)
				return
			}
		}
		a.Store.mu.Lock()
		id, ok := a.Store.Data.Identities[req.SystemName]
		if !ok || !equalCredentials(id.Credentials, req.Credentials) {
			a.Store.mu.Unlock()
			apiError(w, 401, "invalid system credentials", r.URL.Path)
			return
		}
		token := randomID()
		exp := time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano)
		s := Session{Token: token, SystemName: req.SystemName, ExpirationTime: exp}
		a.Store.Data.Sessions[token] = s
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		jsonOut(w, 200, s)
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/authentication/identity/verify/"):
		if a.Config.Secure {
			if _, err := a.requester(r); err != nil {
				apiError(w, 401, err.Error(), r.URL.Path)
				return
			}
		}
		token := strings.TrimPrefix(r.URL.Path, "/authentication/identity/verify/")
		a.Store.mu.RLock()
		s, ok := a.Store.Data.Sessions[token]
		a.Store.mu.RUnlock()
		if !ok || s.ExpirationTime <= now() {
			apiError(w, 401, "invalid or expired token", r.URL.Path)
			return
		}
		jsonOut(w, 200, map[string]any{"verified": true, "systemName": s.SystemName, "expirationTime": s.ExpirationTime})
	case r.Method == http.MethodPost && r.URL.Path == "/authentication/identity/logout":
		owner, err := a.requester(r)
		if err != nil {
			apiError(w, 401, err.Error(), r.URL.Path)
			return
		}
		var req map[string]any
		_ = decode(r, &req)
		token := mapString(req["token"])
		if token == "" {
			token = strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		}
		a.Store.mu.Lock()
		if s, exists := a.Store.Data.Sessions[token]; exists && s.SystemName != owner {
			a.Store.mu.Unlock()
			apiError(w, 403, "cannot log out another system", r.URL.Path)
			return
		}
		delete(a.Store.Data.Sessions, token)
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		w.WriteHeader(204)
	case strings.HasPrefix(r.URL.Path, "/authentication/mgmt/"):
		if _, err := a.manager(r); err != nil {
			apiError(w, 403, err.Error(), r.URL.Path)
			return
		}
		a.authenticationManagement(w, r)
	case r.Method == http.MethodGet && r.URL.Path == "/authentication/general/mgmt/config":
		if _, err := a.manager(r); err != nil {
			apiError(w, 403, err.Error(), r.URL.Path)
			return
		}
		jsonOut(w, 200, a.runtimeConfig())
	default:
		apiError(w, 404, "No such Authentication operation", r.URL.Path)
	}
}

func equalCredentials(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func (a *App) authenticationManagement(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/authentication/mgmt/identities":
		var req Identity
		if err := decode(r, &req); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		if req.SystemName == "" {
			apiError(w, 400, "systemName is empty", r.URL.Path)
			return
		}
		req.CreatedAt = now()
		a.Store.mu.Lock()
		a.Store.Data.Identities[req.SystemName] = req
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		jsonOut(w, 201, req)
	case r.Method == http.MethodPost && r.URL.Path == "/authentication/mgmt/identities/query":
		a.Store.mu.RLock()
		out := []Identity{}
		for _, k := range sortedKeys(a.Store.Data.Identities) {
			id := a.Store.Data.Identities[k]
			id.Credentials = nil
			out = append(out, id)
		}
		a.Store.mu.RUnlock()
		jsonOut(w, 200, listResponse(out))
	case r.Method == http.MethodPost && r.URL.Path == "/authentication/mgmt/sessions":
		a.Store.mu.RLock()
		out := []Session{}
		for _, k := range sortedKeys(a.Store.Data.Sessions) {
			out = append(out, a.Store.Data.Sessions[k])
		}
		a.Store.mu.RUnlock()
		jsonOut(w, 200, listResponse(out))
	case r.Method == http.MethodDelete && r.URL.Path == "/authentication/mgmt/identities":
		var names []string
		if err := decode(r, &names); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		a.Store.mu.Lock()
		for _, n := range names {
			delete(a.Store.Data.Identities, n)
		}
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		w.WriteHeader(204)
	default:
		apiError(w, 404, "No such Authentication management operation", r.URL.Path)
	}
}

func (a *App) authorizationHTTP(w http.ResponseWriter, r *http.Request) {
	if _, err := a.requester(r); err != nil {
		apiError(w, 401, err.Error(), r.URL.Path)
		return
	}
	switch {
	case r.Method == http.MethodPost && (r.URL.Path == "/authorization/grant" || r.URL.Path == "/authorization/mgmt/grant"):
		if _, err := a.manager(r); err != nil {
			apiError(w, 403, err.Error(), r.URL.Path)
			return
		}
		var raw map[string]any
		if err := decode(r, &raw); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		g := grantFrom(raw)
		if g.Consumer == "" || g.Provider == "" || g.ServiceDefinition == "" {
			apiError(w, 400, "consumer, provider and serviceDefinition are required", r.URL.Path)
			return
		}
		a.Store.mu.Lock()
		a.Store.Data.Grants = append(a.Store.Data.Grants, g)
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		jsonOut(w, 201, g)
	case r.Method == http.MethodPost && (r.URL.Path == "/authorization/verify" || r.URL.Path == "/authorization/mgmt/check"):
		var raw map[string]any
		if err := decode(r, &raw); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		g := grantFrom(raw)
		authorized := a.isGranted(g)
		jsonOut(w, 200, map[string]any{"authorized": authorized, "allowed": authorized})
	case r.Method == http.MethodPost && (r.URL.Path == "/authorization/lookup" || r.URL.Path == "/authorization/mgmt/query"):
		a.Store.mu.RLock()
		out := append([]Grant(nil), a.Store.Data.Grants...)
		a.Store.mu.RUnlock()
		jsonOut(w, 200, listResponse(out))
	case r.Method == http.MethodPost && (r.URL.Path == "/authorization/token/generate" || r.URL.Path == "/authorization/mgmt/tokens/generate"):
		if a.Config.Secure {
			apiError(w, 501, "asymmetric authorization-token profile is not yet implemented", r.URL.Path)
			return
		}
		var raw map[string]any
		if err := decode(r, &raw); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		payload, _ := json.Marshal(raw)
		mac := hmac.New(sha256.New, []byte(a.Config.TokenSecret))
		_, _ = mac.Write(payload)
		token := base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
		jsonOut(w, 200, map[string]any{"token": token, "expiresAt": time.Now().UTC().Add(time.Hour).Format(time.RFC3339)})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/authorization/token/verify/"):
		valid := verifySigned(strings.TrimPrefix(r.URL.Path, "/authorization/token/verify/"), a.Config.TokenSecret)
		jsonOut(w, 200, map[string]any{"valid": valid})
	case r.Method == http.MethodGet && r.URL.Path == "/authorization/token/public-key":
		text(w, 200, "HMAC-SHA256 test-cloud token profile")
	default:
		apiError(w, 404, "No such ConsumerAuthorization operation", r.URL.Path)
	}
}

func grantFrom(m map[string]any) Grant {
	g := Grant{Consumer: mapString(m["consumer"]), Provider: mapString(m["provider"]), ServiceDefinition: mapString(m["serviceDefinition"]), Cloud: mapString(m["cloud"]), Operations: stringSlice(m["operations"])}
	if g.Consumer == "" {
		g.Consumer = mapString(m["consumerSystemName"])
	}
	if g.Provider == "" {
		g.Provider = mapString(m["providerSystemName"])
	}
	if g.ServiceDefinition == "" {
		g.ServiceDefinition = mapString(m["serviceDefinitionName"])
	}
	return g
}
func (a *App) isGranted(q Grant) bool {
	a.Store.mu.RLock()
	defer a.Store.mu.RUnlock()
	for _, g := range a.Store.Data.Grants {
		if strings.EqualFold(g.Consumer, q.Consumer) && strings.EqualFold(g.Provider, q.Provider) && strings.EqualFold(g.ServiceDefinition, q.ServiceDefinition) && g.Cloud == q.Cloud {
			if len(q.Operations) == 0 {
				return true
			}
			for _, op := range q.Operations {
				if !containsFold(g.Operations, op) {
					return false
				}
			}
			return true
		}
	}
	return false
}
func verifySigned(token, secret string) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return false
	}
	payload, e1 := base64.RawURLEncoding.DecodeString(parts[0])
	sig, e2 := base64.RawURLEncoding.DecodeString(parts[1])
	if e1 != nil || e2 != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hmac.Equal(sig, mac.Sum(nil))
}

func (a *App) orchestrationHTTP(w http.ResponseWriter, r *http.Request) {
	requester, err := a.requester(r)
	if err != nil {
		apiError(w, 401, err.Error(), r.URL.Path)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/orchestration/pull":
		var req map[string]any
		if err := decode(r, &req); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		def := serviceRequirement(req)
		if def == "" {
			apiError(w, 400, "serviceDefinition is required", r.URL.Path)
			return
		}
		lookup := map[string]any{"serviceDefinitionNames": []string{def}}
		b, err := a.call(http.MethodPost, a.Config.RegistryURL+"/serviceregistry/service-discovery/lookup", lookup, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
		if err != nil {
			apiError(w, 502, err.Error(), r.URL.Path)
			return
		}
		var result map[string]any
		_ = json.Unmarshal(b, &result)
		entries, _ := result["entries"].([]any)
		response := map[string]any{"requesterSystemName": requester, "results": entries, "count": len(entries)}
		a.Store.mu.Lock()
		a.Store.Data.Records = append(a.Store.Data.Records, map[string]any{"kind": "orchestration", "requester": requester, "serviceDefinition": def, "resultCount": len(entries), "createdAt": now()})
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		jsonOut(w, 200, response)
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/mgmt/"):
		a.createResource(w, r, "orchestration")
	case r.Method == http.MethodDelete && strings.Contains(r.URL.Path, "/mgmt/simple-store/remove"):
		if _, err := a.manager(r); err != nil {
			apiError(w, 403, err.Error(), r.URL.Path)
			return
		}
		id := qString(r, "id")
		if id == "" {
			id = qString(r, "uuids")
		}
		a.Store.mu.Lock()
		delete(a.Store.Data.Resources, id)
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		jsonOut(w, 200, map[string]any{"id": id, "removed": true})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/query"):
		a.queryResources(w, "orchestration")
	default:
		apiError(w, 404, "No such ServiceOrchestration operation", r.URL.Path)
	}
}

func serviceRequirement(req map[string]any) string {
	if s := mapString(req["serviceDefinition"]); s != "" {
		return s
	}
	if m, ok := req["serviceRequirement"].(map[string]any); ok {
		return mapString(m["serviceDefinition"])
	}
	if m, ok := req["orchestrationRequest"].(map[string]any); ok {
		return serviceRequirement(m)
	}
	return ""
}

func (a *App) dataManagerHTTP(w http.ResponseWriter, r *http.Request) {
	owner, err := a.requester(r)
	if err != nil {
		apiError(w, 401, err.Error(), r.URL.Path)
		return
	}
	switch r.Method {
	case http.MethodPut, http.MethodPost:
		var payload any
		if err := decode(r, &payload); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		record := map[string]any{"id": randomID(), "sourceSystemName": owner, "path": r.URL.Path, "data": payload, "createdAt": now()}
		a.Store.mu.Lock()
		a.Store.Data.Records = append(a.Store.Data.Records, record)
		_ = a.Store.SaveLocked()
		a.Store.mu.Unlock()
		jsonOut(w, 201, record)
	case http.MethodGet:
		a.Store.mu.RLock()
		out := append([]map[string]any(nil), a.Store.Data.Records...)
		a.Store.mu.RUnlock()
		jsonOut(w, 200, listResponse(out))
	default:
		apiError(w, 405, "method not allowed", r.URL.Path)
	}
}

func (a *App) eventHTTP(w http.ResponseWriter, r *http.Request) {
	owner, err := a.requester(r)
	if err != nil {
		apiError(w, 401, err.Error(), r.URL.Path)
		return
	}
	switch {
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "subscription"):
		a.createResourceOwned(w, r, "event-subscription", owner)
	case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "publish"):
		var payload map[string]any
		if err := decode(r, &payload); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		eventType := mapString(payload["eventType"])
		a.Store.mu.RLock()
		matched := 0
		for _, v := range a.Store.Data.Resources {
			if v.Kind == "event-subscription" && (eventType == "" || mapString(v.Payload["eventType"]) == eventType) {
				matched++
			}
		}
		a.Store.mu.RUnlock()
		jsonOut(w, 200, map[string]any{"eventId": randomID(), "matchedSubscriptions": matched, "publishedAt": now()})
	case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "mgmt"):
		a.queryResources(w, "event-subscription")
	default:
		apiError(w, 404, "No such EventHandler operation", r.URL.Path)
	}
}

func (a *App) certificateHTTP(w http.ResponseWriter, r *http.Request) {
	if a.Config.Secure {
		apiError(w, 501, "cloud-CA issuance and onboarding migration are not yet implemented; no self-signed fallback is allowed", r.URL.Path)
		return
	}
	if r.Method == http.MethodGet && (strings.Contains(r.URL.Path, "ca-certificate") || strings.HasSuffix(r.URL.Path, "/ca")) {
		cert, err := generateCertificate(a.Config.SystemName + ".Root")
		if err != nil {
			apiError(w, 500, err.Error(), r.URL.Path)
			return
		}
		text(w, 200, mapString(cert["certificate"]))
		return
	}
	if r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "certificate") || strings.Contains(r.URL.Path, "sharedsecret")) {
		var req map[string]any
		if err := decode(r, &req); err != nil {
			apiError(w, 400, err.Error(), r.URL.Path)
			return
		}
		name := mapString(req["name"])
		if name == "" {
			name = mapString(req["systemName"])
		}
		if name == "" {
			name = "OnboardedSystem"
		}
		cert, err := generateCertificate(name)
		if err != nil {
			apiError(w, 500, err.Error(), r.URL.Path)
			return
		}
		cert["systemName"] = name
		cert["serviceRegistryUrl"] = a.Config.RegistryURL
		jsonOut(w, 201, cert)
		return
	}
	apiError(w, 404, "No such certificate operation", r.URL.Path)
}

func (a *App) runtimeConfig() map[string]any {
	return map[string]any{"role": a.Config.Role, "systemName": a.Config.SystemName, "port": a.Config.Port, "version": "5.2.2", "implementation": "go"}
}

func (a *App) createResource(w http.ResponseWriter, r *http.Request, kind string) {
	owner, _ := a.requester(r)
	a.createResourceOwned(w, r, kind, owner)
}
func (a *App) createResourceOwned(w http.ResponseWriter, r *http.Request, kind, owner string) {
	var payload map[string]any
	if err := decode(r, &payload); err != nil {
		apiError(w, 400, err.Error(), r.URL.Path)
		return
	}
	t := now()
	res := Resource{ID: randomID(), Kind: kind, Owner: owner, Payload: payload, CreatedAt: t, UpdatedAt: t}
	a.Store.mu.Lock()
	a.Store.Data.Resources[res.ID] = res
	_ = a.Store.SaveLocked()
	a.Store.mu.Unlock()
	jsonOut(w, 201, res)
}
func (a *App) queryResources(w http.ResponseWriter, kind string) {
	a.Store.mu.RLock()
	out := []Resource{}
	for _, k := range sortedKeys(a.Store.Data.Resources) {
		v := a.Store.Data.Resources[k]
		if kind == "" || v.Kind == kind {
			out = append(out, v)
		}
	}
	a.Store.mu.RUnlock()
	jsonOut(w, 200, listResponse(out))
}

func nearest(samples []Resource, features map[string]any, k int) (float64, bool) {
	type pair struct{ d, t float64 }
	pairs := []pair{}
	for _, s := range samples {
		f, _ := s.Payload["features"].(map[string]any)
		target, ok := number(s.Payload["target"])
		if !ok {
			continue
		}
		d := 0.0
		valid := true
		for n, v := range features {
			x, ok := number(v)
			if !ok {
				valid = false
				break
			}
			y, ok := number(f[n])
			if !ok {
				valid = false
				break
			}
			d += (x - y) * (x - y)
		}
		if valid {
			pairs = append(pairs, pair{math.Sqrt(d), target})
		}
	}
	if len(pairs) == 0 {
		return 0, false
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].d < pairs[j].d })
	if k < 1 {
		k = 1
	}
	if k > len(pairs) {
		k = len(pairs)
	}
	sum := 0.0
	for i := 0; i < k; i++ {
		sum += pairs[i].t
	}
	return sum / float64(k), true
}
func number(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case json.Number:
		f, e := x.Float64()
		return f, e == nil
	case int:
		return float64(x), true
	default:
		return 0, false
	}
}
func fmtStatus(name string) map[string]any {
	return map[string]any{"systemName": name, "status": "AVAILABLE", "version": "5.2.2", "implementation": "go", "timestamp": now()}
}
func keyFromPath(p string) string {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	return parts[len(parts)-1]
}
func unavailable(message string) map[string]any {
	return map[string]any{"available": false, "reason": message, "results": []any{}}
}
func qString(r *http.Request, key string) string { return strings.TrimSpace(r.URL.Query().Get(key)) }
func ensureString(v any, field string) (string, error) {
	s := mapString(v)
	if s == "" {
		return "", fmt.Errorf("%s is required", field)
	}
	return s, nil
}
