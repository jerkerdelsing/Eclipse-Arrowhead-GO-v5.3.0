package cloud

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/scrypt"
)

var (
	managerHistoryMu sync.Mutex
	managerHistory   []map[string]any
	managerConsole   = newManagerConsoleAuth()
)

type consoleSession struct{ expires time.Time }
type managerConsoleAuthState struct {
	mu          sync.Mutex
	salt, hash  []byte
	sessions    map[string]consoleSession
	failures    []time.Time
	lockedUntil time.Time
	allowed     map[string]bool
}

func newManagerConsoleAuth() *managerConsoleAuthState {
	a := &managerConsoleAuthState{sessions: map[string]consoleSession{}, allowed: map[string]bool{}}
	for _, host := range csv(env("CONSOLE_ALLOWED_HOSTS", "127.0.0.1,localhost,[::1]")) {
		a.allowed[strings.ToLower(host)] = true
	}
	parts := strings.Split(env("CONSOLE_PASSWORD_HASH", ""), ":")
	if len(parts) == 3 && parts[0] == "scrypt" {
		a.salt, _ = base64.StdEncoding.DecodeString(parts[1])
		a.hash, _ = base64.StdEncoding.DecodeString(parts[2])
		if len(a.salt) < 16 || len(a.hash) < 32 {
			a.salt, a.hash = nil, nil
		}
	}
	return a
}

func consoleHost(value string) string {
	v := strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(v, "[") {
		if i := strings.Index(v, "]"); i >= 0 {
			return v[:i+1]
		}
	}
	return strings.Split(v, ":")[0]
}
func (a *managerConsoleAuthState) originAllowed(r *http.Request) bool {
	if !a.allowed[consoleHost(r.Host)] {
		return false
	}
	if origin := r.Header.Get("Origin"); origin != "" {
		if origin == "null" {
			return false
		}
		u, err := url.Parse(origin)
		if err != nil || !a.allowed[consoleHost(u.Host)] {
			return false
		}
	}
	return true
}
func managerCookie(r *http.Request) string {
	if c, err := r.Cookie("ah_console"); err == nil {
		return c.Value
	}
	return ""
}
func (a *managerConsoleAuthState) authenticated(r *http.Request) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	token := managerCookie(r)
	session, ok := a.sessions[token]
	if !ok || time.Now().After(session.expires) {
		delete(a.sessions, token)
		return false
	}
	return true
}
func (a *managerConsoleAuthState) login(password string) (int, string, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if now.Before(a.lockedUntil) {
		return 429, "", int(time.Until(a.lockedUntil).Seconds()) + 1
	}
	ok := false
	if len(password) > 0 && len(password) <= 256 && len(a.hash) >= 32 {
		if candidate, err := scrypt.Key([]byte(password), a.salt, 16384, 8, 1, len(a.hash)); err == nil {
			ok = subtle.ConstantTimeCompare(candidate, a.hash) == 1
		}
	}
	if !ok {
		cutoff := now.Add(-5 * time.Minute)
		kept := a.failures[:0]
		for _, at := range a.failures {
			if at.After(cutoff) {
				kept = append(kept, at)
			}
		}
		a.failures = append(kept, now)
		if len(a.failures) >= 5 {
			a.lockedUntil = now.Add(time.Minute)
			a.failures = nil
		}
		return 401, "", 0
	}
	a.failures = nil
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	token := base64.RawURLEncoding.EncodeToString(raw)
	seconds := 8 * 3600
	if parsed, err := strconv.Atoi(env("CONSOLE_SESSION_SECONDS", "28800")); err == nil && parsed > 0 {
		seconds = parsed
	}
	a.sessions[token] = consoleSession{now.Add(time.Duration(seconds) * time.Second)}
	return 204, fmt.Sprintf("ah_console=%s; HttpOnly; SameSite=Strict; Path=/; Max-Age=%d", token, seconds), 0
}
func (a *managerConsoleAuthState) logout(r *http.Request) {
	a.mu.Lock()
	delete(a.sessions, managerCookie(r))
	a.mu.Unlock()
}

type runtimeContainer struct {
	ID, Name, Service, DisplayName, Image, State, Status, Health, Created string
	Managed                                                               bool
}

var systemToCompose = map[string]string{
	"ServiceRegistry": "serviceregistry", "Authentication": "authentication",
	"ConsumerAuthorization": "consumerauthorization", "DynamicServiceOrchestration": "serviceorchestration-dynamic",
	"SimpleStoreServiceOrchestration": "serviceorchestration-simple", "DataManager": "datamanager",
	"EventHandler": "eventhandler", "Onboarding": "onboarding", "Blacklist": "blacklist",
	"TranslationManager": "translationmanager", "DeviceQoSEvaluator": "deviceqosevaluator",
	"CertificateAuthority": "certificateauthority", "Gatekeeper": "gatekeeper", "GateTunnel": "gatetunnel",
	"SysMonitor": "sysmonitor", "AIGym": "aigym", "LocalCloudManager": "localcloudmanager",
	"Configuration": "configuration", "Choreographer": "choreographer", "TimeManager": "timemanager",
	"PlantDescriptionEngine": "plantdescriptionengine",
}

func managedComposeServices() map[string]bool {
	out := map[string]bool{}
	for _, service := range systemToCompose {
		out[service] = true
	}
	return out
}

func serveManagerAsset(w http.ResponseWriter, path string) bool {
	name, contentType := "ui/index.html", "text/html; charset=utf-8"
	switch path {
	case "/app.js", "/assets/app.js":
		name, contentType = "app.js", "text/javascript; charset=utf-8"
	case "/styles.css", "/assets/styles.css":
		name, contentType = "styles.css", "text/css; charset=utf-8"
	case "/", "/ui":
		name = "index.html"
	default:
		return false
	}
	root := env("LOCALCLOUDMANAGER_UI_ROOT", "/ui")
	b, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		b, err = os.ReadFile(filepath.Join("internal", "cloud", "ui", name))
	}
	if err != nil {
		b, err = os.ReadFile(filepath.Join("ui", name))
	}
	if err != nil {
		b, err = managerAssets.ReadFile("ui/" + name)
	}
	if err != nil {
		http.Error(w, "dashboard asset missing", 500)
		return true
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
	return true
}

func (a *App) managerAPI(w http.ResponseWriter, r *http.Request) bool {
	p := r.URL.Path
	if strings.HasPrefix(p, "/api/") {
		w.Header().Set("Cache-Control", "no-store")
		if !managerConsole.originAllowed(r) {
			jsonOut(w, 403, map[string]any{"error": "Host or Origin is not an allowed console address"})
			return true
		}
		if len(managerConsole.hash) == 0 {
			jsonOut(w, 503, map[string]any{"error": "Console password is not configured (CONSOLE_PASSWORD_HASH)"})
			return true
		}
		if p == "/api/session" {
			a.managerSession(w, r)
			return true
		}
		if !managerConsole.authenticated(r) {
			jsonOut(w, 401, map[string]any{"error": "Console login required"})
			return true
		}
	}
	switch {
	case r.Method == http.MethodGet && p == "/api/overview":
		payload, err := a.managerOverview()
		a.managerResult(w, r, 200, payload, err)
	case r.Method == http.MethodGet && p == "/api/service-registry-management":
		payload, err := a.managerOverview()
		if err == nil {
			payload = map[string]any{"collectedAt": payload["collectedAt"], "cloud": payload["cloud"], "summary": payload["registryManagement"].(map[string]any)["summary"], "devices": payload["registryManagement"].(map[string]any)["devices"], "runtimeOnly": payload["registryManagement"].(map[string]any)["runtimeOnly"], "errors": payload["errors"]}
		}
		a.managerResult(w, r, 200, payload, err)
	case r.Method == http.MethodGet && p == "/api/datamanager":
		payload, err := a.managerData(r)
		a.managerResult(w, r, 200, payload, err)
	case r.Method == http.MethodGet && p == "/api/consumers":
		payload, err := a.managerConsumers()
		a.managerResult(w, r, 200, payload, err)
	case r.Method == http.MethodGet && p == "/api/intercloud":
		a.managerResult(w, r, 200, a.managerIntercloud(), nil)
	case r.Method == http.MethodGet && p == "/api/sysmonitor":
		payload, err := a.managerSysMonitor(r)
		a.managerResult(w, r, 200, payload, err)
	case r.Method == http.MethodGet && p == "/api/sysmonitor/subscriptions":
		payload, err := a.managerSysMonitorSubscriptions()
		a.managerResult(w, r, 200, payload, err)
	case (r.Method == http.MethodPut || r.Method == http.MethodDelete) && strings.HasPrefix(p, "/api/sysmonitor/subscriptions/"):
		if !confirmed(r) {
			jsonOut(w, 428, map[string]any{"error": "Missing action confirmation header"})
			return true
		}
		provider := strings.TrimPrefix(p, "/api/sysmonitor/subscriptions/")
		a.managerResult(w, r, 200, map[string]any{"providerSystem": provider, "updated": r.Method == http.MethodPut, "removed": r.Method == http.MethodDelete}, nil)
	case r.Method == http.MethodGet && p == "/api/plantdescriptions":
		payload, err := a.managerPlantDescriptions()
		a.managerResult(w, r, 200, payload, err)
	case strings.HasPrefix(p, "/api/plantdescriptions") && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodPatch || r.Method == http.MethodDelete):
		if !confirmed(r) {
			jsonOut(w, 428, map[string]any{"error": "Missing action confirmation header"})
			return true
		}
		payload, status, err := a.managerPlantMutation(r)
		a.managerResult(w, r, status, payload, err)
	case strings.HasPrefix(p, "/api/orchestration/policies"):
		return a.editorPoliciesHTTP(w,r)
	case r.Method == http.MethodPut && strings.HasPrefix(p, "/api/orchestration/rules/"):
		return a.editorRulePriorityHTTP(w,r)
	case r.Method == http.MethodGet && p == "/api/orchestration/rules":
		payload, err := a.managerRules()
		a.managerResult(w, r, 200, payload, err)
	case r.Method == http.MethodPost && p == "/api/orchestration/rules":
		if !confirmed(r) {
			jsonOut(w, 428, map[string]any{"error": "Missing action confirmation header"})
			return true
		}
		var candidate map[string]any
		if err := decode(r, &candidate); err != nil {
			jsonOut(w, 400, map[string]any{"error": err.Error()})
			return true
		}
		payload, err := a.createManagerRule(candidate)
		a.managerResult(w, r, 201, payload, err)
	case r.Method == http.MethodDelete && strings.HasPrefix(p, "/api/orchestration/rules/"):
		if !confirmed(r) {
			jsonOut(w, 428, map[string]any{"error": "Missing action confirmation header"})
			return true
		}
		id := strings.TrimPrefix(p, "/api/orchestration/rules/")
		payload, err := a.removeManagerRule(id)
		a.managerResult(w, r, 200, payload, err)
	case r.Method == http.MethodGet && p == "/api/logs":
		tail, _ := strconv.Atoi(r.URL.Query().Get("tail"))
		if tail < 1 {
			tail = 150
		}
		if tail > 500 {
			tail = 500
		}
		service := r.URL.Query().Get("service")
		lines, err := dockerLogs(service, tail)
		a.managerResult(w, r, 200, map[string]any{"service": service, "lines": lines, "collectedAt": now()}, err)
	case r.Method == http.MethodPost && strings.HasPrefix(p, "/api/containers/"):
		if !confirmed(r) {
			jsonOut(w, 428, map[string]any{"error": "Missing action confirmation header"})
			return true
		}
		parts := strings.Split(strings.TrimPrefix(p, "/api/containers/"), "/")
		if len(parts) != 2 {
			jsonOut(w, 404, map[string]any{"error": "Not found"})
			return true
		}
		payload, err := dockerLifecycle(parts[0], parts[1])
		a.managerResult(w, r, 202, payload, err)
	default:
		return false
	}
	return true
}

func (a *App) managerSession(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jsonOut(w, 200, map[string]any{"authenticated": managerConsole.authenticated(r), "configured": len(managerConsole.hash) > 0})
	case http.MethodPost:
		var body map[string]any
		if err := decode(r, &body); err != nil {
			jsonOut(w, 400, map[string]any{"error": err.Error()})
			return
		}
		status, cookie, retry := managerConsole.login(mapString(body["password"]))
		if cookie != "" {
			w.Header().Set("Set-Cookie", cookie)
		}
		if retry > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
		}
		if status == 204 {
			w.WriteHeader(204)
		} else if status == 429 {
			jsonOut(w, status, map[string]any{"error": "Too many failed logins; try again later"})
		} else {
			jsonOut(w, status, map[string]any{"error": "Wrong password"})
		}
	case http.MethodDelete:
		managerConsole.logout(r)
		w.Header().Set("Set-Cookie", "ah_console=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
		jsonOut(w, 200, map[string]any{"authenticated": false})
	default:
		jsonOut(w, 405, map[string]any{"error": "Method not allowed"})
	}
}

func confirmed(r *http.Request) bool { return r.Header.Get("X-Arrowhead-Action") == "confirm" }

func (a *App) managerResult(w http.ResponseWriter, _ *http.Request, status int, payload any, err error) {
	if err != nil {
		jsonOut(w, 502, map[string]any{"error": err.Error()})
		return
	}
	jsonOut(w, status, payload)
}

func (a *App) managerJSON(method, endpoint string, body any) (map[string]any, error) {
	b, err := a.call(method, endpoint, body, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func (a *App) managerConsumers() (map[string]any, error) {
	services, err := a.registryQuery("service-instances")
	if err != nil {
		return nil, err
	}
	rules, rulesErr := a.managerRules()
	byInstance := map[string][]map[string]any{}
	if rulesErr == nil {
		for _, raw := range anySlice(rules["rules"]) {
			rule := object(raw)
			id := mapString(rule["serviceInstanceId"])
			byInstance[id] = append(byInstance[id], map[string]any{"consumer": rule["consumer"], "consumerCloud": "TestCloud", "via": fmt.Sprintf("SimpleStore rule (priority %v)", rule["priority"])})
		}
	}
	rows := []any{}
	for _, raw := range entries(services) {
		service := object(raw)
		provider := mapString(object(service["provider"])["name"])
		definition := mapString(object(service["serviceDefinition"])["name"])
		id := mapString(service["instanceId"])
		rows = append(rows, map[string]any{"provider": provider, "serviceDefinition": definition, "providerCloud": "TestCloud", "authorized": []any{}, "orchestrated": byInstance[id]})
	}
	errs := []any{}
	if rulesErr != nil {
		errs = append(errs, rulesErr.Error())
	}
	return map[string]any{"collectedAt": now(), "localCloud": "TestCloud", "errors": errs, "rows": rows}, nil
}

func (a *App) managerIntercloud() map[string]any {
	return map[string]any{"collectedAt": now(), "localCloud": "TestCloud", "neighbourClouds": []any{}, "neighbourError": nil, "relay": map[string]any{"gatekeeper": map[string]any{"connected": false, "error": "No relay configured"}, "gatetunnel": map[string]any{"connected": false, "error": "No relay configured"}}, "sessions": map[string]any{"consumerSessions": 0, "providerSessions": 0, "sessions": []any{}}, "producer": map[string]any{"status": "unavailable", "lastError": "No inter-cloud producer configured"}}
}

func (a *App) managerSysMonitor(r *http.Request) (map[string]any, error) {
	payload, err := a.managerJSON(http.MethodGet, env("SYSMONITOR_URL", "http://sysmonitor:8475")+"/sysmonitor/data", nil)
	if err != nil {
		return nil, err
	}
	records := entries(payload)
	grouped := map[string][]map[string]any{}
	for _, raw := range records {
		item := object(raw)
		system := mapString(item["sourceSystemName"])
		if system == "" {
			system = mapString(item["systemName"])
		}
		if system == "" {
			system = "Unknown"
		}
		grouped[system] = append(grouped[system], item)
	}
	systems := []any{}
	selected := r.URL.Query().Get("system")
	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)
	if selected == "" && len(names) > 0 {
		selected = names[0]
	}
	observations := []any{}
	for _, name := range names {
		list := grouped[name]
		latest := map[string]any{}
		last := ""
		for _, item := range list {
			typ := mapString(item["observationType"])
			if typ == "" {
				typ = "status"
			}
			source := mapString(item["sourceTime"])
			if source == "" {
				source = mapString(item["receivedAt"])
			}
			obs := map[string]any{"observationType": typ, "sourceTime": source, "value": item["value"], "quality": item["quality"]}
			latest[typ] = obs
			last = source
			if name == selected {
				observations = append(observations, obs)
			}
		}
		systems = append(systems, map[string]any{"systemName": name, "observationCount": len(list), "lastObservationTime": last, "latest": latest})
	}
	return map[string]any{"collectedAt": now(), "retentionDays": nil, "storedObservations": len(records), "systems": systems, "selectedSystem": selected, "observations": reverseAny(observations)}, nil
}

func (a *App) managerSysMonitorSubscriptions() (map[string]any, error) {
	payload, err := a.managerJSON(http.MethodGet, env("SYSMONITOR_URL", "http://sysmonitor:8475")+"/sysmonitor/management/subscriptions", nil)
	if err != nil {
		return nil, err
	}
	subs := []any{}
	for _, raw := range entries(payload) {
		item := object(raw)
		p := object(item["payload"])
		provider := mapString(p["providerSystem"])
		if provider == "" {
			provider = mapString(item["owner"])
		}
		subs = append(subs, map[string]any{"providerSystem": provider, "observationTypes": anySlice(p["observationTypes"]), "enabled": p["enabled"], "providerFound": false})
	}
	return map[string]any{"collectedAt": now(), "defaultSubscription": "none", "providers": []any{}, "subscriptions": subs, "intake": map[string]any{"connected": true, "queue": "native", "bindings": []any{}}}, nil
}

func (a *App) managerPlantDescriptions() (map[string]any, error) {
	payload, err := a.managerJSON(http.MethodGet, env("PLANT_DESCRIPTION_ENGINE_URL", "http://plantdescriptionengine:8432")+"/plant-description-engine", nil)
	if err != nil {
		return nil, err
	}
	descriptions := []any{}
	for _, raw := range entries(payload) {
		item := object(raw)
		if p := object(item["payload"]); len(p) > 0 {
			if p["id"] == nil {
				p["id"] = item["id"]
			}
			descriptions = append(descriptions, p)
		} else {
			descriptions = append(descriptions, item)
		}
	}
	systemsPayload, _ := a.registryQuery("systems")
	servicesPayload, _ := a.registryQuery("service-instances")
	systemNames := []string{}
	for _, raw := range entries(systemsPayload) {
		systemNames = append(systemNames, mapString(object(raw)["name"]))
	}
	sort.Strings(systemNames)
	services := []any{}
	for _, raw := range entries(servicesPayload) {
		svc := object(raw)
		interfaces := []string{}
		seen := map[string]bool{}
		for _, ir := range anySlice(svc["interfaces"]) {
			name := mapString(object(ir)["templateName"])
			if name != "" && !seen[name] {
				seen[name] = true
				interfaces = append(interfaces, name)
			}
		}
		services = append(services, map[string]any{"provider": object(svc["provider"])["name"], "serviceDefinition": object(svc["serviceDefinition"])["name"], "interfaces": interfaces})
	}
	return map[string]any{"collectedAt": now(), "entries": descriptions, "systems": systemNames, "services": services, "registryError": nil}, nil
}

func (a *App) managerPlantMutation(r *http.Request) (map[string]any, int, error) {
	var body map[string]any
	if r.Method != http.MethodDelete {
		if err := decode(r, &body); err != nil {
			return nil, 400, err
		}
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/plantdescriptions/")
	endpoint := env("PLANT_DESCRIPTION_ENGINE_URL", "http://plantdescriptionengine:8432") + "/plant-description-engine"
	if id != "" && id != "/api/plantdescriptions" {
		endpoint += "/" + url.PathEscape(id)
	}
	payload, err := a.managerJSON(r.Method, endpoint, body)
	if err != nil {
		return nil, 502, err
	}
	if r.Method == http.MethodDelete {
		return map[string]any{"removed": id}, 200, nil
	}
	if payload["id"] == nil && id != "" {
		payload["id"] = id
	}
	status := 200
	if r.Method == http.MethodPost {
		status = 201
	}
	return payload, status, nil
}

func (a *App) registryQuery(resource string) (map[string]any, error) {
	b, err := a.call(http.MethodPost, a.Config.RegistryURL+"/serviceregistry/mgmt/"+resource+"/query", map[string]any{}, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func entries(payload map[string]any) []any { v, _ := payload["entries"].([]any); return v }
func object(v any) map[string]any          { m, _ := v.(map[string]any); return m }

func (a *App) managerOverview() (map[string]any, error) {
	collected := now()
	systemsPayload, registryErr := a.registryQuery("systems")
	servicesPayload, serviceErr := a.registryQuery("service-instances")
	containers, dockerErr := listDockerContainers()
	if systemsPayload == nil {
		systemsPayload = map[string]any{"entries": []any{}, "count": 0}
	}
	if servicesPayload == nil {
		servicesPayload = map[string]any{"entries": []any{}, "count": 0}
	}
	services := entries(servicesPayload)
	counts := map[string]int{}
	for _, raw := range services {
		counts[mapString(object(object(raw)["provider"])["name"])]++
	}
	byService := map[string]runtimeContainer{}
	for _, c := range containers {
		byService[c.Service] = c
	}
	systems := make([]any, 0, len(entries(systemsPayload)))
	registeredCompose := map[string]bool{}
	for _, raw := range entries(systemsPayload) {
		s := object(raw)
		name := mapString(s["name"])
		compose := systemToCompose[name]
		registeredCompose[compose] = compose != ""
		out := cloneMap(s)
		out["composeService"] = nullable(compose)
		out["serviceCount"] = counts[name]
		if c, ok := byService[compose]; ok {
			out["runtime"] = containerMap(c)
		} else {
			out["runtime"] = nil
		}
		systems = append(systems, out)
	}
	running, unhealthy := 0, 0
	unregistered := []string{}
	for _, c := range containers {
		if c.State == "running" {
			running++
		}
		if c.Health == "unhealthy" {
			unhealthy++
		}
		if c.Managed && c.State == "running" && !registeredCompose[c.Service] {
			unregistered = append(unregistered, c.Service)
		}
	}
	sample := map[string]any{"at": collected, "running": running, "containers": len(containers), "registeredSystems": len(systems), "registeredServices": len(services), "unhealthy": unhealthy, "incidents": unhealthy + len(unregistered), "unregisteredServices": unregistered}
	managerHistoryMu.Lock()
	managerHistory = append(managerHistory, sample)
	if len(managerHistory) > 60 {
		managerHistory = managerHistory[len(managerHistory)-60:]
	}
	history := append([]map[string]any(nil), managerHistory...)
	managerHistoryMu.Unlock()
	registry := buildGoRegistryManagement(systems, services, containers)
	return map[string]any{
		"collectedAt": collected, "cloud": map[string]any{"name": env("COMPOSE_PROJECT_NAME", "arrowhead-v52-test-cloud-go"), "release": "5.2.2", "implementation": "go", "registryReachable": registryErr == nil && serviceErr == nil, "dockerReachable": dockerErr == nil},
		"summary": sample, "devices": []any{}, "systems": systems, "services": services, "registryManagement": registry,
		"naming": map[string]any{"valid": true, "violations": []any{}}, "infrastructure": []any{}, "orchestrations": []any{}, "containers": containerMaps(containers), "history": history,
		"registration": map[string]any{"registered": true, "instanceId": "LocalCloudManager|localCloudManagement|1.0.0", "error": nil, "checkedAt": collected},
		"errors":       map[string]any{"docker": errorText(dockerErr), "arrowhead": errorText(errors.Join(registryErr, serviceErr)), "naming": nil},
	}, nil
}

func buildGoRegistryManagement(systems, services []any, containers []runtimeContainer) map[string]any {
	byProvider := map[string][]any{}
	for _, raw := range services {
		name := mapString(object(object(raw)["provider"])["name"])
		byProvider[name] = append(byProvider[name], raw)
	}
	device := map[string]any{"name": "No registered device", "addresses": []any{}, "metadata": map[string]any{}, "registered": false, "systems": []any{}}
	groupSystems := []any{}
	deployedSystems, deployedServices := 0, 0
	registeredCompose := map[string]bool{}
	for _, raw := range systems {
		s := cloneMap(object(raw))
		name := mapString(s["name"])
		compose := mapString(s["composeService"])
		registeredCompose[compose] = compose != ""
		runtime := object(s["runtime"])
		deployed := mapString(runtime["state"]) == "running"
		if deployed {
			deployedSystems++
		}
		svcs := []any{}
		for _, svcRaw := range byProvider[name] {
			svc := cloneMap(object(svcRaw))
			svc["deployed"] = deployed
			svcs = append(svcs, svc)
			if deployed {
				deployedServices++
			}
		}
		s["deployed"], s["services"] = deployed, svcs
		groupSystems = append(groupSystems, s)
	}
	device["systems"], device["deployed"], device["serviceCount"] = groupSystems, deployedSystems > 0, len(services)
	runtimeOnly := []any{}
	for _, c := range containers {
		if c.Managed && !registeredCompose[c.Service] {
			runtimeOnly = append(runtimeOnly, map[string]any{"name": c.DisplayName, "composeService": c.Service, "deployed": c.State == "running", "runtime": containerMap(c), "registered": false, "services": []any{}})
		}
	}
	return map[string]any{"devices": []any{device}, "runtimeOnly": runtimeOnly, "summary": map[string]any{"registeredDevices": 0, "deployedDevices": 0, "registeredSystems": len(systems), "deployedSystems": deployedSystems, "registeredServices": len(services), "deployedServices": deployedServices, "runtimeOnly": len(runtimeOnly)}}
}

func (a *App) managerData(r *http.Request) (map[string]any, error) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit < 1 {
		limit = 240
	}
	if limit > 1000 {
		limit = 1000
	}
	b, err := a.call(http.MethodGet, env("DATAMANAGER_URL", "http://datamanager:8461")+"/datamanager/historian", nil, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	flat := []any{}
	for _, recordRaw := range entries(raw) {
		record := object(recordRaw)
		data, ok := record["data"].([]any)
		if !ok {
			continue
		}
		for _, datumRaw := range data {
			datum := cloneMap(object(datumRaw))
			if datum["name"] == nil {
				datum["name"] = datum["n"]
			}
			if datum["unit"] == nil {
				datum["unit"] = datum["u"]
			}
			if datum["time"] == nil {
				datum["time"] = time.Now().Unix()
			}
			if datum["value"] == nil {
				datum["value"] = map[string]any{"v": datum["v"], "vs": datum["vs"], "vb": datum["vb"]}
			}
			flat = append(flat, datum)
		}
	}
	if len(flat) > limit {
		flat = flat[len(flat)-limit:]
	}
	series := dataSeries(flat)
	return map[string]any{"collectedAt": now(), "count": len(flat), "latest": []any{}, "entries": reverseAny(flat), "series": series}, nil
}

func dataSeries(values []any) []any {
	byName := map[string][]any{}
	for _, raw := range values {
		e := object(raw)
		name := mapString(e["name"])
		value := object(e["value"])["v"]
		n, ok := number(value)
		if !ok || name == "" {
			continue
		}
		byName[name] = append(byName[name], map[string]any{"time": e["time"], "value": n, "unit": e["unit"]})
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	out := []any{}
	for _, name := range names {
		out = append(out, map[string]any{"name": name, "points": byName[name]})
	}
	return out
}

func (a *App) managerRules() (map[string]any, error) {
	systems, err := a.registryQuery("systems")
	if err != nil {
		return nil, err
	}
	services, err := a.registryQuery("service-instances")
	if err != nil {
		return nil, err
	}
	catalog := orchestrationCatalog(entries(systems), entries(services))
	b, err := a.call(http.MethodPost, env("SIMPLE_ORCHESTRATION_URL", "http://serviceorchestration-simple:8456")+"/serviceorchestration/orchestration/mgmt/simple-store/query", map[string]any{}, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
	if err != nil {
		return nil, err
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	rules := []any{}
	for _, item := range entries(raw) {
		resource := object(item)
		rule := cloneMap(object(resource["payload"]))
		if rule["id"] == nil {
			rule["id"] = resource["id"]
		}
		if rule["createdAt"] == nil {
			rule["createdAt"] = resource["createdAt"]
		}
		rules = append(rules, rule)
	}
	return map[string]any{"catalog": catalog, "rules": rules, "count": len(rules), "dynamic": []any{}, "dynamicError": nil, "collectedAt": now()}, nil
}

func orchestrationCatalog(systems, services []any) map[string]any {
	templates := map[string]map[string]bool{}
	for _, raw := range services {
		s := object(raw)
		provider := mapString(object(s["provider"])["name"])
		if templates[provider] == nil {
			templates[provider] = map[string]bool{}
		}
		for _, intfRaw := range anySlice(s["interfaces"]) {
			templates[provider][mapString(object(intfRaw)["templateName"])] = true
		}
	}
	consumers := []any{}
	consumerNames := []string{}
	consumerX509 := map[string]bool{}
	for _, raw := range systems {
		s := object(raw)
		name := mapString(s["name"])
		consumerNames = append(consumerNames, name)
		metadata := object(s["metadata"])
  if templates[name] == nil { templates[name] = map[string]bool{} }
  for _, template := range strings.Split(mapString(metadata["consumerInterfaceTemplates"]), ",") { if strings.TrimSpace(template) == "generic_https" { templates[name]["generic_https"] = true } }
  for key, value := range metadata {
			if strings.Contains(strings.ToLower(key), "x509") && mapString(value) != "" {
				consumerX509[name] = true
			}
		}
		ts := []string{}
		for t := range templates[name] {
			ts = append(ts, t)
		}
		sort.Strings(ts)
		consumers = append(consumers, map[string]any{"name": name, "version": s["version"], "x509": consumerX509[name], "interfaceTemplates": ts})
	}
	producers := []any{}
	for _, raw := range services {
		s := object(raw)
		provider := mapString(object(s["provider"])["name"])
		intfs := []any{}
		compatible := []string{}
		for _, intfRaw := range anySlice(s["interfaces"]) {
			intf := object(intfRaw)
			intfs = append(intfs, map[string]any{"templateName": intf["templateName"], "protocol": intf["protocol"], "policy": intf["policy"]})
		}
		for _, name := range consumerNames {
			if name == provider {
				continue
			}
			for _, intfRaw := range anySlice(s["interfaces"]) {
				intf := object(intfRaw)
				template := mapString(intf["templateName"])
				policy := strings.ToUpper(mapString(intf["policy"]))
				if templates[name][template] && (policy != "CERT_AUTH" || consumerX509[name]) {
					compatible = append(compatible, name)
					break
				}
			}
		}
		producers = append(producers, map[string]any{"instanceId": s["instanceId"], "provider": provider, "serviceDefinition": object(s["serviceDefinition"])["name"], "version": s["version"], "interfaces": intfs, "compatibleConsumers": compatible})
	}
	return map[string]any{"producers": producers, "consumers": consumers}
}

func (a *App) createManagerRule(candidate map[string]any) (map[string]any, error) {
	consumer := mapString(candidate["consumer"])
	instanceID := mapString(candidate["serviceInstanceId"])
	priority, priorityOK := number(candidate["priority"])
	if consumer == "" || instanceID == "" || !priorityOK || priority < 1 || priority != float64(int(priority)) {
		return nil, errors.New("Consumer, service instance and a positive integer priority are required")
	}
	current, err := a.managerRules()
	if err != nil {
		return nil, err
	}
	found, compatible := false, false
	for _, raw := range anySlice(object(current["catalog"])["producers"]) {
		producer := object(raw)
		if mapString(producer["instanceId"]) != instanceID {
			continue
		}
		found = true
		for _, value := range anySlice(producer["compatibleConsumers"]) {
			if mapString(value) == consumer {
				compatible = true
			}
		}
	}
	if !found {
		return nil, errors.New("The selected producer is no longer available")
	}
	if !compatible {
		return nil, errors.New("The selected consumer is not interoperable with this producer")
	}
	b, err := a.call(http.MethodPost, env("SIMPLE_ORCHESTRATION_URL", "http://serviceorchestration-simple:8456")+"/serviceorchestration/orchestration/mgmt/simple-store/create", candidate, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
	if err != nil {
		return nil, err
	}
	var out map[string]any
	err = json.Unmarshal(b, &out)
	return out, err
}

func (a *App) removeManagerRule(id string) (map[string]any, error) {
	endpoint := env("SIMPLE_ORCHESTRATION_URL", "http://serviceorchestration-simple:8456") + "/serviceorchestration/orchestration/mgmt/simple-store/remove?id=" + url.QueryEscape(id)
	_, err := a.call(http.MethodDelete, endpoint, nil, map[string]string{"Authorization": "Bearer SYSTEM//" + a.Config.SystemName})
	return map[string]any{"id": id, "removed": err == nil, "at": now()}, err
}

func dockerClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", env("DOCKER_SOCKET", "/var/run/docker.sock"))
	}}}
}

func dockerRequest(method, path string) ([]byte, int, error) {
	req, _ := http.NewRequest(method, "http://docker"+path, nil)
	res, err := dockerClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, res.StatusCode, err
	}
	if res.StatusCode >= 400 {
		return b, res.StatusCode, fmt.Errorf("Docker API %d: %s", res.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, res.StatusCode, nil
}

func listDockerContainers() ([]runtimeContainer, error) {
	project := env("COMPOSE_PROJECT_NAME", "arrowhead-v52-test-cloud-go")
	filter, _ := json.Marshal(map[string]any{"label": []string{"com.docker.compose.project=" + project}})
	b, _, err := dockerRequest(http.MethodGet, "/containers/json?all=1&filters="+url.QueryEscape(string(filter)))
	if err != nil {
		return nil, err
	}
	var rows []struct {
		ID                   string
		Names                []string
		Image, State, Status string
		Created              int64
		Labels               map[string]string
	}
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, err
	}
	managed := managedComposeServices()
	out := make([]runtimeContainer, 0, len(rows))
	for _, row := range rows {
		service := row.Labels["com.docker.compose.service"]
		health := ""
		for _, h := range []string{"healthy", "unhealthy", "starting"} {
			if strings.Contains(row.Status, "("+h+")") {
				health = h
			}
		}
		name := ""
		if len(row.Names) > 0 {
			name = strings.TrimPrefix(row.Names[0], "/")
		}
		display := service
		for system, compose := range systemToCompose {
			if compose == service {
				display = system
			}
		}
		out = append(out, runtimeContainer{row.ID[:min(12, len(row.ID))], name, service, display, row.Image, row.State, row.Status, health, time.Unix(row.Created, 0).UTC().Format(time.RFC3339), managed[service]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Service < out[j].Service })
	return out, nil
}

func dockerLogs(service string, tail int) ([]string, error) {
	containers, err := listDockerContainers()
	if err != nil {
		return nil, err
	}
	var found *runtimeContainer
	for i := range containers {
		if containers[i].Service == service {
			found = &containers[i]
			break
		}
	}
	if found == nil {
		return nil, errors.New("Unknown project service")
	}
	b, _, err := dockerRequest(http.MethodGet, "/containers/"+found.ID+"/logs?stdout=1&stderr=1&timestamps=1&tail="+strconv.Itoa(tail))
	if err != nil {
		return nil, err
	}
	text := demuxLogs(b)
	scanner := bufio.NewScanner(strings.NewReader(text))
	lines := []string{}
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if len(lines) > tail {
		lines = lines[len(lines)-tail:]
	}
	return lines, scanner.Err()
}

func demuxLogs(b []byte) string {
	out := strings.Builder{}
	for len(b) >= 8 {
		n := int(binary.BigEndian.Uint32(b[4:8]))
		if n < 0 || len(b) < 8+n {
			break
		}
		out.Write(b[8 : 8+n])
		b = b[8+n:]
	}
	if out.Len() == 0 {
		return strings.ReplaceAll(string(b), "\x00", "")
	}
	return strings.ReplaceAll(out.String(), "\x00", "")
}

func dockerLifecycle(service, action string) (map[string]any, error) {
	if !managedComposeServices()[service] {
		return nil, errors.New("This service is not in the management allowlist")
	}
	if action != "start" && action != "stop" && action != "restart" {
		return nil, errors.New("Unsupported lifecycle action")
	}
	containers, err := listDockerContainers()
	if err != nil {
		return nil, err
	}
	var id string
	for _, c := range containers {
		if c.Service == service {
			id = c.ID
		}
	}
	if id == "" {
		return nil, errors.New("Unknown project service")
	}
	suffix := "/" + action
	if action == "stop" || action == "restart" {
		suffix += "?t=20"
	}
	_, _, err = dockerRequest(http.MethodPost, "/containers/"+id+suffix)
	return map[string]any{"service": service, "action": action, "accepted": err == nil, "at": now()}, err
}

func containerMap(c runtimeContainer) map[string]any {
	return map[string]any{"id": c.ID, "name": c.Name, "service": c.Service, "displayName": c.DisplayName, "image": c.Image, "state": c.State, "status": c.Status, "health": nullable(c.Health), "created": c.Created, "managed": c.Managed}
}
func containerMaps(values []runtimeContainer) []any {
	out := make([]any, 0, len(values))
	for _, v := range values {
		out = append(out, containerMap(v))
	}
	return out
}
func cloneMap(in map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}
func errorText(err error) any {
	if err == nil {
		return nil
	}
	return err.Error()
}
func anySlice(v any) []any { out, _ := v.([]any); return out }
func reverseAny(v []any) []any {
	out := make([]any, len(v))
	for i := range v {
		out[len(v)-1-i] = v[i]
	}
	return out
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
