package cloud

import (
	"net"
	"net/http"
	"strings"
)

func address(v string) Address {
	t := "HOSTNAME"
	if ip := net.ParseIP(v); ip != nil {
		if ip.To4() != nil {
			t = "IPV4"
		} else {
			t = "IPV6"
		}
	}
	return Address{Type: t, Address: v}
}

func (a *App) registryHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.Contains(r.URL.Path, "/mgmt/") {
		if _, err := a.manager(r); err != nil {
			apiError(w, http.StatusForbidden, err.Error(), r.URL.Path)
			return
		}
	} else if _, err := a.requester(r); err != nil {
		apiError(w, http.StatusUnauthorized, err.Error(), r.URL.Path)
		return
	}
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/serviceregistry/system-discovery/register":
		a.registerSystem(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/serviceregistry/system-discovery/lookup":
		a.lookupSystems(w, r)
	case r.Method == http.MethodDelete && r.URL.Path == "/serviceregistry/system-discovery/revoke":
		a.revokeSystem(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/serviceregistry/service-discovery/register":
		a.registerService(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/serviceregistry/service-discovery/lookup":
		a.lookupServices(w, r)
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/serviceregistry/service-discovery/revoke/"):
		a.revokeService(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/serviceregistry/mgmt/systems/query":
		a.lookupSystems(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/serviceregistry/mgmt/service-instances/query":
		a.lookupServices(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/serviceregistry/mgmt/service-definitions/query":
		a.queryDefinitions(w)
	case r.Method == http.MethodGet && r.URL.Path == "/serviceregistry/general/mgmt/config":
		jsonOut(w, 200, map[string]any{"systemName": a.Config.SystemName, "version": "5.2.2", "implementation": "go"})
	default:
		apiError(w, 404, "No such ServiceRegistry operation", r.URL.Path)
	}
}

func (a *App) registerSystem(w http.ResponseWriter, r *http.Request) {
	name, _ := a.requester(r)
	var req map[string]any
	if err := decode(r, &req); err != nil {
		apiError(w, 400, err.Error(), r.URL.Path)
		return
	}
	if n := mapString(req["name"]); n != "" {
		if a.Config.Secure && n != name {
			apiError(w, 403, "cannot register another system identity", r.URL.Path)
			return
		}
		name = n
	}
	if name == "" {
		apiError(w, 400, "system name is empty", r.URL.Path)
		return
	}
	version := mapString(req["version"])
	if version == "" {
		version = "1.0.0"
	}
	var addrs []Address
	if xs, ok := req["addresses"].([]any); ok {
		for _, x := range xs {
			if s, ok := x.(string); ok {
				addrs = append(addrs, address(s))
			}
		}
	}
	meta, _ := req["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	a.Store.mu.Lock()
	old, ok := a.Store.Data.Systems[name]
	created := now()
	if ok {
		created = old.CreatedAt
	}
	sys := System{Name: name, Metadata: meta, Version: version, Addresses: addrs, CreatedAt: created, UpdatedAt: now()}
	a.Store.Data.Systems[name] = sys
	err := a.Store.SaveLocked()
	a.Store.mu.Unlock()
	if err != nil {
		apiError(w, 500, err.Error(), r.URL.Path)
		return
	}
	jsonOut(w, 200, sys)
}

func (a *App) lookupSystems(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := decode(r, &req); err != nil {
		apiError(w, 400, err.Error(), r.URL.Path)
		return
	}
	names := stringSlice(req["systemNames"])
	if len(names) == 0 {
		names = stringSlice(req["names"])
	}
	a.Store.mu.RLock()
	out := []System{}
	for _, k := range sortedKeys(a.Store.Data.Systems) {
		v := a.Store.Data.Systems[k]
		if containsFold(names, v.Name) {
			out = append(out, v)
		}
	}
	a.Store.mu.RUnlock()
	jsonOut(w, 200, listResponse(out))
}

func (a *App) revokeSystem(w http.ResponseWriter, r *http.Request) {
	name, _ := a.requester(r)
	if q := r.URL.Query().Get("name"); q != "" {
		if a.Config.Secure && q != name {
			apiError(w, 403, "cannot revoke another system identity", r.URL.Path)
			return
		}
		name = q
	}
	a.Store.mu.Lock()
	delete(a.Store.Data.Systems, name)
	for id, s := range a.Store.Data.Services {
		if strings.EqualFold(s.Provider.Name, name) {
			delete(a.Store.Data.Services, id)
		}
	}
	err := a.Store.SaveLocked()
	a.Store.mu.Unlock()
	if err != nil {
		apiError(w, 500, err.Error(), r.URL.Path)
		return
	}
	w.WriteHeader(204)
}

func (a *App) registerService(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := decode(r, &req); err != nil {
		apiError(w, 400, err.Error(), r.URL.Path)
		return
	}
	provider := mapString(req["systemName"])
	if provider == "" {
		provider, _ = a.requester(r)
	}
	if a.Config.Secure {
		caller, _ := a.requester(r)
		if provider != caller {
			apiError(w, 403, "provider must be the authenticated caller", r.URL.Path)
			return
		}
	}
	defName := mapString(req["serviceDefinitionName"])
	if a.Config.Secure && defName == "identity" && provider != "Authentication" {
		apiError(w, 403, "identity service is reserved for Authentication", r.URL.Path)
		return
	}
	if defName == "" {
		apiError(w, 400, "serviceDefinitionName is empty", r.URL.Path)
		return
	}
	version := mapString(req["version"])
	if version == "" {
		version = "1.0.0"
	}
	a.Store.mu.Lock()
	sys, ok := a.Store.Data.Systems[provider]
	if !ok {
		a.Store.mu.Unlock()
		apiError(w, 400, "provider system is not registered", r.URL.Path)
		return
	}
	t := now()
	def, ok := a.Store.Data.Definitions[defName]
	if !ok {
		def = Definition{Name: defName, CreatedAt: t, UpdatedAt: t}
		a.Store.Data.Definitions[defName] = def
	}
	meta, _ := req["metadata"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	interfaces := []Interface{}
	if raw, ok := req["interfaces"].([]any); ok {
		for _, entry := range raw {
			m, _ := entry.(map[string]any)
			props, _ := m["properties"].(map[string]any)
			interfaces = append(interfaces, Interface{TemplateName: mapString(m["templateName"]), Protocol: mapString(m["protocol"]), Policy: mapString(m["policy"]), Properties: props})
		}
	}
	id := provider + "|" + defName + "|" + version
	old, exists := a.Store.Data.Services[id]
	created := t
	if exists {
		created = old.CreatedAt
	}
	svc := Service{InstanceID: id, Provider: sys, ServiceDefinition: def, Version: version, Metadata: meta, Interfaces: interfaces, CreatedAt: created, UpdatedAt: t}
	a.Store.Data.Services[id] = svc
	err := a.Store.SaveLocked()
	a.Store.mu.Unlock()
	if err != nil {
		apiError(w, 500, err.Error(), r.URL.Path)
		return
	}
	jsonOut(w, 200, svc)
}

func (a *App) lookupServices(w http.ResponseWriter, r *http.Request) {
	var req map[string]any
	if err := decode(r, &req); err != nil {
		apiError(w, 400, err.Error(), r.URL.Path)
		return
	}
	defs := stringSlice(req["serviceDefinitionNames"])
	providers := stringSlice(req["providerNames"])
	ids := stringSlice(req["instanceIds"])
	a.Store.mu.RLock()
	out := []Service{}
	for _, k := range sortedKeys(a.Store.Data.Services) {
		v := a.Store.Data.Services[k]
		if containsFold(defs, v.ServiceDefinition.Name) && containsFold(providers, v.Provider.Name) && containsFold(ids, v.InstanceID) {
			out = append(out, v)
		}
	}
	a.Store.mu.RUnlock()
	jsonOut(w, 200, listResponse(out))
}

func (a *App) revokeService(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/serviceregistry/service-discovery/revoke/")
	a.Store.mu.Lock()
	delete(a.Store.Data.Services, id)
	err := a.Store.SaveLocked()
	a.Store.mu.Unlock()
	if err != nil {
		apiError(w, 500, err.Error(), r.URL.Path)
		return
	}
	w.WriteHeader(204)
}

func (a *App) queryDefinitions(w http.ResponseWriter) {
	a.Store.mu.RLock()
	out := []Definition{}
	for _, k := range sortedKeys(a.Store.Data.Definitions) {
		out = append(out, a.Store.Data.Definitions[k])
	}
	a.Store.mu.RUnlock()
	jsonOut(w, 200, listResponse(out))
}
