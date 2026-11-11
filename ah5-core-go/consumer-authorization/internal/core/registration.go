// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

type Service struct {
	Definition string              `json:"serviceDefinition"`
	BasePath   string              `json:"basePath"`
	Operations map[string]Document `json:"operations"`
}

func service(def, path string, ops ...string) Service {
	s := Service{def, path, map[string]Document{}}
	for _, op := range ops {
		p := strings.SplitN(op, " ", 3)
		s.Operations[p[0]] = Document{"method": p[1], "path": p[2]}
	}
	return s
}
func (a *App) Services() []Service {
	out := []Service{service("generalManagement", a.base()+"/general/mgmt", "get-log POST /logs", "get-config GET /get-config")}
	switch a.Config.Role {
	case "authentication":
		out = append(out, service("identity", "/authentication/identity", "identity-login POST /login", "identity-logout POST /logout", "identity-change-credentials POST /change", "identity-verify GET /verify/{token}"), service("identityManagement", "/authentication/mgmt", "identity-mgmt-create POST /identities", "identity-mgmt-update PUT /identities", "identity-mgmt-remove DELETE /identities", "identity-mgmt-query POST /identities/query", "identity-mgmt-session-close DELETE /sessions", "identity-mgmt-session-query POST /sessions"))
	case "consumer-authorization":
		b := "/consumerauthorization/authorization"
		out = append(out, service("authorization", b, "grant POST /grant", "revoke DELETE /revoke/{instanceId}", "lookup POST /lookup", "verify POST /verify"), service("authorizationManagement", b+"/mgmt", "grant-policies POST /grant", "revoke-policies DELETE /revoke", "query-policies POST /query", "check-policies POST /check"), service("authorizationToken", "/consumerauthorization/authorization-token", "generate POST /generate", "verify GET /token/verify/{token}", "get-public-key GET /public-key", "register-encryption-key POST /encryption-key", "unregister-encryption-key DELETE /encryption-key"), service("authorizationTokenManagement", b+"/mgmt/token", "generate-tokens POST /generate", "query-tokens POST /query", "revoke-tokens DELETE /revoke", "add-encryption-keys POST /encryption-key", "remove-encryption-keys DELETE /encryption-key"))
	default:
		b := "/serviceorchestration/orchestration"
		out = append(out, service("serviceOrchestration", b, "pull POST /pull", "subscribe POST /subscribe", "unsubscribe DELETE /unsubscribe/{id}"), service("serviceOrchestrationPushManagement", b+"/mgmt/push", "subscribe POST /subscribe", "trigger POST /trigger", "unsubscribe DELETE /unsubscribe", "query POST /query"), service("serviceOrchestrationHistoryManagement", b+"/mgmt/history", "query POST /query"))
		if a.Config.Role == "serviceorchestration-simple" {
			out = append(out, service("serviceOrchestrationSimpleStoreManagement", b+"/mgmt/simple-store", "create POST /create", "query POST /query", "modify-priorities PUT /modify-priorities", "remove DELETE /remove"))
		} else {
			out = append(out, service("serviceOrchestrationPlantManagement", "/serviceorchestration/mgmt/plant-rules", "query POST /query", "replace PUT /replace"))
			out = append(out, service("serviceOrchestrationLockManagement", b+"/mgmt/lock", "create POST /create", "query POST /query", "remove DELETE /remove/{owner}"))
		}
	}
	return out
}
func (a *App) Register(ctx context.Context) error {
	if a.Config.AdvertiseAddress == "" || a.Config.AdvertisePort < 1 || a.Config.AdvertisePort > 65535 {
		return fmt.Errorf("registration requires advertiseAddress and advertisePort")
	}
	if e := a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/system-discovery/register", Document{"version": "5.2.2", "addresses": []string{a.Config.AdvertiseAddress}, "metadata": Document{"implementation": "Go"}}, nil); e != nil {
		return e
	}
	for _, s := range a.Services() {
		req := Document{"systemName": a.Config.Name, "serviceDefinitionName": s.Definition, "version": "1.0.0", "interfaces": []Document{{"templateName": "generic_https", "protocol": "https", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{a.Config.AdvertiseAddress}, "accessPort": a.Config.AdvertisePort, "basePath": s.BasePath, "operations": s.Operations}}}}
		if mi := a.mqttInterface(s); mi != nil {
			req["interfaces"] = append(req["interfaces"].([]Document), mi)
		}
		// Bootstrap services, discoverable under restricted Service Registry discovery as in the Java reference:
		// identity and orchestration before any authorization-backed choice, authorization and tokens for the
		// management filters and token checks of other systems.
		switch s.Definition {
		case "identity", "serviceOrchestration", "authorization", "authorizationToken":
			req["metadata"] = Document{"unrestrictedDiscovery": true}
		}
		if e := a.Remote.Call(ctx, "registry", "POST", "/serviceregistry/service-discovery/register", req, nil); e != nil {
			return fmt.Errorf("register %s: %w", s.Definition, e)
		}
	}
	if a.Config.MonitorEnabled {
		if e := a.registerMonitor(ctx); e != nil {
			return fmt.Errorf("register sysMonitor: %w", e)
		}
	}
	return nil
}
func (a *App) RunRegistration(ctx context.Context) {
	if !a.Config.Register {
		return
	}
	a.background.Add(1)
	go func() {
		defer a.background.Done()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			if e := a.Register(ctx); e != nil {
				log.Printf("%s registration unavailable (%T); retrying", a.Config.Role, e)
			}
			if a.Config.MonitorEnabled {
				deadline, cancel := context.WithTimeout(ctx, 10*time.Second)
				if e := a.publishMonitor(deadline); e != nil {
					log.Printf("%s monitoring publication failed: %v", a.Config.Role, e)
				}
				cancel()
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// contractOf returns the registered service definition and operation of a route (method and route pattern), for
// the authorization management policy; empty when the route is not part of a registered service.
func (a *App) contractOf(method, path string) (string, string) {
	for _, s := range a.Services() {
		for name, op := range s.Operations {
			if strings.EqualFold(str(op, "method"), method) && s.BasePath+str(op, "path") == path {
				return s.Definition, name
			}
		}
	}
	return "", ""
}
