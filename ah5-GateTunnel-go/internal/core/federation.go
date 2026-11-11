// SPDX-License-Identifier: EPL-2.0
package core

import (
	relay "arrowhead/ah5-support-go/gatetunnel/internal/relay"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

func (a *App) federationRoutes() {
	base := a.base()
	for _, r := range []struct{ method, path, access string }{{"GET", "/echo", "identity"}, {"POST", "/init_gsd", "identity"}, {"POST", "/init_multi_gsd", "identity"}, {"POST", "/init_icn", "identity"}, {"GET", "/mgmt/clouds", "management"}, {"POST", "/mgmt/clouds", "management"}, {"DELETE", "/mgmt/clouds/{operator}/{name}", "management"}, {"GET", "/mgmt/relays", "management"}, {"POST", "/mgmt/relays", "management"}, {"GET", "/publickey", "identity"}, {"POST", "/connect_provider", "identity"}, {"POST", "/connect_consumer", "identity"}, {"POST", "/close_sessions", "identity"}, {"GET", "/mgmt/sessions", "management"}, {"POST", "/mgmt/sessions/close", "management"}, {"POST", "/intercloud/provider", "identity"}, {"POST", "/intercloud/consumer", "identity"}, {"GET", "/mgmt/status", "management"}} {
		r := r
		if a.Config.Role == "Gatekeeper" && (strings.Contains(r.path, "session") || strings.Contains(r.path, "connect_") || strings.Contains(r.path, "publickey") || strings.Contains(r.path, "intercloud/")) {
			continue
		}
		if a.Config.Role == "GateTunnel" && (strings.Contains(r.path, "init_") || strings.Contains(r.path, "clouds") || strings.Contains(r.path, "relays")) {
			continue
		}
		a.route(r.method, base+r.path, r.access, func(w http.ResponseWriter, req *http.Request) (any, int, error) {
			if a.relayHandler == nil {
				return nil, 0, &APIError{503, "Federation is not enabled/configured"}
			}
			a.relayHandler.ServeHTTP(w, req)
			return nil, 0, nil
		})
	}
}
func (a *App) authenticateRequest(r *http.Request) (string, error) {
	p, e := certificateIdentity(r, a.Config.CloudSuffix)
	if e != nil {
		return "", e
	}
	prefix := "Bearer IDENTITY-TOKEN//"
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, prefix) {
		return "", forbidden()
	}
	token := strings.TrimPrefix(h, prefix)
	if len(token) > 128 || strings.ContainsAny(token, "/?#\r\n") {
		return "", forbidden()
	}
	var v Document
	if e = a.Remote.Call(r.Context(), "authentication", "GET", "/authentication/identity/verify/"+token, nil, &v); e != nil {
		return "", e
	}
	if !flag(v, "verified") || str(v, "systemName") != p.Name {
		return "", forbidden()
	}
	return p.Name, nil
}
func (a *App) startFederation(ctx context.Context) error {
	if a.Config.Role != "Gatekeeper" && a.Config.Role != "GateTunnel" {
		return nil
	}
	if !a.Config.FederationEnabled {
		return nil
	}
	parts := strings.Split(a.Config.CloudSuffix, ".")
	role := strings.ToLower(a.Config.Role)
	call := func(method, endpoint string, in any, _ map[string]string) ([]byte, error) {
		u, e := url.Parse(endpoint)
		if e != nil {
			return nil, e
		}
		provider, origin := "", ""
		for name, raw := range a.Config.Upstreams {
			p, e := url.Parse(raw)
			if e == nil && p.Scheme == u.Scheme && p.Host == u.Host {
				provider, origin = name, raw
				break
			}
		}
		for name, raw := range map[string]string{"Authentication": a.Config.AuthenticationURL, "ServiceRegistry": a.Config.ServiceRegistryURL, "ConsumerAuthorization": a.Config.AuthorizationURL} {
			p, e := url.Parse(raw)
			if e == nil && p.Scheme == u.Scheme && p.Host == u.Host {
				provider, origin = name, raw
			}
		}
		if provider == "" {
			return nil, errors.New("Relay endpoint is not an explicitly configured authority")
		}
		var out json.RawMessage
		e = a.Remote.callAt(ctx, provider, origin, method, u.RequestURI(), in, &out)
		return []byte(out), e
	}
	f, e := relay.New(relay.Config{Role: role, SystemName: a.Config.Name, Cloud: parts[0], Organization: parts[1], RegistryURL: a.Config.ServiceRegistryURL, Secure: true}, a.Config.State+".federation", a.TLS, call, a.authenticateRequest, func() (string, error) { return a.Remote.ownToken(ctx) }, a.Remote.client)
	if e != nil {
		return e
	}
	if e = f.Start(); e != nil {
		return e
	}
	a.relayHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// relay link and inter-cloud session status (the former plain-HTTP health document), over mTLS for management
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/mgmt/status") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.Status())
			return
		}
		if a.Config.Role == "Gatekeeper" {
			f.GatekeeperHTTP(w, r, caller(r).Name)
		} else {
			f.TunnelHTTP(w, r, caller(r).Name)
		}
	})
	a.background.Add(1)
	go func() { defer a.background.Done(); <-ctx.Done(); f.Close() }()
	return nil
}
