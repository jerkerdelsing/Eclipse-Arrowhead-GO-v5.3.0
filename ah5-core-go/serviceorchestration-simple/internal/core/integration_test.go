// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testCloud struct {
	pki                                      *testPKI
	auth, authz, dynamic, simple             *App
	authURL, authzURL, dynamicURL, simpleURL string
	clients                                  map[string]*Remote
	policy                                   atomic.Value
}

func serveTLS(t *testing.T, p *testPKI, name string, handler http.Handler) *httptest.Server {
	t.Helper()
	s := httptest.NewUnstartedServer(handler)
	s.TLS = p.tls(p.cert(t, name, "sy"))
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}
func isolatedCloud(t *testing.T) *testCloud {
	t.Helper()
	p := newPKI(t)
	f := &testCloud{pki: p, clients: map[string]*Remote{}}
	f.policy.Store("CERT_AUTH")
	passwordPath := filepath.Join(t.TempDir(), "password")
	if e := os.WriteFile(passwordPath, []byte("test-password"), 0600); e != nil {
		t.Fatal(e)
	}
	f.auth = fixture(t, "authentication")
	f.auth.Config.Name = "Authentication"
	authServer := serveTLS(t, p, "Authentication", f.auth)
	f.authURL = authServer.URL
	for _, name := range []string{"Sysop", "Consumer", "Provider", "Orchestrator", "SimpleOrchestrator", "ConsumerAuthorization"} {
		seed(t, f.auth, name, name == "Sysop")
	}
	makeApp := func(role, name string) *App {
		a := fixture(t, role)
		a.Config.Name = name
		a.Config.PasswordFile = passwordPath
		a.Config.AuthenticationURL = f.authURL
		a.Config.ManagementWhitelist = []string{"Orchestrator"}
		a.TLS = p.tls(p.cert(t, name, "sy"))
		a.Remote = NewRemote(a.Config, a.TLS)
		return a
	}
	f.authz = makeApp("consumer-authorization", "ConsumerAuthorization")
	f.authzURL = serveTLS(t, p, "ConsumerAuthorization", f.authz).URL
	registry := serveTLS(t, p, "ServiceRegistry", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/serviceregistry/service-discovery/lookup" || r.Header.Get("Authorization") == "" {
			respond(w, 400, Document{})
			return
		}
		respond(w, 200, Document{"entries": []Document{{"instanceId": "Provider|temperature|1.0.0", "provider": Document{"name": "Provider"}, "serviceDefinition": Document{"name": "temperature"}, "version": "1.0.0", "metadata": Document{}, "interfaces": []Document{{"templateName": "generic_https", "protocol": "https", "policy": f.policy.Load(), "properties": Document{"operations": Document{"read": Document{"method": "GET", "path": "/"}}}}}}}, "count": 1})
	}))
	f.dynamic = makeApp("serviceorchestration-dynamic", "Orchestrator")
	f.dynamic.Config.ServiceRegistryURL = registry.URL
	f.dynamic.Config.AuthorizationURL = f.authzURL
	f.dynamic.Remote = NewRemote(f.dynamic.Config, f.dynamic.TLS)
	f.dynamicURL = serveTLS(t, p, "Orchestrator", f.dynamic).URL
	f.simple = makeApp("serviceorchestration-simple", "SimpleOrchestrator")
	f.simpleURL = serveTLS(t, p, "SimpleOrchestrator", f.simple).URL
	for _, name := range []string{"Sysop", "Consumer", "Provider"} {
		cfg := Config{Name: name, CloudSuffix: testSuffix, PasswordFile: passwordPath, AuthenticationURL: f.authURL, AuthorizationURL: f.authzURL}
		f.clients[name] = NewRemote(cfg, p.tls(p.cert(t, name, "sy")))
	}
	return f
}
func (f *testCloud) call(t *testing.T, name, provider, base, method, path string, body any) Document {
	t.Helper()
	c := f.clients[name]
	token, e := c.ownToken(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	var out Document
	e = c.request(context.Background(), provider, base, method, path, token, body, &out)
	if e != nil {
		t.Fatalf("%s %s: %v", method, path, e)
	}
	return out
}
func (f *testCloud) grant(t *testing.T) {
	t.Helper()
	f.call(t, "Provider", "ConsumerAuthorization", f.authzURL, "POST", "/consumerauthorization/authorization/grant", Document{"targetType": "SERVICE_DEF", "target": "temperature", "defaultPolicy": Document{"policyType": "WHITELIST", "policyList": []string{"Consumer"}}})
}
func TestIsolatedMTLSCoreFlow(t *testing.T) {
	f := isolatedCloud(t)
	f.grant(t)
	// Signed identity tokens are not needed: Java-compatible UUID sessions are verified over pinned mTLS.
	c := f.clients["Consumer"]
	var decision bool
	e := c.Call(context.Background(), "authorization", "POST", "/consumerauthorization/authorization/verify", Document{"provider": "Provider", "targetType": "SERVICE_DEF", "target": "temperature"}, &decision)
	if e != nil || !decision {
		t.Fatal(decision, e)
	}
	tokenResult := f.call(t, "Consumer", "ConsumerAuthorization", f.authzURL, "POST", "/consumerauthorization/authorization-token/generate", Document{"provider": "Provider", "targetType": "SERVICE_DEF", "target": "temperature", "tokenVariant": "TIME_LIMITED_TOKEN_AUTH"})
	v := f.call(t, "Provider", "ConsumerAuthorization", f.authzURL, "GET", "/consumerauthorization/authorization-token/token/verify/"+url.PathEscape(str(tokenResult, "token")), nil)
	if !flag(v, "verified") || str(v, "consumer") != "Consumer" {
		t.Fatal(v)
	}
	pull := Document{"serviceRequirement": Document{"serviceDefinition": "temperature"}, "orchestrationFlags": Document{"MATCHMAKING": true}, "exclusivityDuration": float64(10)}
	result := f.call(t, "Consumer", "Orchestrator", f.dynamicURL, "POST", "/serviceorchestration/orchestration/pull", pull)
	if len(list(result, "results")) != 1 {
		t.Fatal(result)
	}
	history := f.call(t, "Sysop", "Orchestrator", f.dynamicURL, "POST", "/serviceorchestration/orchestration/mgmt/history/query", Document{})
	if number(history, "count", 0) != 1 || str(list(history, "entries")[0].(map[string]any), "status") != "DONE" {
		t.Fatal(history)
	}
	// Exercise encrypted/opaque-token orchestration through the real Go authorization implementation.
	f.policy.Store("TIME_LIMITED_TOKEN_AUTH")
	result = f.call(t, "Consumer", "Orchestrator", f.dynamicURL, "POST", "/serviceorchestration/orchestration/pull", pull)
	entry := list(result, "results")[0].(map[string]any)
	if len(obj(entry, "authorizationTokens")) != 1 {
		t.Fatal(result)
	}
	// Management deny at MGMT level wins over the provider's grant.
	f.call(t, "Sysop", "ConsumerAuthorization", f.authzURL, "POST", "/consumerauthorization/authorization/mgmt/grant", Document{"list": []Document{{"provider": "Provider", "targetType": "SERVICE_DEF", "target": "temperature", "defaultPolicy": Document{"policyType": "WHITELIST", "policyList": []string{}}}}})
	decision = true
	e = c.Call(context.Background(), "authorization", "POST", "/consumerauthorization/authorization/verify", Document{"provider": "Provider", "targetType": "SERVICE_DEF", "target": "temperature"}, &decision)
	if e != nil || decision {
		t.Fatal(decision, e)
	}
}
func TestUsageLimitedVerificationConcurrentMTLS(t *testing.T) {
	f := isolatedCloud(t)
	f.grant(t)
	result := f.call(t, "Consumer", "ConsumerAuthorization", f.authzURL, "POST", "/consumerauthorization/authorization-token/generate", Document{"provider": "Provider", "targetType": "SERVICE_DEF", "target": "temperature", "tokenVariant": "USAGE_LIMITED_TOKEN_AUTH"})
	client := f.clients["Provider"]
	var successes atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var v Document
			e := client.Call(context.Background(), "authorization", "GET", "/consumerauthorization/authorization-token/token/verify/"+url.PathEscape(str(result, "token")), nil, &v)
			if e != nil {
				t.Error(e)
			}
			if flag(v, "verified") {
				successes.Add(1)
			}
		}()
	}
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatal("expected exactly one successful verification", successes.Load())
	}
}
func TestSimpleStoreHTTPAndPushDelivery(t *testing.T) {
	f := isolatedCloud(t)
	store := f.call(t, "Sysop", "SimpleOrchestrator", f.simpleURL, "POST", "/serviceorchestration/orchestration/mgmt/simple-store/create", Document{"candidates": []Document{{"consumer": "Consumer", "serviceInstanceId": "Provider|temperature|1.0.0", "priority": float64(1)}}})
	if number(store, "count", 0) != 1 {
		t.Fatal(store)
	}
	result := f.call(t, "Consumer", "SimpleOrchestrator", f.simpleURL, "POST", "/serviceorchestration/orchestration/pull", Document{})
	if len(list(result, "results")) != 1 {
		t.Fatal(result)
	}
	callback := make(chan Document, 1)
	target := serveTLS(t, f.pki, "Consumer", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var v Document
		d, e := decode(w, r)
		if e == nil {
			v = d
			callback <- v
		}
		w.WriteHeader(200)
	}))
	u, _ := url.Parse(target.URL)
	sub := f.call(t, "Sysop", "SimpleOrchestrator", f.simpleURL, "POST", "/serviceorchestration/orchestration/mgmt/push/subscribe", Document{"subscriptions": []Document{{"targetSystemName": "Consumer", "duration": float64(60), "orchestrationRequest": Document{}, "notifyInterface": Document{"protocol": "HTTPS", "properties": Document{"address": u.Hostname(), "port": u.Port(), "method": "POST", "path": "/notify"}}}}})
	if number(sub, "count", 0) != 1 {
		t.Fatal(sub)
	}
	id := str(list(sub, "entries")[0].(map[string]any), "id")
	trigger := f.call(t, "Sysop", "SimpleOrchestrator", f.simpleURL, "POST", "/serviceorchestration/orchestration/mgmt/push/trigger", Document{"subscriptionIds": []string{id}})
	if len(list(trigger, "jobs")) != 1 {
		t.Fatal(trigger)
	}
	f.simple.processPush(context.Background())
	select {
	case v := <-callback:
		if len(list(v, "results")) != 1 {
			t.Fatal(v)
		}
	case <-time.After(time.Second):
		t.Fatal("callback not delivered")
	}
}
func TestScopedPolicyPrecedence(t *testing.T) {
	a := fixture(t, "consumer-authorization")
	r := httptest.NewRequest("POST", "/", nil)
	base := Document{"provider": "Provider", "consumer": "Consumer", "cloud": "LOCAL", "targetType": "SERVICE_DEF", "target": "temperature"}
	_ = a.Store.Update(func(d database) error {
		_, _, e := grantRow(d, Document{"provider": "Provider", "cloud": "LOCAL", "targetType": "SERVICE_DEF", "target": "temperature", "defaultPolicy": Document{"policyType": "ALL"}, "scopedPolicies": Document{"read": Document{"policyType": "WHITELIST", "policyList": []any{"Other"}}}}, "PROVIDER", "Provider")
		return e
	})
	yes, e := a.granted(r, base)
	if e != nil || yes {
		t.Fatal("all scopes must pass", yes, e)
	}
	base["scope"] = "write"
	yes, e = a.granted(r, base)
	if e != nil || !yes {
		t.Fatal("default fallback failed", yes, e)
	}
	base["scope"] = "read"
	yes, e = a.granted(r, base)
	if e != nil || yes {
		t.Fatal(yes, e)
	}
}

func TestInterCloudOrchestrationThroughGatekeeper(t *testing.T) {
	f := isolatedCloud(t)
	var negotiations atomic.Int32
	refuse := atomic.Bool{}
	gatekeeper := serveTLS(t, f.pki, "Gatekeeper", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in Document
		_ = json.NewDecoder(r.Body).Decode(&in)
		if r.Header.Get("Authorization") == "" || str(in, "consumerSystem") != "Consumer" {
			respond(w, 403, Document{})
			return
		}
		switch r.URL.Path {
		case "/gatekeeper/init_gsd":
			respond(w, 200, Document{"results": []Document{{"cloud": "TestCloud", "providerName": "RemoteProvider"}}})
		case "/gatekeeper/init_icn":
			negotiations.Add(1)
			if refuse.Load() {
				respond(w, 200, Document{"negotiated": false, "reason": "not authorized"})
				return
			}
			respond(w, 200, Document{"negotiated": true, "providerCloud": "TestCloud|Company", "providerName": "RemoteProvider", "serviceDefinition": "temperature", "version": "1.0.0",
				"interface": Document{"templateName": "generic_https", "protocol": "https", "policy": "CERT_AUTH", "properties": Document{"accessAddresses": []string{"gatetunnel"}, "accessPort": 8001, "basePath": "/temperature", "operations": Document{"read": Document{"method": "GET", "path": "/"}}}}})
		default:
			respond(w, 404, Document{})
		}
	}))
	pull := func(flags Document) Document {
		return f.call(t, "Consumer", "Orchestrator", f.dynamicURL, "POST", "/serviceorchestration/orchestration/pull", Document{"serviceRequirement": Document{"serviceDefinition": "temperature", "operations": []string{"read"}}, "orchestrationFlags": flags})
	}
	// no Gatekeeper configured: empty result with a warning, not an error
	if res := pull(Document{"ONLY_INTERCLOUD": true}); len(list(res, "results")) != 0 || !contains(list(res, "warnings"), "interCloudDisabled") {
		t.Fatal(res)
	}
	f.dynamic.Config.GatekeeperURL = gatekeeper.URL
	f.dynamic.Remote = NewRemote(f.dynamic.Config, f.dynamic.TLS)
	res := pull(Document{"ONLY_INTERCLOUD": true})
	results := list(res, "results")
	if len(results) != 1 {
		t.Fatal(res)
	}
	first := results[0].(map[string]any)
	intf := list(first, "interfaces")[0].(map[string]any)
	if str(first, "cloudIdentitifer") != "TestCloud|Company" || str(first, "providerName") != "RemoteProvider" || list(obj(intf, "properties"), "accessAddresses")[0] != "gatetunnel" {
		t.Fatal(first)
	}
	// ALLOW_INTERCLOUD: no local grant -> falls back to the neighbour cloud; with a local grant -> local result only
	before := negotiations.Load()
	if res = pull(Document{"ALLOW_INTERCLOUD": true}); len(list(res, "results")) != 1 || negotiations.Load() != before+1 {
		t.Fatal("no inter-cloud fallback", res)
	}
	f.grant(t)
	before = negotiations.Load()
	res = pull(Document{"ALLOW_INTERCLOUD": true})
	if len(list(res, "results")) != 1 || str(list(res, "results")[0].(map[string]any), "cloudIdentitifer") != "LOCAL" || negotiations.Load() != before {
		t.Fatal("local provider not preferred", res)
	}
	refuse.Store(true)
	if res = pull(Document{"ONLY_INTERCLOUD": true}); len(list(res, "results")) != 0 {
		t.Fatal("refused negotiation returned a result", res)
	}
}

func TestMonitorRegistrationAndBrokerURL(t *testing.T) {
	f := isolatedCloud(t)
	var offer atomic.Value
	registry := serveTLS(t, f.pki, "ServiceRegistry", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in Document
		_ = json.NewDecoder(r.Body).Decode(&in)
		if str(in, "serviceDefinitionName") == "sysMonitor" {
			offer.Store(in)
		}
		respond(w, 201, Document{})
	}))
	a := f.dynamic
	a.Config.ServiceRegistryURL = registry.URL
	a.Config.AdvertiseAddress, a.Config.AdvertisePort = "orchestrator", 8441
	a.Config.MonitorEnabled, a.Config.AMQPURL = true, "amqps://amqp-broker:5671"
	a.Config.CloudSuffix = testSuffix
	a.Remote = NewRemote(a.Config, a.TLS)
	if e := a.Register(context.Background()); e != nil {
		t.Fatal(e)
	}
	got, _ := offer.Load().(Document)
	intf := list(got, "interfaces")[0].(map[string]any)
	props := obj(intf, "properties")
	if str(intf, "templateName") != "generic_amqps" || str(props, "baseRoutingKey") != strings.Split(testSuffix, ".")[0]+".sysmonitor.Orchestrator.Orchestrator" || number(props, "accessPort", 0) != 5671 {
		t.Fatal(got)
	}
	for _, bad := range []string{"amqp://amqp-broker:5672", "amqps://user:pw@amqp-broker:5671", "amqps://:99999"} {
		a.Config.AMQPURL = bad
		if _, _, e := a.amqpEndpoint(); e == nil {
			t.Fatal("broker URL accepted:", bad)
		}
	}
}

func TestCoreManagementAuthorizationPolicy(t *testing.T) {
	f := isolatedCloud(t)
	f.call(t, "Sysop", "ConsumerAuthorization", f.authzURL, "POST", "/consumerauthorization/authorization/mgmt/grant", Document{"list": []Document{{"provider": "Orchestrator", "targetType": "SERVICE_DEF", "target": "serviceOrchestrationHistoryManagement", "defaultPolicy": Document{"policyType": "WHITELIST", "policyList": []string{"Other"}}, "scopedPolicies": Document{"query": Document{"policyType": "WHITELIST", "policyList": []string{"Consumer"}}}}}})
	c := f.clients["Consumer"]
	token, e := c.ownToken(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	status := func(path string) int {
		var out Document
		e := c.request(context.Background(), "Orchestrator", f.dynamicURL, "POST", path, token, Document{}, &out)
		var ae *APIError
		if errors.As(e, &ae) {
			return ae.Status
		}
		if e != nil {
			t.Fatal(e)
		}
		return 200
	}
	if s := status("/serviceorchestration/orchestration/mgmt/history/query"); s != 403 {
		t.Fatal("whitelist policy: non-whitelisted caller allowed", s)
	}
	f.dynamic.Config.ManagementPolicy = "authorization"
	if s := status("/serviceorchestration/orchestration/mgmt/history/query"); s != 200 {
		t.Fatal("authorization policy: granted operation refused", s)
	}
	if s := status("/serviceorchestration/orchestration/mgmt/lock/query"); s != 403 {
		t.Fatal("authorization policy: ungranted operation allowed", s)
	}
}

func TestPushByProxyDeliversToSubscriber(t *testing.T) {
	f := isolatedCloud(t)
	f.call(t, "Sysop", "SimpleOrchestrator", f.simpleURL, "POST", "/serviceorchestration/orchestration/mgmt/simple-store/create", Document{"candidates": []Document{{"consumer": "Consumer", "serviceInstanceId": "Provider|temperature|1.0.0", "priority": float64(1)}}})
	f.simple.Config.ManagementWhitelist = []string{"Provider"}
	deliver := func(callbackIdentity string) bool {
		got := make(chan bool, 1)
		srv := serveTLS(t, f.pki, callbackIdentity, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got <- true; w.WriteHeader(200) }))
		u, _ := url.Parse(srv.URL)
		sub := f.call(t, "Provider", "SimpleOrchestrator", f.simpleURL, "POST", "/serviceorchestration/orchestration/mgmt/push/subscribe", Document{"subscriptions": []Document{{"targetSystemName": "Consumer", "duration": float64(60), "orchestrationRequest": Document{}, "notifyInterface": Document{"protocol": "HTTPS", "properties": Document{"address": u.Hostname(), "port": u.Port(), "method": "POST", "path": "/result"}}}}})
		id := str(list(sub, "entries")[0].(map[string]any), "id")
		f.call(t, "Provider", "SimpleOrchestrator", f.simpleURL, "POST", "/serviceorchestration/orchestration/mgmt/push/trigger", Document{"subscriptionIds": []string{id}})
		f.simple.processPush(context.Background())
		select {
		case <-got:
			return true
		case <-time.After(time.Second):
			return false
		}
	}
	if !deliver("Provider") {
		t.Fatal("proxy subscription result not delivered to the subscriber")
	}
	if deliver("Consumer") {
		t.Fatal("proxy subscription result delivered to an endpoint with the target's identity")
	}
}
