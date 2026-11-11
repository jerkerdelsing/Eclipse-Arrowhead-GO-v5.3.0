package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

func TestAuthorityServiceRegistrationReserved(t *testing.T) {
	e := newEnv(t, nil)
	status, body := e.do("POST", "/serviceregistry/system-discovery/register", "AuditClient", map[string]any{"version": "1.0.0", "addresses": []string{"localhost"}})
	expect(t, status, 201, body)
	status, body = e.do("POST", "/serviceregistry/service-discovery/register", "AuditClient", map[string]any{"serviceDefinitionName": "identity", "version": "1.0.0", "interfaces": []any{httpIface("localhost", 9999)}})
	expect(t, status, 403, body)
}

func TestAuthorityProviderSubstitutionRejected(t *testing.T) {
	e := newEnv(t, nil)
	var calls atomic.Int32
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte(`{"verified":true,"systemName":"AuditClient","sysop":true}`))
	}))
	defer fake.Close()
	host, portText, _ := net.SplitHostPort(fake.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)
	// A malicious legacy registration already persisted before the fix must not
	// be selected, even if it is the only identity service in the snapshot.
	e.rg.store.Update(func(st *state) error {
		st.Instances["fake"] = &Instance{System: "AuditClient", Definition: identitySvcDef, Interfaces: []InstanceInterface{{Template: "generic_http", Properties: Meta{"accessAddresses": []any{host}, "accessPort": port, "basePath": "/identity", "operations": map[string]any{"identity-verify": map[string]any{"method": "GET", "path": "/verify"}}}}}}
		return nil
	})
	e.cfg.AuthenticationPolicy = "outsourced"
	auth := NewAuthenticator(e.cfg, e.rg, NewLogger(20), nil)
	auth.token = "fixture"
	req := httptest.NewRequest("POST", "/serviceregistry/mgmt/systems/query", nil)
	req.TLS = withCert("AuditClient.GoCloud.Company.arrowhead.eu")
	req.Header.Set("Authorization", "Bearer IDENTITY-TOKEN//forged")
	if _, _, err := auth.authOutsourced(req); err == nil {
		t.Fatal("substituted identity provider granted access")
	}
	if calls.Load() != 0 {
		t.Fatal("untrusted verifier contacted")
	}
}
