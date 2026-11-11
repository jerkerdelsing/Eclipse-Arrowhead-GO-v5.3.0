package main

import (
	"net/http/httptest"
	"testing"
)

func TestV522ManagementAuthorizationTarget(t *testing.T) {
	for _, tc := range []struct{ method, path, target, scope string }{{"POST", "/serviceregistry/mgmt/systems/query", "serviceRegistryManagement", "system-query"}, {"GET", "/serviceregistry/general/mgmt/get-config", "generalManagement", "get-config"}, {"POST", "/unregistered", "", ""}} {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		target, scope := managementTarget(r)
		if target != tc.target || scope != tc.scope {
			t.Fatalf("%s %s: got %s %s", tc.method, tc.path, target, scope)
		}
	}
}
