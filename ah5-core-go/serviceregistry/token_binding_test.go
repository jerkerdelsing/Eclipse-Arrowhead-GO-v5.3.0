package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"strings"
	"testing"
)

func withCert(cn string) *tls.ConnectionState {
	return &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}}}
}

func TestBindToCertificate(t *testing.T) {
	r := httptest.NewRequest("GET", "/serviceregistry/monitor/echo", nil)
	r.TLS = withCert("Blacklist.TestCloud.Company.arrowhead.eu")
	if err := bindToCertificate(r, "Blacklist"); err != nil {
		t.Fatalf("matching certificate refused: %v", err)
	}
	if err := bindToCertificate(r, "LocalCloudManager"); err == nil {
		t.Fatal("stolen token accepted from another certificate")
	}
	r.TLS = &tls.ConnectionState{}
	if err := bindToCertificate(r, "Blacklist"); err == nil {
		t.Fatal("token accepted over TLS without a client certificate")
	}
	r.TLS = nil
	if err := bindToCertificate(r, "Blacklist"); err != nil {
		t.Fatalf("plain HTTP should be left to the token: %v", err)
	}
}

func TestIsIdentityLookup(t *testing.T) {
	cases := map[string]bool{
		`{"serviceDefinitionNames":["identity"]}`:              true,
		`{"serviceDefinitionNames":["identity","sysMonitor"]}`: false,
		`{"serviceDefinitionNames":["serviceDiscovery"]}`:      false,
		`not json`: false,
	}
	for body, want := range cases {
		r := httptest.NewRequest("POST", "/serviceregistry/service-discovery/lookup", strings.NewReader(body))
		if got := isIdentityLookup(r); got != want {
			t.Errorf("%s: got %v, want %v", body, got, want)
		}
	}
	r := httptest.NewRequest("POST", "/serviceregistry/service-discovery/register", strings.NewReader(`{"serviceDefinitionNames":["identity"]}`))
	if isIdentityLookup(r) {
		t.Error("register must not be exempt")
	}
}
