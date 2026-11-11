// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// J4: the core runtime refuses peers whose certificate is on the CRL, and fails closed without a current CRL.
func TestCheckPeerRevocation(t *testing.T) {
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "TestCloud.Company.arrowhead.eu"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	ca, _ := x509.ParseCertificate(caDER)
	leaf := func(serial int64) *x509.Certificate {
		k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tpl := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "Peer"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
		der, _ := x509.CreateCertificate(rand.Reader, tpl, ca, &k.PublicKey, caKey)
		c, _ := x509.ParseCertificate(der)
		return c
	}
	revoked, good := leaf(7), leaf(8)
	writeCRL := func(next time.Time) string {
		der, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: next,
			RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: big.NewInt(7), RevocationTime: time.Now()}}}, ca, caKey)
		if e != nil {
			t.Fatal(e)
		}
		path := filepath.Join(t.TempDir(), "ca.crl")
		_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), 0o600)
		return path
	}
	state := func(c *x509.Certificate) tls.ConnectionState {
		return tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c, ca}}}
	}
	current := writeCRL(time.Now().Add(time.Hour))
	if checkPeerRevocation(current, state(revoked)) == nil {
		t.Fatal("revoked certificate accepted")
	}
	if e := checkPeerRevocation(current, state(good)); e != nil {
		t.Fatalf("good certificate refused: %v", e)
	}
	if checkPeerRevocation(writeCRL(time.Now().Add(-time.Second)), state(good)) == nil {
		t.Fatal("expired CRL accepted")
	}
	if checkPeerRevocation(filepath.Join(t.TempDir(), "missing.crl"), state(good)) == nil {
		t.Fatal("missing CRL accepted")
	}
	if e := checkPeerRevocation("", state(revoked)); e != nil {
		t.Fatalf("no configured CRL must not refuse: %v", e)
	}
}

// J12: no Blacklist URL, Blacklist itself and excluded systems are never checked; an unreachable Blacklist refuses.
func TestCheckBlacklistScope(t *testing.T) {
	a := &App{Config: Config{Name: "ServiceOrchestration"}}
	if a.checkBlacklist(context.Background(), "Consumer") != nil {
		t.Fatal("filter active without blacklistURL")
	}
	a.Config.BlacklistURL = "https://127.0.0.1:1"
	a.Config.BlacklistExclude = []string{"ServiceRegistry"}
	a.Remote = NewRemote(a.Config, nil)
	for _, name := range []string{"Blacklist", "ServiceRegistry", "ServiceOrchestration"} {
		if a.checkBlacklist(context.Background(), name) != nil {
			t.Fatalf("%s must not be checked", name)
		}
	}
	if e := a.checkBlacklist(context.Background(), "Consumer"); e == nil {
		t.Fatal("unreachable Blacklist must refuse (fail closed)")
	}
	a.Config.BlacklistOptional = true
	a.Remote = NewRemote(a.Config, nil)
	if a.checkBlacklist(context.Background(), "Consumer") != nil {
		t.Fatal("blacklistOptional must let the request through")
	}
}
