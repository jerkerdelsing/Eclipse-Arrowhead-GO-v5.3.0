package cloud

import (
	"bytes"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// AH-GT-1 (J5): wire compatibility with the reference implementation (testdata/ahgt1, made by
// ah5-support-java-spring/JavaSupportRuntime/src/test/resources/ahgt1/make_vector.py), key exchange verification,
// sealing, and replay protection.

const providerCN, consumerCN = "GateTunnel.GoCloud.Company.arrowhead.eu", "GateTunnel.TestCloud.Company.arrowhead.eu"

func vectorFixture(t *testing.T) (map[string]any, *sessionSecurity, *sessionSecurity) {
	t.Helper()
	dir := filepath.Join("testdata", "ahgt1")
	raw, err := os.ReadFile(filepath.Join(dir, "vector.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector map[string]any
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	// the reference vector's PKI has no CA keys left to issue CRLs; revocation is tested with testdata/ahgt1/revocation
	consumer, err := loadSessionIdentity(filepath.Join(dir, "TestCloud-relay.key"), filepath.Join(dir, "TestCloud-relay-chain.crt"), filepath.Join(dir, "org-ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	provider, err := loadSessionIdentity(filepath.Join(dir, "GoCloud-relay.key"), filepath.Join(dir, "GoCloud-relay-chain.crt"), filepath.Join(dir, "org-ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	consumer.revocation = noCRL
	provider.revocation = noCRL
	return vector, consumer, provider
}

func x25519Private(t *testing.T, v any) *ecdh.PrivateKey {
	raw, err := base64.StdEncoding.DecodeString(mapString(v))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func TestAHGT1VerifiesTheReferenceKeyExchange(t *testing.T) {
	vector, consumer, provider := vectorFixture(t)
	session, pe, ce := object(vector["session"]), object(vector["providerExchange"]), object(vector["consumerExchange"])
	if err := consumer.verifyPeer(pe["certificateChain"], providerCN, pe["signature"], ahgtTranscript("provider", session)); err != nil {
		t.Fatalf("reference provider exchange refused: %v", err)
	}
	if err := provider.verifyPeer(ce["certificateChain"], consumerCN, ce["signature"], ahgtTranscript("consumer", session)); err != nil {
		t.Fatalf("reference consumer exchange refused: %v", err)
	}
	if consumer.verifyPeer(pe["certificateChain"], consumerCN, pe["signature"], ahgtTranscript("provider", session)) == nil {
		t.Fatal("wrong peer name accepted")
	}
	tampered := map[string]any{}
	for k, v := range session {
		tampered[k] = v
	}
	tampered["provider"] = "OtherProvider"
	if consumer.verifyPeer(pe["certificateChain"], providerCN, pe["signature"], ahgtTranscript("provider", tampered)) == nil {
		t.Fatal("tampered transcript accepted")
	}
	// GoCloud's relay certificate under TestCloud's cross-certificate: wrong issuer and outside its name constraint
	goChain, _ := os.ReadFile(filepath.Join("testdata", "ahgt1", "GoCloud-relay-chain.crt"))
	testChain, _ := os.ReadFile(filepath.Join("testdata", "ahgt1", "TestCloud-relay-chain.crt"))
	end := "-----END CERTIFICATE-----\n"
	mixed := string(goChain)[:strings.Index(string(goChain), end)+len(end)] + string(testChain)[strings.Index(string(testChain), end)+len(end):]
	if consumer.verifyPeer(mixed, providerCN, pe["signature"], ahgtTranscript("provider", session)) == nil {
		t.Fatal("chain across clouds accepted")
	}
	own, err := provider.sign(ahgtTranscript("provider", session))
	if err != nil {
		t.Fatal(err)
	}
	if err = consumer.verifyPeer(pe["certificateChain"], providerCN, own, ahgtTranscript("provider", session)); err != nil {
		t.Fatalf("own signature refused: %v", err)
	}
}

func TestAHGT1NameConstraintIsEnforced(t *testing.T) {
	// the leaf of TestCloud is checked against GoCloud's cross-certificate constraint (OU=GoCloud): refused
	dir := filepath.Join("testdata", "ahgt1")
	load := func(name string) []byte { b, _ := os.ReadFile(filepath.Join(dir, name)); return b }
	parse := func(b []byte) []string { return strings.SplitAfter(string(b), "-----END CERTIFICATE-----\n") }
	test, gocloud := parse(load("TestCloud-relay-chain.crt")), parse(load("GoCloud-relay-chain.crt"))
	certs := func(pemText string) []byte { return []byte(pemText) }
	leafCert, crossCert := mustCert(t, certs(test[0])), mustCert(t, certs(gocloud[1]))
	if withinDirectoryConstraint(crossCert, leafCert) == nil {
		t.Fatal("TestCloud relay certificate accepted under GoCloud's name constraint")
	}
	if err := withinDirectoryConstraint(mustCert(t, certs(test[1])), leafCert); err != nil {
		t.Fatalf("own constraint refused: %v", err)
	}
}

func TestAHGT1DerivesTheReferenceKeysAndOpensItsMessages(t *testing.T) {
	t.Setenv("SESSION_CLOCK_SKEW_SECONDS", "1000000000") // the vector's timestamps are from its creation
	vector, _, _ := vectorFixture(t)
	session := object(vector["session"])
	id := mapString(session["sessionId"])
	fromConsumer, err := deriveKeys(x25519Private(t, vector["consumerEphemeralPrivate"]), session["providerKey"], id)
	if err != nil {
		t.Fatal(err)
	}
	fromProvider, err := deriveKeys(x25519Private(t, vector["providerEphemeralPrivate"]), session["consumerKey"], id)
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []string{"c2p", "p2c"} {
		want, _ := base64.StdEncoding.DecodeString(mapString(vector[direction+"Key"]))
		if !bytes.Equal(want, fromConsumer[direction]) || !bytes.Equal(want, fromProvider[direction]) {
			t.Fatalf("%s key differs from the reference", direction)
		}
	}
	seq, content, err := openMessage(fromProvider["c2p"], id, "c2p", object(vector["request"]))
	if err != nil || seq != 7 || content["path"] != "/datamanager/data-historian/put-data" {
		t.Fatalf("reference request: seq=%d content=%v err=%v", seq, content, err)
	}
	if _, reply, err := openMessage(fromConsumer["p2c"], id, "p2c", object(vector["reply"])); err != nil || reply["status"] != float64(201) {
		t.Fatalf("reference reply: %v %v", reply, err)
	}
	if _, _, err := openMessage(fromProvider["c2p"], id, "p2c", object(vector["request"])); err == nil {
		t.Fatal("opened with the wrong direction")
	}
	if _, _, err := openMessage(fromProvider["c2p"], "other-session", "c2p", object(vector["request"])); err == nil {
		t.Fatal("opened with the wrong session")
	}
	changed := map[string]any{}
	for k, v := range object(vector["request"]) {
		changed[k] = v
	}
	c := mapString(changed["ciphertext"])
	if c[0] == 'A' {
		changed["ciphertext"] = "B" + c[1:]
	} else {
		changed["ciphertext"] = "A" + c[1:]
	}
	if _, _, err := openMessage(fromProvider["c2p"], id, "c2p", changed); err == nil {
		t.Fatal("changed ciphertext opened")
	}
}

func TestAHGT1RoundTripStaleAndReplay(t *testing.T) {
	a, aPub, _ := newEphemeral()
	b, bPub, _ := newEphemeral()
	ka, _ := deriveKeys(a, bPub, "s1")
	kb, _ := deriveKeys(b, aPub, "s1")
	sealed, err := sealMessage(ka["c2p"], "s1", "c2p", 3, map[string]any{"method": "GET", "path": "/x"})
	if err != nil {
		t.Fatal(err)
	}
	wire, _ := json.Marshal(sealed)
	var envelope map[string]any
	_ = json.Unmarshal(wire, &envelope)
	if seq, content, err := openMessage(kb["c2p"], "s1", "c2p", envelope); err != nil || seq != 3 || content["path"] != "/x" {
		t.Fatalf("round trip: %d %v %v", seq, content, err)
	}
	t.Setenv("SESSION_CLOCK_SKEW_SECONDS", "-1")
	if _, _, err := openMessage(kb["c2p"], "s1", "c2p", envelope); err == nil {
		t.Fatal("stale message accepted")
	}
	w := newReplayWindow(4)
	for _, step := range []struct {
		seq  uint64
		want bool
	}{{1, true}, {3, true}, {3, false}, {2, true}, {0, false}, {9, true}, {4, false}, {6, true}} {
		if w.accept(step.seq) != step.want {
			t.Fatalf("replay window: %d should be %v", step.seq, step.want)
		}
	}
}

func mustCert(t *testing.T, pemText []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(pemText)
	if block == nil {
		t.Fatal("no PEM certificate")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func noCRL(cert, issuer *x509.Certificate) error { return nil }

// SOS-4: the peer's own key exchange, verified with the given CRL files of testdata/ahgt1/revocation ("" if accepted).
func revocationVerdict(t *testing.T, crls ...string) string {
	t.Helper()
	dir := filepath.Join("testdata", "ahgt1", "revocation")
	files := make([]string, len(crls))
	for i, c := range crls {
		files[i] = filepath.Join(dir, c)
	}
	peer, err := loadSessionSecurity(filepath.Join(dir, "peer-relay.key"), filepath.Join(dir, "peer-relay-chain.crt"), filepath.Join(dir, "org-ca.crt"), files)
	if err != nil {
		t.Fatal(err)
	}
	session := map[string]any{"sessionId": "revocation", "providerKey": "k"}
	exchange, err := peer.exchange("provider", session)
	if err != nil {
		t.Fatal(err)
	}
	if err = peer.verifyPeer(exchange["certificateChain"], "GateTunnel.PeerCloud.Company.arrowhead.eu", exchange["signature"], ahgtTranscript("provider", session)); err != nil {
		return err.Error()
	}
	return ""
}

func TestAHGT1PeerChainIsCheckedAgainstTheCloudAndOrganizationCRLs(t *testing.T) {
	for _, c := range []struct {
		crls []string
		want string
	}{
		{[]string{"peer-ca.crl", "org-ca.crl"}, ""},
		{[]string{"peer-ca-revoked.crl", "org-ca.crl"}, "peer certificate GateTunnel.PeerCloud.Company.arrowhead.eu is revoked"},
		{[]string{"peer-ca.crl", "org-ca-revoked.crl"}, "peer certificate PeerCloud.Company.arrowhead.eu is revoked"},
		{[]string{"peer-ca.crl", "peer-ca-revoked.crl", "org-ca.crl"}, "peer certificate GateTunnel.PeerCloud.Company.arrowhead.eu is revoked"},
		{[]string{"org-ca.crl"}, "no CRL of PeerCloud.Company.arrowhead.eu is configured"},
		{[]string{"peer-ca.crl"}, "no CRL of Company.arrowhead.eu is configured"},
		{[]string{"peer-ca-forged.crl", "org-ca.crl"}, "no CRL of PeerCloud.Company.arrowhead.eu is configured"},
		{[]string{"peer-ca-expired.crl", "org-ca.crl"}, "the CRL of PeerCloud.Company.arrowhead.eu is out of date"},
		{[]string{"peer-ca-expired.crl", "peer-ca.crl", "org-ca.crl"}, ""},
	} {
		if got := revocationVerdict(t, c.crls...); got != c.want {
			t.Errorf("%v: got %q, want %q", c.crls, got, c.want)
		}
	}
}

func TestAHGT1CRLFilesAreMandatoryAndAMissingCheckRefusesEveryPeer(t *testing.T) {
	dir := filepath.Join("testdata", "ahgt1", "revocation")
	for _, files := range [][]string{nil, {filepath.Join(dir, "missing.crl")}, {filepath.Join(dir, "org-ca.crt")}} {
		if _, err := crlRevocation(files); err == nil {
			t.Errorf("CRL files %v accepted", files)
		}
	}
	peer, err := loadSessionIdentity(filepath.Join(dir, "peer-relay.key"), filepath.Join(dir, "peer-relay-chain.crt"), filepath.Join(dir, "org-ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	session := map[string]any{"sessionId": "revocation", "providerKey": "k"}
	exchange, _ := peer.exchange("provider", session)
	if peer.verifyPeer(exchange["certificateChain"], "GateTunnel.PeerCloud.Company.arrowhead.eu", exchange["signature"], ahgtTranscript("provider", session)) == nil {
		t.Fatal("peer accepted without a revocation check")
	}
}
