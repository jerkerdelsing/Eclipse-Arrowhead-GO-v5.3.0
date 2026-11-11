package cloud

// AH-GT-1: end-to-end protection of inter-cloud GateTunnel sessions (security finding J5). Wire-compatible with the
// reference Arrowhead-test-cloud-java/gatetunnel/src/session_security.py and the Java support runtime
// (ah5-support-java-spring/JavaSupportRuntime, SessionSecurity.java).
//
// Key exchange, once per session, carried by the Gatekeepers' ICN messages and the first tunnel request: each GateTunnel
// makes an ephemeral X25519 key and signs a transcript of the session parameters and the ephemeral key(s) with its relay
// key (RSA-PSS, SHA-256, salt 32). The signature comes with the relay chain (relay certificate + cross-certificate of its
// cloud CA), verified against the organization CA, the cross-certificate's name constraint and the expected peer name.
// Both sides derive one AES-256-GCM key per direction (HKDF-SHA256, salt = session id). Every relayed request and reply
// is sealed (AAD = protocol, session, direction, sequence); requests carry a sequence number and a timestamp, so
// duplicates and stale messages are refused, and a reply must carry the sequence number of its request.
//
// Revocation (security finding SOS-4, 2026-11-10): after the chain verifies, the relay certificate must not be listed by
// a current CRL of its cloud CA, and the cross-certificate not by a current CRL of the organization CA. The CRL files
// (RELAY_CRL_FILES) are read again for every key exchange; a missing, forged or out-of-date CRL refuses it.

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"
)

const ahgtProtocol = "AH-GT-1"

var oidNameConstraints = asn1.ObjectIdentifier{2, 5, 29, 30}
var oidDNQualifier = asn1.ObjectIdentifier{2, 5, 4, 46}

type securityError struct{ reason string }

func (e securityError) Error() string         { return e.reason }
func secErr(format string, args ...any) error { return securityError{fmt.Sprintf(format, args...)} }

type sessionSecurity struct {
	key      *rsa.PrivateKey
	chainPEM string
	orgCA    *x509.Certificate
	// revocation checks one certificate of the peer chain against its issuer; nil refuses every peer
	revocation func(cert, issuer *x509.Certificate) error
}

// crlRevocation reads the CRL files (PEM or DER) for every check; each must hold a CRL at start.
func crlRevocation(files []string) (func(cert, issuer *x509.Certificate) error, error) {
	if len(files) == 0 {
		return nil, errors.New("AH-GT-1 needs RELAY_CRL_FILES: the CRLs of the organization CA and the peer cloud CAs")
	}
	for _, f := range files {
		crls, err := readCRLs(f)
		if err != nil {
			return nil, fmt.Errorf("CRL file %s: %w", f, err)
		}
		if len(crls) == 0 {
			return nil, fmt.Errorf("no CRL in %s", f)
		}
	}
	files = append([]string(nil), files...)
	return func(cert, issuer *x509.Certificate) error {
		var all []*x509.RevocationList
		for _, f := range files {
			crls, err := readCRLs(f)
			if err != nil {
				return secErr("CRL file %s is unreadable", f)
			}
			all = append(all, crls...)
		}
		return checkRevocation(cert, issuer, all, time.Now())
	}, nil
}

func readCRLs(file string) ([]*x509.RevocationList, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if !bytes.Contains(raw, []byte("-----BEGIN")) {
		crl, err := x509.ParseRevocationList(raw)
		if err != nil {
			return nil, err
		}
		return []*x509.RevocationList{crl}, nil
	}
	var out []*x509.RevocationList
	for {
		var block *pem.Block
		block, raw = pem.Decode(raw)
		if block == nil {
			return out, nil
		}
		if block.Type != "X509 CRL" {
			continue
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, err
		}
		out = append(out, crl)
	}
}

// checkRevocation: the certificate must not be listed by any current CRL that the issuer signed, and at least one such
// CRL must exist.
func checkRevocation(cert, issuer *x509.Certificate, crls []*x509.RevocationList, now time.Time) error {
	signed, current := false, false
	for _, crl := range crls {
		if !bytes.Equal(crl.RawIssuer, issuer.RawSubject) || crl.CheckSignatureFrom(issuer) != nil {
			continue
		}
		signed = true
		if now.Before(crl.ThisUpdate) || crl.NextUpdate.IsZero() || now.After(crl.NextUpdate) {
			continue
		}
		current = true
		for _, entry := range crl.RevokedCertificateEntries {
			if entry.SerialNumber != nil && entry.SerialNumber.Cmp(cert.SerialNumber) == 0 {
				return secErr("peer certificate %s is revoked", cert.Subject.CommonName)
			}
		}
	}
	if !signed {
		return secErr("no CRL of %s is configured", issuer.Subject.CommonName)
	}
	if !current {
		return secErr("the CRL of %s is out of date", issuer.Subject.CommonName)
	}
	return nil
}

func loadSessionSecurity(keyFile, chainFile, orgCAFile string, crlFiles []string) (*sessionSecurity, error) {
	revocation, err := crlRevocation(crlFiles)
	if err != nil {
		return nil, err
	}
	s, err := loadSessionIdentity(keyFile, chainFile, orgCAFile)
	if err != nil {
		return nil, err
	}
	s.revocation = revocation
	return s, nil
}

// loadSessionIdentity loads the relay key, chain and organization CA without a revocation check (which refuses peers).
func loadSessionIdentity(keyFile, chainFile, orgCAFile string) (*sessionSecurity, error) {
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("relay key is not PEM")
	}
	var key *rsa.PrivateKey
	if parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes); e == nil {
		key, _ = parsed.(*rsa.PrivateKey)
	} else if parsed, e := x509.ParsePKCS1PrivateKey(block.Bytes); e == nil {
		key = parsed
	}
	if key == nil {
		return nil, errors.New("relay key must be an RSA key")
	}
	chain, err := os.ReadFile(chainFile)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(orgCAFile)
	if err != nil {
		return nil, err
	}
	caBlock, _ := pem.Decode(caPEM)
	if caBlock == nil {
		return nil, errors.New("organization CA is not PEM")
	}
	ca, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return nil, err
	}
	return &sessionSecurity{key: key, chainPEM: string(chain), orgCA: ca}, nil
}

var pssOptions = &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}

func (s *sessionSecurity) sign(transcript []byte) (string, error) {
	digest := sha256.Sum256(transcript)
	sig, err := rsa.SignPSS(rand.Reader, s.key, crypto.SHA256, digest[:], pssOptions)
	return base64.StdEncoding.EncodeToString(sig), err
}

// exchange is the own half of the key exchange: ephemeral key, signature over the transcript, relay chain.
func (s *sessionSecurity) exchange(role string, session map[string]any) (map[string]any, error) {
	sig, err := s.sign(ahgtTranscript(role, session))
	if err != nil {
		return nil, err
	}
	return map[string]any{role + "Key": session[role+"Key"], "signature": sig, "certificateChain": s.chainPEM}, nil
}

// verifyPeer checks relay certificate -> cross-certificate -> organization CA (signatures, validity, CA flags, the
// directory-name constraint of the cross-certificate), the expected peer name and profile, and the transcript signature.
// The chain is checked by hand: Go's x509.Verify does not support directory-name constraints.
func (s *sessionSecurity) verifyPeer(chainPEM any, expectedCN string, signature any, transcript []byte) error {
	var certs []*x509.Certificate
	rest := []byte(mapString(chainPEM))
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return secErr("peer chain is malformed")
		}
		certs = append(certs, c)
	}
	if len(certs) != 2 {
		return secErr("peer chain must be relay certificate + cross-certificate")
	}
	leaf, cross := certs[0], certs[1]
	if err := leaf.CheckSignatureFrom(cross); err != nil {
		return secErr("peer chain does not verify: %v", err)
	}
	if err := cross.CheckSignatureFrom(s.orgCA); err != nil {
		return secErr("peer chain does not verify: %v", err)
	}
	now := time.Now()
	for _, c := range []*x509.Certificate{leaf, cross, s.orgCA} {
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			return secErr("peer chain is outside its validity period")
		}
	}
	if !cross.IsCA || !cross.BasicConstraintsValid {
		return secErr("peer cross-certificate is not a CA")
	}
	if leaf.IsCA {
		return secErr("peer relay certificate must not be a CA")
	}
	if err := withinDirectoryConstraint(cross, leaf); err != nil {
		return err
	}
	if s.revocation == nil {
		return secErr("no revocation check is configured")
	}
	if err := s.revocation(leaf, cross); err != nil {
		return err
	}
	if err := s.revocation(cross, s.orgCA); err != nil {
		return err
	}
	if leaf.Subject.CommonName != expectedCN {
		return secErr("peer relay certificate is not %s", expectedCN)
	}
	profile := ""
	for _, a := range leaf.Subject.Names {
		if a.Type.Equal(oidDNQualifier) {
			profile = fmt.Sprint(a.Value)
		}
	}
	if profile != "sy" {
		return secErr("peer relay certificate is not a system (sy) certificate")
	}
	pub, ok := leaf.PublicKey.(*rsa.PublicKey)
	if !ok {
		return secErr("peer relay key is not RSA")
	}
	sig, err := base64.StdEncoding.DecodeString(mapString(signature))
	if err != nil {
		return secErr("peer key-exchange signature is malformed")
	}
	digest := sha256.Sum256(transcript)
	if rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, pssOptions) != nil {
		return secErr("peer key-exchange signature is invalid")
	}
	return nil
}

type generalSubtree struct {
	Base asn1.RawValue
}
type nameConstraintsExt struct {
	Permitted []generalSubtree `asn1:"optional,tag:0"`
	Excluded  []generalSubtree `asn1:"optional,tag:1"`
}

// withinDirectoryConstraint requires the leaf's subject to start with one permitted directoryName subtree of the issuer.
func withinDirectoryConstraint(issuer, leaf *x509.Certificate) error {
	var raw []byte
	for _, e := range issuer.Extensions {
		if e.Id.Equal(oidNameConstraints) {
			raw = e.Value
		}
	}
	if raw == nil {
		return secErr("peer cross-certificate has no name constraint")
	}
	var nc nameConstraintsExt
	if rest, err := asn1.Unmarshal(raw, &nc); err != nil || len(rest) > 0 {
		return secErr("peer cross-certificate name constraint is malformed")
	}
	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(leaf.RawSubject, &subject); err != nil {
		return secErr("peer relay certificate subject is malformed")
	}
	for _, tree := range nc.Permitted {
		if tree.Base.Class != asn1.ClassContextSpecific || tree.Base.Tag != 4 {
			continue
		}
		var permitted pkix.RDNSequence
		if _, err := asn1.Unmarshal(tree.Base.Bytes, &permitted); err != nil {
			continue
		}
		if len(permitted) <= len(subject) && reflect.DeepEqual(rdnStrings(subject[:len(permitted)]), rdnStrings(permitted)) {
			return nil
		}
	}
	return secErr("peer relay certificate is outside its cloud's name constraint")
}

func rdnStrings(rdns pkix.RDNSequence) []string {
	out := []string{}
	for _, set := range rdns {
		for _, a := range set {
			out = append(out, a.Type.String()+"="+fmt.Sprint(a.Value))
		}
	}
	return out
}

// ahgtTranscript is the canonical byte string both sides sign: protocol, role, session parameters and the
// ephemeral key(s) so far.
func ahgtTranscript(role string, s map[string]any) []byte {
	fields := []string{ahgtProtocol, role, mapString(s["sessionId"]), mapString(s["consumer"]), mapString(s["consumerCloud"]), mapString(s["provider"]),
		mapString(s["serviceDefinition"]), mapString(s["consumerGateTunnel"]), mapString(s["providerGateTunnel"]), mapString(s["providerKey"])}
	if role == "consumer" {
		fields = append(fields, mapString(s["consumerKey"]))
	}
	return []byte(strings.Join(fields, "\n"))
}

func newEphemeral() (*ecdh.PrivateKey, string, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	return key, base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func deriveKeys(own *ecdh.PrivateKey, peerPublic any, sessionID string) (map[string][]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(mapString(peerPublic))
	if err != nil {
		return nil, secErr("peer key is malformed")
	}
	peer, err := ecdh.X25519().NewPublicKey(raw)
	if err != nil {
		return nil, secErr("peer key is not an X25519 public key")
	}
	shared, err := own.ECDH(peer)
	if err != nil {
		return nil, secErr("key agreement failed")
	}
	keys := map[string][]byte{}
	for _, direction := range []string{"c2p", "p2c"} {
		k, err := hkdf.Key(sha256.New, shared, []byte(sessionID), ahgtProtocol+" "+direction, 32)
		if err != nil {
			return nil, err
		}
		keys[direction] = k
	}
	return keys, nil
}

func ahgtAAD(sessionID, direction string, sequence uint64) []byte {
	return []byte(ahgtProtocol + "|" + sessionID + "|" + direction + "|" + strconv.FormatUint(sequence, 10))
}

func sealMessage(key []byte, sessionID, direction string, sequence uint64, content map[string]any) (map[string]any, error) {
	plain := map[string]any{}
	for k, v := range content {
		plain[k] = v
	}
	plain["timestamp"] = float64(time.Now().UnixNano()) / 1e9
	data, err := json.Marshal(plain)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return map[string]any{"seq": sequence, "nonce": base64.StdEncoding.EncodeToString(nonce),
		"ciphertext": base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, data, ahgtAAD(sessionID, direction, sequence)))}, nil
}

func openMessage(key []byte, sessionID, direction string, envelope map[string]any) (uint64, map[string]any, error) {
	refused := secErr("message does not decrypt or authenticate")
	seq, ok := number(envelope["seq"])
	if !ok || seq < 0 || seq != math.Trunc(seq) {
		return 0, nil, refused
	}
	sequence := uint64(seq)
	nonce, err1 := base64.StdEncoding.DecodeString(mapString(envelope["nonce"]))
	sealed, err2 := base64.StdEncoding.DecodeString(mapString(envelope["ciphertext"]))
	if err1 != nil || err2 != nil || len(nonce) != 12 {
		return 0, nil, refused
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return 0, nil, refused
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return 0, nil, refused
	}
	plain, err := gcm.Open(nil, nonce, sealed, ahgtAAD(sessionID, direction, sequence))
	if err != nil {
		return 0, nil, refused
	}
	var content map[string]any
	decoder := json.NewDecoder(bytes.NewReader(plain))
	if decoder.Decode(&content) != nil {
		return 0, nil, refused
	}
	skew, err := strconv.ParseFloat(env("SESSION_CLOCK_SKEW_SECONDS", "120"), 64)
	if err != nil {
		skew = 120
	}
	timestamp, _ := number(content["timestamp"])
	if math.Abs(float64(time.Now().UnixNano())/1e9-timestamp) > skew {
		return 0, nil, secErr("message is outside the accepted time window")
	}
	return sequence, content, nil
}

// replayWindow accepts each sequence number once, within a sliding window above the highest seen.
type replayWindow struct {
	mu      sync.Mutex
	size    uint64
	highest uint64
	seen    map[uint64]bool
}

func newReplayWindow(size uint64) *replayWindow {
	return &replayWindow{size: size, seen: map[uint64]bool{}}
}

func (w *replayWindow) accept(sequence uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if sequence == 0 || w.seen[sequence] || (w.highest > w.size && sequence <= w.highest-w.size) {
		return false
	}
	w.seen[sequence] = true
	if sequence > w.highest {
		w.highest = sequence
	}
	for s := range w.seen {
		if w.highest > w.size && s <= w.highest-w.size {
			delete(w.seen, s)
		}
	}
	return true
}
