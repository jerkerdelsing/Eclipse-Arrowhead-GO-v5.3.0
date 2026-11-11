// SPDX-License-Identifier: EPL-2.0
// Profile policy follows JavaSupportRuntime/CertificateAuthority.java.
package core

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var qualifier = asn1.ObjectIdentifier{2, 5, 4, 46}

func parseCertificate(encoded string) (*x509.Certificate, error) {
	data := []byte(encoded)
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	} else {
		b, e := base64.StdEncoding.DecodeString(encoded)
		if e != nil {
			return nil, bad("Invalid certificate encoding")
		}
		data = b
	}
	cert, e := x509.ParseCertificate(data)
	if e != nil {
		return nil, bad("Invalid certificate")
	}
	return cert, nil
}
func (a *App) caSigner() (*x509.Certificate, crypto.Signer, error) {
	b, e := os.ReadFile(a.Config.CACertificate)
	if e != nil {
		return nil, nil, e
	}
	block, _ := pem.Decode(b)
	if block == nil {
		return nil, nil, errors.New("Invalid CA PEM")
	}
	root, e := x509.ParseCertificate(block.Bytes)
	if e != nil || !root.IsCA {
		return nil, nil, errors.New("Invalid CA certificate")
	}
	st, e := os.Stat(a.Config.CASigningKey)
	if e != nil {
		return nil, nil, e
	}
	if st.Mode().Perm()&0077 != 0 {
		return nil, nil, errors.New("CA key must be owner-only readable")
	}
	b, e = os.ReadFile(a.Config.CASigningKey)
	if e != nil {
		return nil, nil, e
	}
	block, _ = pem.Decode(b)
	if block == nil {
		return nil, nil, errors.New("Invalid CA key")
	}
	var key any
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, e = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, e = x509.ParseECPrivateKey(block.Bytes)
	default:
		key, e = x509.ParsePKCS8PrivateKey(block.Bytes)
	}
	if e != nil {
		return nil, nil, e
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("Unsupported CA key")
	}
	aPub, _ := x509.MarshalPKIXPublicKey(root.PublicKey)
	bPub, _ := x509.MarshalPKIXPublicKey(signer.Public())
	if string(aPub) != string(bPub) {
		return nil, nil, errors.New("CA certificate/key mismatch")
	}
	return root, signer, nil
}
func (a *App) signCertificate(req Document, actor principal) (Document, error) {
	root, key, e := a.caSigner()
	if e != nil {
		return nil, e
	}
	encoded := str(req, "encodedCSR")
	if encoded == "" {
		encoded = str(req, "csr")
	}
	data := []byte(encoded)
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	} else {
		data, e = base64.StdEncoding.DecodeString(encoded)
		if e != nil {
			return nil, bad("Invalid CSR")
		}
	}
	csr, e := x509.ParseCertificateRequest(data)
	if e != nil || csr.CheckSignature() != nil {
		return nil, bad("CSR signature is invalid")
	}
	count := 0
	for _, n := range csr.Subject.Names {
		if n.Type.Equal(asn1.ObjectIdentifier{2, 5, 4, 3}) {
			count++
		}
	}
	name := csr.Subject.CommonName
	suffix := "." + a.Config.CloudSuffix
	short := strings.TrimSuffix(name, suffix)
	if count != 1 || !strings.HasSuffix(name, suffix) || !regexp.MustCompile(`^[A-Z][A-Za-z0-9]{0,62}$`).MatchString(short) {
		return nil, bad("CSR requires one PascalCase common name in the configured local cloud")
	}
	reserved := Systems[short].Name != ""
	for _, n := range []string{"Sysop", "LocalCloudManager", "Authentication", "ServiceRegistry", "ConsumerAuthorization", "ServiceOrchestration", "DynamicServiceOrchestration", "SimpleStoreServiceOrchestration", "Relay"} {
		if short == n {
			reserved = true
		}
	}
	if reserved && !actor.Sysop {
		return nil, forbidden()
	}
	profileName := str(req, "profile")
	if profileName == "" {
		for _, n := range csr.Subject.Names {
			if n.Type.Equal(qualifier) {
				profileName, _ = n.Value.(string)
			}
		}
	}
	if profileName == "" {
		profileName = "sy"
	}
	allowed := actor.Sysop || actor.Name == "Onboarding" && (profileName == "on" || profileName == "de" || profileName == "sy") || actor.Name == "CertificateAuthority" && profileName == "sy" // J6: not the console identity
	names := map[string]string{"on": "ON_BOARDING", "de": "DEVICE", "sy": "SYSTEM", "op": "OPERATOR"}
	if names[profileName] == "" {
		return nil, bad("Invalid profile")
	}
	if !allowed {
		return nil, forbidden()
	}
	limit := 365 * 24 * time.Hour
	if profileName == "on" {
		limit = 24 * time.Hour
	}
	start := time.Now().UTC().Add(-time.Minute)
	if s := str(req, "validAfter"); s != "" {
		start, e = time.Parse(time.RFC3339Nano, s)
		if e != nil {
			return nil, bad("Invalid validAfter")
		}
	}
	end := start.Add(limit)
	if s := str(req, "validBefore"); s != "" {
		end, e = time.Parse(time.RFC3339Nano, s)
		if e != nil {
			return nil, bad("Invalid validBefore")
		}
	}
	if end.After(root.NotAfter) {
		end = root.NotAfter
	}
	if !end.After(start) || !end.After(time.Now()) || end.After(start.Add(limit)) || start.Before(root.NotBefore) {
		return nil, bad("Invalid certificate validity")
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 159))
	if e != nil {
		return nil, e
	}
	serial.SetBit(serial, 158, 1)
	tmpl := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{Country: root.Subject.Country, Organization: root.Subject.Organization, OrganizationalUnit: []string{"Arrowhead Systems"}, CommonName: name, ExtraNames: []pkix.AttributeTypeAndValue{{Type: qualifier, Value: profileName}}}, NotBefore: start, NotAfter: end, BasicConstraintsValid: true, IsCA: false, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	addresses := list(req, "addresses")
	if req["addresses"] == nil {
		for _, s := range csr.DNSNames {
			addresses = append(addresses, s)
		}
		for _, ip := range csr.IPAddresses {
			addresses = append(addresses, ip.String())
		}
	}
	if len(addresses) > 16 {
		return nil, bad("Too many SANs")
	}
	dns := regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	for _, v := range addresses {
		s, ok := v.(string)
		if !ok {
			return nil, bad("Invalid SAN")
		}
		if ip := net.ParseIP(s); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if dns.MatchString(s) && !strings.Contains(s, "..") {
			tmpl.DNSNames = append(tmpl.DNSNames, s)
		} else {
			return nil, bad("Invalid SAN")
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, tmpl, root, csr.PublicKey, key)
	if e != nil {
		return nil, e
	}
	var id float64
	e = a.Store.Update(func(d database) error {
		for _, row := range d["certificates"] {
			if str(row, "common_name") == name && str(row, "created_by") != actor.Name && row["revoked_at"] == nil && !expired(str(row, "valid_until")) {
				return forbidden()
			}
		}
		var index string
		index, id = nextID(d, "certificates")
		bucket(d, "certificates")[index] = Document{"id": id, "serial_number": serial.String(), "common_name": name, "created_by": actor.Name, "certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), "valid_after": start.Format(time.RFC3339Nano), "valid_until": end.Format(time.RFC3339Nano), "created_at": now(), "revoked_at": nil}
		return nil
	})
	if e != nil {
		return nil, e
	}
	return Document{"id": id, "certificateChain": []string{base64.StdEncoding.EncodeToString(der), base64.StdEncoding.EncodeToString(root.Raw)}, "commonName": name, "profile": names[profileName], "serialNumber": serial.String(), "validAfter": start.Format(time.RFC3339Nano), "validBefore": end.Format(time.RFC3339Nano)}, nil
}
func (a *App) caCRL() ([]byte, error) {
	root, key, e := a.caSigner()
	if e != nil {
		return nil, e
	}
	entries := []x509.RevocationListEntry{}
	for _, row := range a.rows("certificates") {
		if s := str(row, "revoked_at"); s != "" {
			serial, ok := new(big.Int).SetString(str(row, "serial_number"), 10)
			if !ok {
				return nil, errors.New("Invalid serial in state")
			}
			t, e := time.Parse(time.RFC3339Nano, s)
			if e != nil {
				return nil, e
			}
			entries = append(entries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: t})
		}
	}
	der, e := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(time.Now().UnixNano()), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(7 * 24 * time.Hour), RevokedCertificateEntries: entries}, root, key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

// publishCRL writes the current CRL to crlExportFile (temporary file + rename, so readers never see a partial file).
func (a *App) publishCRL() error {
	if a.Config.CRLExportFile == "" {
		return nil
	}
	v, e := a.caCRL()
	if e != nil {
		return e
	}
	tmp, e := os.CreateTemp(filepath.Dir(a.Config.CRLExportFile), ".crl-*")
	if e != nil {
		return e
	}
	defer os.Remove(tmp.Name())
	if _, e = tmp.Write(v); e == nil {
		e = tmp.Sync()
	}
	if e2 := tmp.Close(); e == nil {
		e = e2
	}
	if e == nil {
		e = os.Chmod(tmp.Name(), 0644)
	}
	if e != nil {
		return e
	}
	return os.Rename(tmp.Name(), a.Config.CRLExportFile)
}

// revoked publishes the CRL after a committed revocation. The revocation stands even if publication fails; the
// failure is logged and retried by the daily publication.
func (a *App) revoked() {
	if e := a.publishCRL(); e != nil {
		log.Printf("CRL publication to %s failed: %v", a.Config.CRLExportFile, e)
	}
}

func (a *App) caRoutes() {
	b := "/certificate-authority"
	a.route("POST", b+"/sign", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		v, e := a.signCertificate(req, caller(r))
		return v, 201, e
	})
	a.route("POST", b+"/checkCertificate", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		s := str(req, "certificate")
		if s == "" {
			s = str(req, "encodedCertificate")
		}
		cert, e := parseCertificate(s)
		if e != nil {
			return nil, 0, e
		}
		root, _, e := a.caSigner()
		if e != nil {
			return nil, 0, e
		}
		status := "UNKNOWN"
		known := false
		if cert.CheckSignatureFrom(root) == nil && cert.Issuer.String() == root.Subject.String() {
			status = "GOOD"
			if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
				status = "EXPIRED"
			}
			for _, row := range a.rows("certificates") {
				if str(row, "serial_number") == cert.SerialNumber.String() {
					known = true
					if row["revoked_at"] != nil {
						status = "REVOKED"
					}
				}
			}
		}
		return Document{"status": status, "valid": status == "GOOD", "serialNumber": cert.SerialNumber.String(), "known": known}, 200, nil
	})
	a.route("GET", b+"/crl", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		v, e := a.caCRL()
		return binaryResponse{v, "application/pkix-crl"}, 200, e
	})
	for _, table := range []string{"certificates", "keys"} {
		t := table
		a.route("GET", b+"/mgmt/"+t, "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return a.rows(t), 200, nil })
		a.route("DELETE", b+"/mgmt/"+t+"/{id}", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			p := caller(r)
			row, e := a.row(t, r.PathValue("id"))
			if e != nil {
				return nil, 0, e
			}
			manager := p.Sysop || p.Name == "CertificateAuthority" // J6: not the console identity LocalCloudManager
			if !manager && (t != "certificates" || p.Name != "Onboarding" || str(row, "created_by") != "Onboarding") {
				return nil, 0, forbidden()
			}
			e = a.Store.Update(func(d database) error {
				if t == "keys" {
					delete(d[t], r.PathValue("id"))
				} else {
					d[t][r.PathValue("id")]["revoked_at"] = now()
				}
				return nil
			})
			if e == nil && t == "certificates" {
				a.revoked()
			}
			return Document{"success": e == nil}, 200, e
		})
	}
	a.route("POST", b+"/mgmt/revocations", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		s := str(req, "certificate")
		if s == "" {
			s = str(req, "encodedCertificate")
		}
		cert, e := parseCertificate(s)
		if e != nil {
			return nil, 0, e
		}
		root, _, e := a.caSigner()
		if e != nil {
			return nil, 0, e
		}
		if cert.CheckSignatureFrom(root) != nil {
			return nil, 0, bad("Certificate was not issued by this CA")
		}
		var id float64
		e = a.Store.Update(func(d database) error {
			for _, row := range d["certificates"] {
				if str(row, "serial_number") == cert.SerialNumber.String() {
					row["revoked_at"] = now()
					id = row["id"].(float64)
					return nil
				}
			}
			index, n := nextID(d, "certificates")
			id = n
			bucket(d, "certificates")[index] = Document{"id": id, "serial_number": cert.SerialNumber.String(), "common_name": cert.Subject.CommonName, "created_by": caller(r).Name, "certificate_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})), "valid_until": cert.NotAfter.UTC().Format(time.RFC3339Nano), "revoked_at": now()}
			return nil
		})
		if e == nil {
			a.revoked()
		}
		return Document{"id": id, "serialNumber": cert.SerialNumber.String(), "revoked": true}, 200, e
	})
	a.route("PUT", b+"/mgmt/keys", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		s := str(req, "publicKey")
		if s == "" {
			s = str(req, "publicKeyPem")
		}
		block, _ := pem.Decode([]byte(s))
		if block == nil {
			return nil, 0, bad("Public key PEM required")
		}
		if _, e = x509.ParsePKIXPublicKey(block.Bytes); e != nil {
			return nil, 0, bad("Invalid public key")
		}
		start, end := time.Now().UTC(), time.Now().UTC().Add(365*24*time.Hour)
		if s := str(req, "validAfter"); s != "" {
			start, e = time.Parse(time.RFC3339Nano, s)
			if e != nil {
				return nil, 0, bad("Invalid validAfter")
			}
		}
		if s := str(req, "validBefore"); s != "" {
			end, e = time.Parse(time.RFC3339Nano, s)
			if e != nil {
				return nil, 0, bad("Invalid validBefore")
			}
		}
		if !end.After(start) {
			return nil, 0, bad("Invalid key validity")
		}
		var id float64
		e = a.Store.Update(func(d database) error {
			index, n := nextID(d, "keys")
			id = n
			bucket(d, "keys")[index] = Document{"id": id, "public_key_pem": s, "description": req["description"], "valid_after": start.Format(time.RFC3339Nano), "valid_before": end.Format(time.RFC3339Nano), "created_at": now()}
			return nil
		})
		return Document{"id": id, "trusted": true}, 201, e
	})
	a.route("POST", b+"/checkTrustedKey", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		key := str(req, "publicKey")
		if key == "" {
			key = str(req, "publicKeyPem")
		}
		if key == "" {
			return nil, 0, bad("publicKey required")
		}
		for _, row := range a.rows("keys") {
			if str(row, "public_key_pem") == key {
				return Document{"trusted": timeRange(now(), str(row, "valid_after"), str(row, "valid_before")), "key": row}, 200, nil
			}
		}
		return Document{"trusted": false, "key": nil}, 200, nil
	})
}
