// SPDX-License-Identifier: EPL-2.0
package core

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

func reservedEnrollment(name string) bool {
	if Systems[name].Name != "" {
		return true
	}
	for _, n := range []string{"ServiceRegistry", "Authentication", "ConsumerAuthorization", "DynamicServiceOrchestration", "SimpleStoreServiceOrchestration", "ServiceOrchestration", "LocalCloudManager", "Sysop", "Relay", "RandomDataProducer", "SmokeClient"} {
		if name == n {
			return true
		}
	}
	return false
}
func (a *App) enrollmentIdentity(r *http.Request) (principal, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		return principal{}, &APIError{401, "Verified enrollment certificate required"}
	}
	leaf := r.TLS.PeerCertificates[0]
	hash := sha256.Sum256(leaf.Raw)
	fingerprint := hex.EncodeToString(hash[:])
	var name string
	e := a.Store.View(func(d database) error {
		if strings.Contains(r.URL.Path, "/certificate/") {
			for key, row := range d["enrollments"] {
				if str(row, "bootstrapFingerprint") == fingerprint && str(row, "state") != "OFFBOARDED" && str(row, "state") != "OFFBOARDING" {
					name = key
					return nil
				}
			}
			return forbidden()
		}
		suffix := "." + a.Config.CloudSuffix
		if !strings.HasSuffix(leaf.Subject.CommonName, suffix) {
			return forbidden()
		}
		name = strings.TrimSuffix(leaf.Subject.CommonName, suffix)
		row := d["enrollments"][name]
		if row == nil || str(row, "state") == "OFFBOARDED" || str(row, "state") == "OFFBOARDING" {
			return forbidden()
		}
		expected, serialKey := "on", "onboardingSerial"
		if strings.HasSuffix(r.URL.Path, "/system") || strings.HasSuffix(r.URL.Path, "/offboard") {
			expected, serialKey = "de", "deviceSerial"
		}
		if profile(leaf) != expected || str(row, serialKey) != leaf.SerialNumber.String() {
			return forbidden()
		}
		return nil
	})
	if e != nil {
		return principal{}, e
	}
	return principal{Name: name}, nil
}

// withSystems adds the onboarded systems of the device (sy certificates issued and not withdrawn), as the
// enrollment's "systems" list of the Onboarding management IDD.
func (a *App) withSystems(row Document) {
	systems := []string{}
	for _, s := range a.rows("issuedSystems") {
		if str(s, "deviceName") == str(row, "deviceName") {
			systems = append(systems, str(s, "systemName"))
		}
	}
	sort.Strings(systems)
	row["systems"] = systems
}
func (a *App) onboardingRoutes() {
	b := "/onboarding"
	a.route("GET", b+"/echo", "certificate", func(w http.ResponseWriter, r *http.Request) (any, int, error) { return textResponse("OK"), 200, nil })
	a.route("GET", b+"/mgmt/enrollments", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		rows := a.rows("enrollments")
		for _, row := range rows {
			a.withSystems(row)
		}
		return Document{"entries": rows, "count": len(rows)}, 200, nil
	})
	a.route("GET", b+"/mgmt/enrollments/{deviceName}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		row, e := a.row("enrollments", r.PathValue("deviceName"))
		if e == nil {
			a.withSystems(row)
		}
		return row, 200, e
	})
	a.route("PUT", b+"/mgmt/enrollments/{deviceName}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		name := r.PathValue("deviceName")
		if !validName(name) || reservedEnrollment(name) {
			return nil, 0, bad("Reserved or invalid device name")
		}
		fp := strings.ToLower(strings.ReplaceAll(str(req, "bootstrapFingerprint"), ":", ""))
		if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(fp) {
			return nil, 0, bad("bootstrapFingerprint must be SHA-256 DER fingerprint")
		}
		names := list(req, "systems")
		if len(names) < 1 || len(names) > 32 {
			return nil, 0, bad("Approve 1–32 systems")
		}
		seen := map[string]bool{}
		for _, v := range names {
			s, ok := v.(string)
			if !ok || !validName(s) || reservedEnrollment(s) || seen[s] {
				return nil, 0, bad("Invalid, duplicate or reserved system name")
			}
			seen[s] = true
		}
		var row Document
		e = a.Store.Update(func(d database) error {
			for other, existing := range d["enrollments"] {
				if other != name && str(existing, "bootstrapFingerprint") == fp {
					return bad("Bootstrap certificate already approved")
				}
				if other != name {
					for system := range seen {
						if contains(list(existing, "approvedSystems"), system) {
							return bad("System already approved for another device")
						}
					}
				}
			}
			row = bucket(d, "enrollments")[name]
			if str(row, "claim") != "" {
				return &APIError{409, "Enrollment operation in progress"}
			}
			if row != nil && str(row, "state") == "DEVICE_REGISTERED" && str(row, "bootstrapFingerprint") != fp {
				return &APIError{409, "Offboard before changing bootstrap identity"}
			}
			if row == nil {
				row = Document{"deviceName": name, "state": "APPROVED"}
			}
			row["bootstrapFingerprint"] = fp
			row["approvedSystems"] = names
			row["approvedBy"] = caller(r).Name
			row["approvedAt"] = now()
			row["updatedAt"] = now()
			if str(row, "state") == "OFFBOARDED" {
				row["state"] = "APPROVED"
			}
			d["enrollments"][name] = row
			return nil
		})
		return row, 200, e
	})
	for _, path := range []string{"/certificate/name", "/certificate/csr", "/device", "/system"} {
		p := path
		a.route("POST", b+p, "enrollment", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			req, e := decodeOptional(w, r)
			if e != nil {
				return nil, 0, e
			}
			return a.enroll(r, req, p)
		})
	}
	a.route("POST", b+"/device/offboard", "enrollment", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		v, e := a.offboard(r, caller(r).Name)
		return v, 200, e
	})
	a.route("POST", b+"/mgmt/enrollments/{deviceName}/offboard", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		v, e := a.offboard(r, r.PathValue("deviceName"))
		return v, 200, e
	})
	a.route("DELETE", b+"/mgmt/enrollments/{deviceName}", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		name := r.PathValue("deviceName")
		v, e := a.offboard(r, name)
		if e == nil && len(v["failed"].([]string)) == 0 {
			_, e = removeRow(a, "enrollments", name)
		}
		return v, 200, e
	})
}
func (a *App) enroll(r *http.Request, req Document, path string) (any, int, error) {
	device := caller(r).Name
	row, e := a.row("enrollments", device)
	if e != nil {
		return nil, 0, e
	}
	if str(row, "state") == "OFFBOARDED" {
		return nil, 0, forbidden()
	}
	name := device
	profileName, kind := "on", "ON_BOARDING"
	if path == "/device" {
		profileName, kind = "de", "DEVICE"
	}
	if path == "/system" {
		name = str(req, "systemName")
		profileName, kind = "sy", "SYSTEM"
		if !contains(list(row, "approvedSystems"), name) {
			return nil, 0, forbidden()
		}
	}
	expected := name + "." + a.Config.CloudSuffix
	if path == "/certificate/name" && str(req, "commonName") != expected {
		return nil, 0, forbidden()
	}
	csrText := str(req, "certificateSigningRequest")
	var privateKey, publicKey string
	if csrText == "" {
		if path == "/certificate/csr" {
			return nil, 0, bad("certificateSigningRequest required")
		}
		key, e := rsa.GenerateKey(rand.Reader, 2048)
		if e != nil {
			return nil, 0, e
		}
		der, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: expected}}, key)
		if e != nil {
			return nil, 0, e
		}
		csrText = base64.StdEncoding.EncodeToString(der)
		privateKey = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
		pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		publicKey = base64.StdEncoding.EncodeToString(pub)
	} else {
		data, e := base64.StdEncoding.DecodeString(csrText)
		if block, _ := pem.Decode([]byte(csrText)); block != nil {
			data = block.Bytes
			e = nil
		}
		if e != nil {
			return nil, 0, bad("Invalid CSR")
		}
		csr, e := x509.ParseCertificateRequest(data)
		if e != nil || csr.CheckSignature() != nil || csr.Subject.CommonName != expected {
			return nil, 0, bad("CSR does not match approved name or signature")
		}
		pub, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
		publicKey = base64.StdEncoding.EncodeToString(pub)
	}
	// Persist a claim before issuing; concurrent steps for one device cannot issue conflicting credentials.
	claim := uuid()
	e = a.Store.Update(func(d database) error {
		current := d["enrollments"][device]
		if str(current, "state") == "OFFBOARDING" || str(current, "state") == "OFFBOARDED" {
			return forbidden()
		}
		if str(current, "claim") != "" {
			return &APIError{409, "An enrollment operation is already in progress"}
		}
		current["claim"] = claim
		return nil
	})
	if e != nil {
		return nil, 0, e
	}
	defer a.Store.Update(func(d database) error {
		if current := d["enrollments"][device]; current != nil && str(current, "claim") == claim {
			delete(current, "claim")
		}
		return nil
	})
	var signed Document
	e = a.consume(r.Context(), "CertificateAuthority", "POST", "/certificate-authority/sign", Document{"encodedCSR": csrText, "profile": profileName, "addresses": req["addresses"]}, &signed)
	if e != nil {
		return nil, 0, e
	}
	committed := false
	defer func() {
		if !committed {
			_ = a.consume(r.Context(), "CertificateAuthority", "DELETE", "/certificate-authority/mgmt/certificates/"+fmt.Sprint(signed["id"]), nil, nil)
		}
	}()
	result := Document{"certificateFormat": "X509", "certificateType": kind, "publicKey": publicKey, "expiresAt": signed["validBefore"]}
	if chain := list(signed, "certificateChain"); len(chain) > 0 {
		result["certificate"] = chain[0]
	} else {
		return nil, 0, &APIError{502, "CA returned no certificate chain"}
	}
	if privateKey != "" {
		result["privateKey"] = privateKey
	}
	credentials := Document{}
	if path == "/device" {
		payload := Document{"devices": []Document{{"name": device, "addresses": req["addresses"], "metadata": req["metadata"]}}}
		e = a.Remote.Call(r.Context(), "registry", "POST", "/serviceregistry/mgmt/devices", payload, nil)
		var ae *APIError
		if errors.As(e, &ae) && ae.Status == 400 {
			// re-onboarding: the registry refuses to create an existing device (it may still host systems), so the
			// device record is updated instead; the original error stands if the update fails too
			if a.Remote.Call(r.Context(), "registry", "PUT", "/serviceregistry/mgmt/devices", payload, nil) == nil {
				e = nil
			}
		}
		if e != nil {
			return nil, 0, e
		}
	}
	if path == "/system" {
		passwordBytes := make([]byte, 32)
		if _, e = rand.Read(passwordBytes); e != nil {
			return nil, 0, e
		}
		credentials["password"] = base64.RawURLEncoding.EncodeToString(passwordBytes)
		identities := Document{"authenticationMethod": "PASSWORD", "identities": []Document{{"systemName": name, "credentials": credentials, "sysop": false}}}
		e = a.Remote.Call(r.Context(), "authentication", "POST", "/authentication/mgmt/identities", identities, nil)
		var ae *APIError
		if errors.As(e, &ae) && ae.Status == 409 {
			// re-onboarding of an approved system: its identity gets the new credentials (sessions are invalidated)
			if a.Remote.Call(r.Context(), "authentication", "PUT", "/authentication/mgmt/identities", identities, nil) == nil {
				e = nil
			}
		}
		if e != nil {
			return nil, 0, e
		}
		// The system registers itself (systemDiscovery register with its sy certificate and identity token, step 5 of
		// the onboarding procedure); a registry entry created here would make that registration fail on its metadata.
	}
	e = a.Store.Update(func(d database) error {
		current := d["enrollments"][device]
		if str(current, "claim") != claim || str(current, "state") == "OFFBOARDED" {
			return forbidden()
		}
		switch profileName {
		case "on":
			current["onboardingCertificateId"] = signed["id"]
			current["onboardingSerial"] = signed["serialNumber"]
			current["state"] = "ONBOARDING_CERTIFICATE_ISSUED"
		case "de":
			current["deviceCertificateId"] = signed["id"]
			current["deviceSerial"] = signed["serialNumber"]
			current["state"] = "DEVICE_REGISTERED"
		case "sy":
			bucket(d, "issuedSystems")[name] = Document{"systemName": name, "deviceName": device, "certificateId": signed["id"], "certificateExpiresAt": signed["validBefore"], "issuedAt": now()}
		}
		current["updatedAt"] = now()
		return nil
	})
	if e != nil {
		return nil, 0, e
	}
	committed = true
	if profileName == "sy" {
		return Document{"systemName": name, "deviceName": device, "certificateChain": signed["certificateChain"], "systemCertificate": result, "authenticationMethod": "PASSWORD", "credentials": credentials, "services": []any{}, "nextStep": "Log in to Authentication using the system certificate and issued credentials"}, 200, nil
	}
	if profileName == "de" {
		return Document{"deviceName": device, "certificateChain": signed["certificateChain"], "deviceCertificate": result, "approvedSystems": row["approvedSystems"], "nextStep": "POST /onboarding/system"}, 200, nil
	}
	return Document{"certificateChain": signed["certificateChain"], "onboardingCertificate": result, "services": []any{}, "nextStep": "POST /onboarding/device"}, 200, nil
}
func (a *App) offboard(r *http.Request, device string) (Document, error) {
	row, e := a.row("enrollments", device)
	if e != nil {
		return nil, e
	}
	if str(row, "claim") != "" {
		return nil, &APIError{409, "Enrollment operation in progress"}
	}
	if e = a.Store.Update(func(d database) error {
		if str(d["enrollments"][device], "claim") != "" {
			return &APIError{409, "Enrollment operation in progress"}
		}
		d["enrollments"][device]["state"] = "OFFBOARDING"
		return nil
	}); e != nil {
		return nil, e
	}
	completed, failed := []string{}, []string{}
	do := func(label string, fn func() error) {
		if fn() != nil {
			failed = append(failed, label)
		} else {
			completed = append(completed, label)
		}
	}
	for _, system := range a.rows("issuedSystems") {
		if str(system, "deviceName") != device {
			continue
		}
		name := str(system, "systemName")
		do("identity:"+name, func() error {
			return a.Remote.Call(r.Context(), "authentication", "DELETE", "/authentication/mgmt/identities?names="+url.QueryEscape(name), nil, nil)
		})
		do("system:"+name, func() error {
			return a.Remote.Call(r.Context(), "registry", "DELETE", "/serviceregistry/mgmt/systems?names="+url.QueryEscape(name), nil, nil)
		})
		do("certificate:"+name, func() error {
			return a.consume(r.Context(), "CertificateAuthority", "DELETE", "/certificate-authority/mgmt/certificates/"+fmt.Sprint(system["certificateId"]), nil, nil)
		})
	}
	if row["deviceCertificateId"] != nil {
		do("device-certificate", func() error {
			return a.consume(r.Context(), "CertificateAuthority", "DELETE", "/certificate-authority/mgmt/certificates/"+fmt.Sprint(row["deviceCertificateId"]), nil, nil)
		})
	}
	if row["onboardingCertificateId"] != nil {
		do("onboarding-certificate", func() error {
			return a.consume(r.Context(), "CertificateAuthority", "DELETE", "/certificate-authority/mgmt/certificates/"+fmt.Sprint(row["onboardingCertificateId"]), nil, nil)
		})
	}
	do("device-registry", func() error {
		return a.Remote.Call(r.Context(), "registry", "DELETE", "/serviceregistry/mgmt/devices?names="+url.QueryEscape(device), nil, nil)
	})
	e = a.Store.Update(func(d database) error {
		row := d["enrollments"][device]
		if len(failed) == 0 {
			row["state"] = "OFFBOARDED"
			// every system of the device is withdrawn (identity, registration, certificate)
			for name, system := range d["issuedSystems"] {
				if str(system, "deviceName") == device {
					delete(d["issuedSystems"], name)
				}
			}
		}
		row["updatedAt"] = now()
		row["lastMessage"] = strings.Join(failed, ",")
		return nil
	})
	return Document{"deviceName": device, "completed": completed, "failed": failed}, e
}
