// SPDX-License-Identifier: EPL-2.0
// HTTP contracts and session semantics derived from ah5-core-java-spring 5.2.2
// (AITIA / Arrowhead Consortia, EPL-2.0).
package core

import (
	"crypto/sha256"
	"encoding/hex"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"strings"
	"time"
)

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func passwordHash(d Document) (string, error) {
	p := str(d, "password")
	if p == "" || len(p) > 72 || len(d) != 1 {
		return "", bad("PASSWORD credentials require only a password of 1–72 bytes")
	}
	b, e := bcrypt.GenerateFromPassword([]byte(p), 10)
	return string(b), e
}
func publicIdentity(d Document) Document {
	return Document{"systemName": d["systemName"], "authenticationMethod": "PASSWORD", "sysop": d["sysop"], "createdBy": d["createdBy"], "createdAt": d["createdAt"], "updatedBy": d["updatedBy"], "updatedAt": d["updatedAt"]}
}
func deleteSessions(d database, name string) {
	for k, s := range bucket(d, "sessions") {
		if str(s, "systemName") == name {
			delete(d["sessions"], k)
		}
	}
}
func (a *App) Bootstrap() error {
	if a.Config.BootstrapPasswordFile == "" {
		return nil
	}
	name := a.Config.BootstrapName
	if name == "" {
		name = "Sysop"
	}
	if !validName(name) {
		return bad("Invalid bootstrap name")
	}
	var count int
	_ = a.Store.View(func(d database) error { count = len(d["identities"]); return nil })
	if count > 0 {
		return nil
	}
	p, e := readSecret(a.Config.BootstrapPasswordFile)
	if e != nil {
		return e
	}
	hash, e := passwordHash(Document{"password": p})
	if e != nil {
		return e
	}
	return a.Store.Update(func(d database) error {
		if len(d["identities"]) != 0 {
			return nil
		}
		bucket(d, "identities")[name] = Document{"systemName": name, "credentialHash": hash, "sysop": true, "createdBy": "bootstrap", "createdAt": now(), "updatedBy": nil, "updatedAt": nil}
		return nil
	})
}
func (a *App) verifyIdentity(token string) (Document, error) {
	out := Document{"verified": false, "systemName": nil, "sysop": nil, "loginTime": nil, "expirationTime": nil}
	e := a.Store.View(func(d database) error {
		s := d["sessions"][digest(token)]
		if s == nil || expired(str(s, "expirationTime")) {
			return nil
		}
		identity := d["identities"][str(s, "systemName")]
		if identity == nil {
			return nil
		}
		out = Document{"verified": true, "systemName": s["systemName"], "sysop": identity["sysop"], "loginTime": s["loginTime"], "expirationTime": s["expirationTime"]}
		return nil
	})
	return out, e
}
func credentialCheck(d database, name string, credentials Document) error {
	row := d["identities"][name]
	if row == nil || bcrypt.CompareHashAndPassword([]byte(str(row, "credentialHash")), []byte(str(credentials, "password"))) != nil {
		return &APIError{401, "Invalid name and/or credentials"}
	}
	return nil
}
func (a *App) authenticationRoutes() {
	for _, operation := range []string{"login", "logout", "change"} {
		op := operation
		a.route("POST", "/authentication/identity/"+op, "certificate", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			req, e := decode(w, r)
			if e != nil {
				return nil, 0, e
			}
			name := str(req, "systemName")
			if !validName(name) || name != caller(r).Name {
				return nil, 0, &APIError{401, "Credentials must belong to the client certificate identity"}
			}
			var result any
			e = a.Store.Update(func(d database) error {
				if e := credentialCheck(d, name, obj(req, "credentials")); e != nil {
					return e
				}
				switch op {
				case "login":
					token := uuid()
					expiration := time.Now().UTC().Add(time.Duration(a.Config.IdentityTTL) * time.Second).Format(time.RFC3339Nano)
					deleteSessions(d, name)
					bucket(d, "sessions")[digest(token)] = Document{"systemName": name, "loginTime": now(), "expirationTime": expiration}
					result = Document{"token": token, "expirationTime": expiration}
				case "logout":
					deleteSessions(d, name)
				case "change":
					hash, e := passwordHash(obj(req, "newCredentials"))
					if e != nil {
						return e
					}
					row := d["identities"][name]
					row["credentialHash"] = hash
					row["updatedAt"] = now()
					row["updatedBy"] = name
					deleteSessions(d, name)
				}
				return nil
			})
			return result, 200, e
		})
	}
	a.route("GET", "/authentication/identity/verify/{token}", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		v, e := a.verifyIdentity(r.PathValue("token"))
		return v, 200, e
	})
	for _, method := range []string{"POST", "PUT"} {
		m := method
		a.route(m, "/authentication/mgmt/identities", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			req, e := decode(w, r)
			if e != nil {
				return nil, 0, e
			}
			items := list(req, "identities")
			if len(items) == 0 || len(items) > 100 {
				return nil, 0, bad("identities must contain 1–100 items")
			}
			if m == "POST" && str(req, "authenticationMethod") != "PASSWORD" {
				return nil, 0, bad("Only PASSWORD authentication is supported by the Java reference")
			}
			rows := []Document{}
			e = a.Store.Update(func(d database) error {
				seen := map[string]bool{}
				for _, item := range items {
					row, ok := item.(map[string]any)
					if !ok {
						return bad("Invalid identity")
					}
					name := str(row, "systemName")
					if !validName(name) || seen[name] {
						return bad("Invalid or duplicate systemName")
					}
					seen[name] = true
					existing := bucket(d, "identities")[name]
					if m == "POST" && existing != nil {
						return &APIError{409, "Identity already exists"}
					}
					if m == "PUT" && existing == nil {
						return &APIError{404, "Identity not found"}
					}
					if existing == nil {
						existing = Document{"systemName": name, "createdBy": caller(r).Name, "createdAt": now(), "updatedBy": nil, "updatedAt": nil}
					}
					if m == "POST" || row["credentials"] != nil {
						hash, e := passwordHash(obj(row, "credentials"))
						if e != nil {
							return e
						}
						existing["credentialHash"] = hash
					}
					if row["sysop"] != nil {
						b, ok := row["sysop"].(bool)
						if !ok {
							return bad("sysop must be boolean")
						}
						existing["sysop"] = b
					} else if m == "POST" {
						existing["sysop"] = false
					}
					if m == "PUT" {
						existing["updatedBy"] = caller(r).Name
						existing["updatedAt"] = now()
						deleteSessions(d, name)
					}
					bucket(d, "identities")[name] = existing
					rows = append(rows, publicIdentity(existing))
				}
				return nil
			})
			status := 200
			if m == "POST" {
				status = 201
			}
			return Document{"identities": rows, "count": len(rows)}, status, e
		})
	}
	a.route("DELETE", "/authentication/mgmt/identities", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		names, e := queryNames(r, "names")
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for _, name := range names {
				delete(bucket(d, "identities"), name)
				deleteSessions(d, name)
			}
			return nil
		})
		return nil, 200, e
	})
	a.route("DELETE", "/authentication/mgmt/sessions", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		names, e := queryNames(r, "names")
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for _, name := range names {
				deleteSessions(d, name)
			}
			return nil
		})
		return nil, 200, e
	})
	for _, kind := range []string{"identities", "sessions"} {
		k := kind
		path := "/authentication/mgmt/identities/query"
		if k == "sessions" {
			path = "/authentication/mgmt/sessions"
		}
		a.route("POST", path, "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
			req, e := decode(w, r)
			if e != nil {
				return nil, 0, e
			}
			for _, field := range []string{"creationFrom", "creationTo", "loginFrom", "loginTo"} {
				if s := str(req, field); s != "" {
					if _, e = time.Parse(time.RFC3339Nano, s); e != nil {
						return nil, 0, bad("Invalid " + field)
					}
				}
			}
			entries := []Document{}
			e = a.Store.View(func(d database) error {
				for _, row := range bucket(d, k) {
					name := str(row, "systemName")
					if !strings.Contains(strings.ToLower(name), strings.ToLower(str(req, "namePart"))) {
						continue
					}
					if k == "sessions" {
						if expired(str(row, "expirationTime")) || !timeRange(str(row, "loginTime"), str(req, "loginFrom"), str(req, "loginTo")) {
							continue
						}
						entries = append(entries, row)
					} else {
						if req["isSysop"] != nil && req["isSysop"] != row["sysop"] {
							continue
						}
						if s := str(req, "createdBy"); s != "" && s != str(row, "createdBy") {
							continue
						}
						if !timeRange(str(row, "createdAt"), str(req, "creationFrom"), str(req, "creationTo")) {
							continue
						}
						if req["hasSession"] != nil {
							has := false
							for _, session := range d["sessions"] {
								if str(session, "systemName") == name && !expired(str(session, "expirationTime")) {
									has = true
								}
							}
							if req["hasSession"] != has {
								continue
							}
						}
						entries = append(entries, publicIdentity(row))
					}
				}
				return nil
			})
			if e != nil {
				return nil, 0, e
			}
			out, e := page(entries, req, k)
			return out, 200, e
		})
	}
}
func timeRange(value, from, to string) bool {
	v, e := time.Parse(time.RFC3339Nano, value)
	if e != nil {
		return false
	}
	if from != "" {
		f, e := time.Parse(time.RFC3339Nano, from)
		if e != nil || v.Before(f) {
			return false
		}
	}
	if to != "" {
		t, e := time.Parse(time.RFC3339Nano, to)
		if e != nil || v.After(t) {
			return false
		}
	}
	return true
}
