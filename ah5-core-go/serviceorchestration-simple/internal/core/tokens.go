// SPDX-License-Identifier: EPL-2.0
package core

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type textResponse string

func (a *App) tokenSecret() (string, error) {
	s, e := readSecret(a.Config.TokenSecretFile)
	if e != nil {
		return "", e
	}
	if len(s) < 32 {
		return "", errors.New("token secret must contain at least 32 bytes")
	}
	return s, nil
}
func (a *App) tokenReference(token string) (string, error) {
	s, e := a.tokenSecret()
	if e != nil {
		return "", e
	}
	mac := hmac.New(sha256.New, []byte(s))
	mac.Write([]byte(token))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil)), nil
}
func (a *App) sealKey(provider, key string) (string, error) {
	s, e := a.tokenSecret()
	if e != nil {
		return "", e
	}
	k := sha256.Sum256([]byte(s))
	block, e := aes.NewCipher(k[:])
	if e != nil {
		return "", e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, e = rand.Read(nonce); e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(gcm.Seal(nonce, nonce, []byte(key), []byte(provider))), nil
}
func (a *App) openKey(provider, sealed string) (string, error) {
	s, e := a.tokenSecret()
	if e != nil {
		return "", e
	}
	k := sha256.Sum256([]byte(s))
	block, e := aes.NewCipher(k[:])
	if e != nil {
		return "", e
	}
	gcm, e := cipher.NewGCM(block)
	if e != nil {
		return "", e
	}
	data, e := base64.StdEncoding.DecodeString(sealed)
	if e != nil || len(data) < gcm.NonceSize() {
		return "", errors.New("invalid sealed key")
	}
	plain, e := gcm.Open(nil, data[:gcm.NonceSize()], data[gcm.NonceSize():], []byte(provider))
	return string(plain), e
}
func encryptWire(token, key, algorithm, iv string) (string, error) {
	block, e := aes.NewCipher([]byte(key))
	if e != nil {
		return "", e
	}
	plain := []byte(token)
	padding := aes.BlockSize - len(plain)%aes.BlockSize
	for i := 0; i < padding; i++ {
		plain = append(plain, byte(padding))
	}
	out := make([]byte, len(plain))
	if algorithm == "AES/CBC/PKCS5Padding" {
		nonce, e := base64.StdEncoding.DecodeString(iv)
		if e != nil || len(nonce) != aes.BlockSize {
			return "", errors.New("invalid IV")
		}
		cipher.NewCBCEncrypter(block, nonce).CryptBlocks(out, plain)
	} else if algorithm == "AES/ECB/PKCS5Padding" {
		for i := 0; i < len(plain); i += aes.BlockSize {
			block.Encrypt(out[i:i+aes.BlockSize], plain[i:i+aes.BlockSize])
		}
	} else {
		return "", bad("Unsupported encryption algorithm")
	}
	return base64.StdEncoding.EncodeToString(out), nil
}
func (a *App) generateToken(d database, req Document, requester string) (Document, error) {
	if str(req, "consumer") == "" {
		req["consumer"] = requester
	}
	if str(req, "consumerCloud") == "" {
		req["consumerCloud"] = "LOCAL"
	}
	if e := require(req, "provider", "consumer", "target", "targetType", "tokenVariant"); e != nil {
		return nil, e
	}
	variant := str(req, "tokenVariant")
	typ := "SELF_CONTAINED_TOKEN"
	limit := any(nil)
	expiry := any(nil)
	var raw string
	expiration := time.Now().UTC().Add(time.Duration(a.Config.TokenTTL) * time.Second)
	if s := str(req, "expiresAt"); s != "" {
		t, e := time.Parse(time.RFC3339Nano, s)
		if e != nil || !t.After(time.Now()) {
			return nil, bad("expiresAt must be in the future")
		}
		expiration = t
	}
	switch variant {
	case "USAGE_LIMITED_TOKEN_AUTH", "TIME_LIMITED_TOKEN_AUTH":
		b := make([]byte, 32)
		if _, e := rand.Read(b); e != nil {
			return nil, e
		}
		raw = base64.URLEncoding.EncodeToString(b)
		if variant == "USAGE_LIMITED_TOKEN_AUTH" {
			typ = "USAGE_LIMITED_TOKEN"
			n := number(req, "usageLimit", a.Config.TokenUsage)
			if n < 1 {
				return nil, bad("usageLimit must be positive")
			}
			limit = n
		} else {
			typ = "TIME_LIMITED_TOKEN"
			expiry = expiration.Format(time.RFC3339Nano)
		}
	case "BASE64_SELF_CONTAINED_TOKEN_AUTH":
		content := strings.Join([]string{str(req, "consumerCloud"), str(req, "consumer"), str(req, "provider"), str(req, "target"), str(req, "scope"), str(req, "targetType"), expiration.Format(time.RFC3339Nano)}, "|")
		raw = base64.URLEncoding.EncodeToString([]byte(content))
		expiry = expiration.Format(time.RFC3339Nano)
	case "RSA_SHA256_JSON_WEB_TOKEN_AUTH", "RSA_SHA512_JSON_WEB_TOKEN_AUTH":
		if a.TLS == nil || len(a.TLS.Certificates) == 0 {
			return nil, bad("RSA server certificate required")
		}
		key, ok := a.TLS.Certificates[0].PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, bad("RSA server certificate required")
		}
		algorithm := "RS256"
		hash := crypto.SHA256
		if variant == "RSA_SHA512_JSON_WEB_TOKEN_AUTH" {
			algorithm = "RS512"
			hash = crypto.SHA512
		}
		header, _ := json.Marshal(Document{"typ": "JWT", "alg": algorithm})
		claims := Document{"jti": uuid(), "iss": a.Config.Name, "iat": time.Now().Unix(), "nbf": time.Now().Add(-time.Minute).Unix(), "exp": expiration.Unix(), "psn": req["provider"], "csn": req["consumer"], "ccn": req["consumerCloud"], "tat": req["targetType"], "tan": req["target"]}
		if s := str(req, "scope"); s != "" {
			claims["sco"] = s
		}
		payload, _ := json.Marshal(claims)
		raw = base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
		var sum []byte
		if hash == crypto.SHA256 {
			h := sha256.Sum256([]byte(raw))
			sum = h[:]
		} else {
			h := sha512.Sum512([]byte(raw))
			sum = h[:]
		}
		sig, e := rsa.SignPKCS1v15(rand.Reader, key, hash, sum)
		if e != nil {
			return nil, e
		}
		raw += "." + base64.RawURLEncoding.EncodeToString(sig)
		expiry = expiration.Format(time.RFC3339Nano)
	default:
		return nil, bad("Unsupported tokenVariant")
	}
	ref, e := a.tokenReference(raw)
	if e != nil {
		return nil, e
	}
	row := Document{"tokenType": typ, "variant": variant, "tokenReference": ref, "requester": requester, "consumerCloud": req["consumerCloud"], "consumer": req["consumer"], "provider": req["provider"], "targetType": req["targetType"], "target": req["target"], "scope": req["scope"], "createdAt": now(), "usageLimit": limit, "usageLeft": limit, "expiresAt": expiry, "token": nil}
	bucket(d, "tokens")[ref] = row
	if typ == "SELF_CONTAINED_TOKEN" {
		if record := d["encryptionKeys"][str(req, "provider")]; record != nil {
			key, e := a.openKey(str(req, "provider"), str(record, "sealedKey"))
			if e != nil {
				return nil, e
			}
			raw, e = encryptWire(raw, key, str(record, "algorithm"), str(record, "keyAdditive"))
			if e != nil {
				return nil, e
			}
		}
	}
	result := Document{}
	for k, v := range row {
		result[k] = v
	}
	result["token"] = raw
	return result, nil
}
func (a *App) registerKey(d database, provider string, req Document) (Document, error) {
	algorithm := str(req, "algorithm")
	if algorithm == "" {
		algorithm = "AES/ECB/PKCS5Padding"
	}
	if algorithm != "AES/ECB/PKCS5Padding" && algorithm != "AES/CBC/PKCS5Padding" {
		return nil, bad("Unsupported encryption algorithm")
	}
	if !validName(provider) {
		return nil, bad("Invalid systemName")
	}
	key := str(req, "key")
	if _, e := aes.NewCipher([]byte(key)); e != nil {
		return nil, bad("AES key must contain 16, 24 or 32 UTF-8 bytes")
	}
	sealed, e := a.sealKey(provider, key)
	if e != nil {
		return nil, e
	}
	iv := ""
	if algorithm == "AES/CBC/PKCS5Padding" {
		b := make([]byte, 16)
		if _, e = rand.Read(b); e != nil {
			return nil, e
		}
		iv = base64.StdEncoding.EncodeToString(b)
	}
	row := Document{"systemName": provider, "sealedKey": sealed, "algorithm": algorithm, "keyAdditive": iv, "createdAt": now()}
	bucket(d, "encryptionKeys")[provider] = row
	return Document{"systemName": provider, "rawKey": key, "algorithm": algorithm, "keyAdditive": iv, "createdAt": row["createdAt"]}, nil
}
func (a *App) tokenRoutes() {
	base := "/consumerauthorization/authorization-token"
	mgmt := "/consumerauthorization/authorization/mgmt/token"
	a.route("POST", base+"/generate", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		req["consumer"] = caller(r).Name
		req["cloud"] = "LOCAL"
		req["consumerCloud"] = "LOCAL"
		yes, e := a.granted(r, req)
		if e != nil {
			return nil, 0, e
		}
		if !yes {
			return nil, 0, forbidden()
		}
		var result Document
		e = a.Store.Update(func(d database) error { result, e = a.generateToken(d, req, caller(r).Name); return e })
		if e != nil {
			return nil, 0, e
		}
		return Document{"tokenType": result["tokenType"], "targetType": result["targetType"], "token": result["token"], "usageLimit": result["usageLimit"], "expiresAt": result["expiresAt"]}, 200, nil
	})
	a.route("GET", base+"/token/verify/{token}", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		ref, e := a.tokenReference(r.PathValue("token"))
		if e != nil {
			return nil, 0, e
		}
		result := Document{"verified": false, "consumerCloud": nil, "consumer": nil, "targetType": nil, "target": nil, "scope": nil}
		e = a.Store.Update(func(d database) error {
			row := d["tokens"][ref]
			if row == nil || str(row, "provider") != caller(r).Name {
				return nil
			}
			if str(row, "tokenType") == "SELF_CONTAINED_TOKEN" {
				return bad("Self-contained tokens must be verified by the provider, not this operation")
			}
			if str(row, "tokenType") == "TIME_LIMITED_TOKEN" {
				if expired(str(row, "expiresAt")) {
					return nil
				}
			} else {
				n := number(row, "usageLeft", 0)
				if n <= 0 {
					return nil
				}
				row["usageLeft"] = n - 1
			}
			result = Document{"verified": true, "consumerCloud": row["consumerCloud"], "consumer": row["consumer"], "targetType": row["targetType"], "target": row["target"], "scope": row["scope"]}
			return nil
		})
		return result, 200, e
	})
	a.route("GET", base+"/public-key", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		if a.TLS == nil || len(a.TLS.Certificates) == 0 {
			return nil, 0, &APIError{404, "Public key unavailable"}
		}
		c, e := x509.ParseCertificate(a.TLS.Certificates[0].Certificate[0])
		if e != nil {
			return nil, 0, e
		}
		b, e := x509.MarshalPKIXPublicKey(c.PublicKey)
		return textResponse(base64.StdEncoding.EncodeToString(b)), 200, e
	})
	a.route("POST", base+"/encryption-key", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		var row Document
		e = a.Store.Update(func(d database) error { row, e = a.registerKey(d, caller(r).Name, req); return e })
		return textResponse(str(row, "keyAdditive")), 200, e
	})
	a.route("DELETE", base+"/encryption-key", "identity", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		found := false
		e := a.Store.Update(func(d database) error {
			found = d["encryptionKeys"][caller(r).Name] != nil
			delete(bucket(d, "encryptionKeys"), caller(r).Name)
			return nil
		})
		return found, 200, e
	})
	a.route("POST", mgmt+"/generate", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		if r.URL.Query().Get("unbound") == "true" {
			return nil, 0, forbidden()
		}
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		items := list(req, "list")
		if len(items) == 0 || len(items) > 100 {
			return nil, 0, bad("list must contain 1–100 requests")
		}
		// As in the Java AuthorizationTokenManagementService, requests without a matching policy
		// (looked up for the consumer's cloud) are dropped rather than failing the whole batch.
		authorized := []Document{}
		for _, v := range items {
			row, ok := v.(map[string]any)
			if !ok {
				return nil, 0, bad("Invalid token request")
			}
			cloud, e := normalizeCloudIdentifier(str(row, "consumerCloud"))
			if e != nil {
				return nil, 0, e
			}
			row["consumerCloud"] = cloud
			row["cloud"] = cloud
			yes, e := a.granted(r, row)
			if e != nil {
				return nil, 0, e
			}
			if yes {
				authorized = append(authorized, row)
			}
		}
		rows := []Document{}
		e = a.Store.Update(func(d database) error {
			for _, v := range authorized {
				row, e := a.generateToken(d, v, caller(r).Name)
				if e != nil {
					return e
				}
				rows = append(rows, row)
			}
			return nil
		})
		return Document{"entries": rows, "count": len(rows)}, 200, e
	})
	a.route("POST", mgmt+"/query", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		rows := []Document{}
		e = a.Store.View(func(d database) error {
			for _, row := range d["tokens"] {
				matches := true
				for _, k := range []string{"requester", "tokenType", "consumerCloud", "consumer", "provider", "targetType", "target"} {
					if str(req, k) != "" && str(req, k) != str(row, k) {
						matches = false
					}
				}
				if matches {
					rows = append(rows, row)
				}
			}
			return nil
		})
		if e != nil {
			return nil, 0, e
		}
		out, e := page(rows, req, "entries")
		return out, 200, e
	})
	a.route("DELETE", mgmt+"/revoke", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		refs, e := queryNames(r, "tokenReferences")
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for _, ref := range refs {
				delete(bucket(d, "tokens"), ref)
			}
			return nil
		})
		return nil, 200, e
	})
	a.route("POST", mgmt+"/encryption-key", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		req, e := decode(w, r)
		if e != nil {
			return nil, 0, e
		}
		if len(list(req, "list")) == 0 {
			return nil, 0, bad("list required")
		}
		rows := []Document{}
		e = a.Store.Update(func(d database) error {
			for _, v := range list(req, "list") {
				req, ok := v.(map[string]any)
				if !ok {
					return bad("Invalid encryption-key request")
				}
				row, e := a.registerKey(d, str(req, "systemName"), req)
				if e != nil {
					return e
				}
				rows = append(rows, row)
			}
			return nil
		})
		return Document{"entries": rows, "count": len(rows)}, 200, e
	})
	a.route("DELETE", mgmt+"/encryption-key", "management", func(w http.ResponseWriter, r *http.Request) (any, int, error) {
		names, e := queryNames(r, "systemNames")
		if e != nil {
			return nil, 0, e
		}
		e = a.Store.Update(func(d database) error {
			for _, name := range names {
				delete(bucket(d, "encryptionKeys"), name)
			}
			return nil
		})
		return nil, 200, e
	})
}

// normalizeCloudIdentifier follows the Java CloudIdentifierNormalizer/Validator: empty or "local"
// (any case) is the local cloud, anything else must be "<Cloud>|<Organization>" with valid names.
func normalizeCloudIdentifier(id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" || strings.EqualFold(id, "LOCAL") {
		return "LOCAL", nil
	}
	parts := strings.Split(id, "|")
	if len(parts) != 2 {
		return "", bad("The specified cloud identifier does not match the naming convention: " + id)
	}
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
		if !validName(parts[i]) {
			return "", bad("The specified cloud identifier does not match the naming convention: " + id)
		}
	}
	return strings.Join(parts, "|"), nil
}
