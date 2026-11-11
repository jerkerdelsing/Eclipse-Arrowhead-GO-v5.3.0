// SPDX-License-Identifier: EPL-2.0
package core

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"encoding/base64"
)

func verifyTestJWT(cert tls.Certificate, parts []string, variant string) error {
	input := []byte(parts[0] + "." + parts[1])
	hash := crypto.SHA256
	h := sha256.Sum256(input)
	sum := h[:]
	if variant == "RSA_SHA512_JSON_WEB_TOKEN_AUTH" {
		hash = crypto.SHA512
		h := sha512.Sum512(input)
		sum = h[:]
	}
	sig, e := base64.RawURLEncoding.DecodeString(parts[2])
	if e != nil {
		return e
	}
	return rsa.VerifyPKCS1v15(&cert.PrivateKey.(*rsa.PrivateKey).PublicKey, hash, sum, sig)
}
