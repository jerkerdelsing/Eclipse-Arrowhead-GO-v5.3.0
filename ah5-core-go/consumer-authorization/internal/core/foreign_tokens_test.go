// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestNormalizeCloudIdentifier(t *testing.T) {
	for in, want := range map[string]string{"": "LOCAL", " local ": "LOCAL", "RemoteCloud|Org": "RemoteCloud|Org", " RemoteCloud | Org ": "RemoteCloud|Org"} {
		if got, e := normalizeCloudIdentifier(in); e != nil || got != want {
			t.Fatalf("%q: %q %v", in, got, e)
		}
	}
	for _, in := range []string{"RemoteCloud", "a|b|c", "Remote Cloud|Org", "|Org"} {
		if _, e := normalizeCloudIdentifier(in); e == nil {
			t.Fatalf("%q accepted", in)
		}
	}
}

func TestForeignConsumerTokenGeneration(t *testing.T) {
	f := isolatedCloud(t)
	const generate = "/consumerauthorization/authorization/mgmt/token/generate"
	f.call(t, "Sysop", "ConsumerAuthorization", f.authzURL, "POST", "/consumerauthorization/authorization/mgmt/grant", Document{"list": []Document{{"cloud": "RemoteCloud|Org", "provider": "Provider", "targetType": "SERVICE_DEF", "target": "temperature", "defaultPolicy": Document{"policyType": "WHITELIST", "policyList": []string{"ForeignConsumer"}}}}})
	request := func(cloud, consumer string) Document {
		return Document{"list": []Document{{"consumerCloud": cloud, "consumer": consumer, "provider": "Provider", "targetType": "SERVICE_DEF", "target": "temperature", "tokenVariant": "RSA_SHA256_JSON_WEB_TOKEN_AUTH"}}}
	}
	out := f.call(t, "Sysop", "ConsumerAuthorization", f.authzURL, "POST", generate, request("RemoteCloud|Org", "ForeignConsumer"))
	entries := list(out, "entries")
	if len(entries) != 1 {
		t.Fatal(out)
	}
	row := entries[0].(map[string]any)
	if str(row, "consumerCloud") != "RemoteCloud|Org" || str(row, "consumer") != "ForeignConsumer" {
		t.Fatal(row)
	}
	parts := strings.Split(str(row, "token"), ".")
	if len(parts) != 3 {
		t.Fatal(row)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims Document
	_ = json.Unmarshal(payload, &claims)
	if str(claims, "ccn") != "RemoteCloud|Org" || str(claims, "csn") != "ForeignConsumer" {
		t.Fatal(claims)
	}
	// A policy of another cloud or for another consumer grants nothing; like Java, the request is dropped.
	for _, tc := range [][2]string{{"OtherCloud|Org", "ForeignConsumer"}, {"RemoteCloud|Org", "Intruder"}, {"LOCAL", "ForeignConsumer"}} {
		out = f.call(t, "Sysop", "ConsumerAuthorization", f.authzURL, "POST", generate, request(tc[0], tc[1]))
		if len(list(out, "entries")) != 0 || number(out, "count", -1) != 0 {
			t.Fatalf("%v: %v", tc, out)
		}
	}
	c := f.clients["Sysop"]
	token, e := c.ownToken(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	var bad Document
	if e = c.request(context.Background(), "ConsumerAuthorization", f.authzURL, "POST", generate, token, request("NoOrganization", "ForeignConsumer"), &bad); !isStatus(e, 400) {
		t.Fatalf("malformed cloud: %v %v", e, bad)
	}
}

func isStatus(e error, status int) bool {
	var api *APIError
	return errors.As(e, &api) && api.Status == status
}
