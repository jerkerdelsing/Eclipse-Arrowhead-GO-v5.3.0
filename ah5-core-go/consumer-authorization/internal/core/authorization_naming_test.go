// SPDX-License-Identifier: EPL-2.0
package core

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func namingGrant() Document {
	return Document{"provider": "TestProvider", "cloud": "LOCAL", "targetType": "SERVICE_DEF", "target": "testSignal", "defaultPolicy": Document{"policyType": "WHITELIST", "policyList": []any{"TestConsumer"}}, "scopedPolicies": Document{"read-value": Document{"policyType": "ALL"}}}
}

func TestAuthorizationGrantCanonicalNames(t *testing.T) {
	tests := []struct {
		field, value string
		valid        bool
	}{
		{"provider", "S", true}, {"provider", "System2", true}, {"provider", strings.Repeat("S", 63), true},
		{"provider", "lowercase", false}, {"provider", "bad_provider", false}, {"provider", "Bad-Provider", false}, {"provider", "System\n", false}, {"provider", "Systém", false}, {"provider", strings.Repeat("S", 64), false},
		{"target", "s", true}, {"target", "service2Value", true}, {"target", strings.Repeat("s", 63), true},
		{"target", "Uppercase", false}, {"target", "bad_signal", false}, {"target", "bad-signal", false}, {"target", "signal\n", false}, {"target", "sıgnal", false}, {"target", strings.Repeat("s", 64), false},
		{"scope", "r", true}, {"scope", "read-value2", true}, {"scope", strings.Repeat("r", 63), true},
		{"scope", "Uppercase", false}, {"scope", "bad_scope", false}, {"scope", "badScope", false}, {"scope", "-read", false}, {"scope", "read-", false}, {"scope", "read--value", false}, {"scope", "1read", false}, {"scope", "read\n", false}, {"scope", "réad", false}, {"scope", strings.Repeat("r", 64), false},
	}
	for _, typ := range []string{"SERVICE_DEF", "EVENT_TYPE"} {
		for i, tc := range tests {
			t.Run(fmt.Sprintf("%s/%s/%02d", typ, tc.field, i), func(t *testing.T) {
				req := namingGrant()
				req["targetType"] = typ
				if tc.field == "scope" {
					req["scopedPolicies"] = Document{tc.value: Document{"policyType": "ALL"}}
				} else {
					req[tc.field] = tc.value
				}
				d := database{}
				row, _, err := grantRow(d, req, "MGMT", "TestOperator")
				if !tc.valid {
					if err == nil {
						t.Fatal("noncanonical policy name accepted", tc.field, tc.value)
					}
					if len(d["policies"]) != 0 {
						t.Fatal("invalid grant modified policy store")
					}
					return
				}
				if err != nil {
					t.Fatal("canonical policy name rejected", err)
				}
				if tc.field != "scope" && str(row, tc.field) != tc.value {
					t.Fatal("identity silently rewritten")
				}
			})
		}
	}
}

func TestAuthorizationGrantPolicyListCanonicalNames(t *testing.T) {
	for _, kind := range []string{"WHITELIST", "BLACKLIST"} {
		for _, name := range []string{"lowercase", "bad_consumer", "Bad-Consumer", "Consumer\n", "Cónsumer", strings.Repeat("C", 64)} {
			t.Run(kind+"/"+name, func(t *testing.T) {
				req := namingGrant()
				req["defaultPolicy"] = Document{"policyType": kind, "policyList": []any{"TestConsumer", name}}
				d := database{}
				if _, _, err := grantRow(d, req, "MGMT", "TestOperator"); err == nil {
					t.Fatal("noncanonical list identity accepted")
				}
				if len(d["policies"]) != 0 {
					t.Fatal("invalid policy list changed store")
				}
			})
		}
	}
}

func TestAuthorizationGrantInvalidNameBatchRollsBack(t *testing.T) {
	store, err := OpenStore("")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Update(func(d database) error { _, _, e := grantRow(d, namingGrant(), "MGMT", "TestOperator"); return e }); err != nil {
		t.Fatal(err)
	}
	var before database
	if err := store.View(func(d database) error { before = d; return nil }); err != nil {
		t.Fatal(err)
	}
	err = store.Update(func(d database) error {
		req := namingGrant()
		req["target"] = "anotherSignal"
		if _, _, e := grantRow(d, req, "MGMT", "TestOperator"); e != nil {
			return e
		}
		req = namingGrant()
		req["provider"] = "bad_provider"
		_, _, e := grantRow(d, req, "MGMT", "TestOperator")
		return e
	})
	if err == nil {
		t.Fatal("mixed valid/invalid batch accepted")
	}
	if err := store.View(func(d database) error {
		if !reflect.DeepEqual(d, before) {
			t.Fatal("failed batch changed existing policies")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
