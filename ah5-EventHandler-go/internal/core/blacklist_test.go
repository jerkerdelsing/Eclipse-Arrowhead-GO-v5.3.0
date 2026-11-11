// SPDX-License-Identifier: EPL-2.0
package core

import (
	"context"
	"testing"
)

// J12: no Blacklist URL, Blacklist itself, excluded systems and the system itself are never checked; an unreachable Blacklist refuses.
func TestCheckBlacklistScope(t *testing.T) {
	a := &App{Config: Config{Name: "TranslationManager"}}
	if a.checkBlacklist(context.Background(), "Consumer") != nil {
		t.Fatal("filter active without blacklistURL")
	}
	a.Config.BlacklistURL = "https://127.0.0.1:1"
	a.Config.BlacklistExclude = []string{"ServiceRegistry"}
	a.Remote = NewRemote(a.Config, nil)
	for _, name := range []string{"Blacklist", "ServiceRegistry", "TranslationManager"} {
		if a.checkBlacklist(context.Background(), name) != nil {
			t.Fatalf("%s must not be checked", name)
		}
	}
	if a.checkBlacklist(context.Background(), "Consumer") == nil {
		t.Fatal("unreachable Blacklist must refuse (fail closed)")
	}
	a.Config.BlacklistOptional = true
	a.Remote = NewRemote(a.Config, nil)
	if a.checkBlacklist(context.Background(), "Consumer") != nil {
		t.Fatal("blacklistOptional must let the request through")
	}
}
