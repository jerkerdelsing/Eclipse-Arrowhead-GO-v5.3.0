// SPDX-License-Identifier: EPL-2.0
package main

import "testing"

func TestResolveListen(t *testing.T) {
	for _, c := range []struct {
		listen, env string
		flag        int
		want        string
	}{
		{DefaultListen, "", 0, "127.0.0.1:8095"},
		{":9000", "", 0, ":9000"},
		{DefaultListen, "9100", 0, "127.0.0.1:9100"},
		{"0.0.0.0:9000", "9100", 9200, "0.0.0.0:9200"},
	} {
		if got, err := ResolveListen(c.listen, c.env, c.flag); err != nil || got != c.want {
			t.Fatalf("ResolveListen(%q,%q,%d) = %q, %v; want %q", c.listen, c.env, c.flag, got, err, c.want)
		}
	}
	for _, bad := range []struct {
		listen, env string
		flag        int
	}{{"no-port", "", 0}, {DefaultListen, "abc", 0}, {DefaultListen, "0", 0}, {DefaultListen, "", 70000}} {
		if _, err := ResolveListen(bad.listen, bad.env, bad.flag); err == nil {
			t.Fatalf("ResolveListen(%+v) accepted", bad)
		}
	}
}
