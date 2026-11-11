package catalog

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func shipped(t *testing.T) *Catalog {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	c, err := Load(filepath.Join(filepath.Dir(f), "..", "..", "catalogs", "gocloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestShippedCatalogLoads(t *testing.T) {
	c := shipped(t)
	if c.Cloud != "GoCloud" || len(c.Systems) < 15 {
		t.Fatalf("unexpected catalog %s with %d systems", c.Cloud, len(c.Systems))
	}
	if c.OwnsService("serviceregistry") || c.OwnsService("authentication") {
		t.Fatal("core services must not be managed")
	}
	if !c.OwnsService("timemanager") || c.OwnsService("timemanager-rust") {
		t.Fatal("own services managed, alternates not")
	}
	if !c.AllowsScript("provision-timemanager-identity.sh") || c.AllowsScript("rotate-secrets.sh") {
		t.Fatal("script allowlist wrong")
	}
}

func TestClosureAndOrder(t *testing.T) {
	c := shipped(t)
	ids, err := c.Closure([]string{"aigym"})
	if err != nil {
		t.Fatal(err)
	}
	ord, err := c.Order(ids)
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]int{}
	for i, id := range ord {
		pos[id] = i
	}
	for _, dep := range []string{"datamanager", "sysmonitor", "mqtt-broker", "amqp-broker"} {
		if _, ok := pos[dep]; !ok {
			t.Fatalf("%s missing from %v", dep, ord)
		}
		if pos[dep] > pos["aigym"] {
			t.Fatalf("%s after aigym in %v", dep, ord)
		}
	}
	if pos["amqp-broker"] > pos["sysmonitor"] {
		t.Fatalf("amqp-broker must precede sysmonitor: %v", ord)
	}
}

func TestValidation(t *testing.T) {
	base := `{"cloud":"X","composeProject":"p","executorType":"t","core":["serviceregistry"],"systems":[%s]}`
	cases := map[string]string{
		"cycle":       `{"id":"a","kind":"support","services":["a"],"requires":["b"]},{"id":"b","kind":"support","services":["b"],"requires":["a"]}`,
		"bad script":  `{"id":"a","kind":"support","services":["a"],"policies":["../evil.sh"]}`,
		"core owned":  `{"id":"a","kind":"support","services":["serviceregistry"]}`,
		"unknown req": `{"id":"a","kind":"support","services":["a"],"requires":["zz"]}`,
		"bad kind":    `{"id":"a","kind":"core","services":["a"]}`,
		"bad service": `{"id":"a","kind":"support","services":["a; rm -rf /"]}`,
	}
	for name, sys := range cases {
		if _, err := Parse([]byte(strings.Replace(base, "%s", sys, 1))); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
