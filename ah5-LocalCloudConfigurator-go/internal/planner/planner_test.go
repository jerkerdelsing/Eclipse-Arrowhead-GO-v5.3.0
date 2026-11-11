package planner

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"arrowhead/ah5-support-go/localcloudconfigurator/internal/catalog"
)

func cat(t *testing.T) *catalog.Catalog {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	c, err := catalog.Load(filepath.Join(filepath.Dir(f), "..", "..", "catalogs", "gocloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func kinds(p *Plan) string {
	var s []string
	for _, st := range p.Steps {
		s = append(s, st.Kind+":"+st.Target)
	}
	return strings.Join(s, " ")
}

func TestFreshSystemGetsProvisionUpPolicy(t *testing.T) {
	p, err := Build(cat(t), Request{Systems: []string{"timemanager"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "provision:provision-timemanager-identity.sh up:timemanager policy:configure-timemanager-policy.sh"
	if kinds(p) != want {
		t.Fatalf("got %q", kinds(p))
	}
}

func TestAlternateLeftAlone(t *testing.T) {
	p, err := Build(cat(t), Request{Systems: []string{"random-data-producer"}}, []string{"datamanager-rust", "amqp-broker"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(kinds(p), "up:datamanager ") || strings.HasPrefix(kinds(p), "up:datamanager") {
		t.Fatalf("Go datamanager must not start while the Rust one runs: %s", kinds(p))
	}
	if kinds(p) != "up:random-data-producer policy:configure-random-producer-policy.sh" {
		t.Fatalf("got %q", kinds(p))
	}
	if len(p.Notes) < 2 {
		t.Fatalf("expected notes, got %v", p.Notes)
	}
}

func TestAlreadyRunningIsNoop(t *testing.T) {
	p, err := Build(cat(t), Request{Systems: []string{"test-translation"}}, []string{"test-translation", "translation-manager"})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Steps) != 0 {
		t.Fatalf("expected no steps, got %s", kinds(p))
	}
	p, _ = Build(cat(t), Request{Systems: []string{"test-translation"}, Reapply: true, Smoke: true}, []string{"test-translation", "translation-manager"})
	if kinds(p) != "policy:configure-translation-policy.sh smoke:smoke-test.sh" {
		t.Fatalf("reapply got %q", kinds(p))
	}
}

func TestRemove(t *testing.T) {
	c := cat(t)
	running := []string{"translation-manager", "test-translation", "docker-proxy", "cloud-monitor-api", "cloud-monitor-ui"}
	p, err := Build(c, Request{Remove: []string{"cloud-monitor"}}, running)
	if err != nil {
		t.Fatal(err)
	}
	if kinds(p) != "stop:cloud-monitor-ui stop:cloud-monitor-api stop:docker-proxy" {
		t.Fatalf("got %q", kinds(p))
	}
	if _, err := Build(c, Request{Remove: []string{"translation-manager"}}, running); err == nil {
		t.Fatal("removing a system a running system requires must fail")
	}
	if _, err := Build(c, Request{Systems: []string{"test-translation"}, Remove: []string{"translation-manager"}}, nil); err == nil {
		t.Fatal("selected and removed must fail")
	}
	if p, err := Build(c, Request{Remove: []string{"translation-manager", "test-translation"}}, running); err != nil || len(p.Steps) != 2 {
		t.Fatalf("removing both: %v %v", err, p)
	}
}

func TestUnknownSystem(t *testing.T) {
	if _, err := Build(cat(t), Request{Systems: []string{"nope"}}, nil); err == nil {
		t.Fatal("expected error")
	}
}
