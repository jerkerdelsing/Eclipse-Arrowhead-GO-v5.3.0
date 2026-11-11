package runner

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"arrowhead/ah5-support-go/localcloudconfigurator/internal/catalog"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/planner"
)

type fakeCmd struct {
	calls []string
	out   string
}

func (f *fakeCmd) Run(_ context.Context, dir, name string, args ...string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " "))
	return f.out, nil
}

func setup(t *testing.T) (*Runner, *fakeCmd) {
	t.Helper()
	_, f, _, _ := runtime.Caller(0)
	c, err := catalog.Load(filepath.Join(filepath.Dir(f), "..", "..", "catalogs", "gocloud.json"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	_ = os.MkdirAll(filepath.Join(dir, "scripts"), 0o755)
	_ = os.WriteFile(filepath.Join(dir, "scripts", "configure-timemanager-policy.sh"), []byte("#!/bin/sh\n"), 0o755)
	fc := &fakeCmd{}
	return &Runner{Catalog: c, CloudDir: dir, Cmd: fc}, fc
}

func TestUpUsesNoDeps(t *testing.T) {
	r, fc := setup(t)
	if _, err := r.Do(context.Background(), planner.Step{Kind: planner.StepUp, Target: "timemanager"}); err != nil {
		t.Fatal(err)
	}
	want := "docker compose -p arrowhead-v52-test-cloud-go up -d --wait --no-deps timemanager"
	if fc.calls[0] != want {
		t.Fatalf("got %q", fc.calls[0])
	}
}

func TestRejectsUncataloguedTargets(t *testing.T) {
	r, fc := setup(t)
	bad := []planner.Step{
		{Kind: planner.StepUp, Target: "serviceregistry"},
		{Kind: planner.StepStop, Target: "authentication"},
		{Kind: planner.StepStop, Target: "timemanager-rust"},
		{Kind: planner.StepPolicy, Target: "rotate-secrets.sh"},
		{Kind: planner.StepPolicy, Target: "../../bin/sh"},
		{Kind: "exec", Target: "ls"},
	}
	for _, s := range bad {
		if _, err := r.Do(context.Background(), s); err == nil {
			t.Errorf("%v accepted", s)
		}
	}
	if len(fc.calls) != 0 {
		t.Fatalf("commands ran: %v", fc.calls)
	}
}

func TestScriptRunsFromCloudDir(t *testing.T) {
	r, fc := setup(t)
	if _, err := r.Do(context.Background(), planner.Step{Kind: planner.StepPolicy, Target: "configure-timemanager-policy.sh"}); err != nil {
		t.Fatal(err)
	}
	if fc.calls[0] != "./scripts/configure-timemanager-policy.sh " {
		t.Fatalf("got %q", fc.calls[0])
	}
	// catalogued but absent on disk
	if _, err := r.Do(context.Background(), planner.Step{Kind: planner.StepPolicy, Target: "configure-aigym-policy.sh"}); err == nil {
		t.Fatal("missing script accepted")
	}
}

func TestRunningParsesBothFormats(t *testing.T) {
	r, fc := setup(t)
	fc.out = `{"Service":"timemanager-rust","State":"running"}` + "\n" + `{"Service":"aigym","State":"running"}` + "\n"
	got, err := r.Running(context.Background())
	if err != nil || strings.Join(got, ",") != "timemanager-rust,aigym" {
		t.Fatalf("%v %v", got, err)
	}
	fc.out = `[{"Service":"a","State":"running"},{"Service":"b","State":"exited"}]`
	got, _ = r.Running(context.Background())
	if strings.Join(got, ",") != "a" {
		t.Fatalf("%v", got)
	}
}

func TestRedact(t *testing.T) {
	in := `{"password":"hunter2"} token=abc Authorization: Bearer eyJhbGc.x.y IDENTITY-TOKEN//deadbeef ok`
	out := Redact(in)
	for _, s := range []string{"hunter2", "abc", "eyJhbGc", "deadbeef"} {
		if strings.Contains(out, s) {
			t.Fatalf("%q leaked in %q", s, out)
		}
	}
	if !strings.Contains(out, "ok") {
		t.Fatal(out)
	}
}
