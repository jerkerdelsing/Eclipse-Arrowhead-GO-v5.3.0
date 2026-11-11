// Package runner carries out deployment steps on the host of a local cloud. It is the work of the ColonyOS cloud
// executor: every request is checked against the executor's own catalog, so a process can only start or stop
// catalogued services and run catalogued scripts from the cloud's scripts/ directory.
package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"arrowhead/ah5-support-go/localcloudconfigurator/internal/catalog"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/planner"
)

// ColonyOS function names served by the cloud executor.
const (
	FuncStatus = "lcc.status"
	FuncStep   = "lcc.step"
)

// Commander runs one command in a directory and returns its combined output.
type Commander interface {
	Run(ctx context.Context, dir string, name string, args ...string) (string, error)
}

// ExecCommander runs real processes.
type ExecCommander struct{}

func (ExecCommander) Run(ctx context.Context, dir, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

// Runner executes steps in one cloud directory.
type Runner struct {
	Catalog  *catalog.Catalog
	CloudDir string
	Cmd      Commander
}

// Running lists the Compose services of the cloud's project that are in state running.
func (r *Runner) Running(ctx context.Context) ([]string, error) {
	out, err := r.Cmd.Run(ctx, r.CloudDir, "docker", "compose", "-p", r.Catalog.ComposeProject,
		"ps", "--status", "running", "--format", "json")
	if err != nil {
		return nil, fmt.Errorf("docker compose ps: %v: %s", err, Redact(out))
	}
	return parsePS(out)
}

// parsePS accepts both the JSON array and the one-object-per-line output of docker compose ps.
func parsePS(out string) ([]string, error) {
	type row struct {
		Service string `json:"Service"`
		State   string `json:"State"`
	}
	var rows []row
	trimmed := strings.TrimSpace(out)
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal([]byte(trimmed), &rows); err != nil {
			return nil, err
		}
	} else {
		for _, line := range strings.Split(trimmed, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			var rw row
			if err := json.Unmarshal([]byte(line), &rw); err != nil {
				return nil, fmt.Errorf("docker compose ps output: %w", err)
			}
			rows = append(rows, rw)
		}
	}
	var names []string
	for _, rw := range rows {
		if rw.State == "" || rw.State == "running" {
			names = append(names, rw.Service)
		}
	}
	return names, nil
}

// Do carries out one step and returns its (redacted) output.
func (r *Runner) Do(ctx context.Context, s planner.Step) (string, error) {
	switch s.Kind {
	case planner.StepUp, planner.StepStop:
		if !r.Catalog.OwnsService(s.Target) {
			return "", fmt.Errorf("service %q is not managed by the %s catalog", s.Target, r.Catalog.Cloud)
		}
		args := []string{"compose", "-p", r.Catalog.ComposeProject}
		if s.Kind == planner.StepUp {
			// --no-deps: dependencies are explicit plan steps, and Compose must not start a Go service whose
			// Rust/Java alternate is running.
			args = append(args, "up", "-d", "--wait", "--no-deps", s.Target)
		} else {
			args = append(args, "stop", s.Target)
		}
		out, err := r.Cmd.Run(ctx, r.CloudDir, "docker", args...)
		return Redact(out), wrap(err, s)
	case planner.StepProvision, planner.StepPolicy, planner.StepSmoke:
		if !r.Catalog.AllowsScript(s.Target) {
			return "", fmt.Errorf("script %q is not in the %s catalog", s.Target, r.Catalog.Cloud)
		}
		rel := filepath.Join("scripts", s.Target)
		if _, err := os.Stat(filepath.Join(r.CloudDir, rel)); err != nil {
			return "", fmt.Errorf("script %s: %w", rel, err)
		}
		out, err := r.Cmd.Run(ctx, r.CloudDir, "./"+rel)
		return Redact(out), wrap(err, s)
	default:
		return "", fmt.Errorf("unknown step kind %q", s.Kind)
	}
}

func wrap(err error, s planner.Step) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s %s: %w", s.Kind, s.Target, err)
}

var (
	secretish = regexp.MustCompile(`(?i)("?(password|passwd|token|secret|prvkey|private[_-]?key)"?\s*[:=]\s*)("[^"]*"|[^\s,}]+)`)
	bearer    = regexp.MustCompile(`(?i)(bearer\s+|IDENTITY-TOKEN//)[^\s"]+`)
)

// Redact masks values that look like credentials, so step output can go to ColonyOS logs.
func Redact(s string) string {
	s = secretish.ReplaceAllString(s, `$1***`)
	return bearer.ReplaceAllString(s, `$1***`)
}
