// Package colony connects the configurator to ColonyOS: the API submits deployment plans as workflows, and the
// cloud executor pulls and carries out their steps.
package colony

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/colonyos/colonies/pkg/client"
	"github.com/colonyos/colonies/pkg/core"

	"arrowhead/ah5-support-go/localcloudconfigurator/internal/planner"
	"arrowhead/ah5-support-go/localcloudconfigurator/internal/runner"
)

// Config locates the ColonyOS server and the identity of this process.
type Config struct {
	Host       string
	Port       int
	TLS        bool
	ColonyName string
	PrvKey     string
}

// ConfigFromEnv reads the standard COLONIES_* variables. The private key comes from COLONIES_PRVKEY_FILE when
// set (Compose secret), else from COLONIES_PRVKEY.
func ConfigFromEnv() (Config, error) {
	c := Config{Host: env("COLONIES_SERVER_HOST", "localhost"), ColonyName: os.Getenv("COLONIES_COLONY_NAME")}
	port, err := strconv.Atoi(env("COLONIES_SERVER_PORT", "50080"))
	if err != nil {
		return c, fmt.Errorf("COLONIES_SERVER_PORT: %w", err)
	}
	c.Port = port
	c.TLS = env("COLONIES_TLS", "false") == "true"
	c.PrvKey = os.Getenv("COLONIES_PRVKEY")
	if f := os.Getenv("COLONIES_PRVKEY_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return c, err
		}
		c.PrvKey = string(trimNL(b))
	}
	if c.ColonyName == "" || c.PrvKey == "" {
		return c, errors.New("COLONIES_COLONY_NAME and COLONIES_PRVKEY(_FILE) are required")
	}
	return c, nil
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func trimNL(b []byte) []byte {
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r' || b[len(b)-1] == ' ') {
		b = b[:len(b)-1]
	}
	return b
}

// Client wraps the ColonyOS client with this identity.
type Client struct {
	cfg Config
	c   *client.ColoniesClient
}

// New creates a client; insecure means plain HTTP (the local stack listens on loopback only).
func New(cfg Config) *Client {
	return &Client{cfg: cfg, c: client.CreateColoniesClient(cfg.Host, cfg.Port, !cfg.TLS, false)}
}

// StepState is the state of one deployment step.
type StepState struct {
	Node      string   `json:"node"`
	ProcessID string   `json:"processId"`
	Kind      string   `json:"kind"`
	Target    string   `json:"target"`
	State     string   `json:"state"`
	Errors    []string `json:"errors,omitempty"`
	Output    string   `json:"output,omitempty"`
}

// Deployment is the state of a submitted workflow.
type Deployment struct {
	ID    string      `json:"id"`
	State string      `json:"state"`
	Steps []StepState `json:"steps"`
}

func stateName(s int) string {
	switch s {
	case core.WAITING:
		return "waiting"
	case core.RUNNING:
		return "running"
	case core.SUCCESS:
		return "success"
	case core.FAILED:
		return "failed"
	}
	return "unknown"
}

// SubmitPlan submits the plan as a chain of processes for executors of the given type.
func (cl *Client) SubmitPlan(p *planner.Plan, executorType string) (string, error) {
	if len(p.Steps) == 0 {
		return "", errors.New("plan has no steps")
	}
	wf := core.CreateWorkflowSpec(cl.cfg.ColonyName)
	prev := ""
	for i, s := range p.Steps {
		fs := stepSpec(cl.cfg.ColonyName, executorType, s)
		fs.NodeName = fmt.Sprintf("s%02d-%s-%s", i+1, s.Kind, s.Target)
		if prev != "" {
			fs.Conditions.Dependencies = []string{prev}
		}
		prev = fs.NodeName
		wf.AddFunctionSpec(fs)
	}
	g, err := cl.c.SubmitWorkflowSpec(wf, cl.cfg.PrvKey)
	if err != nil {
		return "", err
	}
	return g.ID, nil
}

func stepSpec(colonyName, executorType string, s planner.Step) *core.FunctionSpec {
	fs := core.CreateEmptyFunctionSpec()
	fs.FuncName = runner.FuncStep
	fs.KwArgs = map[string]interface{}{"kind": s.Kind, "target": s.Target, "system": s.System}
	fs.Conditions.ColonyName = colonyName
	fs.Conditions.ExecutorType = executorType
	fs.MaxWaitTime = -1
	fs.MaxExecTime = 900
	fs.MaxRetries = 0
	fs.Label = "localcloudconfigurator"
	return fs
}

// Deployment reads the state of a submitted workflow.
func (cl *Client) Deployment(id string) (*Deployment, error) {
	g, err := cl.c.GetProcessGraph(id, cl.cfg.PrvKey)
	if err != nil {
		return nil, err
	}
	d := &Deployment{ID: g.ID, State: stateName(g.State)}
	for _, pid := range g.ProcessIDs {
		pr, err := cl.c.GetProcess(pid, cl.cfg.PrvKey)
		if err != nil {
			return nil, err
		}
		st := StepState{Node: pr.FunctionSpec.NodeName, ProcessID: pr.ID, State: stateName(pr.State), Errors: pr.Errors}
		st.Kind, _ = pr.FunctionSpec.KwArgs["kind"].(string)
		st.Target, _ = pr.FunctionSpec.KwArgs["target"].(string)
		if len(pr.Output) > 0 {
			st.Output, _ = pr.Output[0].(string)
		}
		d.Steps = append(d.Steps, st)
	}
	sortSteps(d.Steps)
	return d, nil
}

func sortSteps(s []StepState) {
	sort.Slice(s, func(i, j int) bool { return s[i].Node < s[j].Node })
}

// Status asks the cloud executor which Compose services run.
func (cl *Client) Status(ctx context.Context, executorType string) ([]string, error) {
	fs := core.CreateEmptyFunctionSpec()
	fs.FuncName = runner.FuncStatus
	fs.Conditions.ColonyName = cl.cfg.ColonyName
	fs.Conditions.ExecutorType = executorType
	fs.MaxWaitTime = 30
	fs.MaxExecTime = 60
	fs.MaxRetries = 0
	fs.Label = "localcloudconfigurator"
	pr, err := cl.c.Submit(fs, cl.cfg.PrvKey)
	if err != nil {
		return nil, err
	}
	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("status: no executor of type %s answered: %w", executorType, ctx.Err())
		case <-time.After(300 * time.Millisecond):
		}
		pr, err = cl.c.GetProcess(pr.ID, cl.cfg.PrvKey)
		if err != nil {
			return nil, err
		}
		switch pr.State {
		case core.FAILED:
			return nil, fmt.Errorf("status failed: %v", pr.Errors)
		case core.SUCCESS:
			var names []string
			for _, o := range pr.Output {
				if s, ok := o.(string); ok {
					names = append(names, s)
				}
			}
			return names, nil
		}
	}
}

// Serve is the executor loop: it registers nothing (registration is done by setup) and handles processes until ctx
// ends.
func (cl *Client) Serve(ctx context.Context, r *runner.Runner, logf func(string, ...any)) error {
	for ctx.Err() == nil {
		pr, err := cl.c.Assign(cl.cfg.ColonyName, 10, "", "", cl.cfg.PrvKey)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			// Assign returns an error on its timeout when nothing is queued.
			if isTimeout(err) {
				continue
			}
			logf("assign: %v", err)
			select {
			case <-ctx.Done():
			case <-time.After(3 * time.Second):
			}
			continue
		}
		cl.handle(ctx, r, pr, logf)
	}
	return nil
}

func isTimeout(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "timeout") || strings.Contains(s, "no processes")
}

func (cl *Client) handle(ctx context.Context, r *runner.Runner, pr *core.Process, logf func(string, ...any)) {
	switch pr.FunctionSpec.FuncName {
	case runner.FuncStatus:
		names, err := r.Running(ctx)
		if err != nil {
			cl.fail(pr, err, logf)
			return
		}
		out := make([]interface{}, len(names))
		for i, n := range names {
			out[i] = n
		}
		if err := cl.c.CloseWithOutput(pr.ID, out, cl.cfg.PrvKey); err != nil {
			logf("close %s: %v", pr.ID, err)
		}
	case runner.FuncStep:
		s := planner.Step{}
		s.Kind, _ = pr.FunctionSpec.KwArgs["kind"].(string)
		s.Target, _ = pr.FunctionSpec.KwArgs["target"].(string)
		s.System, _ = pr.FunctionSpec.KwArgs["system"].(string)
		logf("step %s %s (%s)", s.Kind, s.Target, pr.ID)
		sctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
		out, err := r.Do(sctx, s)
		cancel()
		if out != "" {
			_ = cl.c.AddLog(pr.ID, tail(out, 8000), cl.cfg.PrvKey)
		}
		if err != nil {
			cl.fail(pr, fmt.Errorf("%v: %s", err, tail(out, 600)), logf)
			return
		}
		if err := cl.c.CloseWithOutput(pr.ID, []interface{}{tail(out, 2000)}, cl.cfg.PrvKey); err != nil {
			logf("close %s: %v", pr.ID, err)
		}
	default:
		cl.fail(pr, fmt.Errorf("unknown function %q", pr.FunctionSpec.FuncName), logf)
	}
}

func (cl *Client) fail(pr *core.Process, err error, logf func(string, ...any)) {
	logf("process %s failed: %v", pr.ID, err)
	if ferr := cl.c.Fail(pr.ID, []string{runner.Redact(err.Error())}, cl.cfg.PrvKey); ferr != nil {
		logf("fail %s: %v", pr.ID, ferr)
	}
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
