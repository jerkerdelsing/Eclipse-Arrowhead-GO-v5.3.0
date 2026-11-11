// Package planner turns an operator's selection into an ordered list of deployment steps for a local cloud.
package planner

import (
	"fmt"
	"sort"

	"arrowhead/ah5-support-go/localcloudconfigurator/internal/catalog"
)

// Step kinds; each maps to one ColonyOS function of the cloud executor.
const (
	StepProvision = "provision" // run an identity provisioning script
	StepUp        = "up"        // start one Compose service
	StepPolicy    = "policy"    // run a policy script
	StepStop      = "stop"      // stop one Compose service
	StepSmoke     = "smoke"     // run a smoke test script
)

// Request is what the operator asks for.
type Request struct {
	// Systems that should run in the cloud; required systems are added automatically.
	Systems []string `json:"systems"`
	// Remove lists systems whose services should be stopped.
	Remove []string `json:"remove,omitempty"`
	// Reapply runs provisioning and policy scripts also for systems that already run.
	Reapply bool `json:"reapply,omitempty"`
	// Smoke appends the catalog's smoke tests.
	Smoke bool `json:"smoke,omitempty"`
}

// Step is one deployment action.
type Step struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	System string `json:"system,omitempty"`
}

// Plan is the ordered result.
type Plan struct {
	Cloud    string   `json:"cloud"`
	Systems  []string `json:"systems"`
	Steps    []Step   `json:"steps"`
	Notes    []string `json:"notes,omitempty"`
}

// Build computes the plan; running holds the Compose services that run now.
func Build(c *catalog.Catalog, req Request, running []string) (*Plan, error) {
	isRunning := map[string]bool{}
	for _, s := range running {
		isRunning[s] = true
	}
	closure, err := c.Closure(req.Systems)
	if err != nil {
		return nil, err
	}
	ordered, err := c.Order(closure)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, id := range ordered {
		keep[id] = true
	}
	p := &Plan{Cloud: c.Cloud, Systems: ordered}

	for _, id := range ordered {
		s, _ := c.System(id)
		if alt := firstRunning(s.Alternates, isRunning); alt != "" {
			p.Notes = append(p.Notes, fmt.Sprintf("%s: alternate implementation %s runs; left as it is", s.Name, alt))
			if req.Reapply {
				p.Steps = append(p.Steps, scripts(StepPolicy, s.Policies, id)...)
			}
			continue
		}
		var missing []string
		for _, svc := range s.Services {
			if !isRunning[svc] {
				missing = append(missing, svc)
			}
		}
		if len(missing) == 0 && !req.Reapply {
			p.Notes = append(p.Notes, fmt.Sprintf("%s: already running", s.Name))
			continue
		}
		p.Steps = append(p.Steps, scripts(StepProvision, s.Provision, id)...)
		for _, svc := range missing {
			p.Steps = append(p.Steps, Step{Kind: StepUp, Target: svc, System: id})
		}
		p.Steps = append(p.Steps, scripts(StepPolicy, s.Policies, id)...)
	}

	remove := append([]string{}, req.Remove...)
	sort.Strings(remove)
	for _, id := range remove {
		s, ok := c.System(id)
		if !ok {
			return nil, fmt.Errorf("unknown system %q", id)
		}
		if keep[id] {
			return nil, fmt.Errorf("system %q is both selected (or required) and to be removed", id)
		}
		if dependent := requiredBy(c, id, isRunning, remove); dependent != "" {
			return nil, fmt.Errorf("system %q is still required by running system %q", id, dependent)
		}
		for _, alt := range s.Alternates {
			if isRunning[alt] {
				p.Notes = append(p.Notes, fmt.Sprintf("%s: alternate %s is managed by its swap targets; not stopped", s.Name, alt))
			}
		}
		for i := len(s.Services) - 1; i >= 0; i-- {
			if isRunning[s.Services[i]] {
				p.Steps = append(p.Steps, Step{Kind: StepStop, Target: s.Services[i], System: id})
			}
		}
	}

	if req.Smoke {
		p.Steps = append(p.Steps, scripts(StepSmoke, c.Smoke, "")...)
	}
	return p, nil
}

func scripts(kind string, names []string, system string) []Step {
	out := make([]Step, 0, len(names))
	for _, n := range names {
		out = append(out, Step{Kind: kind, Target: n, System: system})
	}
	return out
}

func firstRunning(services []string, isRunning map[string]bool) string {
	for _, s := range services {
		if isRunning[s] {
			return s
		}
	}
	return ""
}

// requiredBy returns a running system (not itself being removed) that requires id.
func requiredBy(c *catalog.Catalog, id string, isRunning map[string]bool, removing []string) string {
	gone := map[string]bool{}
	for _, r := range removing {
		gone[r] = true
	}
	for _, s := range c.Systems {
		if gone[s.ID] {
			continue
		}
		if firstRunning(s.Services, isRunning) == "" && firstRunning(s.Alternates, isRunning) == "" {
			continue
		}
		for _, r := range s.Requires {
			if r == id {
				return s.ID
			}
		}
	}
	return ""
}
