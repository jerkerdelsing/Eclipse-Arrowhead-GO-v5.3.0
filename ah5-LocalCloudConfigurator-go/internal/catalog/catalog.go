// Package catalog describes which support and application systems a local cloud can host and how each one is
// deployed there: its Compose services, the identity provisioning scripts and the policy scripts.
package catalog

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"sort"
)

// Kinds of systems an operator can pick.
const (
	KindInfrastructure = "infrastructure"
	KindSupport        = "support"
	KindApplication    = "application"
)

var (
	serviceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
	scriptName  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,80}\.sh$`)
)

// System is one selectable system of a local cloud.
type System struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	Kind      string   `json:"kind"`
	Services  []string `json:"services"`
	// Alternates are Compose services of another implementation of the same system (for example a Rust or Java
	// swap). When one of them runs, the system counts as present and its own services are left alone.
	Alternates []string `json:"alternates,omitempty"`
	Requires   []string `json:"requires,omitempty"`
	Provision  []string `json:"provision,omitempty"`
	Policies   []string `json:"policies,omitempty"`
}

// Catalog is the deployment description of one local cloud.
type Catalog struct {
	Cloud          string   `json:"cloud"`
	ComposeProject string   `json:"composeProject"`
	ExecutorType   string   `json:"executorType"`
	Core           []string `json:"core"`
	Smoke          []string `json:"smoke"`
	Systems        []System `json:"systems"`

	byID map[string]*System
}

// Load reads and validates a catalog file.
func Load(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse decodes and validates a catalog.
func Parse(data []byte) (*Catalog, error) {
	var c Catalog
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Catalog) validate() error {
	if c.Cloud == "" || c.ComposeProject == "" || c.ExecutorType == "" {
		return fmt.Errorf("catalog: cloud, composeProject and executorType are required")
	}
	c.byID = map[string]*System{}
	owner := map[string]string{}
	for _, s := range c.Core {
		if !serviceName.MatchString(s) {
			return fmt.Errorf("catalog: invalid core service %q", s)
		}
		owner[s] = "core"
	}
	for _, s := range c.Smoke {
		if !scriptName.MatchString(s) {
			return fmt.Errorf("catalog: invalid smoke script %q", s)
		}
	}
	for i := range c.Systems {
		s := &c.Systems[i]
		if !serviceName.MatchString(s.ID) {
			return fmt.Errorf("catalog: invalid system id %q", s.ID)
		}
		if _, dup := c.byID[s.ID]; dup {
			return fmt.Errorf("catalog: duplicate system %q", s.ID)
		}
		switch s.Kind {
		case KindInfrastructure, KindSupport, KindApplication:
		default:
			return fmt.Errorf("catalog: system %q has unknown kind %q", s.ID, s.Kind)
		}
		if len(s.Services) == 0 {
			return fmt.Errorf("catalog: system %q has no services", s.ID)
		}
		for _, svc := range append(append([]string{}, s.Services...), s.Alternates...) {
			if !serviceName.MatchString(svc) {
				return fmt.Errorf("catalog: system %q has invalid service %q", s.ID, svc)
			}
			if o, taken := owner[svc]; taken {
				return fmt.Errorf("catalog: service %q belongs to both %s and %s", svc, o, s.ID)
			}
			owner[svc] = s.ID
		}
		for _, sc := range append(append([]string{}, s.Provision...), s.Policies...) {
			if !scriptName.MatchString(sc) {
				return fmt.Errorf("catalog: system %q has invalid script %q", s.ID, sc)
			}
		}
		c.byID[s.ID] = s
	}
	for _, s := range c.Systems {
		for _, r := range s.Requires {
			if _, ok := c.byID[r]; !ok {
				return fmt.Errorf("catalog: system %q requires unknown system %q", s.ID, r)
			}
		}
	}
	if _, err := c.Order(c.IDs()); err != nil {
		return err
	}
	return nil
}

// System returns the system with the given id.
func (c *Catalog) System(id string) (*System, bool) {
	s, ok := c.byID[id]
	return s, ok
}

// IDs lists all system ids in catalog order.
func (c *Catalog) IDs() []string {
	ids := make([]string, 0, len(c.Systems))
	for _, s := range c.Systems {
		ids = append(ids, s.ID)
	}
	return ids
}

// Closure adds every system the selection requires, transitively.
func (c *Catalog) Closure(selected []string) ([]string, error) {
	seen := map[string]bool{}
	var visit func(string) error
	visit = func(id string) error {
		if seen[id] {
			return nil
		}
		s, ok := c.byID[id]
		if !ok {
			return fmt.Errorf("unknown system %q", id)
		}
		seen[id] = true
		for _, r := range s.Requires {
			if err := visit(r); err != nil {
				return err
			}
		}
		return nil
	}
	for _, id := range selected {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	return out, nil
}

// Order sorts the given systems so that each comes after the systems it requires; ties keep catalog order.
func (c *Catalog) Order(ids []string) ([]string, error) {
	pos := map[string]int{}
	for i, s := range c.Systems {
		pos[s.ID] = i
	}
	want := map[string]bool{}
	for _, id := range ids {
		if _, ok := c.byID[id]; !ok {
			return nil, fmt.Errorf("unknown system %q", id)
		}
		want[id] = true
	}
	sorted := append([]string{}, ids...)
	sort.SliceStable(sorted, func(i, j int) bool { return pos[sorted[i]] < pos[sorted[j]] })
	var out []string
	state := map[string]int{} // 1 visiting, 2 done
	var visit func(string) error
	visit = func(id string) error {
		switch state[id] {
		case 1:
			return fmt.Errorf("catalog: dependency cycle at %q", id)
		case 2:
			return nil
		}
		state[id] = 1
		for _, r := range c.byID[id].Requires {
			if want[r] {
				if err := visit(r); err != nil {
					return err
				}
			}
		}
		state[id] = 2
		out = append(out, id)
		return nil
	}
	for _, id := range sorted {
		if err := visit(id); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// OwnsService reports whether a Compose service may be started or stopped through this catalog. Core services are
// never touched by the configurator.
func (c *Catalog) OwnsService(name string) bool {
	for _, s := range c.Systems {
		for _, svc := range s.Services {
			if svc == name {
				return true
			}
		}
	}
	return false
}

// AllowsScript reports whether a script is named by the catalog.
func (c *Catalog) AllowsScript(name string) bool {
	for _, sc := range c.Smoke {
		if sc == name {
			return true
		}
	}
	for _, s := range c.Systems {
		for _, sc := range append(append([]string{}, s.Provision...), s.Policies...) {
			if sc == name {
				return true
			}
		}
	}
	return false
}
