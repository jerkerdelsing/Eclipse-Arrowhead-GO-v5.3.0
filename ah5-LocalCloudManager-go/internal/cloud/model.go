package cloud

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Address struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

type System struct {
	Name      string         `json:"name"`
	Metadata  map[string]any `json:"metadata"`
	Version   string         `json:"version"`
	Addresses []Address      `json:"addresses"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt string         `json:"updatedAt"`
}

type Interface struct {
	TemplateName string         `json:"templateName"`
	Protocol     string         `json:"protocol"`
	Policy       string         `json:"policy"`
	Properties   map[string]any `json:"properties"`
}

type Definition struct {
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

type Service struct {
	InstanceID        string         `json:"instanceId"`
	Provider          System         `json:"provider"`
	ServiceDefinition Definition     `json:"serviceDefinition"`
	Version           string         `json:"version"`
	ExpiresAt         *string        `json:"expiresAt"`
	Metadata          map[string]any `json:"metadata"`
	Interfaces        []Interface    `json:"interfaces"`
	CreatedAt         string         `json:"createdAt"`
	UpdatedAt         string         `json:"updatedAt"`
}

type Identity struct {
	SystemName  string            `json:"systemName"`
	Credentials map[string]string `json:"credentials"`
	CreatedAt   string            `json:"createdAt"`
}

type Session struct {
	Token          string `json:"token"`
	SystemName     string `json:"systemName"`
	ExpirationTime string `json:"expirationTime"`
}

type Grant struct {
	Consumer          string   `json:"consumer"`
	Provider          string   `json:"provider"`
	ServiceDefinition string   `json:"serviceDefinition"`
	Operations        []string `json:"operations"`
	Cloud             string   `json:"cloud,omitempty"`
}

type Resource struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Owner     string         `json:"owner,omitempty"`
	Payload   map[string]any `json:"payload"`
	CreatedAt string         `json:"createdAt"`
	UpdatedAt string         `json:"updatedAt"`
}

type State struct {
	Systems     map[string]System     `json:"systems"`
	Definitions map[string]Definition `json:"definitions"`
	Services    map[string]Service    `json:"services"`
	Identities  map[string]Identity   `json:"identities"`
	Sessions    map[string]Session    `json:"sessions"`
	Grants      []Grant               `json:"grants"`
	Resources   map[string]Resource   `json:"resources"`
	Records     []map[string]any      `json:"records"`
}

type Store struct {
	mu   sync.RWMutex
	path string
	Data State
}

func newState() State {
	return State{Systems: map[string]System{}, Definitions: map[string]Definition{}, Services: map[string]Service{}, Identities: map[string]Identity{}, Sessions: map[string]Session{}, Grants: []Grant{}, Resources: map[string]Resource{}, Records: []map[string]any{}}
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, Data: newState()}
	b, err := os.ReadFile(path)
	if err == nil {
		if err := json.Unmarshal(b, &s.Data); err != nil {
			return nil, err
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	s.ensureMaps()
	return s, nil
}

func (s *Store) ensureMaps() {
	if s.Data.Systems == nil {
		s.Data.Systems = map[string]System{}
	}
	if s.Data.Definitions == nil {
		s.Data.Definitions = map[string]Definition{}
	}
	if s.Data.Services == nil {
		s.Data.Services = map[string]Service{}
	}
	if s.Data.Identities == nil {
		s.Data.Identities = map[string]Identity{}
	}
	if s.Data.Sessions == nil {
		s.Data.Sessions = map[string]Session{}
	}
	if s.Data.Resources == nil {
		s.Data.Resources = map[string]Resource{}
	}
	if s.Data.Grants == nil {
		s.Data.Grants = []Grant{}
	}
	if s.Data.Records == nil {
		s.Data.Records = []map[string]any{}
	}
}

func (s *Store) SaveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s.Data, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func now() string { return time.Now().UTC().Format(time.RFC3339Nano) }

func listResponse[T any](entries []T) map[string]any {
	return map[string]any{"entries": entries, "count": len(entries)}
}
