package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// state is the whole database. Entities are treated as immutable: an update replaces the pointer
// in a cloned state, so readers holding the previous state are never disturbed (copy-on-write).
type state struct {
	NextID    int64                  `json:"nextId"`
	Devices   map[string]*Device     `json:"devices"`
	Systems   map[string]*System     `json:"systems"`
	Defs      map[string]*ServiceDef `json:"serviceDefinitions"`
	Templates map[string]*Template   `json:"interfaceTemplates"`
	Instances map[string]*Instance   `json:"serviceInstances"`
}

func newState() *state {
	return &state{
		Devices:   map[string]*Device{},
		Systems:   map[string]*System{},
		Defs:      map[string]*ServiceDef{},
		Templates: map[string]*Template{},
		Instances: map[string]*Instance{},
	}
}

func (s *state) clone() *state {
	c := &state{NextID: s.NextID}
	c.Devices = make(map[string]*Device, len(s.Devices))
	for k, v := range s.Devices {
		c.Devices[k] = v
	}
	c.Systems = make(map[string]*System, len(s.Systems))
	for k, v := range s.Systems {
		c.Systems[k] = v
	}
	c.Defs = make(map[string]*ServiceDef, len(s.Defs))
	for k, v := range s.Defs {
		c.Defs[k] = v
	}
	c.Templates = make(map[string]*Template, len(s.Templates))
	for k, v := range s.Templates {
		c.Templates[k] = v
	}
	c.Instances = make(map[string]*Instance, len(s.Instances))
	for k, v := range s.Instances {
		c.Instances[k] = v
	}
	return c
}

func (s *state) newID() int64 {
	s.NextID++
	return s.NextID
}

// deleteSystem removes the system and (cascade) its service instances.
func (s *state) deleteSystem(name string) bool {
	if _, ok := s.Systems[name]; !ok {
		return false
	}
	delete(s.Systems, name)
	for id, in := range s.Instances {
		if in.System == name {
			delete(s.Instances, id)
		}
	}
	return true
}

// deleteDefinition removes the service definition and (cascade) its service instances.
func (s *state) deleteDefinition(name string) {
	if _, ok := s.Defs[name]; !ok {
		return
	}
	delete(s.Defs, name)
	for id, in := range s.Instances {
		if in.Definition == name {
			delete(s.Instances, id)
		}
	}
}

// deleteTemplate removes the template and (cascade) the instance interfaces that use it.
func (s *state) deleteTemplate(name string) {
	if _, ok := s.Templates[name]; !ok {
		return
	}
	delete(s.Templates, name)
	for id, in := range s.Instances {
		var kept []InstanceInterface
		changed := false
		for _, f := range in.Interfaces {
			if f.Template == name {
				changed = true
				continue
			}
			kept = append(kept, f)
		}
		if changed {
			cp := *in
			cp.Interfaces = kept
			s.Instances[id] = &cp
		}
	}
}

func (s *state) systemsOfDevice(device string) []*System {
	var out []*System
	for _, sys := range s.Systems {
		if sys.DeviceName == device {
			out = append(out, sys)
		}
	}
	return out
}

// Store wraps the state with locking and optional JSON persistence.
type Store struct {
	mu   sync.RWMutex
	st   *state
	file string
}

func NewStore(file string) (*Store, error) {
	s := &Store{st: newState(), file: file}
	if file != "" {
		b, err := os.ReadFile(file)
		switch {
		case err == nil && len(b) > 0:
			loaded := newState()
			if err := json.Unmarshal(b, loaded); err != nil {
				return nil, err
			}
			if loaded.Devices == nil {
				loaded.Devices = map[string]*Device{}
			}
			if loaded.Systems == nil {
				loaded.Systems = map[string]*System{}
			}
			if loaded.Defs == nil {
				loaded.Defs = map[string]*ServiceDef{}
			}
			if loaded.Templates == nil {
				loaded.Templates = map[string]*Template{}
			}
			if loaded.Instances == nil {
				loaded.Instances = map[string]*Instance{}
			}
			s.st = loaded
		case err != nil && !os.IsNotExist(err):
			return nil, err
		}
	}
	if err := s.Update(func(st *state) error { ensureDefaultTemplates(st); return nil }); err != nil {
		return nil, err
	}
	return s, nil
}

// View runs fn with a consistent read-only snapshot.
func (s *Store) View(fn func(st *state)) {
	s.mu.RLock()
	st := s.st
	s.mu.RUnlock()
	fn(st)
}

// Update runs fn on a copy of the state; if it returns nil the copy replaces the current state
// (and is persisted). Errors leave the state untouched, like a rolled back transaction.
func (s *Store) Update(fn func(st *state) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.st.clone()
	if err := fn(c); err != nil {
		return err
	}
	if err := s.persist(c); err != nil {
		return errInternal("Database operation error")
	}
	s.st = c
	return nil
}

func (s *Store) persist(st *state) error {
	if s.file == "" {
		return nil
	}
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.file)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".sr-data-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.file)
}

// ensureDefaultTemplates mirrors default_inserts.sql (INSERT IGNORE).
func ensureDefaultTemplates(st *state) {
	type tp = TemplateProp
	add := func(name, protocol string, props ...tp) {
		if _, ok := st.Templates[name]; ok {
			return
		}
		t := time.Now().UTC().Truncate(time.Second)
		st.Templates[name] = &Template{ID: st.newID(), Name: name, Protocol: protocol, Props: props, CreatedAt: t, UpdatedAt: t}
	}
	httpProps := []tp{
		{Name: "accessAddresses", Mandatory: true, Validator: "NOT_EMPTY_ADDRESS_LIST"},
		{Name: "accessPort", Mandatory: true, Validator: "PORT"},
		{Name: "basePath", Mandatory: true},
		{Name: "operations", Mandatory: false, Validator: "HTTP_OPERATIONS"},
	}
	mqttProps := []tp{
		{Name: "accessAddresses", Mandatory: true, Validator: "NOT_EMPTY_ADDRESS_LIST"},
		{Name: "accessPort", Mandatory: true, Validator: "PORT"},
		{Name: "baseTopic", Mandatory: true},
		{Name: "operations", Mandatory: true, Validator: "NOT_EMPTY_STRING_SET|OPERATION"},
	}
	add("generic_http", "http", httpProps...)
	add("generic_https", "https", httpProps...)
	add("generic_mqtt", "tcp", mqttProps...)
	add("generic_mqtts", "ssl", mqttProps...)
	amqpProps := []tp{
		{Name: "accessAddresses", Mandatory: true, Validator: "NOT_EMPTY_ADDRESS_LIST"},
		{Name: "accessPort", Mandatory: true, Validator: "PORT"},
		{Name: "exchange", Mandatory: true},
		{Name: "baseRoutingKey", Mandatory: true},
		{Name: "operations", Mandatory: true, Validator: "NOT_EMPTY_STRING_SET|OPERATION"},
	}
	add("generic_amqp", "amqp", amqpProps...)
	add("generic_amqps", "amqps", amqpProps...)
}
