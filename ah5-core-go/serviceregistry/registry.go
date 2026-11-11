package main

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Registry implements the service layer (validation, normalization, database semantics) of the
// ServiceRegistry core system.
type Registry struct {
	cfg   *Config
	rules *Rules
	store *Store
	log   *Logger
	now   func() time.Time
}

func NewRegistry(cfg *Config, store *Store, log *Logger) *Registry {
	return &Registry{
		cfg:   cfg,
		rules: NewRules(cfg),
		store: store,
		log:   log,
		now:   func() time.Time { return time.Now().UTC().Truncate(time.Millisecond) },
	}
}

// ---------------------------------------------------------------------------------------------
// pagination

var (
	sortableDevice   = []string{"id", "name", "createdAt"}
	sortableSystem   = []string{"id", "name", "createdAt"}
	sortableDef      = []string{"id", "name", "createdAt"}
	sortableInstance = []string{"id", "serviceInstanceId", "createdAt"}
	sortableTemplate = []string{"id", "name", "createdAt"}
	sortableLog      = []string{"logId", "entryDate", "logger", "logLevel"}
)

type pageReq struct {
	page, size int
	desc       bool
	sortField  string
}

func (rg *Registry) validatePage(p *PageDTO, sortable []string) error {
	if p == nil {
		return nil
	}
	max := rg.rules.MaxPageSize
	if p.Size != nil {
		if p.Page == nil {
			return errInvalid("If size parameter is defined then page parameter cannot be undefined")
		}
		if *p.Size > max {
			return errInvalid("The page size cannot be larger than " + itoa(max))
		}
	}
	if p.Page != nil && p.Size == nil {
		return errInvalid("If page parameter is defined then size parameter cannot be undefined")
	}
	if !isBlank(p.Direction) {
		d := upperTrim(p.Direction)
		if d != "ASC" && d != "DESC" {
			return errInvalid("Direction is invalid. Only ASC or DESC are allowed")
		}
	}
	if !isBlank(p.SortField) && !containsStr(sortable, strings.TrimSpace(p.SortField)) {
		return errInvalid("Sort field is invalid. Only the following are allowed: " + joinList(sortable))
	}
	return nil
}

func (rg *Registry) pageRequest(p *PageDTO, defaultDesc bool, sortable []string, defSort string) (pageReq, error) {
	if p == nil {
		return pageReq{0, rg.rules.MaxPageSize, defaultDesc, defSort}, nil
	}
	if err := rg.validatePage(p, sortable); err != nil {
		return pageReq{}, err
	}
	pr := pageReq{page: 0, size: rg.rules.MaxPageSize, desc: defaultDesc, sortField: defSort}
	if p.Page != nil && *p.Page >= 0 {
		pr.page = *p.Page
	}
	if p.Size != nil && *p.Size >= 1 {
		pr.size = *p.Size
	}
	if !isBlank(p.Direction) {
		pr.desc = upperTrim(p.Direction) == "DESC"
	}
	if !isBlank(p.SortField) {
		pr.sortField = strings.TrimSpace(p.SortField)
	}
	return pr, nil
}

var allPages = pageReq{page: 0, size: int(^uint(0) >> 1)}

func itoa(i int) string { return strconv.Itoa(i) }

// sortAndPage sorts items with cmp (field-aware) and returns the requested page and the total.
func sortAndPage[T any](items []T, pr pageReq, cmp func(a, b T, field string) int) ([]T, int) {
	total := len(items)
	if pr.sortField != "" {
		sort.SliceStable(items, func(i, j int) bool {
			c := cmp(items[i], items[j], pr.sortField)
			if pr.desc {
				return c > 0
			}
			return c < 0
		})
	}
	start := 0
	if pr.page > 0 && pr.size > 0 {
		if pr.page > total/pr.size+1 {
			start = total
		} else {
			start = pr.page * pr.size
		}
	}
	if start >= total {
		return []T{}, total
	}
	end := total
	if pr.size < total-start {
		end = start + pr.size
	}
	return items[start:end], total
}

func cmpInt(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpTime(a, b time.Time) int {
	switch {
	case a.Before(b):
		return -1
	case a.After(b):
		return 1
	}
	return 0
}

func cmpStr(a, b string) int { return strings.Compare(a, b) }

func cmpDevice(a, b *Device, f string) int {
	switch f {
	case "name":
		return cmpStr(a.Name, b.Name)
	case "createdAt":
		if c := cmpTime(a.CreatedAt, b.CreatedAt); c != 0 {
			return c
		}
	}
	return cmpInt(a.ID, b.ID)
}

func cmpSystem(a, b *System, f string) int {
	switch f {
	case "name":
		return cmpStr(a.Name, b.Name)
	case "createdAt":
		if c := cmpTime(a.CreatedAt, b.CreatedAt); c != 0 {
			return c
		}
	}
	return cmpInt(a.ID, b.ID)
}

func cmpDef(a, b *ServiceDef, f string) int {
	switch f {
	case "name":
		return cmpStr(a.Name, b.Name)
	case "createdAt":
		if c := cmpTime(a.CreatedAt, b.CreatedAt); c != 0 {
			return c
		}
	}
	return cmpInt(a.ID, b.ID)
}

func cmpTemplate(a, b *Template, f string) int {
	switch f {
	case "name":
		return cmpStr(a.Name, b.Name)
	case "createdAt":
		if c := cmpTime(a.CreatedAt, b.CreatedAt); c != 0 {
			return c
		}
	}
	return cmpInt(a.ID, b.ID)
}

func cmpInstance(a, b *Instance, f string) int {
	switch f {
	case "serviceInstanceId":
		return cmpStr(a.InstanceID, b.InstanceID)
	case "createdAt":
		if c := cmpTime(a.CreatedAt, b.CreatedAt); c != 0 {
			return c
		}
	}
	return cmpInt(a.ID, b.ID)
}

// ---------------------------------------------------------------------------------------------
// conversions entity -> DTO

func ts(t time.Time) string { return formatInstant(t) }

func toAddressDTOs(a []Address) []Address {
	out := make([]Address, len(a))
	copy(out, a)
	return out
}

func (rg *Registry) deviceResp(d *Device) DeviceResp {
	return DeviceResp{Name: d.Name, Metadata: d.Metadata, Addresses: toAddressDTOs(d.Addresses), CreatedAt: ts(d.CreatedAt), UpdatedAt: ts(d.UpdatedAt)}
}

func deviceTerse(d *Device) *DeviceResp { return &DeviceResp{Name: d.Name} }

// systemResp converts a system. mode: "full" (device with details), "terse" (device name only),
// "plain" (neither addresses nor device).
func (rg *Registry) systemResp(st *state, s *System, mode string) SystemResp {
	r := SystemResp{Name: s.Name, Metadata: s.Metadata, Version: s.Version, CreatedAt: ts(s.CreatedAt), UpdatedAt: ts(s.UpdatedAt)}
	if mode == "plain" {
		return r
	}
	r.Addresses = toAddressDTOs(s.Addresses)
	if s.DeviceName != "" {
		if d, ok := st.Devices[s.DeviceName]; ok {
			if mode == "terse" {
				r.Device = deviceTerse(d)
			} else {
				dr := rg.deviceResp(d)
				r.Device = &dr
			}
		}
	}
	return r
}

func (rg *Registry) instanceRespBase(st *state, in *Instance, providerMode string) InstanceResp {
	r := InstanceResp{
		InstanceID: in.InstanceID,
		Version:    in.Version,
		Metadata:   in.Metadata,
		CreatedAt:  ts(in.CreatedAt),
		UpdatedAt:  ts(in.UpdatedAt),
		Interfaces: []InterfaceResp{},
	}
	if sys, ok := st.Systems[in.System]; ok {
		r.Provider = rg.systemResp(st, sys, providerMode)
	} else {
		r.Provider = SystemResp{Name: in.System}
	}
	if d, ok := st.Defs[in.Definition]; ok {
		r.ServiceDefinition = ServiceDefResp{Name: d.Name, CreatedAt: ts(d.CreatedAt), UpdatedAt: ts(d.UpdatedAt)}
	} else {
		r.ServiceDefinition = ServiceDefResp{Name: in.Definition}
	}
	if in.ExpiresAt != nil {
		r.ExpiresAt = ts(*in.ExpiresAt)
	}
	for _, f := range in.Interfaces {
		proto := ""
		if t, ok := st.Templates[f.Template]; ok {
			proto = t.Protocol
		}
		r.Interfaces = append(r.Interfaces, InterfaceResp{TemplateName: f.Template, Protocol: proto, Policy: f.Policy, Properties: f.Properties})
	}
	return r
}

func (rg *Registry) templateResp(t *Template) TemplateResp {
	r := TemplateResp{Name: t.Name, Protocol: t.Protocol, CreatedAt: ts(t.CreatedAt), UpdatedAt: ts(t.UpdatedAt), PropertyRequirements: []TemplatePropResp{}}
	for _, p := range t.Props {
		pr := TemplatePropResp{Name: p.Name, Mandatory: p.Mandatory}
		if p.Validator != "" {
			parts := strings.Split(p.Validator, validatorDelimiter)
			pr.Validator = parts[0]
			params := []string{}
			if len(parts) > 1 {
				params = parts[1:]
			}
			pr.ValidatorParams = &params
		}
		r.PropertyRequirements = append(r.PropertyRequirements, pr)
	}
	return r
}

// TemplatePropResp is the response form of a template property (validatorParams is only present
// when a validator is defined, like the NON_NULL serialization of the Java DTO).
type TemplatePropResp struct {
	Name            string    `json:"name"`
	Mandatory       bool      `json:"mandatory"`
	Validator       string    `json:"validator,omitempty"`
	ValidatorParams *[]string `json:"validatorParams,omitempty"`
}

// ---------------------------------------------------------------------------------------------
// shared validation pieces

func (rg *Registry) checkMetadata(m Meta) error {
	if len(m) > 0 {
		return validateMetadataKeys(map[string]any(m))
	}
	return nil
}

func (rg *Registry) validateAddrAgainstType(typ string, addrs []string) error {
	for _, a := range addrs {
		if err := rg.rules.ValidateAddress(typ, a); err != nil {
			return err
		}
	}
	return nil
}

func normAddrList(rules *Rules, in []string) []string {
	if len(in) == 0 {
		return nil
	}
	return mapStrings(in, rules.NormAddress)
}

func normList(in []string, f func(string) string) []string {
	if len(in) == 0 {
		return nil
	}
	return mapStrings(in, f)
}

func metaEqual(a, b Meta) bool {
	if len(a) == 0 && len(b) == 0 {
		return true
	}
	return evalOp("EQUALS", map[string]any(a), map[string]any(b))
}

func parseExpiry(s string) (*time.Time, error) {
	if isBlank(s) {
		return nil, nil
	}
	t, err := parseInstant(s)
	if err != nil {
		return nil, err
	}
	t = t.UTC()
	return &t, nil
}

func stringSliceIn(s string, list []string) bool { return containsStr(list, s) }

func joinNames(l []string) string { return strings.Join(l, ", ") }
