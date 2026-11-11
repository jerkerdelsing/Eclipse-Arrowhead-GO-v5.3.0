package main

import (
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------------------------
// interfaces

func (rg *Registry) rawValidateInterfaces(ifaces []InterfaceReq) error {
	for _, i := range ifaces {
		if isBlank(i.TemplateName) {
			return errInvalid("Interface template name is missing")
		}
		if isBlank(i.Policy) {
			return errInvalid("Interface policy is missing")
		}
		if !isPolicy(upperTrim(i.Policy)) {
			return errInvalid("Invalid interface policy")
		}
		if len(i.Properties) == 0 {
			return errInvalid("Interface properties are missing")
		}
		if err := rg.checkMetadata(i.Properties); err != nil {
			return err
		}
	}
	return nil
}

func (rg *Registry) normalizeInterface(i InterfaceReq) InterfaceReq {
	proto := ""
	if !isBlank(i.Protocol) {
		proto = strings.ToLower(strings.TrimSpace(i.Protocol))
	}
	return InterfaceReq{
		TemplateName: rg.rules.NormTemplateName(i.TemplateName),
		Protocol:     proto,
		Policy:       upperTrim(i.Policy),
		Properties:   i.Properties,
	}
}

func (rg *Registry) normalizeInterfaces(in []InterfaceReq) []InterfaceReq {
	out := make([]InterfaceReq, 0, len(in))
	for _, i := range in {
		out = append(out, rg.normalizeInterface(i))
	}
	return out
}

// validateInterfaces validates the (normalized) interface instances against the templates and
// returns them with normalized property values.
func (rg *Registry) validateInterfaces(st *state, ifaces []InterfaceReq) ([]InterfaceReq, error) {
	out := make([]InterfaceReq, 0, len(ifaces))
	for _, i := range ifaces {
		if err := rg.rules.ValidateTemplateName(i.TemplateName); err != nil {
			return nil, err
		}
		props := copyMeta(i.Properties)
		tpl, ok := st.Templates[i.TemplateName]
		if !ok {
			if isBlank(i.Protocol) {
				return nil, errInvalid("Interface protocol is missing")
			}
			if utf16Len(i.Protocol) > interfaceProtocolMax {
				return nil, errInvalid("Interface protocol is too long")
			}
			for k := range props {
				if utf16Len(k) > interfacePropNameMax {
					return nil, errInvalid("Interface property name is too long")
				}
			}
			if err := rg.rules.normalizeAddressProperty(props); err != nil {
				return nil, err
			}
			out = append(out, InterfaceReq{TemplateName: i.TemplateName, Protocol: i.Protocol, Policy: i.Policy, Properties: props})
			continue
		}
		if !isBlank(i.Protocol) && i.Protocol != tpl.Protocol {
			return nil, errInvalid(i.Protocol + " protocol is invalid for " + i.TemplateName)
		}
		for _, tp := range tpl.Props {
			val, present := props[tp.Name]
			if (!present || val == nil) && tp.Mandatory {
				return nil, errInvalid(tp.Name + " interface property is missing for " + tpl.Name)
			}
			if present && val != nil && tp.Validator != "" {
				parts := strings.Split(tp.Validator, validatorDelimiter)
				vtype := parts[0]
				if !containsStr(validatorTypes, vtype) {
					return nil, errInvalid("Unknown property validator: " + vtype)
				}
				if vtype != "NOT_EMPTY_ADDRESS_LIST" {
					if err := rg.rules.normalizeAddressProperty(props); err != nil {
						return nil, err
					}
				}
				norm, err := rg.rules.validateAndNormalizeProperty(vtype, props[tp.Name], parts[1:])
				if err != nil {
					return nil, err
				}
				props[tp.Name] = norm
			}
		}
		out = append(out, InterfaceReq{TemplateName: i.TemplateName, Protocol: i.Protocol, Policy: i.Policy, Properties: props})
	}
	return out, nil
}

// buildInterfaces creates the interface entities of an instance (creating templates when the
// interface policy allows it).
func (rg *Registry) buildInterfaces(st *state, ifaces []InterfaceReq) ([]InstanceInterface, error) {
	policy := rg.cfg.ServiceDiscoveryInterfacePolicy
	out := make([]InstanceInterface, 0, len(ifaces))
	for _, i := range ifaces {
		tpl, ok := st.Templates[i.TemplateName]
		if !ok {
			if policy == "restricted" {
				return nil, errInvalid("Interface template does not exist: " + i.TemplateName)
			}
			if isBlank(i.Protocol) {
				return nil, errInvalid("No protocol has been defined")
			}
			now := rg.now()
			tpl = &Template{ID: st.newID(), Name: i.TemplateName, Protocol: i.Protocol, CreatedAt: now, UpdatedAt: now}
			if policy == "extendable" {
				for _, k := range sortedKeys(i.Properties) {
					tpl.Props = append(tpl.Props, TemplateProp{Name: k, Mandatory: true})
				}
			}
			st.Templates[i.TemplateName] = tpl
		} else {
			if !isBlank(i.Protocol) && !strings.EqualFold(tpl.Protocol, i.Protocol) {
				return nil, errInvalid("Interface has different protocol than " + i.TemplateName + " template")
			}
			for _, p := range tpl.Props {
				if p.Mandatory {
					if _, has := i.Properties[p.Name]; !has {
						return nil, errInvalid("Mandatory interface property is missing: " + p.Name)
					}
				}
			}
		}
		out = append(out, InstanceInterface{Template: i.TemplateName, Policy: i.Policy, Properties: copyMeta(i.Properties)})
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------
// instance creation

func (rg *Registry) normalizeInstance(r *InstanceReq) InstanceReq {
	exp := ""
	if !isBlank(r.ExpiresAt) {
		exp = strings.TrimSpace(r.ExpiresAt)
	}
	return InstanceReq{
		SystemName:            rg.rules.NormSystemName(r.SystemName),
		ServiceDefinitionName: rg.rules.NormServiceDef(r.ServiceDefinitionName),
		Version:               rg.rules.NormVersion(r.Version),
		ExpiresAt:             exp,
		Metadata:              r.Metadata,
		Interfaces:            rg.normalizeInterfaces(r.Interfaces),
	}
}

func (rg *Registry) createInstances(st *state, cands []InstanceReq) ([]*Instance, error) {
	for _, c := range cands {
		if expected := authorityProvider(c.ServiceDefinitionName); expected != "" && c.SystemName != expected {
			return nil, errForbidden("Authority service " + c.ServiceDefinitionName + " is reserved for " + expected)
		}
		// core and support service definitions only for their owning systems (J9)
		if owners, reserved := rg.cfg.ReservedDefs[c.ServiceDefinitionName]; reserved && !slices.Contains(owners, c.SystemName) {
			return nil, errForbidden("Service definition " + c.ServiceDefinitionName + " is reserved for " + strings.Join(owners, ", "))
		}
	}
	ids := map[string]bool{}
	tnames := map[string]bool{}
	for _, c := range cands {
		ids[calcInstanceID(c.SystemName, c.ServiceDefinitionName, c.Version)] = true
		for _, i := range c.Interfaces {
			tnames[i.TemplateName] = true
		}
	}
	for id := range ids {
		delete(st.Instances, id)
	}
	if rg.cfg.ServiceDiscoveryInterfacePolicy == "restricted" {
		for _, t := range sortedKeys(tnames) {
			if _, ok := st.Templates[t]; !ok {
				return nil, errInvalid("Interface template does not exist: " + t)
			}
		}
	}
	now := rg.now()
	out := make([]*Instance, 0, len(cands))
	for _, c := range cands {
		if _, ok := st.Systems[c.SystemName]; !ok {
			return nil, errInvalid("System does not exist: " + c.SystemName)
		}
		if _, ok := st.Defs[c.ServiceDefinitionName]; !ok {
			st.Defs[c.ServiceDefinitionName] = &ServiceDef{ID: st.newID(), Name: c.ServiceDefinitionName, CreatedAt: now, UpdatedAt: now}
		}
		exp, err := parseExpiry(c.ExpiresAt)
		if err != nil {
			return nil, errInvalid("Expiration time has an invalid time format")
		}
		ifaces, err := rg.buildInterfaces(st, c.Interfaces)
		if err != nil {
			return nil, err
		}
		id := calcInstanceID(c.SystemName, c.ServiceDefinitionName, c.Version)
		in := &Instance{
			ID: st.newID(), InstanceID: id, System: c.SystemName, Definition: c.ServiceDefinitionName, Version: c.Version,
			ExpiresAt: exp, Metadata: copyMeta(c.Metadata), Interfaces: ifaces, CreatedAt: now, UpdatedAt: now,
		}
		st.Instances[id] = in
		out = append(out, in)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------
// ServiceDiscovery: register

func (rg *Registry) RegisterService(req *InstanceReq) (InstanceResp, error) {
	if req == nil {
		return InstanceResp{}, errInvalid("Request payload is missing")
	}
	if isBlank(req.SystemName) {
		return InstanceResp{}, errInvalid("System name is empty")
	}
	if isBlank(req.ServiceDefinitionName) {
		return InstanceResp{}, errInvalid("Service definition name is empty")
	}
	if !isBlank(req.ExpiresAt) {
		exp, err := parseInstant(req.ExpiresAt)
		if err != nil {
			return InstanceResp{}, errInvalid("Expiration time has an invalid time format")
		}
		if rg.now().After(exp) {
			return InstanceResp{}, errInvalid("Expiration time is in the past")
		}
	}
	if err := rg.checkMetadata(req.Metadata); err != nil {
		return InstanceResp{}, err
	}
	if len(req.Interfaces) == 0 {
		return InstanceResp{}, errInvalid("Service interface list is empty")
	}
	if err := rg.rawValidateInterfaces(req.Interfaces); err != nil {
		return InstanceResp{}, err
	}
	n := rg.normalizeInstance(req)
	var resp InstanceResp
	err := rg.store.Update(func(st *state) error {
		if err := rg.rules.ValidateSystemName(n.SystemName); err != nil {
			return err
		}
		if err := rg.rules.ValidateServiceDef(n.ServiceDefinitionName); err != nil {
			return err
		}
		if err := rg.rules.ValidateVersion(n.Version); err != nil {
			return err
		}
		ifaces, err := rg.validateInterfaces(st, n.Interfaces)
		if err != nil {
			return err
		}
		for _, i := range ifaces {
			if !policyOfferable(i.Policy) {
				return errInvalid("Invalid interface policy: " + i.Policy)
			}
		}
		if v, ok := n.Metadata[metaKeyAllowExclusivity]; ok {
			s, isStr := v.(string)
			if !isStr {
				return errInvalid(metaKeyAllowExclusivity + " metadata must have the string representation of an integer value.")
			}
			if _, err := strconv.Atoi(s); err != nil {
				return errInvalid(metaKeyAllowExclusivity + " metadata must have the string representation of an integer value.")
			}
		}
		n.Interfaces = ifaces
		ins, err := rg.createInstances(st, []InstanceReq{n})
		if err != nil {
			return err
		}
		resp = rg.instanceResp(st, ins[0], "full")
		return nil
	})
	return resp, err
}

func (rg *Registry) instanceResp(st *state, in *Instance, providerMode string) InstanceResp {
	return rg.instanceRespIf(st, in, in.Interfaces, providerMode)
}

func (rg *Registry) instanceRespIf(st *state, in *Instance, ifaces []InstanceInterface, providerMode string) InstanceResp {
	cp := *in
	cp.Interfaces = ifaces
	return rg.instanceRespBase(st, &cp, providerMode)
}

// ---------------------------------------------------------------------------------------------
// lookup / query

type lookupFilter struct {
	instanceIDs   []string
	providerNames []string
	defNames      []string
	versions      []string
	alivesAt      *time.Time
	metaReqs      []Meta
	addressTypes  []string
	templateNames []string
	propReqs      []Meta
	policies      []string
}

func (f *lookupFilter) hasFilters() bool {
	return len(f.instanceIDs) > 0 || len(f.providerNames) > 0 || len(f.defNames) > 0 || len(f.versions) > 0 ||
		f.alivesAt != nil || len(f.metaReqs) > 0 || len(f.addressTypes) > 0 || len(f.templateNames) > 0 ||
		len(f.propReqs) > 0 || len(f.policies) > 0
}

// validateLookup validates the raw lookup/query filters (messages of ServiceDiscoveryValidation
// and ManagementValidation) and returns the normalized filter.
func (rg *Registry) validateLookup(r *InstanceLookupReq) (*lookupFilter, error) {
	if len(r.InstanceIDs) == 0 && len(r.ProviderNames) == 0 && len(r.ServiceDefinitionNames) == 0 {
		return nil, errInvalid("One of the following filters must be used: 'instanceIds', 'providerNames', 'serviceDefinitionNames'")
	}
	checks := []struct {
		l   []string
		msg string
	}{
		{r.InstanceIDs, "Instance id list contains null or empty element"},
		{r.ProviderNames, "Provider name list contains null or empty element"},
		{r.ServiceDefinitionNames, "Service definition name list contains null or empty element"},
		{r.Versions, "Version list contains null or empty element"},
	}
	for _, c := range checks {
		if len(c.l) > 0 && containsNullOrEmpty(c.l) {
			return nil, errInvalid(c.msg)
		}
	}
	f := &lookupFilter{}
	if !isBlank(r.AlivesAt) {
		t, err := parseInstant(r.AlivesAt)
		if err != nil {
			return nil, errInvalid("Alive time has an invalid time format")
		}
		t = t.UTC()
		f.alivesAt = &t
	}
	if len(r.MetadataRequirementsList) > 0 && containsNilMeta(r.MetadataRequirementsList) {
		return nil, errInvalid("Metadata requirements list contains null element")
	}
	for _, t := range r.AddressTypes {
		if isBlank(t) {
			return nil, errInvalid("Address type list contains null or empty element")
		}
		if !validAddressType(strings.ToUpper(t)) {
			return nil, errInvalid("Address type list contains invalid element: " + t)
		}
	}
	if len(r.InterfaceTemplateNames) > 0 && containsNullOrEmpty(r.InterfaceTemplateNames) {
		return nil, errInvalid("Interface template list contains null or empty element")
	}
	if len(r.InterfacePropertyRequirementsList) > 0 && containsNilMeta(r.InterfacePropertyRequirementsList) {
		return nil, errInvalid("Interface property requirements list contains null element")
	}
	for _, p := range r.Policies {
		if isBlank(p) {
			return nil, errInvalid("Policy list contains null or empty element")
		}
		if !isPolicy(strings.ToUpper(p)) {
			return nil, errInvalid("Policy list contains invalid element: " + p)
		}
	}
	// normalization
	f.instanceIDs = normList(r.InstanceIDs, rg.rules.NormInstanceID)
	f.providerNames = normList(r.ProviderNames, rg.rules.NormSystemName)
	f.defNames = normList(r.ServiceDefinitionNames, rg.rules.NormServiceDef)
	f.versions = normList(r.Versions, rg.rules.NormVersion)
	f.metaReqs = r.MetadataRequirementsList
	f.addressTypes = normList(r.AddressTypes, upperTrim)
	f.templateNames = normList(r.InterfaceTemplateNames, rg.rules.NormTemplateName)
	f.propReqs = r.InterfacePropertyRequirementsList
	f.policies = normList(r.Policies, upperTrim)
	// validation of normalized values
	for _, id := range f.instanceIDs {
		if err := rg.rules.ValidateInstanceID(id); err != nil {
			return nil, err
		}
	}
	for _, n := range f.providerNames {
		if err := rg.rules.ValidateSystemName(n); err != nil {
			return nil, err
		}
	}
	for _, n := range f.defNames {
		if err := rg.rules.ValidateServiceDef(n); err != nil {
			return nil, err
		}
	}
	for _, v := range f.versions {
		if err := rg.rules.ValidateVersion(v); err != nil {
			return nil, err
		}
	}
	for _, n := range f.templateNames {
		if err := rg.rules.ValidateTemplateName(n); err != nil {
			return nil, err
		}
	}
	for _, p := range f.policies {
		if !policyOfferable(p) {
			return nil, errInvalid("Invalid interface policy: " + p)
		}
	}
	return f, nil
}

type matchedInstance struct {
	in     *Instance
	ifaces []InstanceInterface
}

// filterInstances applies the lookup filter. Expired candidates are skipped and returned in
// `expired` so the caller can purge them (like the reference implementation does).
func (rg *Registry) filterInstances(st *state, f *lookupFilter) ([]matchedInstance, []string, error) {
	var candidates []*Instance
	baseSystem, baseDef := false, false
	switch {
	case len(f.instanceIDs) > 0:
		for _, id := range f.instanceIDs {
			if in, ok := st.Instances[id]; ok {
				candidates = append(candidates, in)
			}
		}
	case len(f.providerNames) > 0:
		baseSystem = true
		for _, in := range st.Instances {
			if containsStr(f.providerNames, in.System) {
				candidates = append(candidates, in)
			}
		}
	case len(f.defNames) > 0:
		baseDef = true
		for _, in := range st.Instances {
			if containsStr(f.defNames, in.Definition) {
				candidates = append(candidates, in)
			}
		}
	default:
		for _, in := range st.Instances {
			candidates = append(candidates, in)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].ID < candidates[j].ID })
	now := rg.now()
	var out []matchedInstance
	var expired []string
	for _, c := range candidates {
		if c.ExpiresAt != nil && now.After(*c.ExpiresAt) {
			expired = append(expired, c.InstanceID)
			continue
		}
		if !baseSystem && len(f.providerNames) > 0 && !containsStr(f.providerNames, c.System) {
			continue
		}
		if !baseDef && len(f.defNames) > 0 && !containsStr(f.defNames, c.Definition) {
			continue
		}
		if len(f.versions) > 0 && !containsStr(f.versions, c.Version) {
			continue
		}
		if f.alivesAt != nil && c.ExpiresAt != nil && c.ExpiresAt.Before(*f.alivesAt) {
			continue
		}
		if len(f.metaReqs) > 0 {
			ok, err := anyMetadataMatch(c.Metadata, f.metaReqs)
			if err != nil {
				return nil, nil, err
			}
			if !ok {
				continue
			}
		}
		var ifaces []InstanceInterface
		for _, itf := range c.Interfaces {
			if len(f.policies) > 0 && !containsStr(f.policies, itf.Policy) {
				continue
			}
			if len(f.templateNames) > 0 && !containsStr(f.templateNames, itf.Template) {
				continue
			}
			props := itf.Properties
			if len(f.propReqs) > 0 {
				ok, err := anyMetadataMatch(props, f.propReqs)
				if err != nil {
					return nil, nil, err
				}
				if !ok {
					continue
				}
			}
			if len(f.addressTypes) > 0 {
				cp := copyMeta(props)
				if !rg.rules.filterOnAddressTypes(cp, f.addressTypes) {
					continue
				}
				props = cp
			}
			ifaces = append(ifaces, InstanceInterface{Template: itf.Template, Policy: itf.Policy, Properties: props})
		}
		if len(ifaces) == 0 {
			continue
		}
		out = append(out, matchedInstance{c, ifaces})
	}
	return out, expired, nil
}

func (rg *Registry) purgeExpired(ids []string) {
	if len(ids) == 0 {
		return
	}
	_ = rg.store.Update(func(st *state) error {
		now := rg.now()
		for _, id := range ids {
			if in, ok := st.Instances[id]; ok && in.ExpiresAt != nil && now.After(*in.ExpiresAt) {
				delete(st.Instances, id)
			}
		}
		return nil
	})
}

// LookupService implements serviceDiscovery/lookup. restricted adds the unrestrictedDiscovery
// metadata requirement.
func (rg *Registry) LookupService(req *InstanceLookupReq, verbose, restricted bool) (InstanceListResp, error) {
	if req == nil {
		return InstanceListResp{}, errInvalid("Request payload is missing")
	}
	f, err := rg.validateLookup(req)
	if err != nil {
		return InstanceListResp{}, err
	}
	if restricted {
		if len(f.metaReqs) == 0 {
			f.metaReqs = []Meta{{}}
		}
		reqs := make([]Meta, 0, len(f.metaReqs))
		for _, m := range f.metaReqs {
			cp := copyMeta(m)
			cp[metaKeyUnrestrictedDiscovery] = true
			reqs = append(reqs, cp)
		}
		f.metaReqs = reqs
	}
	if verbose && !rg.cfg.DiscoveryVerbose {
		return InstanceListResp{}, errForbidden("Verbose is not allowed")
	}
	var resp InstanceListResp
	var expired []string
	var ferr error
	rg.store.View(func(st *state) {
		ms, exp, err := rg.filterInstances(st, f)
		if err != nil {
			ferr = err
			return
		}
		expired = exp
		sort.Slice(ms, func(i, j int) bool { return ms[i].in.InstanceID > ms[j].in.InstanceID })
		mode := "plain"
		if verbose {
			mode = "full"
		}
		resp.Entries = make([]InstanceResp, 0, len(ms))
		for _, m := range ms {
			resp.Entries = append(resp.Entries, rg.instanceRespIf(st, m.in, m.ifaces, mode))
		}
		resp.Count = int64(len(ms))
	})
	rg.purgeExpired(expired)
	return resp, ferr
}

func (rg *Registry) RevokeService(identifiedSystem, instanceID string) (bool, error) {
	if isBlank(identifiedSystem) {
		return false, errInvalid("System name is empty")
	}
	if isBlank(instanceID) {
		return false, errInvalid("Service instance ID is missing")
	}
	sysName := rg.rules.NormSystemName(identifiedSystem)
	id := rg.rules.NormInstanceID(instanceID)
	if err := rg.rules.ValidateSystemName(sysName); err != nil {
		return false, err
	}
	if err := rg.rules.ValidateInstanceID(id); err != nil {
		return false, err
	}
	if systemNameOfInstanceID(id) != sysName {
		return false, errForbidden("Revoking other systems' service is forbidden")
	}
	found := false
	err := rg.store.Update(func(st *state) error {
		if _, ok := st.Instances[id]; ok {
			delete(st.Instances, id)
			found = true
		}
		return nil
	})
	return found, err
}
