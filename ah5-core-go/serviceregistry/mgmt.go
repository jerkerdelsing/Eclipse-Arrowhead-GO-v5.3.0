package main

import (
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------------------------
// devices

func (rg *Registry) validateDeviceList(req *DeviceListReq) error {
	if req == nil {
		return errInvalid("Request payload is missing")
	}
	if len(req.Devices) == 0 {
		return errInvalid("Request payload is empty")
	}
	names := map[string]bool{}
	for _, d := range req.Devices {
		if d == nil {
			return errInvalid("Device list contains null element")
		}
		if isBlank(d.Name) {
			return errInvalid("Device name is empty")
		}
		n := rg.rules.NormDeviceName(d.Name)
		if names[n] {
			return errInvalid("Duplicated device name: " + n)
		}
		names[n] = true
		if len(d.Addresses) == 0 {
			return errInvalid("At least one device address is needed for every device")
		}
		for _, a := range d.Addresses {
			if isBlank(a) {
				return errInvalid("Address is missing")
			}
		}
		if err := rg.checkMetadata(d.Metadata); err != nil {
			return err
		}
	}
	return nil
}

func (rg *Registry) normalizeValidateDevices(req *DeviceListReq) ([]normDevice, error) {
	if err := rg.validateDeviceList(req); err != nil {
		return nil, err
	}
	out := make([]normDevice, 0, len(req.Devices))
	for _, d := range req.Devices {
		n := rg.normalizeDevice(d)
		if err := rg.validateNormDevice(n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (rg *Registry) deviceListResp(ds []*Device) DeviceListResp {
	resp := DeviceListResp{Entries: make([]DeviceResp, 0, len(ds)), Count: int64(len(ds))}
	for _, d := range ds {
		resp.Entries = append(resp.Entries, rg.deviceResp(d))
	}
	return resp
}

func (rg *Registry) CreateDevices(req *DeviceListReq) (DeviceListResp, error) {
	cands, err := rg.normalizeValidateDevices(req)
	if err != nil {
		return DeviceListResp{}, err
	}
	var resp DeviceListResp
	err = rg.store.Update(func(st *state) error {
		ds, err := rg.createDevices(st, cands)
		if err != nil {
			return err
		}
		resp = rg.deviceListResp(ds)
		return nil
	})
	return resp, err
}

func (rg *Registry) UpdateDevices(req *DeviceListReq) (DeviceListResp, error) {
	cands, err := rg.normalizeValidateDevices(req)
	if err != nil {
		return DeviceListResp{}, err
	}
	var resp DeviceListResp
	err = rg.store.Update(func(st *state) error {
		ds, err := rg.updateDevices(st, cands)
		if err != nil {
			return err
		}
		resp = rg.deviceListResp(ds)
		return nil
	})
	return resp, err
}

func (rg *Registry) QueryDevices(req *DeviceQueryReq) (DeviceListResp, error) {
	var pg *PageDTO
	var names, addrs []string
	var addrType string
	var reqs []Meta
	if req != nil {
		if err := rg.validatePage(req.Pagination, sortableDevice); err != nil {
			return DeviceListResp{}, err
		}
		if len(req.DeviceNames) > 0 && containsNullOrEmpty(req.DeviceNames) {
			return DeviceListResp{}, errInvalid("Device name list contains null or empty element")
		}
		if len(req.Addresses) > 0 && containsNullOrEmpty(req.Addresses) {
			return DeviceListResp{}, errInvalid("Address list contains null or empty element")
		}
		if !isBlank(req.AddressType) && !validAddressType(strings.ToUpper(req.AddressType)) {
			return DeviceListResp{}, errInvalid("Invalid address type: " + req.AddressType)
		}
		if len(req.MetadataRequirementList) > 0 && containsNilMeta(req.MetadataRequirementList) {
			return DeviceListResp{}, errInvalid("Metadata requirement list contains null element")
		}
		pg = req.Pagination
		names = normList(req.DeviceNames, rg.rules.NormDeviceName)
		addrs = normAddrList(rg.rules, req.Addresses)
		if !isBlank(req.AddressType) {
			addrType = upperTrim(req.AddressType)
		}
		reqs = req.MetadataRequirementList
	}
	for _, n := range names {
		if err := rg.rules.ValidateDeviceName(n); err != nil {
			return DeviceListResp{}, err
		}
	}
	if addrType != "" && len(addrs) > 0 {
		if err := rg.validateAddrAgainstType(addrType, addrs); err != nil {
			return DeviceListResp{}, err
		}
	}
	pr, err := rg.pageRequest(pg, true, sortableDevice, "name")
	if err != nil {
		return DeviceListResp{}, err
	}
	var resp DeviceListResp
	var ferr error
	rg.store.View(func(st *state) {
		ds, err := rg.filterDevices(st, names, addrs, addrType, reqs)
		if err != nil {
			ferr = err
			return
		}
		page, total := sortAndPage(ds, pr, cmpDevice)
		resp = rg.deviceListResp(page)
		resp.Count = int64(total)
	})
	return resp, ferr
}

func (rg *Registry) validateNameList(names []string, missingMsg, nullMsg string) error {
	if len(names) == 0 {
		return errInvalid(missingMsg)
	}
	if containsNullOrEmpty(names) {
		return errInvalid(nullMsg)
	}
	return nil
}

func (rg *Registry) RemoveDevices(names []string) error {
	if err := rg.validateNameList(names, "Device name list is missing or empty", "Device name list contains null or empty element"); err != nil {
		return err
	}
	norm := mapStrings(names, rg.rules.NormDeviceName)
	for _, n := range norm {
		if err := rg.rules.ValidateDeviceName(n); err != nil {
			return err
		}
	}
	return rg.store.Update(func(st *state) error {
		var existing []string
		for _, n := range norm {
			if _, ok := st.Devices[n]; ok {
				existing = append(existing, n)
			}
		}
		for _, n := range existing {
			if len(st.systemsOfDevice(n)) > 0 {
				return errLocked("At least one system is assigned to these devices")
			}
		}
		for _, n := range existing {
			delete(st.Devices, n)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------------------------
// systems

func (rg *Registry) normalizeValidateSystems(req *SystemListReq) ([]normSystem, error) {
	if req == nil {
		return nil, errInvalid("Request payload is missing")
	}
	if len(req.Systems) == 0 {
		return nil, errInvalid("Request payload is empty")
	}
	names := map[string]bool{}
	for _, s := range req.Systems {
		if s == nil {
			return nil, errInvalid("System list contains null element")
		}
		if isBlank(s.Name) {
			return nil, errInvalid("System name is empty")
		}
		n := rg.rules.NormSystemName(s.Name)
		if names[n] {
			return nil, errInvalid("Duplicated system name: " + n)
		}
		names[n] = true
		for _, a := range s.Addresses {
			if isBlank(a) {
				return nil, errInvalid("Address value is missing")
			}
		}
		if len(s.Addresses) == 0 && isBlank(s.DeviceName) {
			return nil, errInvalid("At least one system address is needed for every system")
		}
		if err := rg.checkMetadata(s.Metadata); err != nil {
			return nil, err
		}
	}
	out := make([]normSystem, 0, len(req.Systems))
	for _, s := range req.Systems {
		n := rg.normalizeSystem(s.Name, s)
		if err := rg.validateNormSystem(n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}

func (rg *Registry) systemListResp(st *state, ss []*System) SystemListResp {
	resp := SystemListResp{Entries: make([]SystemResp, 0, len(ss)), Count: int64(len(ss))}
	for _, s := range ss {
		resp.Entries = append(resp.Entries, rg.systemResp(st, s, "full"))
	}
	return resp
}

func (rg *Registry) CreateSystems(req *SystemListReq) (SystemListResp, error) {
	cands, err := rg.normalizeValidateSystems(req)
	if err != nil {
		return SystemListResp{}, err
	}
	var resp SystemListResp
	err = rg.store.Update(func(st *state) error {
		ss, err := rg.createSystems(st, cands)
		if err != nil {
			return err
		}
		resp = rg.systemListResp(st, ss)
		return nil
	})
	return resp, err
}

func (rg *Registry) UpdateSystems(req *SystemListReq) (SystemListResp, error) {
	cands, err := rg.normalizeValidateSystems(req)
	if err != nil {
		return SystemListResp{}, err
	}
	var resp SystemListResp
	err = rg.store.Update(func(st *state) error {
		ss, err := rg.updateSystems(st, cands)
		if err != nil {
			return err
		}
		resp = rg.systemListResp(st, ss)
		return nil
	})
	return resp, err
}

func (rg *Registry) QuerySystems(req *SystemQueryReq, verbose bool) (SystemListResp, error) {
	var pg *PageDTO
	var names, addrs, versions, devNames []string
	var addrType string
	var reqs []Meta
	if req != nil {
		if err := rg.validatePage(req.Pagination, sortableSystem); err != nil {
			return SystemListResp{}, err
		}
		if len(req.SystemNames) > 0 && containsNullOrEmpty(req.SystemNames) {
			return SystemListResp{}, errInvalid("System name list contains null or empty element")
		}
		if len(req.Addresses) > 0 && containsNullOrEmpty(req.Addresses) {
			return SystemListResp{}, errInvalid("Address list contains null or empty element")
		}
		if !isBlank(req.AddressType) && !validAddressType(strings.ToUpper(req.AddressType)) {
			return SystemListResp{}, errInvalid("Invalid address type: " + req.AddressType)
		}
		if len(req.MetadataRequirementList) > 0 && containsNilMeta(req.MetadataRequirementList) {
			return SystemListResp{}, errInvalid("Metadata requirement list contains null element")
		}
		if len(req.Versions) > 0 && containsNullOrEmpty(req.Versions) {
			return SystemListResp{}, errInvalid("Version list contains null or empty element")
		}
		if len(req.DeviceNames) > 0 && containsNullOrEmpty(req.DeviceNames) {
			return SystemListResp{}, errInvalid("Device name list contains null or empty element")
		}
		pg = req.Pagination
		names = normList(req.SystemNames, rg.rules.NormSystemName)
		addrs = normAddrList(rg.rules, req.Addresses)
		if !isBlank(req.AddressType) {
			addrType = upperTrim(req.AddressType)
		}
		reqs = req.MetadataRequirementList
		versions = normList(req.Versions, rg.rules.NormVersion)
		devNames = normList(req.DeviceNames, rg.rules.NormDeviceName)
	}
	if err := rg.validateSystemFilters(names, addrs, addrType, versions, devNames); err != nil {
		return SystemListResp{}, err
	}
	pr, err := rg.pageRequest(pg, true, sortableSystem, "createdAt")
	if err != nil {
		return SystemListResp{}, err
	}
	return rg.querySystemsInternal(names, addrs, addrType, reqs, versions, devNames, pr, func(st *state, s *System) SystemResp {
		if verbose {
			return rg.systemResp(st, s, "full")
		}
		return rg.systemResp(st, s, "terse")
	})
}

func (rg *Registry) RemoveSystems(names []string) error {
	if err := rg.validateNameList(names, "System name list is missing or empty", "System name list contains null or empty element"); err != nil {
		return err
	}
	norm := mapStrings(names, rg.rules.NormSystemName)
	for _, n := range norm {
		if err := rg.rules.ValidateSystemName(n); err != nil {
			return err
		}
	}
	return rg.store.Update(func(st *state) error {
		for _, n := range norm {
			st.deleteSystem(n)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------------------------
// service definitions

func (rg *Registry) QueryServiceDefinitions(pg *PageDTO) (ServiceDefListResp, error) {
	pr, err := rg.pageRequest(pg, true, sortableDef, "name")
	if err != nil {
		return ServiceDefListResp{}, err
	}
	var resp ServiceDefListResp
	rg.store.View(func(st *state) {
		defs := make([]*ServiceDef, 0, len(st.Defs))
		for _, d := range st.Defs {
			defs = append(defs, d)
		}
		page, total := sortAndPage(defs, pr, cmpDef)
		resp.Entries = defsResp(page)
		resp.Count = int64(total)
	})
	return resp, nil
}

func defsResp(defs []*ServiceDef) []ServiceDefResp {
	out := make([]ServiceDefResp, 0, len(defs))
	for _, d := range defs {
		out = append(out, ServiceDefResp{Name: d.Name, CreatedAt: ts(d.CreatedAt), UpdatedAt: ts(d.UpdatedAt)})
	}
	return out
}

func (rg *Registry) CreateServiceDefinitions(req *ServiceDefListReq) (ServiceDefListResp, error) {
	if req == nil {
		return ServiceDefListResp{}, errInvalid("Request payload is missing")
	}
	if len(req.ServiceDefinitionNames) == 0 {
		return ServiceDefListResp{}, errInvalid("Service definition name list is empty")
	}
	if containsNullOrEmpty(req.ServiceDefinitionNames) {
		return ServiceDefListResp{}, errInvalid("Service definition name list contains null or empty element")
	}
	seen := map[string]bool{}
	norm := make([]string, 0, len(req.ServiceDefinitionNames))
	for _, n := range req.ServiceDefinitionNames {
		nn := rg.rules.NormServiceDef(n)
		if seen[nn] {
			return ServiceDefListResp{}, errInvalid("Duplicated service defitition name: " + n)
		}
		seen[nn] = true
		norm = append(norm, nn)
	}
	for _, n := range norm {
		if err := rg.rules.ValidateServiceDef(n); err != nil {
			return ServiceDefListResp{}, err
		}
	}
	var resp ServiceDefListResp
	err := rg.store.Update(func(st *state) error {
		var existing []string
		for _, n := range norm {
			if _, ok := st.Defs[n]; ok {
				existing = append(existing, n)
			}
		}
		if len(existing) > 0 {
			return errInvalid("Service definition names already exists: " + joinNames(existing))
		}
		now := rg.now()
		var created []*ServiceDef
		for _, n := range norm {
			d := &ServiceDef{ID: st.newID(), Name: n, CreatedAt: now, UpdatedAt: now}
			st.Defs[n] = d
			created = append(created, d)
		}
		resp.Entries = defsResp(created)
		resp.Count = int64(len(created))
		return nil
	})
	return resp, err
}

func (rg *Registry) RemoveServiceDefinitions(names []string) error {
	if err := rg.validateNameList(names, "Service definition name list is missing or empty", "Service definition name list contains null or empty element"); err != nil {
		return err
	}
	norm := mapStrings(names, rg.rules.NormServiceDef)
	for _, n := range norm {
		if err := rg.rules.ValidateServiceDef(n); err != nil {
			return err
		}
	}
	return rg.store.Update(func(st *state) error {
		for _, n := range norm {
			st.deleteDefinition(n)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------------------------
// service instances

const expiryFormatMsg = "Expiration time has an invalid time format, UTC string expected (example: 2024-10-11T14:30:00Z)"

func (rg *Registry) checkExpiry(s string) error {
	if isBlank(s) {
		return nil
	}
	exp, err := parseInstant(s)
	if err != nil {
		return errInvalid(expiryFormatMsg)
	}
	if rg.now().After(exp) {
		return errInvalid("Expiration time is in the past")
	}
	return nil
}

func (rg *Registry) instanceListResp(st *state, ins []*Instance) InstanceListResp {
	resp := InstanceListResp{Entries: make([]InstanceResp, 0, len(ins)), Count: int64(len(ins))}
	for _, in := range ins {
		resp.Entries = append(resp.Entries, rg.instanceResp(st, in, "full"))
	}
	return resp
}

func (rg *Registry) CreateServiceInstances(req *InstanceCreateListReq) (InstanceListResp, error) {
	if req == nil {
		return InstanceListResp{}, errInvalid("Request payload is missing")
	}
	if len(req.Instances) == 0 {
		return InstanceListResp{}, errInvalid("Request payload is empty")
	}
	ids := map[string]bool{}
	for _, in := range req.Instances {
		if in == nil {
			return InstanceListResp{}, errInvalid("Service instance list contains null element")
		}
		if isBlank(in.SystemName) {
			return InstanceListResp{}, errInvalid("System name is empty")
		}
		if isBlank(in.ServiceDefinitionName) {
			return InstanceListResp{}, errInvalid("Service definition name is empty")
		}
		id := calcInstanceID(rg.rules.NormSystemName(in.SystemName), rg.rules.NormServiceDef(in.ServiceDefinitionName), rg.rules.NormVersion(in.Version))
		if ids[id] {
			return InstanceListResp{}, errInvalid("Duplicated instance: " + id)
		}
		ids[id] = true
		if err := rg.checkExpiry(in.ExpiresAt); err != nil {
			return InstanceListResp{}, err
		}
		if err := rg.checkMetadata(in.Metadata); err != nil {
			return InstanceListResp{}, err
		}
		if len(in.Interfaces) == 0 {
			return InstanceListResp{}, errInvalid("Service interface list is empty")
		}
		if err := rg.rawValidateInterfaces(in.Interfaces); err != nil {
			return InstanceListResp{}, err
		}
	}
	cands := make([]InstanceReq, 0, len(req.Instances))
	for _, in := range req.Instances {
		cands = append(cands, rg.normalizeInstance(in))
	}
	var resp InstanceListResp
	err := rg.store.Update(func(st *state) error {
		for i := range cands {
			c := &cands[i]
			if err := rg.rules.ValidateSystemName(c.SystemName); err != nil {
				return err
			}
			if err := rg.rules.ValidateServiceDef(c.ServiceDefinitionName); err != nil {
				return err
			}
			if err := rg.rules.ValidateVersion(c.Version); err != nil {
				return err
			}
			ifaces, err := rg.validateInterfaces(st, c.Interfaces)
			if err != nil {
				return err
			}
			for _, f := range ifaces {
				if !policyOfferable(f.Policy) {
					return errInvalid("Invalid interface policy: " + f.Policy)
				}
			}
			c.Interfaces = ifaces
		}
		ins, err := rg.createInstances(st, cands)
		if err != nil {
			return err
		}
		resp = rg.instanceListResp(st, ins)
		return nil
	})
	return resp, err
}

func (rg *Registry) UpdateServiceInstances(req *InstanceUpdateListReq) (InstanceListResp, error) {
	if req == nil {
		return InstanceListResp{}, errInvalid("Request payload is missing")
	}
	if len(req.Instances) == 0 {
		return InstanceListResp{}, errInvalid("Request payload is empty")
	}
	ids := map[string]bool{}
	for _, in := range req.Instances {
		if in == nil {
			return InstanceListResp{}, errInvalid("Service instance list contains null element")
		}
		if isBlank(in.InstanceID) {
			return InstanceListResp{}, errInvalid("Instance id is empty")
		}
		n := rg.rules.NormInstanceID(in.InstanceID)
		if ids[n] {
			return InstanceListResp{}, errInvalid("Duplicated instance id: " + in.InstanceID)
		}
		ids[n] = true
		if err := rg.checkExpiry(in.ExpiresAt); err != nil {
			return InstanceListResp{}, err
		}
		if err := rg.checkMetadata(in.Metadata); err != nil {
			return InstanceListResp{}, err
		}
		if len(in.Interfaces) == 0 {
			return InstanceListResp{}, errInvalid("Service interface list is empty")
		}
		if err := rg.rawValidateInterfaces(in.Interfaces); err != nil {
			return InstanceListResp{}, err
		}
	}
	var resp InstanceListResp
	err := rg.store.Update(func(st *state) error {
		now := rg.now()
		updated := make([]*Instance, 0, len(req.Instances))
		for _, u := range req.Instances {
			id := rg.rules.NormInstanceID(u.InstanceID)
			if err := rg.rules.ValidateInstanceID(id); err != nil {
				return err
			}
			ifaces, err := rg.validateInterfaces(st, rg.normalizeInterfaces(u.Interfaces))
			if err != nil {
				return err
			}
			for _, f := range ifaces {
				if !policyOfferable(f.Policy) {
					return errInvalid("Invalid interface policy: " + f.Policy)
				}
			}
			old, ok := st.Instances[id]
			if !ok {
				return errInvalid("Instance id does not exist: " + id)
			}
			exp, err := parseExpiry(u.ExpiresAt)
			if err != nil {
				return errInvalid(expiryFormatMsg)
			}
			built, err := rg.buildInterfaces(st, ifaces)
			if err != nil {
				return err
			}
			cp := *old
			cp.Metadata = copyMeta(u.Metadata)
			cp.ExpiresAt = exp
			cp.Interfaces = built
			cp.UpdatedAt = now
			st.Instances[id] = &cp
			updated = append(updated, &cp)
		}
		resp = rg.instanceListResp(st, updated)
		return nil
	})
	return resp, err
}

func (rg *Registry) RemoveServiceInstances(ids []string) error {
	if err := rg.validateNameList(ids, "Instance id list is empty", "Instance id list contains null or empty element"); err != nil {
		return err
	}
	norm := mapStrings(ids, rg.rules.NormInstanceID)
	for _, id := range norm {
		if err := rg.rules.ValidateInstanceID(id); err != nil {
			return err
		}
	}
	return rg.store.Update(func(st *state) error {
		for _, id := range norm {
			delete(st.Instances, id)
		}
		return nil
	})
}

func (rg *Registry) QueryServiceInstances(req *InstanceQueryReq, verbose bool) (InstanceListResp, error) {
	if req == nil {
		return InstanceListResp{}, errInvalid("Request payload is missing")
	}
	if err := rg.validatePage(req.Pagination, sortableInstance); err != nil {
		return InstanceListResp{}, err
	}
	f, err := rg.validateLookup(&req.InstanceLookupReq)
	if err != nil {
		return InstanceListResp{}, err
	}
	pr, err := rg.pageRequest(req.Pagination, true, sortableInstance, "serviceInstanceId")
	if err != nil {
		return InstanceListResp{}, err
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
		page, total := sortAndPage(ms, pr, func(a, b matchedInstance, field string) int { return cmpInstance(a.in, b.in, field) })
		mode := "plain"
		if verbose {
			mode = "full"
		}
		resp.Entries = make([]InstanceResp, 0, len(page))
		for _, m := range page {
			resp.Entries = append(resp.Entries, rg.instanceRespIf(st, m.in, m.ifaces, mode))
		}
		resp.Count = int64(total)
	})
	rg.purgeExpired(expired)
	return resp, ferr
}

// ---------------------------------------------------------------------------------------------
// interface templates

func (rg *Registry) CreateInterfaceTemplates(req *TemplateListReq) (TemplateListResp, error) {
	if req == nil {
		return TemplateListResp{}, errInvalid("Request payload is missing")
	}
	if len(req.InterfaceTemplates) == 0 {
		return TemplateListResp{}, errInvalid("Request payload is empty")
	}
	names := map[string]bool{}
	for _, t := range req.InterfaceTemplates {
		if t == nil {
			return TemplateListResp{}, errInvalid("Interface template list contains null element")
		}
		if isBlank(t.Name) {
			return TemplateListResp{}, errInvalid("Interface template name is empty")
		}
		n := rg.rules.NormTemplateName(t.Name)
		if names[n] {
			return TemplateListResp{}, errInvalid("Duplicated interface template name: " + t.Name)
		}
		names[n] = true
		if isBlank(t.Protocol) {
			return TemplateListResp{}, errInvalid("Interface template protocol is empty")
		}
		props := map[string]bool{}
		for _, p := range t.PropertyRequirements {
			if p == nil {
				return TemplateListResp{}, errInvalid("Interface template contains null property")
			}
			if isBlank(p.Name) {
				return TemplateListResp{}, errInvalid("Interface template property name is empty")
			}
			if strings.Contains(p.Name, metaKeyDelimiter) {
				return TemplateListResp{}, errInvalid("Invalid interface template property name: " + p.Name + ", it should not contain " + metaKeyDelimiter + " character")
			}
			if props[strings.TrimSpace(p.Name)] {
				return TemplateListResp{}, errInvalid("Duplicated interface template property name: " + t.Name + compositeDelimiter + p.Name)
			}
			props[strings.TrimSpace(p.Name)] = true
			if len(p.ValidatorParams) > 0 {
				if isBlank(p.Validator) {
					return TemplateListResp{}, errInvalid("Interface template property validator is empty while validator params are defined")
				}
				if containsNullOrEmpty(p.ValidatorParams) {
					return TemplateListResp{}, errInvalid("Interface template property validator parameter list contains null or empty element")
				}
			}
		}
	}
	// normalization + validation
	type normTpl struct {
		name, protocol string
		props          []TemplateProp
	}
	norm := make([]normTpl, 0, len(req.InterfaceTemplates))
	for _, t := range req.InterfaceTemplates {
		nt := normTpl{name: rg.rules.NormTemplateName(t.Name), protocol: strings.ToLower(strings.TrimSpace(t.Protocol))}
		if err := rg.rules.ValidateTemplateName(nt.name); err != nil {
			return TemplateListResp{}, err
		}
		if utf16Len(nt.protocol) > interfaceProtocolMax {
			return TemplateListResp{}, errInvalid("Interface protocol is too long")
		}
		for _, p := range t.PropertyRequirements {
			name := strings.TrimSpace(p.Name)
			if utf16Len(name) > interfacePropNameMax {
				return TemplateListResp{}, errInvalid("Interface property name is too long")
			}
			validator := ""
			if !isBlank(p.Validator) {
				validator = upperTrim(p.Validator)
				if !containsStr(validatorTypes, validator) {
					return TemplateListResp{}, errInvalid("Unknown property validator: " + validator)
				}
				for _, vp := range p.ValidatorParams {
					validator += validatorDelimiter + strings.TrimSpace(vp)
				}
			}
			nt.props = append(nt.props, TemplateProp{Name: name, Mandatory: p.Mandatory, Validator: validator})
		}
		norm = append(norm, nt)
	}
	var resp TemplateListResp
	err := rg.store.Update(func(st *state) error {
		now := rg.now()
		var created []*Template
		for _, nt := range norm {
			if _, ok := st.Templates[nt.name]; ok {
				return errInvalid("Interface template already exists: " + nt.name)
			}
			t := &Template{ID: st.newID(), Name: nt.name, Protocol: nt.protocol, Props: nt.props, CreatedAt: now, UpdatedAt: now}
			st.Templates[nt.name] = t
			created = append(created, t)
		}
		resp = rg.templateListResp(created, int64(len(created)))
		return nil
	})
	return resp, err
}

func (rg *Registry) templateListResp(ts []*Template, count int64) TemplateListResp {
	resp := TemplateListResp{Entries: make([]TemplateResp, 0, len(ts)), Count: count}
	for _, t := range ts {
		resp.Entries = append(resp.Entries, rg.templateResp(t))
	}
	return resp
}

func (rg *Registry) QueryInterfaceTemplates(req *TemplateQueryReq) (TemplateListResp, error) {
	var pg *PageDTO
	var names, protocols []string
	if req != nil {
		if err := rg.validatePage(req.Pagination, sortableTemplate); err != nil {
			return TemplateListResp{}, err
		}
		if len(req.TemplateNames) > 0 && containsNullOrEmpty(req.TemplateNames) {
			return TemplateListResp{}, errInvalid("Interface template name list contains empty element")
		}
		if len(req.Protocols) > 0 && containsNullOrEmpty(req.Protocols) {
			return TemplateListResp{}, errInvalid("Interface template protocol list contains empty element")
		}
		pg = req.Pagination
		names = normList(req.TemplateNames, rg.rules.NormTemplateName)
		protocols = normList(req.Protocols, func(s string) string { return strings.ToLower(strings.TrimSpace(s)) })
	}
	for _, n := range names {
		if err := rg.rules.ValidateTemplateName(n); err != nil {
			return TemplateListResp{}, err
		}
	}
	pr, err := rg.pageRequest(pg, true, sortableTemplate, "name")
	if err != nil {
		return TemplateListResp{}, err
	}
	var resp TemplateListResp
	rg.store.View(func(st *state) {
		var ts []*Template
		for _, t := range st.Templates {
			if len(names) > 0 && !containsStr(names, t.Name) {
				continue
			}
			if len(protocols) > 0 && !containsStr(protocols, t.Protocol) {
				continue
			}
			ts = append(ts, t)
		}
		page, total := sortAndPage(ts, pr, cmpTemplate)
		resp = rg.templateListResp(page, int64(total))
	})
	return resp, nil
}

func (rg *Registry) RemoveInterfaceTemplates(names []string) error {
	if err := rg.validateNameList(names, "Interface template name list is missing or empty", "Interface template name list contains null or empty element"); err != nil {
		return err
	}
	norm := mapStrings(names, rg.rules.NormTemplateName)
	for _, n := range norm {
		if err := rg.rules.ValidateTemplateName(n); err != nil {
			return err
		}
	}
	return rg.store.Update(func(st *state) error {
		for _, n := range norm {
			st.deleteTemplate(n)
		}
		return nil
	})
}

// ---------------------------------------------------------------------------------------------
// general management

func (rg *Registry) GetConfig(keys []string) (KeyValuesDTO, error) {
	if len(keys) == 0 {
		return KeyValuesDTO{}, errInvalid("The list of the requested configuration keys is null or empty")
	}
	if containsNullOrEmpty(keys) {
		return KeyValuesDTO{}, errInvalid("The list of the requested configuration keys contains a null or empty value")
	}
	pub := rg.cfg.PublicConfig()
	out := map[string]string{}
	for _, k := range keys {
		k = strings.TrimSpace(k)
		if v, ok := pub[k]; ok {
			out[k] = v
		}
	}
	return KeyValuesDTO{Map: out}, nil
}

func (rg *Registry) GetLogs(req *LogReq) (LogEntryListResp, error) {
	var pg *PageDTO
	var levels []string
	var from, to *time.Time
	loggerSub := ""
	if req != nil {
		if err := rg.validatePage(req.Pagination, sortableLog); err != nil {
			return LogEntryListResp{}, err
		}
		pg = req.Pagination
		parse := func(s, field string) (*time.Time, error) {
			if isBlank(s) {
				return nil, nil
			}
			t, err := parseInstant(s)
			if err != nil {
				return nil, errInvalid("Invalid date time in field: " + field + ". Please use a UTC date time in ISO-8601 format")
			}
			t = t.UTC()
			return &t, nil
		}
		var err error
		if from, err = parse(req.From, "from"); err != nil {
			return LogEntryListResp{}, err
		}
		if to, err = parse(req.To, "to"); err != nil {
			return LogEntryListResp{}, err
		}
		if from != nil && to != nil && to.Before(*from) {
			return LogEntryListResp{}, errInvalid("Invalid time interval")
		}
		if !isBlank(req.Severity) {
			sev := upperTrim(req.Severity)
			idx := -1
			for i, l := range logLevelsInOrder {
				if l == sev {
					idx = i
				}
			}
			if idx < 0 {
				return LogEntryListResp{}, errInvalid("Invalid severity is specified. Allowed values are: " + joinList(logLevelsInOrder))
			}
			levels = logLevelsInOrder[idx:]
		}
		loggerSub = strings.TrimSpace(req.Logger)
	}
	pr, err := rg.pageRequest(pg, true, sortableLog, "entryDate")
	if err != nil {
		return LogEntryListResp{}, err
	}
	entries := rg.log.Entries(levels, from, to, loggerSub)
	page, total := sortAndPage(entries, pr, func(a, b LogEntry, field string) int {
		switch field {
		case "logger":
			return cmpStr(a.Logger, b.Logger)
		case "logLevel":
			return cmpStr(a.Level, b.Level)
		case "logId":
			return cmpInt(a.ID, b.ID)
		}
		if c := cmpTime(a.Date, b.Date); c != 0 {
			return c
		}
		return cmpInt(a.ID, b.ID)
	})
	resp := LogEntryListResp{Entries: make([]LogEntryDTO, 0, len(page)), Count: int64(total)}
	for _, e := range page {
		resp.Entries = append(resp.Entries, LogEntryDTO{LogID: itoa(int(e.ID)), EntryDate: ts(e.Date), Logger: e.Logger, Severity: e.Level, Message: e.Message, Exception: e.Exception})
	}
	return resp, nil
}

var _ = sort.Strings
