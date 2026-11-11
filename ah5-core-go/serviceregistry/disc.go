package main

import (
	"sort"
	"strings"
)

// ---------------------------------------------------------------------------------------------
// normalized forms

type normDevice struct {
	Name      string
	Metadata  Meta
	Addresses []Address
}

type normSystem struct {
	Name       string
	Metadata   Meta
	Version    string
	Addresses  []Address
	DeviceName string
}

func (rg *Registry) normalizeDevice(req *DeviceReq) normDevice {
	return normDevice{
		Name:      rg.rules.NormDeviceName(req.Name),
		Metadata:  req.Metadata,
		Addresses: rg.rules.NormalizeAddresses(req.Addresses),
	}
}

func (rg *Registry) validateNormDevice(n normDevice) error {
	if err := rg.rules.ValidateDeviceName(n.Name); err != nil {
		return err
	}
	for _, a := range n.Addresses {
		if err := rg.rules.ValidateAddress(a.Type, a.Address); err != nil {
			return err
		}
	}
	return nil
}

func (rg *Registry) normalizeSystem(name string, req *SystemReq) normSystem {
	n := normSystem{
		Name:      rg.rules.NormSystemName(name),
		Metadata:  req.Metadata,
		Version:   rg.rules.NormVersion(req.Version),
		Addresses: rg.rules.NormalizeAddresses(req.Addresses),
	}
	if !isBlank(req.DeviceName) {
		n.DeviceName = rg.rules.NormDeviceName(req.DeviceName)
	}
	return n
}

func (rg *Registry) validateNormSystem(n normSystem) error {
	if err := rg.rules.ValidateSystemName(n.Name); err != nil {
		return err
	}
	if err := rg.rules.ValidateVersion(n.Version); err != nil {
		return err
	}
	for _, a := range n.Addresses {
		if err := rg.rules.ValidateAddress(a.Type, a.Address); err != nil {
			return err
		}
	}
	if n.DeviceName != "" {
		if err := rg.rules.ValidateDeviceName(n.DeviceName); err != nil {
			return err
		}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// db-level helpers shared by discovery and management

func (rg *Registry) createDevices(st *state, cands []normDevice) ([]*Device, error) {
	var existing []string
	for _, c := range cands {
		if _, ok := st.Devices[c.Name]; ok {
			existing = append(existing, c.Name)
		}
	}
	if len(existing) > 0 {
		return nil, errInvalid("Device with names already exists: " + joinNames(existing))
	}
	now := rg.now()
	out := make([]*Device, 0, len(cands))
	for _, c := range cands {
		d := &Device{ID: st.newID(), Name: c.Name, Metadata: copyMeta(c.Metadata), Addresses: append([]Address(nil), c.Addresses...), CreatedAt: now, UpdatedAt: now}
		st.Devices[c.Name] = d
		out = append(out, d)
	}
	return out, nil
}

func (rg *Registry) updateDevices(st *state, cands []normDevice) ([]*Device, error) {
	var missing []string
	for _, c := range cands {
		if _, ok := st.Devices[c.Name]; !ok {
			missing = append(missing, c.Name)
		}
	}
	if len(missing) > 0 {
		return nil, errInvalid("Device(s) not exists: " + joinNames(missing))
	}
	now := rg.now()
	out := make([]*Device, 0, len(cands))
	for _, c := range cands {
		old := st.Devices[c.Name]
		d := &Device{ID: old.ID, Name: old.Name, Metadata: copyMeta(c.Metadata), Addresses: append([]Address(nil), c.Addresses...), CreatedAt: old.CreatedAt, UpdatedAt: now}
		st.Devices[c.Name] = d
		out = append(out, d)
	}
	return out, nil
}

func (rg *Registry) checkDeviceNamesExist(st *state, cands []normSystem) error {
	var missing []string
	seen := map[string]bool{}
	for _, c := range cands {
		if c.DeviceName == "" || seen[c.DeviceName] {
			continue
		}
		seen[c.DeviceName] = true
		if _, ok := st.Devices[c.DeviceName]; !ok {
			missing = append(missing, c.DeviceName)
		}
	}
	if len(missing) > 0 {
		return errInvalid("Device names do not exist: " + joinNames(missing))
	}
	return nil
}

var inheritableAddressTypes = []string{addrIPv4, addrIPv6, addrHostname}

func systemAddresses(st *state, c normSystem) ([]Address, error) {
	if len(c.Addresses) > 0 {
		return append([]Address(nil), c.Addresses...), nil
	}
	dev := st.Devices[c.DeviceName]
	var out []Address
	if dev != nil {
		for _, a := range dev.Addresses {
			if containsStr(inheritableAddressTypes, a.Type) {
				out = append(out, a)
			}
		}
	}
	if len(out) == 0 {
		return nil, errInvalid("At least one system address is needed for every system")
	}
	return out, nil
}

func (rg *Registry) createSystems(st *state, cands []normSystem) ([]*System, error) {
	var existing []string
	for _, c := range cands {
		if _, ok := st.Systems[c.Name]; ok {
			existing = append(existing, c.Name)
		}
	}
	if len(existing) > 0 {
		return nil, errInvalid("Systems with names already exist: " + joinNames(existing))
	}
	if err := rg.checkDeviceNamesExist(st, cands); err != nil {
		return nil, err
	}
	now := rg.now()
	out := make([]*System, 0, len(cands))
	for _, c := range cands {
		addrs, err := systemAddresses(st, c)
		if err != nil {
			return nil, err
		}
		s := &System{ID: st.newID(), Name: c.Name, Metadata: copyMeta(c.Metadata), Version: c.Version, Addresses: addrs, DeviceName: c.DeviceName, CreatedAt: now, UpdatedAt: now}
		st.Systems[c.Name] = s
		out = append(out, s)
	}
	return out, nil
}

func (rg *Registry) updateSystems(st *state, cands []normSystem) ([]*System, error) {
	var missing []string
	for _, c := range cands {
		if _, ok := st.Systems[c.Name]; !ok {
			missing = append(missing, c.Name)
		}
	}
	if len(missing) > 0 {
		return nil, errInvalid("System(s) not exists: " + joinNames(missing))
	}
	if err := rg.checkDeviceNamesExist(st, cands); err != nil {
		return nil, err
	}
	now := rg.now()
	out := make([]*System, 0, len(cands))
	for _, c := range cands {
		old := st.Systems[c.Name]
		addrs, err := systemAddresses(st, c)
		if err != nil {
			return nil, err
		}
		s := &System{ID: old.ID, Name: old.Name, Metadata: copyMeta(c.Metadata), Version: c.Version, Addresses: addrs, DeviceName: c.DeviceName, CreatedAt: old.CreatedAt, UpdatedAt: now}
		st.Systems[c.Name] = s
		out = append(out, s)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------
// filters (devices, systems)

func hasAddressType(addrs []Address, typ string) bool {
	for _, a := range addrs {
		if a.Type == typ {
			return true
		}
	}
	return false
}

func hasAnyAddress(addrs []Address, list []string) bool {
	for _, a := range addrs {
		if containsStr(list, a.Address) {
			return true
		}
	}
	return false
}

func (rg *Registry) filterDevices(st *state, names, addresses []string, addrType string, reqs []Meta) ([]*Device, error) {
	var out []*Device
	for _, d := range st.Devices {
		if len(names) > 0 && !containsStr(names, d.Name) {
			continue
		}
		if addrType != "" && !hasAddressType(d.Addresses, addrType) {
			continue
		}
		if len(addresses) > 0 && !hasAnyAddress(d.Addresses, addresses) {
			continue
		}
		if len(reqs) > 0 {
			ok, err := anyMetadataMatch(d.Metadata, reqs)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
		}
		out = append(out, d)
	}
	return out, nil
}

func (rg *Registry) filterSystems(st *state, names, addresses []string, addrType string, reqs []Meta, versions, deviceNames []string) ([]*System, error) {
	var out []*System
	for _, s := range st.Systems {
		if len(names) > 0 && !containsStr(names, s.Name) {
			continue
		}
		if addrType != "" && !hasAddressType(s.Addresses, addrType) {
			continue
		}
		if len(addresses) > 0 && !hasAnyAddress(s.Addresses, addresses) {
			continue
		}
		if len(versions) > 0 && !containsStr(versions, s.Version) {
			continue
		}
		if len(deviceNames) > 0 && (s.DeviceName == "" || !containsStr(deviceNames, s.DeviceName)) {
			continue
		}
		if len(reqs) > 0 {
			ok, err := anyMetadataMatch(s.Metadata, reqs)
			if err != nil {
				return nil, err
			}
			if !ok {
				continue
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------
// DeviceDiscovery

func (rg *Registry) RegisterDevice(req *DeviceReq) (DeviceResp, bool, error) {
	if req == nil {
		return DeviceResp{}, false, errInvalid("Request payload is missing")
	}
	if isBlank(req.Name) {
		return DeviceResp{}, false, errInvalid("Device name is empty")
	}
	if len(req.Addresses) == 0 {
		return DeviceResp{}, false, errInvalid("At least one device address is needed")
	}
	for _, a := range req.Addresses {
		if isBlank(a) {
			return DeviceResp{}, false, errInvalid("Address is missing")
		}
	}
	if err := rg.checkMetadata(req.Metadata); err != nil {
		return DeviceResp{}, false, err
	}
	n := rg.normalizeDevice(req)
	if err := rg.validateNormDevice(n); err != nil {
		return DeviceResp{}, false, err
	}
	var resp DeviceResp
	created := false
	err := rg.store.Update(func(st *state) error {
		if ex, ok := st.Devices[n.Name]; ok {
			if len(ex.Metadata) > 0 || len(n.Metadata) > 0 {
				if (len(ex.Metadata) > 0 && len(n.Metadata) == 0) || len(ex.Metadata) == 0 {
					return errInvalid("Device with name '" + n.Name + "' already exists, but provided metadata is not matching")
				}
				if !metaEqual(ex.Metadata, n.Metadata) {
					return errInvalid("Device with name '" + n.Name + "' already exists, but provided metadata is not matching")
				}
			}
			if !addressListMatching(ex.Addresses, n.Addresses) {
				return errInvalid("Device with name '" + n.Name + "' already exists, but provided addresses are not matching")
			}
			resp = rg.deviceResp(ex)
			return nil
		}
		ds, err := rg.createDevices(st, []normDevice{n})
		if err != nil {
			return err
		}
		resp = rg.deviceResp(ds[0])
		created = true
		return nil
	})
	return resp, created, err
}

func (rg *Registry) LookupDevice(req *DeviceLookupReq) (DeviceListResp, error) {
	var names, addrs []string
	var addrType string
	var reqs []Meta
	if req != nil {
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
	if addrType != "" {
		if err := rg.validateAddrAgainstType(addrType, addrs); err != nil {
			return DeviceListResp{}, err
		}
	}
	var resp DeviceListResp
	var ferr error
	rg.store.View(func(st *state) {
		ds, err := rg.filterDevices(st, names, addrs, addrType, reqs)
		if err != nil {
			ferr = err
			return
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i].ID < ds[j].ID })
		resp.Entries = make([]DeviceResp, 0, len(ds))
		for _, d := range ds {
			resp.Entries = append(resp.Entries, rg.deviceResp(d))
		}
		resp.Count = int64(len(ds))
	})
	return resp, ferr
}

func (rg *Registry) RevokeDevice(name string) (bool, error) {
	if isBlank(name) {
		return false, errInvalid("Device name is empty")
	}
	n := rg.rules.NormDeviceName(name)
	if err := rg.rules.ValidateDeviceName(n); err != nil {
		return false, err
	}
	found := false
	err := rg.store.Update(func(st *state) error {
		if _, ok := st.Devices[n]; !ok {
			return nil
		}
		if len(st.systemsOfDevice(n)) > 0 {
			return errLocked("At least one system is assigned to this device")
		}
		delete(st.Devices, n)
		found = true
		return nil
	})
	return found, err
}

// ---------------------------------------------------------------------------------------------
// SystemDiscovery

func (rg *Registry) RegisterSystem(name string, req *SystemRegisterReq) (SystemResp, bool, error) {
	if req == nil {
		return SystemResp{}, false, errInvalid("Request payload is missing")
	}
	return rg.registerSystem(&SystemReq{Name: name, Metadata: req.Metadata, Version: req.Version, Addresses: req.Addresses, DeviceName: req.DeviceName})
}

func (rg *Registry) registerSystem(req *SystemReq) (SystemResp, bool, error) {
	if req == nil {
		return SystemResp{}, false, errInvalid("Request payload is missing")
	}
	if isBlank(req.Name) {
		return SystemResp{}, false, errInvalid("System name is empty")
	}
	for _, a := range req.Addresses {
		if isBlank(a) {
			return SystemResp{}, false, errInvalid("Address is missing")
		}
	}
	if len(req.Addresses) == 0 && isBlank(req.DeviceName) {
		return SystemResp{}, false, errInvalid("At least one system address is needed for every system")
	}
	if err := rg.checkMetadata(req.Metadata); err != nil {
		return SystemResp{}, false, err
	}
	n := rg.normalizeSystem(req.Name, req)
	if err := rg.validateNormSystem(n); err != nil {
		return SystemResp{}, false, err
	}
	var resp SystemResp
	created := false
	err := rg.store.Update(func(st *state) error {
		if ex, ok := st.Systems[n.Name]; ok {
			if err := rg.checkSameSystem(st, ex, n); err != nil {
				return err
			}
			resp = rg.systemResp(st, ex, "full")
			return nil
		}
		ss, err := rg.createSystems(st, []normSystem{n})
		if err != nil {
			return err
		}
		resp = rg.systemResp(st, ss[0], "full")
		created = true
		return nil
	})
	return resp, created, err
}

func (rg *Registry) checkSameSystem(st *state, ex *System, n normSystem) error {
	prefix := "System with name: " + ex.Name + " already exists, but provided "
	if !metaEqual(ex.Metadata, n.Metadata) {
		return errInvalid(prefix + "metadata is not matching")
	}
	if ex.Version != n.Version {
		return errInvalid(prefix + "version is not matching")
	}
	newAddrs := append([]Address(nil), n.Addresses...)
	if len(newAddrs) == 0 && ex.DeviceName != "" {
		if dev, ok := st.Devices[ex.DeviceName]; ok {
			for _, a := range dev.Addresses {
				if containsStr(inheritableAddressTypes, a.Type) {
					newAddrs = append(newAddrs, a)
				}
			}
		}
	}
	if !addressListMatching(ex.Addresses, newAddrs) {
		return errInvalid(prefix + "address list is not matching")
	}
	if ex.DeviceName != n.DeviceName {
		return errInvalid(prefix + "device name is not matching")
	}
	return nil
}

func (rg *Registry) LookupSystem(req *SystemLookupReq, verbose bool) (SystemListResp, error) {
	var names, addrs, versions, devNames []string
	var addrType string
	var reqs []Meta
	if req != nil {
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
		if len(req.Versions) > 0 && hasNullString(req.Versions) {
			return SystemListResp{}, errInvalid("Version list contains null element")
		}
		if len(req.DeviceNames) > 0 && containsNullOrEmpty(req.DeviceNames) {
			return SystemListResp{}, errInvalid("Device name list contains null or empty element")
		}
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
	return rg.querySystemsInternal(names, addrs, addrType, reqs, versions, devNames, pageReq{desc: true, sortField: "createdAt", size: allPages.size},
		func(st *state, s *System) SystemResp {
			if verbose && rg.cfg.DiscoveryVerbose {
				return rg.systemResp(st, s, "full")
			}
			return rg.systemResp(st, s, "terse")
		})
}

func hasNullString(l []string) bool { return false } // a JSON null cannot be told apart from "" in []string

func (rg *Registry) validateSystemFilters(names, addrs []string, addrType string, versions, devNames []string) error {
	for _, n := range names {
		if err := rg.rules.ValidateSystemName(n); err != nil {
			return err
		}
	}
	if addrType != "" && len(addrs) > 0 {
		if err := rg.validateAddrAgainstType(addrType, addrs); err != nil {
			return err
		}
	}
	for _, v := range versions {
		if err := rg.rules.ValidateVersion(v); err != nil {
			return err
		}
	}
	for _, n := range devNames {
		if err := rg.rules.ValidateDeviceName(n); err != nil {
			return err
		}
	}
	return nil
}

func (rg *Registry) querySystemsInternal(names, addrs []string, addrType string, reqs []Meta, versions, devNames []string, pr pageReq, conv func(*state, *System) SystemResp) (SystemListResp, error) {
	var resp SystemListResp
	var ferr error
	rg.store.View(func(st *state) {
		ss, err := rg.filterSystems(st, names, addrs, addrType, reqs, versions, devNames)
		if err != nil {
			ferr = err
			return
		}
		page, total := sortAndPage(ss, pr, cmpSystem)
		resp.Entries = make([]SystemResp, 0, len(page))
		for _, s := range page {
			resp.Entries = append(resp.Entries, conv(st, s))
		}
		resp.Count = int64(total)
	})
	return resp, ferr
}

func (rg *Registry) RevokeSystem(name string) (bool, error) {
	if isBlank(name) {
		return false, errInvalid("System name is empty")
	}
	n := rg.rules.NormSystemName(name)
	if err := rg.rules.ValidateSystemName(n); err != nil {
		return false, err
	}
	found := false
	err := rg.store.Update(func(st *state) error {
		found = st.deleteSystem(n)
		return nil
	})
	return found, err
}
