package main

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------------------------
// Meta: a JSON object (metadata, interface properties, metadata requirements).
// Integers decode to int64 and decimals to float64, so that the Java Integer/Double
// distinction used by the metadata operators is preserved. A nil Meta is JSON null.

type Meta map[string]any

func (m *Meta) UnmarshalJSON(b []byte) error {
	if string(bytes.TrimSpace(b)) == "null" {
		*m = nil
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	if raw == nil {
		raw = map[string]any{}
	}
	*m = Meta(fixNums(raw).(map[string]any))
	return nil
}

func fixNums(v any) any {
	switch t := v.(type) {
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	case map[string]any:
		for k, x := range t {
			t[k] = fixNums(x)
		}
		return t
	case []any:
		for i, x := range t {
			t[i] = fixNums(x)
		}
		return t
	}
	return v
}

func deepCopy(v any) any {
	switch t := v.(type) {
	case Meta:
		if t == nil {
			return Meta(nil)
		}
		out := make(Meta, len(t))
		for k, x := range t {
			out[k] = deepCopy(x)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = deepCopy(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = deepCopy(x)
		}
		return out
	case []string:
		return append([]string(nil), t...)
	}
	return v
}

func copyMeta(m Meta) Meta {
	if m == nil {
		return nil
	}
	return deepCopy(m).(Meta)
}

// ---------------------------------------------------------------------------------------------
// entities

type Address struct {
	Type    string `json:"type"`
	Address string `json:"address"`
}

type Device struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Metadata  Meta      `json:"metadata,omitempty"`
	Addresses []Address `json:"addresses"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type System struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	Metadata   Meta      `json:"metadata,omitempty"`
	Version    string    `json:"version"`
	Addresses  []Address `json:"addresses"`
	DeviceName string    `json:"deviceName,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	UpdatedAt  time.Time `json:"updatedAt"`
}

type ServiceDef struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type TemplateProp struct {
	Name      string `json:"name"`
	Mandatory bool   `json:"mandatory"`
	Validator string `json:"validator,omitempty"` // NAME|param|param
}

type Template struct {
	ID        int64          `json:"id"`
	Name      string         `json:"name"`
	Protocol  string         `json:"protocol"`
	Props     []TemplateProp `json:"props"`
	CreatedAt time.Time      `json:"createdAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

type InstanceInterface struct {
	Template   string `json:"template"`
	Policy     string `json:"policy"`
	Properties Meta   `json:"properties"`
}

type Instance struct {
	ID         int64               `json:"id"`
	InstanceID string              `json:"instanceId"`
	System     string              `json:"system"`
	Definition string              `json:"definition"`
	Version    string              `json:"version"`
	ExpiresAt  *time.Time          `json:"expiresAt,omitempty"`
	Metadata   Meta                `json:"metadata,omitempty"`
	Interfaces []InstanceInterface `json:"interfaces"`
	CreatedAt  time.Time           `json:"createdAt"`
	UpdatedAt  time.Time           `json:"updatedAt"`
}

// ---------------------------------------------------------------------------------------------
// request DTOs

type PageDTO struct {
	Page      *int   `json:"page"`
	Size      *int   `json:"size"`
	Direction string `json:"direction"`
	SortField string `json:"sortField"`
}

type DeviceReq struct {
	Name      string   `json:"name"`
	Metadata  Meta     `json:"metadata"`
	Addresses []string `json:"addresses"`
}

type DeviceListReq struct {
	Devices []*DeviceReq `json:"devices"`
}

type DeviceLookupReq struct {
	DeviceNames             []string `json:"deviceNames"`
	Addresses               []string `json:"addresses"`
	AddressType             string   `json:"addressType"`
	MetadataRequirementList []Meta   `json:"metadataRequirementList"`
}

type DeviceQueryReq struct {
	Pagination              *PageDTO `json:"pagination"`
	DeviceNames             []string `json:"deviceNames"`
	Addresses               []string `json:"addresses"`
	AddressType             string   `json:"addressType"`
	MetadataRequirementList []Meta   `json:"metadataRequirementList"`
}

type SystemReq struct {
	Name       string   `json:"name"`
	Metadata   Meta     `json:"metadata"`
	Version    string   `json:"version"`
	Addresses  []string `json:"addresses"`
	DeviceName string   `json:"deviceName"`
}

type SystemRegisterReq struct {
	Metadata   Meta     `json:"metadata"`
	Version    string   `json:"version"`
	Addresses  []string `json:"addresses"`
	DeviceName string   `json:"deviceName"`
}

type SystemListReq struct {
	Systems []*SystemReq `json:"systems"`
}

type SystemLookupReq struct {
	SystemNames             []string `json:"systemNames"`
	Addresses               []string `json:"addresses"`
	AddressType             string   `json:"addressType"`
	MetadataRequirementList []Meta   `json:"metadataRequirementList"`
	Versions                []string `json:"versions"`
	DeviceNames             []string `json:"deviceNames"`
}

type SystemQueryReq struct {
	Pagination              *PageDTO `json:"pagination"`
	SystemNames             []string `json:"systemNames"`
	Addresses               []string `json:"addresses"`
	AddressType             string   `json:"addressType"`
	MetadataRequirementList []Meta   `json:"metadataRequirementList"`
	Versions                []string `json:"versions"`
	DeviceNames             []string `json:"deviceNames"`
}

type ServiceDefListReq struct {
	ServiceDefinitionNames []string `json:"serviceDefinitionNames"`
}

type InterfaceReq struct {
	TemplateName string `json:"templateName"`
	Protocol     string `json:"protocol"`
	Policy       string `json:"policy"`
	Properties   Meta   `json:"properties"`
}

type InstanceReq struct { // ServiceInstanceRequestDTO (also used for the "create" variants)
	SystemName            string         `json:"systemName"`
	ServiceDefinitionName string         `json:"serviceDefinitionName"`
	Version               string         `json:"version"`
	ExpiresAt             string         `json:"expiresAt"`
	Metadata              Meta           `json:"metadata"`
	Interfaces            []InterfaceReq `json:"interfaces"`
}

type InstanceCreateReq struct { // ServiceInstanceCreateRequestDTO (no system name)
	ServiceDefinitionName string         `json:"serviceDefinitionName"`
	Version               string         `json:"version"`
	ExpiresAt             string         `json:"expiresAt"`
	Metadata              Meta           `json:"metadata"`
	Interfaces            []InterfaceReq `json:"interfaces"`
}

type InstanceCreateListReq struct {
	Instances []*InstanceReq `json:"instances"`
}

type InstanceUpdateReq struct {
	InstanceID string         `json:"instanceId"`
	ExpiresAt  string         `json:"expiresAt"`
	Metadata   Meta           `json:"metadata"`
	Interfaces []InterfaceReq `json:"interfaces"`
}

type InstanceUpdateListReq struct {
	Instances []*InstanceUpdateReq `json:"instances"`
}

type InstanceLookupReq struct {
	InstanceIDs                       []string `json:"instanceIds"`
	ProviderNames                     []string `json:"providerNames"`
	ServiceDefinitionNames            []string `json:"serviceDefinitionNames"`
	Versions                          []string `json:"versions"`
	AlivesAt                          string   `json:"alivesAt"`
	MetadataRequirementsList          []Meta   `json:"metadataRequirementsList"`
	AddressTypes                      []string `json:"addressTypes"`
	InterfaceTemplateNames            []string `json:"interfaceTemplateNames"`
	InterfacePropertyRequirementsList []Meta   `json:"interfacePropertyRequirementsList"`
	Policies                          []string `json:"policies"`
}

type InstanceQueryReq struct {
	Pagination *PageDTO `json:"pagination"`
	InstanceLookupReq
}

type TemplatePropDTO struct {
	Name            string   `json:"name"`
	Mandatory       bool     `json:"mandatory"`
	Validator       string   `json:"validator,omitempty"`
	ValidatorParams []string `json:"validatorParams,omitempty"`
}

type TemplateReq struct {
	Name                 string             `json:"name"`
	Protocol             string             `json:"protocol"`
	PropertyRequirements []*TemplatePropDTO `json:"propertyRequirements"`
}

type TemplateListReq struct {
	InterfaceTemplates []*TemplateReq `json:"interfaceTemplates"`
}

type TemplateQueryReq struct {
	Pagination    *PageDTO `json:"pagination"`
	TemplateNames []string `json:"templateNames"`
	Protocols     []string `json:"protocols"`
}

type LogReq struct {
	Pagination *PageDTO `json:"pagination"`
	From       string   `json:"from"`
	To         string   `json:"to"`
	Severity   string   `json:"severity"`
	Logger     string   `json:"logger"`
}

// ---------------------------------------------------------------------------------------------
// response DTOs

type DeviceResp struct {
	Name      string    `json:"name"`
	Metadata  Meta      `json:"metadata,omitempty"`
	Addresses []Address `json:"addresses,omitempty"`
	CreatedAt string    `json:"createdAt,omitempty"`
	UpdatedAt string    `json:"updatedAt,omitempty"`
}

type DeviceListResp struct {
	Entries []DeviceResp `json:"entries"`
	Count   int64        `json:"count"`
}

type SystemResp struct {
	Name      string      `json:"name"`
	Metadata  Meta        `json:"metadata,omitempty"`
	Version   string      `json:"version"`
	Addresses []Address   `json:"addresses,omitempty"`
	Device    *DeviceResp `json:"device,omitempty"`
	CreatedAt string      `json:"createdAt,omitempty"`
	UpdatedAt string      `json:"updatedAt,omitempty"`
}

type SystemListResp struct {
	Entries []SystemResp `json:"entries"`
	Count   int64        `json:"count"`
}

type ServiceDefResp struct {
	Name      string `json:"name"`
	CreatedAt string `json:"createdAt,omitempty"`
	UpdatedAt string `json:"updatedAt,omitempty"`
}

type ServiceDefListResp struct {
	Entries []ServiceDefResp `json:"entries"`
	Count   int64            `json:"count"`
}

type InterfaceResp struct {
	TemplateName string `json:"templateName"`
	Protocol     string `json:"protocol"`
	Policy       string `json:"policy"`
	Properties   Meta   `json:"properties,omitempty"`
}

type InstanceResp struct {
	InstanceID        string          `json:"instanceId"`
	Provider          SystemResp      `json:"provider"`
	ServiceDefinition ServiceDefResp  `json:"serviceDefinition"`
	Version           string          `json:"version"`
	ExpiresAt         string          `json:"expiresAt,omitempty"`
	Metadata          Meta            `json:"metadata,omitempty"`
	Interfaces        []InterfaceResp `json:"interfaces"`
	CreatedAt         string          `json:"createdAt,omitempty"`
	UpdatedAt         string          `json:"updatedAt,omitempty"`
}

type InstanceListResp struct {
	Entries []InstanceResp `json:"entries"`
	Count   int64          `json:"count"`
}

type TemplateResp struct {
	Name                 string             `json:"name"`
	Protocol             string             `json:"protocol"`
	PropertyRequirements []TemplatePropResp `json:"propertyRequirements"`
	CreatedAt            string             `json:"createdAt,omitempty"`
	UpdatedAt            string             `json:"updatedAt,omitempty"`
}

type TemplateListResp struct {
	Entries []TemplateResp `json:"entries"`
	Count   int64          `json:"count"`
}

type LogEntryDTO struct {
	LogID     string `json:"logId,omitempty"`
	EntryDate string `json:"entryDate,omitempty"`
	Logger    string `json:"logger,omitempty"`
	Severity  string `json:"severity,omitempty"`
	Message   string `json:"message,omitempty"`
	Exception string `json:"exception,omitempty"`
}

type LogEntryListResp struct {
	Entries []LogEntryDTO `json:"entries"`
	Count   int64         `json:"count"`
}

type KeyValuesDTO struct {
	Map map[string]string `json:"map"`
}

// ---------------------------------------------------------------------------------------------
// misc helpers shared by the services

func emptyStrList(l []string) bool { return len(l) == 0 }

// containsNullOrEmpty: a JSON null in a []string decodes to "", which Java treats as null/empty too.
func containsNullOrEmpty(l []string) bool { return containsBlank(l) }

func containsNilMeta(l []Meta) bool {
	for _, m := range l {
		if m == nil {
			return true
		}
	}
	return false
}

func upperTrim(s string) string { return strings.ToUpper(strings.TrimSpace(s)) }

func mapStrings(in []string, f func(string) string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, f(s))
	}
	return out
}

func joinList(l []string) string { return "[" + strings.Join(l, ", ") + "]" }

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func isValidAddressType(s string) bool { return validAddressType(s) }

var offerableBad = "TRANSLATION_BRIDGE_TOKEN_AUTH"

var allPolicies = []string{"NONE", "CERT_AUTH", "TIME_LIMITED_TOKEN_AUTH", "USAGE_LIMITED_TOKEN_AUTH",
	"BASE64_SELF_CONTAINED_TOKEN_AUTH", "RSA_SHA256_JSON_WEB_TOKEN_AUTH", "RSA_SHA512_JSON_WEB_TOKEN_AUTH", "TRANSLATION_BRIDGE_TOKEN_AUTH"}

func isPolicy(s string) bool        { return containsStr(allPolicies, s) }
func policyOfferable(s string) bool { return s != offerableBad }
