package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Interface property validators (MINMAX, PORT, NOT_EMPTY_ADDRESS_LIST, NOT_EMPTY_STRING_SET,
// HTTP_OPERATIONS) and the address-property processor of the Java reference implementation.

var validatorTypes = []string{"MINMAX", "PORT", "NOT_EMPTY_ADDRESS_LIST", "NOT_EMPTY_STRING_SET", "HTTP_OPERATIONS"}

const validatorDelimiter = "|"

var standardHTTPMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE"}

func isNumber(v any) (isInt bool, isReal bool) {
	switch v.(type) {
	case int64, int, int32:
		return true, false
	case float64, float32:
		return false, true
	}
	return false, false
}

func toInt64(v any) int64 {
	switch t := v.(type) {
	case int64:
		return t
	case int:
		return int64(t)
	case int32:
		return int64(t)
	case float64:
		return int64(t)
	case float32:
		return int64(t)
	}
	return 0
}

func toFloat64(v any) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case float32:
		return float64(t)
	}
	return float64(toInt64(v))
}

// validateAndNormalizeProperty runs one validator of the given type (name only, without args).
func (r *Rules) validateAndNormalizeProperty(vtype string, value any, args []string) (any, error) {
	switch vtype {
	case "MINMAX":
		return validateMinMax(value, args)
	case "PORT":
		isInt, _ := isNumber(value)
		if isInt {
			return validateMinMax(value, []string{"1", fmt.Sprint(maxPort)})
		}
		return nil, errInvalid("Property value should be an integer")
	case "NOT_EMPTY_ADDRESS_LIST":
		return r.validateAddressList(value)
	case "NOT_EMPTY_STRING_SET":
		return r.validateStringSet(value, args)
	case "HTTP_OPERATIONS":
		return r.validateHTTPOperations(value)
	}
	return nil, errInvalid("Unknown property validator: " + vtype)
}

func validateMinMax(value any, args []string) (any, error) {
	isInt, isReal := isNumber(value)
	if !isInt && !isReal {
		return nil, errInvalid("Property value should be a number")
	}
	if len(args) < 2 {
		return nil, errInvalid("Missing minimum and/or maximum values")
	}
	if isReal {
		var min, max float64
		if _, err := fmt.Sscanf(strings.TrimSpace(args[0]), "%g", &min); err != nil {
			return nil, errInvalid("Invalid minimum and/or maximum values")
		}
		if _, err := fmt.Sscanf(strings.TrimSpace(args[1]), "%g", &max); err != nil {
			return nil, errInvalid("Invalid minimum and/or maximum values")
		}
		v := toFloat64(value)
		if v < min || v > max {
			return nil, errInvalid("Invalid property value")
		}
		return value, nil
	}
	var min, max int64
	if _, err := fmt.Sscanf(args[0], "%d", &min); err != nil {
		return nil, errInvalid("Invalid minimum and/or maximum values")
	}
	if _, err := fmt.Sscanf(args[1], "%d", &max); err != nil {
		return nil, errInvalid("Invalid minimum and/or maximum values")
	}
	v := toInt64(value)
	if v < min || v > max {
		return nil, errInvalid("Invalid property value")
	}
	return value, nil
}

func (r *Rules) validateAddressList(value any) (any, error) {
	list, ok := value.([]any)
	if !ok {
		if sl, ok2 := value.([]string); ok2 {
			list = make([]any, len(sl))
			for i, s := range sl {
				list[i] = s
			}
			ok = true
		}
	}
	if !ok {
		return nil, errInvalid("Property value should be a list of strings")
	}
	if len(list) == 0 {
		return nil, errInvalid("Property value should be a non-empty list of strings")
	}
	out := make([]any, 0, len(list))
	for _, el := range list {
		s, ok := el.(string)
		if !ok {
			return nil, errInvalid("Property value should be a list of strings")
		}
		if isBlank(s) {
			return nil, errInvalid("Property value should be a list of non-blank strings")
		}
		norm := r.NormAddress(strings.TrimSpace(s))
		typ := r.DetectAddressType(norm)
		if typ != addrIPv4 && typ != addrIPv6 && typ != addrHostname {
			return nil, errInvalid("Unacceptable address type in property value: " + typ)
		}
		if err := r.ValidateAddress(typ, norm); err != nil {
			return nil, err
		}
		out = append(out, norm)
	}
	return out, nil
}

func (r *Rules) validateStringSet(value any, args []string) (any, error) {
	list, ok := value.([]any)
	if !ok {
		return nil, errInvalid("Property value should be a set/list of string values")
	}
	if len(list) == 0 {
		return nil, errInvalid("Property value should be a non-empty set/list")
	}
	isOperation := len(args) > 0 && strings.EqualFold(strings.TrimSpace(args[0]), "OPERATION")
	seen := map[string]bool{}
	out := make([]any, 0, len(list))
	for _, el := range list {
		s, ok := el.(string)
		if !ok {
			return nil, errInvalid("Value should be a string")
		}
		var n string
		if isOperation {
			n = r.NormOperationName(s)
			if err := r.ValidateOperationName(n); err != nil {
				return nil, err
			}
		} else {
			if isBlank(s) {
				return nil, errInvalid("Value should be a non-empty string")
			}
			n = strings.TrimSpace(s)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out, nil
}

func (r *Rules) validateHTTPOperations(value any) (any, error) {
	m, ok := toMap(value)
	if !ok {
		return nil, errInvalid("Property value should be a map of operations")
	}
	if len(m) == 0 {
		return nil, errInvalid("Property value should be a non-empty map")
	}
	out := map[string]any{}
	for _, key := range sortedKeys(m) {
		nk := r.NormOperationName(key)
		if err := r.ValidateOperationName(nk); err != nil {
			return nil, err
		}
		model, ok := toMap(m[key])
		if !ok {
			return nil, errInvalid("Value should be a HttpOperationModel record")
		}
		path, _ := model["path"].(string)
		method, _ := model["method"].(string)
		if _, p := model["path"]; !p {
			return nil, errInvalid("Value should be a HttpOperationModel record")
		}
		if _, p := model["method"]; !p {
			return nil, errInvalid("Value should be a HttpOperationModel record")
		}
		if isBlank(path) {
			return nil, errInvalid("Path should be non-empty")
		}
		um := strings.ToUpper(strings.TrimSpace(method))
		if isBlank(method) || !containsStr(standardHTTPMethods, um) {
			return nil, errInvalid("Method should be a standard HTTP method")
		}
		out[nk] = map[string]any{"path": strings.TrimSpace(path), "method": um}
	}
	return out, nil
}

// ---------------------------------------------------------------------------------------------
// address property processor

type addressData struct {
	addresses []string
	key       string
	isList    bool
}

func (r *Rules) discoverAddresses(props Meta) addressData {
	var d addressData
	for _, key := range sortedKeys(props) {
		if d.key != "" {
			break
		}
		for _, alias := range r.AddressAliasNames {
			if !strings.EqualFold(key, alias) {
				continue
			}
			if list, ok := props[key].([]any); ok {
				for _, v := range list {
					if s, ok := v.(string); ok {
						d.addresses = append(d.addresses, s)
					}
				}
				if len(d.addresses) > 0 {
					d.key = key
					d.isList = true
					break
				}
			} else if s, ok := props[key].(string); ok && !isBlank(s) {
				d.key = key
				d.isList = false
				d.addresses = append(d.addresses, s)
				break
			}
		}
	}
	return d
}

// normalizeAddressProperty finds the address property of the interface properties (by alias) and
// replaces it with its normalized form; invalid addresses are rejected.
func (r *Rules) normalizeAddressProperty(props Meta) error {
	d := r.discoverAddresses(props)
	if len(d.addresses) == 0 {
		return nil
	}
	norm := make([]any, 0, len(d.addresses))
	for _, a := range d.addresses {
		n := r.NormAddress(a)
		typ := r.DetectAddressType(n)
		if err := r.ValidateAddress(typ, n); err != nil {
			return err
		}
		norm = append(norm, n)
	}
	if d.isList {
		props[d.key] = norm
	} else {
		props[d.key] = norm[0]
	}
	return nil
}

// filterOnAddressTypes keeps only the addresses of the given types in the (copied) properties;
// returns false if no address matches.
func (r *Rules) filterOnAddressTypes(props Meta, types []string) bool {
	d := r.discoverAddresses(props)
	if len(d.addresses) == 0 {
		return false
	}
	var matching []any
	for _, a := range d.addresses {
		t := r.DetectAddressType(a)
		for _, f := range types {
			if strings.EqualFold(f, t) {
				matching = append(matching, a)
				break
			}
		}
	}
	if len(matching) == 0 {
		return false
	}
	if d.isList {
		props[d.key] = matching
	} else {
		props[d.key] = matching[0]
	}
	return true
}

// marshalJSONString is a tiny helper for logging.
func marshalJSONString(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}
