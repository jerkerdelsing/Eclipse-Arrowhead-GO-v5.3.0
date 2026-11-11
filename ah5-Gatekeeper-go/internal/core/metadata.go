// SPDX-License-Identifier: EPL-2.0
package core

import (
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf16"
)

func metadataValue(d Document, path string) any {
	var v any = d
	for _, k := range strings.Split(strings.TrimSpace(path), ".") {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		if i := strings.Index(k, "["); i >= 0 && strings.HasSuffix(k, "]") {
			idx, e := strconv.Atoi(k[i+1 : len(k)-1])
			if e == nil && idx >= 0 {
				a, ok := m[k[:i]].([]any)
				if !ok || idx >= len(a) {
					return nil
				}
				v = a[idx]
				continue
			}
		}
		v = m[k]
	}
	return v
}
func metaCompare(left, right any, op string) (bool, error) {
	op = strings.ToUpper(strings.TrimSpace(op))
	negative := strings.HasPrefix(op, "NOT_")
	if negative {
		op = strings.TrimPrefix(op, "NOT_")
	}
	if op == "SIZE_NOT_EQUALS" {
		op = "SIZE_EQUALS"
		negative = true
	}
	var result bool
	l, ls := left.(string)
	r, rs := right.(string)
	switch op {
	case "EQUALS":
		result = reflect.DeepEqual(left, right)
	case "EQUALS_IGNORE_CASE":
		result = ls && rs && strings.EqualFold(l, r)
	case "INCLUDES", "INCLUDES_IGNORE_CASE", "STARTS_WITH", "STARTS_WITH_IGNORE_CASE", "ENDS_WITH", "ENDS_WITH_IGNORE_CASE":
		if strings.HasSuffix(op, "_IGNORE_CASE") {
			l, r = strings.ToLower(l), strings.ToLower(r)
			op = strings.TrimSuffix(op, "_IGNORE_CASE")
		}
		if ls && rs {
			switch op {
			case "INCLUDES":
				result = strings.Contains(l, r)
			case "STARTS_WITH":
				result = strings.HasPrefix(l, r)
			case "ENDS_WITH":
				result = strings.HasSuffix(l, r)
			}
		}
	case "REGEXP":
		if !rs {
			return false, bad("REGEXP requires a string")
		}
		re, e := regexp.Compile("^(?:" + r + ")$")
		if e != nil {
			return false, bad("REGEXP must use Go/RE2 syntax")
		}
		result = ls && re.MatchString(l)
	case "LESS_THAN", "LESS_THAN_OR_EQUALS_TO", "GREATER_THAN", "GREATER_THAN_OR_EQUALS_TO":
		a, ok := left.(float64)
		b, bok := right.(float64)
		if ok && bok {
			switch op {
			case "LESS_THAN":
				result = a < b
			case "LESS_THAN_OR_EQUALS_TO":
				result = a <= b
			case "GREATER_THAN":
				result = a > b
			case "GREATER_THAN_OR_EQUALS_TO":
				result = a >= b
			}
		}
	case "SIZE_EQUALS":
		n := -1
		switch a := left.(type) {
		case string:
			n = len(utf16.Encode([]rune(a)))
		case []any:
			n = len(a)
		}
		b, ok := right.(float64)
		result = ok && n >= 0 && float64(n) == b
	case "CONTAINS":
		if a, ok := left.([]any); ok {
			for _, x := range a {
				if reflect.DeepEqual(x, right) {
					result = true
					break
				}
			}
		}
	case "CONTAINS_ANY":
		if a, ok := left.([]any); ok {
			if b, ok := right.([]any); ok {
				for _, x := range a {
					for _, y := range b {
						if reflect.DeepEqual(x, y) {
							result = true
						}
					}
				}
			}
		}
	case "IN":
		if a, ok := right.([]any); ok {
			for _, x := range a {
				if reflect.DeepEqual(x, left) {
					result = true
					break
				}
			}
		}
	default:
		return false, bad("Unknown metadata operation: " + op)
	}
	if negative {
		return !result, nil
	}
	return result, nil
}
func metadataMatch(metadata, requirements Document) (bool, error) {
	for key, req := range requirements {
		op, value := "EQUALS", req
		if m, ok := req.(map[string]any); ok && m["op"] != nil && m["value"] != nil {
			op = str(m, "op")
			value = m["value"]
		}
		v := metadataValue(metadata, key)
		if v == nil {
			return false, nil
		}
		yes, e := metaCompare(v, value, op)
		if e != nil || !yes {
			return false, e
		}
	}
	return true, nil
}
