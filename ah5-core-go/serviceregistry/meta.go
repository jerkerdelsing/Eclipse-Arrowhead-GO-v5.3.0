package main

import (
	"fmt"
	"reflect"
	"regexp"
	"strconv"
	"strings"
)

// Metadata requirement matching (MetadataRequirementsMatcher, MetaOps and the evaluators of the
// Java reference implementation).

var metaOps = map[string]bool{
	"EQUALS": true, "NOT_EQUALS": true, "EQUALS_IGNORE_CASE": true, "NOT_EQUALS_IGNORE_CASE": true,
	"INCLUDES": true, "NOT_INCLUDES": true, "INCLUDES_IGNORE_CASE": true, "NOT_INCLUDES_IGNORE_CASE": true,
	"STARTS_WITH": true, "NOT_STARTS_WITH": true, "STARTS_WITH_IGNORE_CASE": true, "NOT_STARTS_WITH_IGNORE_CASE": true,
	"ENDS_WITH": true, "NOT_ENDS_WITH": true, "ENDS_WITH_IGNORE_CASE": true, "NOT_ENDS_WITH_IGNORE_CASE": true,
	"REGEXP": true, "LESS_THAN": true, "LESS_THAN_OR_EQUALS_TO": true, "GREATER_THAN": true, "GREATER_THAN_OR_EQUALS_TO": true,
	"SIZE_EQUALS": true, "SIZE_NOT_EQUALS": true, "CONTAINS": true, "NOT_CONTAINS": true,
	"CONTAINS_ANY": true, "NOT_CONTAINS_ANY": true, "IN": true, "NOT_IN": true,
}

type metaExpr struct {
	keyPath string
	op      string
	value   any
}

func parseRequirements(req Meta) ([]metaExpr, error) {
	exprs := make([]metaExpr, 0, len(req))
	for _, key := range sortedKeys(req) {
		val := req[key]
		if m, ok := toMap(val); ok {
			opv, hasOp := m["op"]
			vv, hasVal := m["value"]
			if hasOp && hasVal {
				opStr := fmt.Sprint(opv)
				op := strings.ToUpper(strings.TrimSpace(opStr))
				if !metaOps[op] {
					return nil, errInvalid("Invalid metadata operation requirement: " + opStr)
				}
				exprs = append(exprs, metaExpr{key, op, vv})
				continue
			}
		}
		exprs = append(exprs, metaExpr{key, "EQUALS", val})
	}
	return exprs, nil
}

func toMap(v any) (map[string]any, bool) {
	switch t := v.(type) {
	case map[string]any:
		return t, true
	case Meta:
		return map[string]any(t), true
	}
	return nil, false
}

// isMetadataMatch returns true if every expression of the requirement holds for the metadata.
func isMetadataMatch(metadata Meta, req Meta) (bool, error) {
	if len(req) == 0 {
		return true, nil
	}
	if len(metadata) == 0 {
		return false, nil
	}
	exprs, err := parseRequirements(req)
	if err != nil {
		return false, err
	}
	for _, e := range exprs {
		act := metadataValueForCompositeKey(metadata, e.keyPath)
		if act == nil {
			return false, nil
		}
		if !evalOp(e.op, act, e.value) {
			return false, nil
		}
	}
	return true, nil
}

// anyMetadataMatch: at least one requirement matches (OR over the list).
func anyMetadataMatch(metadata Meta, reqs []Meta) (bool, error) {
	for _, r := range reqs {
		ok, err := isMetadataMatch(metadata, r)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
	}
	return false, nil
}

func metadataValueForCompositeKey(metadata Meta, compositeKey string) any {
	if len(metadata) == 0 || isBlank(compositeKey) {
		return nil
	}
	var cur any = map[string]any(metadata)
	for _, key := range javaSplit(strings.TrimSpace(compositeKey), ".") {
		cur = valueForKey(cur, key)
		if cur == nil {
			return nil
		}
	}
	return cur
}

func valueForKey(st any, key string) any {
	m, ok := toMap(st)
	if !ok {
		return nil
	}
	arrayAccessor := isArrayAccessor(key)
	if arrayAccessor {
		openIdx := strings.Index(key, "[")
		endIdx := strings.Index(key, "]")
		keyPart := key[:openIdx]
		idx, err := strconv.Atoi(key[openIdx+1 : endIdx])
		if err != nil {
			idx = -1
		}
		if idx >= 0 {
			if v, ok := m[keyPart]; ok {
				if l, ok := v.([]any); ok && len(l) > idx {
					return l[idx]
				}
			}
		} else {
			arrayAccessor = false
		}
	}
	if !arrayAccessor {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return nil
}

func isArrayAccessor(key string) bool {
	openIdx := strings.Index(key, "[")
	endIdx := strings.Index(key, "]")
	return openIdx != -1 && endIdx == len(key)-1 && openIdx != endIdx-1
}

// ---------------------------------------------------------------------------------------------
// evaluators

func evalOp(op string, left, right any) bool {
	if strings.HasPrefix(op, "NOT_") || op == "SIZE_NOT_EQUALS" {
		base := strings.TrimPrefix(op, "NOT_")
		if op == "SIZE_NOT_EQUALS" {
			base = "SIZE_EQUALS"
		}
		return !evalOp(base, left, right)
	}
	switch op {
	case "EQUALS":
		return reflect.DeepEqual(normalizeForEquals(left), normalizeForEquals(right))
	case "EQUALS_IGNORE_CASE":
		l, r, ok := twoStrings(left, right)
		return ok && strings.EqualFold(l, r)
	case "INCLUDES":
		l, r, ok := twoStrings(left, right)
		return ok && strings.Contains(l, r)
	case "INCLUDES_IGNORE_CASE":
		l, r, ok := twoStrings(left, right)
		return ok && strings.Contains(strings.ToLower(l), strings.ToLower(r))
	case "STARTS_WITH":
		l, r, ok := twoStrings(left, right)
		return ok && strings.HasPrefix(l, r)
	case "STARTS_WITH_IGNORE_CASE":
		l, r, ok := twoStrings(left, right)
		return ok && strings.HasPrefix(strings.ToLower(l), strings.ToLower(r))
	case "ENDS_WITH":
		l, r, ok := twoStrings(left, right)
		return ok && strings.HasSuffix(l, r)
	case "ENDS_WITH_IGNORE_CASE":
		l, r, ok := twoStrings(left, right)
		return ok && strings.HasSuffix(strings.ToLower(l), strings.ToLower(r))
	case "REGEXP":
		l, r, ok := twoStrings(left, right)
		if !ok {
			return false
		}
		re, err := regexp.Compile("^(?:" + r + ")$")
		return err == nil && re.MatchString(l)
	case "LESS_THAN":
		return numCompare(left, right, func(c int) bool { return c < 0 })
	case "LESS_THAN_OR_EQUALS_TO":
		return numCompare(left, right, func(c int) bool { return c <= 0 })
	case "GREATER_THAN":
		return numCompare(left, right, func(c int) bool { return c > 0 })
	case "GREATER_THAN_OR_EQUALS_TO":
		return numCompare(left, right, func(c int) bool { return c >= 0 })
	case "SIZE_EQUALS":
		n, ok := right.(int64)
		if f, isF := right.(float64); isF {
			n, ok = int64(f), true
		}
		if !ok {
			return false
		}
		switch l := left.(type) {
		case string:
			return int64(utf16Len(l)) == n
		case []any:
			return int64(len(l)) == n
		}
		return false
	case "CONTAINS":
		l, ok := left.([]any)
		if !ok {
			return false
		}
		return listContains(l, right)
	case "CONTAINS_ANY":
		l, ok1 := left.([]any)
		r, ok2 := right.([]any)
		if !ok1 || !ok2 {
			return false
		}
		for _, x := range l {
			if listContains(r, x) {
				return true
			}
		}
		return false
	case "IN":
		r, ok := right.([]any)
		return ok && listContains(r, left)
	}
	return false
}

func normalizeForEquals(v any) any {
	if m, ok := v.(Meta); ok {
		return map[string]any(m)
	}
	return v
}

func listContains(l []any, v any) bool {
	for _, x := range l {
		if reflect.DeepEqual(normalizeForEquals(x), normalizeForEquals(v)) {
			return true
		}
	}
	return false
}

func twoStrings(a, b any) (string, string, bool) {
	l, ok1 := a.(string)
	r, ok2 := b.(string)
	return l, r, ok1 && ok2
}

// numCompare mirrors the Java evaluators: a real left value is compared as double, an integral
// left value as long (the right value is converted to long if it is integral, to double otherwise).
func numCompare(left, right any, pred func(int) bool) bool {
	var lf, rf float64
	var li, ri int64
	lReal, rReal := false, false
	switch l := left.(type) {
	case int64:
		li = l
	case float64:
		lf, lReal = l, true
	default:
		return false
	}
	switch r := right.(type) {
	case int64:
		ri = r
	case float64:
		rf, rReal = r, true
	default:
		return false
	}
	cmpF := func(a, b float64) int {
		switch {
		case a < b:
			return -1
		case a > b:
			return 1
		}
		return 0
	}
	if lReal {
		if rReal {
			return pred(cmpF(lf, rf))
		}
		return pred(cmpF(lf, float64(ri)))
	}
	if rReal {
		return pred(cmpF(float64(li), rf))
	}
	switch {
	case li < ri:
		return pred(-1)
	case li > ri:
		return pred(1)
	}
	return pred(0)
}
