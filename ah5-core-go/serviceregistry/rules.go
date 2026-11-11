package main

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Column sizes from ArrowheadEntity / Constants.
const (
	varcharTiny   = 14
	varcharSmall  = 63
	varcharMedium = 255
	varcharLarge  = 1024

	deviceNameMax        = varcharSmall
	systemNameMax        = varcharSmall
	systemVersionMax     = varcharTiny
	serviceDefNameMax    = varcharSmall
	serviceOpNameMax     = varcharSmall
	addressMax           = varcharLarge
	interfaceTemplateMax = varcharSmall
	interfaceProtocolMax = varcharSmall
	interfacePropNameMax = varcharSmall

	compositeDelimiter = "|"
	metaKeyDelimiter   = "."

	metaKeyUnrestrictedDiscovery = "unrestrictedDiscovery"
	metaKeyAllowExclusivity      = "allowExclusivity"

	maxPort = 65535
)

// Rules bundles the normalization and validation logic that depends on configuration.
type Rules struct {
	Extended          bool
	AllowSelf         bool
	AllowNonRoutable  bool
	MaxPageSize       int
	AddressAliasNames []string
}

func NewRules(c *Config) *Rules {
	return &Rules{
		Extended:          c.NormalizationMode == "extended",
		AllowSelf:         c.AllowSelfAddressing,
		AllowNonRoutable:  c.AllowNonRoutableAddressing,
		MaxPageSize:       c.MaxPageSize,
		AddressAliasNames: c.ServiceAddressAlias,
	}
}

// ---------------------------------------------------------------------------------------------
// generic helpers

func isBlank(s string) bool { return strings.TrimSpace(s) == "" }

// javaSplit mimics String.split(regex) with limit 0: trailing empty strings are removed.
func javaSplit(s, sep string) []string {
	parts := strings.Split(s, sep)
	for len(parts) > 0 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) == 0 {
		// Java returns [""] for the empty input and an empty array if everything was a separator
		if s == "" {
			return []string{""}
		}
	}
	return parts
}

func containsBlank(list []string) bool {
	for _, s := range list {
		if isBlank(s) {
			return true
		}
	}
	return false
}

func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r >= 0x10000 {
			n += 2
		} else {
			n++
		}
	}
	return n
}

var (
	whitespaceRe = regexp.MustCompile(`[\s\p{Z}]+`)
	delimiterRe  = regexp.MustCompile(`[_\-]+`)
)

func snakeToCamelOrPascal(snake string, pascal bool) string {
	if snake == "" {
		return ""
	}
	runes := []rune(snake)
	var sb strings.Builder
	first := runes[0]
	if pascal {
		first = unicode.ToUpper(first)
	} else {
		first = unicode.ToLower(first)
	}
	sb.WriteRune(first)
	found := false
	for _, r := range runes[1:] {
		switch {
		case r == '_':
			found = true
		case found:
			sb.WriteRune(unicode.ToUpper(r))
			found = false
		default:
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

func snakeToKebab(snake string) string {
	if snake == "" {
		return ""
	}
	return delimiterRe.ReplaceAllString(strings.ToLower(snake), "-")
}

func (r *Rules) transformBase(name string) string {
	s := whitespaceRe.ReplaceAllString(name, "_")
	return delimiterRe.ReplaceAllString(s, "_")
}

// ---------------------------------------------------------------------------------------------
// names: normalizers

func (r *Rules) normalizeWith(name string, conv func(string) string) string {
	if isBlank(name) {
		return ""
	}
	res := strings.TrimSpace(name)
	if r.Extended {
		res = conv(r.transformBase(res))
	}
	return res
}

func (r *Rules) NormSystemName(n string) string {
	return r.normalizeWith(n, func(s string) string { return snakeToCamelOrPascal(s, true) })
}
func (r *Rules) NormServiceDef(n string) string {
	return r.normalizeWith(n, func(s string) string { return snakeToCamelOrPascal(s, false) })
}
func (r *Rules) NormDeviceName(n string) string {
	return r.normalizeWith(n, strings.ToUpper)
}
func (r *Rules) NormTemplateName(n string) string {
	return r.normalizeWith(n, strings.ToLower)
}
func (r *Rules) NormOperationName(n string) string {
	return r.normalizeWith(n, snakeToKebab)
}

func (r *Rules) NormVersion(v string) string {
	if isBlank(v) {
		return "1.0.0"
	}
	cand := strings.TrimSpace(v)
	chunks := javaSplit(cand, ".")
	switch len(chunks) {
	case 1:
		return chunks[0] + ".0.0"
	case 2:
		return chunks[0] + "." + chunks[1] + ".0"
	}
	return cand
}

func (r *Rules) NormInstanceID(id string) string {
	parts := javaSplit(id, compositeDelimiter)
	parts[0] = r.NormSystemName(parts[0])
	if len(parts) > 1 {
		parts[1] = r.NormServiceDef(parts[1])
	}
	if len(parts) > 2 {
		parts[2] = r.NormVersion(parts[2])
	}
	return strings.Join(parts, compositeDelimiter)
}

// ---------------------------------------------------------------------------------------------
// names: validators

var (
	systemNameRe   = regexp.MustCompile(`^(?:[A-Z]|[A-Z][0-9A-Za-z]+)$`)
	serviceDefRe   = regexp.MustCompile(`^(?:[a-z]|[a-z][0-9A-Za-z]+)$`)
	deviceNameRe   = regexp.MustCompile(`^(?:[A-Z]|[A-Z][0-9A-Z_]*[0-9A-Z])$`)
	templateNameRe = regexp.MustCompile(`^(?:[a-z]|[a-z][0-9a-z_]*[0-9a-z])$`)
	operationRe    = regexp.MustCompile(`^(?:[a-z]|[a-z][0-9a-z\-]*[0-9a-z])$`)
)

func (r *Rules) ValidateSystemName(n string) error {
	if isBlank(n) || !systemNameRe.MatchString(n) || utf16Len(n) > systemNameMax {
		return errInvalid("The specified system name does not match the naming convention: " + n)
	}
	return nil
}
func (r *Rules) ValidateServiceDef(n string) error {
	if isBlank(n) || !serviceDefRe.MatchString(n) || utf16Len(n) > serviceDefNameMax {
		return errInvalid("The specified service definition name does not match the naming convention: " + n)
	}
	return nil
}
func (r *Rules) ValidateDeviceName(n string) error {
	if isBlank(n) || !deviceNameRe.MatchString(n) || utf16Len(n) > deviceNameMax {
		return errInvalid("The specified device name does not match the naming convention: " + n)
	}
	return nil
}
func (r *Rules) ValidateTemplateName(n string) error {
	if isBlank(n) || !templateNameRe.MatchString(n) || utf16Len(n) > interfaceTemplateMax {
		return errInvalid("The specified interface template name does not match the naming convention: " + n)
	}
	return nil
}
func (r *Rules) ValidateOperationName(n string) error {
	if isBlank(n) || !operationRe.MatchString(n) || utf16Len(n) > serviceOpNameMax {
		return errInvalid("The specified service operation name does not match the naming convention: " + n)
	}
	return nil
}

var digitsRe = regexp.MustCompile(`^[0-9]+$`)

func (r *Rules) ValidateVersion(v string) error {
	const prefix = "Version verification failure: "
	if utf16Len(v) > systemVersionMax {
		return errInvalid(prefix + "version is too long")
	}
	if strings.Count(v, ".") != 2 {
		return errInvalid(prefix + "version must contain exactly 2 separator . characters")
	}
	chunks := javaSplit(v, ".")
	if len(chunks) != 3 {
		return errInvalid(prefix + "version must contain exactly 3 numbers")
	}
	for _, c := range chunks {
		if !digitsRe.MatchString(c) {
			return errInvalid(prefix + "the version should only contain numbers and separator . characters")
		}
	}
	return nil
}

func (r *Rules) ValidateInstanceID(id string) error {
	bad := errInvalid("The specified service instance identifier does not match the naming convention: " + id)
	if isBlank(id) {
		return bad
	}
	parts := javaSplit(id, compositeDelimiter)
	if len(parts) != 3 {
		return bad
	}
	if err := r.ValidateSystemName(parts[0]); err != nil {
		return err
	}
	if err := r.ValidateServiceDef(parts[1]); err != nil {
		return err
	}
	return r.ValidateVersion(parts[2])
}

func calcInstanceID(system, def, version string) string {
	return system + compositeDelimiter + def + compositeDelimiter + version
}

func systemNameOfInstanceID(id string) string {
	return javaSplit(id, compositeDelimiter)[0]
}

// ---------------------------------------------------------------------------------------------
// metadata keys

func validateMetadataKeys(v any) error {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if strings.Contains(k, metaKeyDelimiter) {
				return errInvalid("Invalid metadata key: " + k + ", it should not contain " + metaKeyDelimiter + " character")
			}
			if err := validateMetadataKeys(val); err != nil {
				return err
			}
		}
	case []any:
		for _, e := range t {
			if err := validateMetadataKeys(e); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// time

// formatInstant mimics DateTimeFormatter.ISO_INSTANT (fraction printed in groups of three digits).
func formatInstant(t time.Time) string {
	t = t.UTC()
	base := t.Format("2006-01-02T15:04:05")
	n := t.Nanosecond()
	switch {
	case n == 0:
		return base + "Z"
	case n%1_000_000 == 0:
		return fmt.Sprintf("%s.%03dZ", base, n/1_000_000)
	case n%1_000 == 0:
		return fmt.Sprintf("%s.%06dZ", base, n/1_000)
	default:
		return fmt.Sprintf("%s.%09dZ", base, n)
	}
}

func formatInstantPtr(t *time.Time) *string {
	if t == nil {
		return nil
	}
	s := formatInstant(*t)
	return &s
}

func parseInstant(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, strings.TrimSpace(s))
}

// ---------------------------------------------------------------------------------------------
// addresses

const (
	addrHostname = "HOSTNAME"
	addrIPv4     = "IPV4"
	addrIPv6     = "IPV6"
	addrMAC      = "MAC"
)

var (
	macRe   = regexp.MustCompile(`^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`)
	ipv4Re  = regexp.MustCompile(`^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$`)
	ipv6Re  = regexp.MustCompile(`^(?:[0-9a-fA-F]{4}:){7}[0-9a-fA-F]{4}$`)
	labelRe = regexp.MustCompile(`^[A-Za-z0-9-]{1,63}$`)
)

func validAddressType(t string) bool {
	switch t {
	case addrHostname, addrIPv4, addrIPv6, addrMAC:
		return true
	}
	return false
}

func hostnameMatches(s string) bool {
	for _, label := range strings.Split(s, ".") {
		if !labelRe.MatchString(label) || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}

func (r *Rules) DetectAddressType(a string) string {
	if macRe.MatchString(a) {
		return addrMAC
	}
	if ipv4Re.MatchString(a) {
		return addrIPv4
	}
	if ipv6Re.MatchString(a) {
		return addrIPv6
	}
	return addrHostname
}

func isHexOctetStr(s string) bool { return len(s) == 2 }

func (r *Rules) NormAddress(address string) string {
	if isBlank(address) {
		return ""
	}
	cand := strings.TrimSpace(strings.ToLower(address))
	hasDot, hasColon, hasDash := strings.Contains(cand, "."), strings.Contains(cand, ":"), strings.Contains(cand, "-")
	if !hasDot && !hasColon && !hasDash {
		return cand
	}
	if len(javaSplit(cand, ".")) == 3 ||
		(hasDash && len(javaSplit(cand, "-")) == 6) ||
		(!strings.Contains(cand, "::") && len(javaSplit(cand, ":")) == 6) {
		return normalizeMAC(cand)
	}
	if hasDot && !hasColon {
		return cand
	}
	if !hasDot && hasColon {
		return normalizeIPv6(cand)
	}
	return normalizeIPv6IPv4Hybrid(cand)
}

func normalizeMAC(cand string) string {
	groups := make([]string, 6)
	if strings.Contains(cand, "-") {
		groups = javaSplit(cand, "-")
	}
	if strings.Contains(cand, ":") {
		groups = javaSplit(cand, ":")
	}
	if strings.Contains(cand, ".") {
		flat := strings.ReplaceAll(cand, ".", "")
		if len(flat) != 12 {
			return cand
		}
		groups = make([]string, 6)
		for i := range groups {
			groups[i] = flat[i*2 : i*2+2]
		}
	}
	for _, g := range groups {
		if len(g) != 2 {
			return cand
		}
	}
	return strings.Join(groups, ":")
}

func normalizeIPv6(cand string) string {
	if len(strings.Split(cand, "::")) > 2 {
		return cand
	}
	var groups []string
	lastAbbrev := -1
	for i, g := range strings.Split(cand, ":") {
		if g == "" {
			lastAbbrev = i
			g = "0000"
		} else if len(g) < 4 {
			g = strings.Repeat("0", 4-len(g)) + g
		}
		groups = append(groups, g)
	}
	size := len(groups)
	if lastAbbrev == -1 {
		if size != 8 {
			return cand
		}
	} else {
		if size > 8 {
			return cand
		}
		for i := 0; i < 8-size; i++ {
			groups = append(groups[:lastAbbrev], append([]string{"0000"}, groups[lastAbbrev:]...)...)
		}
	}
	return strings.Join(groups, ":")
}

func normalizeIPv6IPv4Hybrid(cand string) string {
	split := javaSplit(cand, ":")
	ip4str := split[len(split)-1]
	ip4parts := javaSplit(ip4str, ".")
	if len(ip4parts) != 4 {
		return cand
	}
	var hex strings.Builder
	for i := 0; i < 4; i++ {
		octet, err := strconv.Atoi(ip4parts[i])
		if err != nil || octet > 255 || octet < 0 {
			return cand
		}
		hex.WriteString(fmt.Sprintf("%02x", octet))
		if i == 1 {
			hex.WriteString(":")
		}
	}
	return normalizeIPv6(strings.Replace(cand, ip4str, hex.String(), 1))
}

func (r *Rules) ValidateAddress(typ, address string) error {
	const prefix = "Address verification failure: "
	if utf16Len(strings.TrimSpace(address)) > addressMax {
		return errInvalid("Address is too long")
	}
	switch typ {
	case addrMAC:
		if !macRe.MatchString(address) {
			return errInvalid(prefix + address + " is not MAC address")
		}
		if strings.EqualFold(address, "ff:ff:ff:ff:ff:ff") {
			return errInvalid(prefix + address + " MAC address is invalid: broadcast address is denied")
		}
		if strings.HasPrefix(address, "01:00:5e:") || strings.HasPrefix(address, "33:33:") {
			return errInvalid(prefix + address + " MAC address is invalid: multicast address is denied")
		}
	case addrIPv4:
		if !ipv4Re.MatchString(address) {
			return errInvalid(prefix + address + " is not IPv4 address")
		}
		if !r.AllowSelf && strings.HasPrefix(address, "127") {
			return errInvalid(prefix + address + " IPv4 address is invalid: self-addressing is disabled")
		}
		if !r.AllowNonRoutable && strings.HasPrefix(address, "169.254") {
			return errInvalid(prefix + address + " IPv4 address is invalid: non-routable-addressing is disabled")
		}
		if address == "0.0.0.0" {
			return errInvalid(prefix + address + " IPv4 address is invalid: placeholder address is denied")
		}
		if address == "255.255.255.255" {
			return errInvalid(prefix + address + " IPv4 address is invalid: local broadcast address is denied")
		}
		first, _ := strconv.Atoi(strings.Split(address, ".")[0])
		if first >= 224 && first <= 239 {
			return errInvalid(prefix + address + " IPv4 address is invalid: multicast addresses are denied")
		}
	case addrIPv6:
		if !ipv6Re.MatchString(address) {
			return errInvalid(prefix + address + " is not IPv6 address")
		}
		if !r.AllowSelf && strings.EqualFold(address, "0000:0000:0000:0000:0000:0000:0000:0001") {
			return errInvalid(prefix + address + " IPv6 address is invalid: self-addressing is disabled")
		}
		if !r.AllowNonRoutable && strings.HasPrefix(address, "fe80") {
			return errInvalid(prefix + address + " IPv6 address is invalid: non-routable-addressing is disabled")
		}
		if strings.EqualFold(address, "0000:0000:0000:0000:0000:0000:0000:0000") {
			return errInvalid(prefix + address + " IPv6 address is invalid: unspecified address is denied")
		}
		if strings.HasPrefix(address, "ff") {
			return errInvalid(prefix + address + " IPv6 address is invalid: multicast addresses are denied")
		}
	default:
		if len(address) > 253 {
			return errInvalid(prefix + address + " hostname is invalid: max length is 253")
		}
		if !hostnameMatches(address) {
			return errInvalid(prefix + address + " is not a hostname")
		}
		first := strings.Split(address, ".")[0]
		hasAlpha := false
		for _, c := range first {
			if unicode.IsLetter(c) {
				hasAlpha = true
				break
			}
		}
		if !hasAlpha {
			return errInvalid(prefix + address + " is not a hostname")
		}
		if !r.AllowSelf && (strings.EqualFold(address, "localhost") || strings.EqualFold(address, "loopback")) {
			return errInvalid(prefix + address + " hostname is invalid: self-addressing is disabled")
		}
	}
	return nil
}

// NormalizeAddresses normalizes raw address strings and detects their types.
func (r *Rules) NormalizeAddresses(raw []string) []Address {
	out := make([]Address, 0, len(raw))
	for _, a := range raw {
		na := r.NormAddress(a)
		out = append(out, Address{Type: r.DetectAddressType(na), Address: na})
	}
	return out
}

func addressListMatching(a, b []Address) bool {
	if len(a) != len(b) {
		return false
	}
	used := make([]bool, len(b))
	for _, x := range a {
		found := false
		for j, y := range b {
			if !used[j] && x == y {
				used[j] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
