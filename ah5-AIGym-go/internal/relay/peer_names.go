package cloud

import (
	"fmt"
	"strings"
)

// A foreign-organisation neighbour needs both this explicit host configuration
// and the normal neighbour allowlist. A management row alone cannot change it.
func parsePeerOrganizations(raw, own, organization string) (map[string]string, error) {
	peers := map[string]string{}
	if strings.TrimSpace(raw) == "" {
		return peers, nil
	}
	valid := func(s string) bool {
		if len(s) == 0 || len(s) > 63 {
			return false
		}
		for i, c := range s {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && (c >= '0' && c <= '9' || c == '_')) {
				return false
			}
		}
		return true
	}
	for _, item := range strings.Split(raw, ",") {
		pair := strings.Split(strings.TrimSpace(item), "=")
		if len(pair) != 2 || !valid(pair[0]) || !valid(pair[1]) || peers[pair[0]] != "" || len(peers) >= 32 {
			return nil, fmt.Errorf("invalid explicit federation peer organization mapping")
		}
		if pair[0] == own && pair[1] != organization {
			return nil, fmt.Errorf("own organization cannot be remapped")
		}
		peers[pair[0]] = pair[1]
	}
	return peers, nil
}

// parseForeignTargets: FEDERATION_FOREIGN_TARGETS (SOS-7, 2026-11-10), "Cloud|Organisation" entries, comma-separated.
// This cloud's consumers reach neighbours of another organisation only when listed; each entry must name a neighbour
// bound to that other organisation in FEDERATION_PEER_ORGANIZATIONS.
func parseForeignTargets(raw, own, organization string, peers map[string]string) (map[string]bool, error) {
	allowed := map[string]bool{}
	for _, item := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(item)
		if entry == "" {
			continue
		}
		pair := strings.Split(entry, "|")
		if len(pair) != 2 || pair[0] == "" || pair[0] == own || pair[1] == organization || peers[pair[0]] != pair[1] {
			return nil, fmt.Errorf("FEDERATION_FOREIGN_TARGETS: %q is not Cloud|Organisation of a neighbour of another organisation bound in FEDERATION_PEER_ORGANIZATIONS", entry)
		}
		allowed[entry] = true
	}
	return allowed, nil
}

// targetAllowed: whether this cloud's consumers may reach the neighbour (own organisation, or listed foreign target).
func (f *Federation) targetAllowed(cloud string) bool {
	organization := f.peerOrganization(cloud)
	return organization == f.app.Config.Organization || f.foreignTargets[cloud+"|"+organization]
}
func (f *Federation) peerOrganization(cloud string) string {
	if value := f.peerOrganizations[cloud]; value != "" {
		return value
	}
	return f.app.Config.Organization
}
func (f *Federation) validTarget(v any) bool {
	name := targetName(v)
	requested := ""
	if raw, ok := v.(string); ok {
		if pair := strings.SplitN(raw, "|", 2); len(pair) == 2 {
			requested = pair[1]
		}
	} else {
		requested = mapString(object(v)["operator"])
	}
	return name != "" && (requested == "" || requested == f.peerOrganization(name))
}
func peerCloudIdentity(peer string) string {
	parts := strings.Split(peer, ".")
	if len(parts) != 5 {
		return ""
	}
	return parts[1] + "|" + parts[2]
}
