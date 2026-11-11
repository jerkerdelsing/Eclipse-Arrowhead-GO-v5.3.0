// SPDX-License-Identifier: EPL-2.0
package cloud

import "testing"

// Endpoint principles: LocalCloudManager listens on SERVER_PORT (or PORT, or --server.port, which sets SERVER_PORT)
// and defaults to 8480.
func TestListeningPortDefaultAndValidation(t *testing.T) {
	if roleSpecs["localcloudmanager"].Port != 8480 {
		t.Fatalf("default port = %d; want 8480", roleSpecs["localcloudmanager"].Port)
	}
	t.Setenv("ARROWHEAD_ROLE", "localcloudmanager")
	for _, bad := range []string{"0", "65536", "abc"} {
		t.Setenv("SERVER_PORT", bad)
		if _, err := NewFromEnv(); err == nil {
			t.Fatalf("SERVER_PORT=%q accepted", bad)
		}
	}
}
