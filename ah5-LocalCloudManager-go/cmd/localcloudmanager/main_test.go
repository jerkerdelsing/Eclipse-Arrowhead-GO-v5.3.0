// SPDX-License-Identifier: EPL-2.0
package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestLauncherRejectsOtherRoles(t *testing.T) {
	if os.Getenv("LCM_LAUNCHER_SUBPROCESS") == "1" {
		os.Args = []string{"LocalCloudManager"}
		main()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=TestLauncherRejectsOtherRoles")
	cmd.Env = append(os.Environ(), "LCM_LAUNCHER_SUBPROCESS=1", "ARROWHEAD_ROLE=gatekeeper")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "only runs the localcloudmanager role") {
		t.Fatalf("error%v output%s", err, out)
	}
}
