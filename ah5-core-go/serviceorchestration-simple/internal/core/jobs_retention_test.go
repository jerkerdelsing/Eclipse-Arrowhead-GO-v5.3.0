// SPDX-License-Identifier: EPL-2.0
package core

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneJobsRetentionAndCap(t *testing.T) {
	at := time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC)
	d := database{"jobs": map[string]Document{}}
	add := func(id, status string, age time.Duration) {
		d["jobs"][id] = Document{"id": id, "status": status, "createdAt": at.Add(-age).Format(time.RFC3339Nano)}
	}
	add("old-done", "DONE", 25*time.Hour)
	add("old-running", "IN_PROGRESS", 48*time.Hour)
	for i := 0; i < maxJobs+5; i++ {
		add(fmt.Sprintf("j%04d", i), "ERROR", time.Duration(maxJobs+5-i)*time.Second)
	}
	pruneJobs(d, at)
	jobs := d["jobs"]
	if len(jobs) != maxJobs {
		t.Fatalf("got %d jobs, want %d", len(jobs), maxJobs)
	}
	if jobs["old-done"] != nil {
		t.Fatal("finished job older than retention kept")
	}
	if jobs["old-running"] == nil {
		t.Fatal("unfinished job pruned")
	}
	// The oldest finished jobs go first: j0000..j0005 (6 = 5 excess + old-running kept).
	for i := 0; i < 6; i++ {
		if jobs[fmt.Sprintf("j%04d", i)] != nil {
			t.Fatalf("oldest job j%04d kept", i)
		}
	}
	if jobs[fmt.Sprintf("j%04d", maxJobs+4)] == nil {
		t.Fatal("newest job pruned")
	}
}

func TestNewJobStartsInProgressAndPrunes(t *testing.T) {
	s, e := OpenStore("")
	if e != nil {
		t.Fatal(e)
	}
	a := &App{Store: s}
	old := time.Now().Add(-2 * jobRetention).UTC().Format(time.RFC3339Nano)
	_ = s.Update(func(d database) error {
		bucket(d, "jobs")["stale"] = Document{"id": "stale", "status": "DONE", "createdAt": old}
		return nil
	})
	j, e := a.newJob("Consumer", "Consumer", "PULL", "svc", "")
	if e != nil {
		t.Fatal(e)
	}
	if str(j, "status") != "IN_PROGRESS" || j["startedAt"] == nil {
		t.Fatalf("job not started: %v", j)
	}
	_ = s.View(func(d database) error {
		if d["jobs"]["stale"] != nil || len(d["jobs"]) != 1 {
			t.Fatalf("jobs after newJob: %v", d["jobs"])
		}
		return nil
	})
}

func TestOpenStoreRemovesStaleTemps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "svc.json")
	own := filepath.Join(dir, ".svc.json.tmp-123")
	other := filepath.Join(dir, ".other.json.tmp-456")
	legacyOld := filepath.Join(dir, ".state-111")
	legacyNew := filepath.Join(dir, ".state-222")
	for _, f := range []string{own, other, legacyOld, legacyNew} {
		if e := os.WriteFile(f, []byte("x"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	past := time.Now().Add(-time.Hour)
	_ = os.Chtimes(legacyOld, past, past)
	s, e := OpenStore(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for f, want := range map[string]bool{own: false, other: true, legacyOld: false, legacyNew: true} {
		if _, e := os.Stat(f); (e == nil) != want {
			t.Errorf("%s exists=%v, want %v", filepath.Base(f), e == nil, want)
		}
	}
	if e := s.Update(func(d database) error { bucket(d, "x")["1"] = Document{}; return nil }); e != nil {
		t.Fatal(e)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, ".svc.json.tmp-*")); len(left) != 0 {
		t.Errorf("temp files left after commit: %v", left)
	}
}
