// SPDX-License-Identifier: EPL-2.0
package core

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
)

// Document is used at the HTTP boundary so Java's JSON property spelling is retained.
type Document = map[string]any
type database map[string]map[string]Document

// Store serializes transactions. Failure before rename never publishes a new state.
// Failure syncing the directory after rename reports an uncertain durable commit.
// One process owns a state file; run independent systems with independent state files.
type Store struct {
	mu   sync.Mutex
	path string
	data database
	lock *os.File
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, data: database{}}
	if path == "" {
		return s, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	l, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(l.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		l.Close()
		return nil, fmt.Errorf("state already owned: %w", err)
	}
	s.lock = l
	// temporary snapshots left by a process killed mid-commit (the lock makes this process the only writer)
	if stale, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".state-*")); len(stale) > 0 {
		for _, name := range stale {
			_ = os.Remove(name)
		}
	}
	b, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(b, &s.data)
		if s.data == nil {
			err = errors.New("null state")
		}
	}
	if err != nil && !os.IsNotExist(err) {
		s.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	return s.lock.Close()
}

// immutableRowTables hold rows that are never modified in place once stored (only added, replaced or deleted).
// Copies share their rows instead of re-encoding them: SysMonitor keeps tens of thousands of observations, and a
// deep copy per transaction (two per Update) exceeded its memory limit.
var immutableRowTables = map[string]bool{"observations": true}

// copyDB deep-copies d row by row (JSON round trip, so copies have decoded JSON types), keeping the transient
// encoding buffers row-sized instead of state-sized.
func copyDB(d database) database {
	c := database{}
	for t, rows := range d {
		if rows == nil {
			c[t] = nil
			continue
		}
		table := make(map[string]Document, len(rows))
		for k, v := range rows {
			if immutableRowTables[t] {
				table[k] = v
			} else {
				table[k] = copyRow(v)
			}
		}
		c[t] = table
	}
	return c
}
func copyRow(row Document) Document {
	b, _ := json.Marshal(row)
	var c Document
	_ = json.Unmarshal(b, &c)
	return c
}

// writeDB streams the state as one JSON object, a row at a time, so a commit does not hold a state-sized buffer.
func writeDB(w *bufio.Writer, d database) error {
	w.WriteByte('{')
	first := true
	for t, rows := range d {
		if !first {
			w.WriteByte(',')
		}
		first = false
		k, _ := json.Marshal(t)
		w.Write(k)
		w.WriteByte(':')
		if rows == nil {
			w.WriteString("null")
			continue
		}
		w.WriteByte('{')
		firstRow := true
		for id, row := range rows {
			v, err := json.Marshal(row)
			if err != nil {
				return err
			}
			if !firstRow {
				w.WriteByte(',')
			}
			firstRow = false
			k, _ = json.Marshal(id)
			w.Write(k)
			w.WriteByte(':')
			w.Write(v)
		}
		w.WriteByte('}')
	}
	w.WriteByte('}')
	return w.Flush()
}
func (s *Store) View(fn func(database) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(copyDB(s.data))
}

// ViewTables is View restricted to the named tables: only those are copied, so frequent reads of small tables do
// not pay for a copy of large ones (SysMonitor observations).
func (s *Store) ViewTables(fn func(database) error, tables ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	part := database{}
	for _, t := range tables {
		if s.data[t] != nil {
			part[t] = s.data[t]
		}
	}
	return fn(copyDB(part))
}

// Select returns copies of the rows of one table for which keep returns true, without copying the others, so
// scans of a large table (SysMonitor observations, outbox) cost only what they return. keep runs under the store
// lock and must not modify or retain the row it is given.
func (s *Store) Select(table string, keep func(Document) bool) []Document {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Document{}
	for _, row := range s.data[table] {
		if keep(row) {
			b, _ := json.Marshal(row)
			var c Document
			_ = json.Unmarshal(b, &c)
			out = append(out, c)
		}
	}
	return out
}

// Count returns the number of rows in a table.
func (s *Store) Count(table string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.data[table])
}

// UpdateTables is Update for callbacks that only add, replace or delete rows of the named tables: fn sees a shallow
// copy of those tables (existing rows are shared with the committed state, so fn must not modify them in place)
// and nothing else. A large append-only table is then not deep-copied once per transaction.
func (s *Store) UpdateTables(fn func(database) error, tables ...string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	part := database{}
	for _, t := range tables {
		if s.data[t] != nil {
			rows := make(map[string]Document, len(s.data[t]))
			for k, v := range s.data[t] {
				rows[k] = v
			}
			part[t] = rows
		}
	}
	if err := fn(part); err != nil {
		return err
	}
	next := database{}
	for t, rows := range s.data {
		next[t] = rows
	}
	for _, t := range tables {
		if part[t] != nil {
			next[t] = part[t]
		} else {
			delete(next, t)
		}
	}
	return s.commit(next, false)
}
func bucket(d database, k string) map[string]Document {
	if d[k] == nil {
		d[k] = map[string]Document{}
	}
	return d[k]
}
func (s *Store) Update(fn func(database) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := copyDB(s.data)
	if err := fn(next); err != nil {
		return err
	}
	return s.commit(next, true)
}

// commit persists next and makes it the current state (callers hold s.mu). With isolate the committed state is a
// copy, so rows the callback still references are not shared with the store (immutable-row tables excepted).
func (s *Store) commit(next database, isolate bool) error {
	if s.path != "" {
		f, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
		if err != nil {
			return err
		}
		name := f.Name()
		defer os.Remove(name)
		if err = f.Chmod(0600); err == nil {
			err = writeDB(bufio.NewWriterSize(f, 1<<16), next)
		}
		if err == nil {
			err = f.Sync()
		}
		closeErr := f.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err = os.Rename(name, s.path); err != nil {
			return err
		}
		// After rename the commit is visible on disk; keep memory consistent even if directory sync fails.
		s.data = next
		if isolate {
			s.data = copyDB(next)
		}
		dir, err := os.Open(filepath.Dir(s.path))
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	s.data = next
	if isolate {
		s.data = copyDB(next)
	}
	return nil
}
