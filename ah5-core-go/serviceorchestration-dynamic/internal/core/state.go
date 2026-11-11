// SPDX-License-Identifier: EPL-2.0
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
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
	removeStaleTemps(path)
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

// tempPattern names transaction files after their state file, so stores sharing a directory never touch each other's.
func tempPattern(path string) string { return "." + filepath.Base(path) + ".tmp-*" }

// removeStaleTemps deletes temporary files of transactions interrupted by a kill (the deferred Remove never ran);
// the caller holds the state lock. Older builds used the shared ".state-*" pattern: those are removed only when
// older than a minute, as another store in the same directory may still be writing one.
func removeStaleTemps(path string) {
	dir := filepath.Dir(path)
	own, _ := filepath.Glob(filepath.Join(dir, tempPattern(path)))
	for _, name := range own {
		os.Remove(name)
	}
	legacy, _ := filepath.Glob(filepath.Join(dir, ".state-*"))
	for _, name := range legacy {
		if info, err := os.Stat(name); err == nil && time.Since(info.ModTime()) > time.Minute {
			os.Remove(name)
		}
	}
}
func (s *Store) Close() error {
	if s.lock == nil {
		return nil
	}
	syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
	return s.lock.Close()
}
func copyDB(d database) database {
	b, _ := json.Marshal(d)
	var c database
	_ = json.Unmarshal(b, &c)
	return c
}
func (s *Store) View(fn func(database) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(copyDB(s.data))
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
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if s.path != "" {
		f, err := os.CreateTemp(filepath.Dir(s.path), tempPattern(s.path))
		if err != nil {
			return err
		}
		name := f.Name()
		defer os.Remove(name)
		if err = f.Chmod(0600); err == nil {
			_, err = f.Write(b)
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
		dir, err := os.Open(filepath.Dir(s.path))
		if err != nil {
			return err
		}
		defer dir.Close()
		return dir.Sync()
	}
	s.data = next
	return nil
}
