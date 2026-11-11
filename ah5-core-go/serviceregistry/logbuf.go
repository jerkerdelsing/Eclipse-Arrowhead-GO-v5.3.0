package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

var logLevelsInOrder = []string{"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL", "OFF"}

type LogEntry struct {
	ID        int64
	Date      time.Time
	Level     string
	Logger    string
	Message   string
	Exception string
}

// Logger prints to stderr and keeps the last N entries in memory for generalManagement/get-log.
type Logger struct {
	mu       sync.Mutex
	buf      []LogEntry
	capacity int
	next     int64
	quiet    bool
}

func NewLogger(capacity int) *Logger {
	if capacity < 1 {
		capacity = 1
	}
	return &Logger{capacity: capacity}
}

func (l *Logger) Log(level, logger, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	l.mu.Lock()
	l.next++
	e := LogEntry{ID: l.next, Date: time.Now().UTC(), Level: level, Logger: logger, Message: msg}
	if len(l.buf) >= l.capacity {
		copy(l.buf, l.buf[1:])
		l.buf[len(l.buf)-1] = e
	} else {
		l.buf = append(l.buf, e)
	}
	quiet := l.quiet
	l.mu.Unlock()
	if !quiet && level != "DEBUG" && level != "TRACE" {
		fmt.Fprintf(os.Stderr, "%s %-5s %s - %s\n", e.Date.Format("2006-01-02T15:04:05.000Z"), level, logger, msg)
	}
}

func (l *Logger) Debugf(logger, format string, args ...any) { l.Log("DEBUG", logger, format, args...) }
func (l *Logger) Infof(logger, format string, args ...any)  { l.Log("INFO", logger, format, args...) }
func (l *Logger) Warnf(logger, format string, args ...any)  { l.Log("WARN", logger, format, args...) }
func (l *Logger) Errorf(logger, format string, args ...any) { l.Log("ERROR", logger, format, args...) }

// Entries returns a copy of the stored entries that match the filters (nil/empty = no filter).
func (l *Logger) Entries(levels []string, from, to *time.Time, loggerSub string) []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []LogEntry
	sub := strings.ToLower(loggerSub)
	for _, e := range l.buf {
		if len(levels) > 0 && !containsStr(levels, e.Level) {
			continue
		}
		if from != nil && e.Date.Before(*from) {
			continue
		}
		if to != nil && e.Date.After(*to) {
			continue
		}
		if sub != "" && !strings.Contains(strings.ToLower(e.Logger), sub) {
			continue
		}
		out = append(out, e)
	}
	return out
}
