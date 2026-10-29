// Package logger provides a minimal leveled logger that writes
// info/debug messages to stdout and warnings/errors to stderr.
package logger

import (
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"time"
)

// Level is a log severity level.
type Level int32

const (
	// LevelDebug is the most verbose level.
	LevelDebug Level = iota
	// LevelInfo is the default level.
	LevelInfo
	// LevelWarn is for warnings.
	LevelWarn
	// LevelError is for errors.
	LevelError
)

var (
	currentLevel atomic.Int32
	stdout       io.Writer = os.Stdout
	stderr       io.Writer = os.Stderr
)

func init() {
	currentLevel.Store(int32(LevelInfo))
}

// SetLevel sets the minimum level that is logged, from a string
// ("debug", "info", "warn" or "error"). Unknown values are ignored.
func SetLevel(s string) {
	switch s {
	case "debug":
		currentLevel.Store(int32(LevelDebug))
	case "info":
		currentLevel.Store(int32(LevelInfo))
	case "warn":
		currentLevel.Store(int32(LevelWarn))
	case "error":
		currentLevel.Store(int32(LevelError))
	}
}

// GetLevel returns the current minimum log level.
func GetLevel() Level {
	return Level(currentLevel.Load())
}

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarn:
		return "WARN"
	case LevelError:
		return "ERROR"
	}
	return "UNKNOWN"
}

func logf(l Level, w io.Writer, format string, args ...any) {
	if l < GetLevel() {
		return
	}
	ts := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	fmt.Fprintf(w, "%s %s %s\n", ts, l, fmt.Sprintf(format, args...))
}

// Debug logs a formatted message at debug level to stdout.
func Debug(format string, args ...any) { logf(LevelDebug, stdout, format, args...) }

// Info logs a formatted message at info level to stdout.
func Info(format string, args ...any) { logf(LevelInfo, stdout, format, args...) }

// Warn logs a formatted message at warn level to stderr.
func Warn(format string, args ...any) { logf(LevelWarn, stderr, format, args...) }

// Error logs a formatted message at error level to stderr.
func Error(format string, args ...any) { logf(LevelError, stderr, format, args...) }
