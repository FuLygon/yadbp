package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

// Level is a log verbosity threshold. Messages below the configured level are
// discarded.
type Level int

const (
	// Debug is for detailed diagnostic messages.
	Debug Level = iota
	// Info is for normal lifecycle and request events.
	Info
	// Warn is for recoverable failures and state changes.
	Warn
	// Error is for failed requests and connection errors.
	Error
	// Fatal is for unrecoverable errors. Fatalf exits with status 1.
	Fatal
	// Silent disables all logging.
	Silent
)

var levelLabels = map[Level]string{
	Debug: "debug",
	Info:  "info",
	Warn:  "warn",
	Error: "error",
	Fatal: "fatal",
}

// ParseLevel converts a case-insensitive level name to a Level.
func ParseLevel(value string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "debug":
		return Debug, nil
	case "info":
		return Info, nil
	case "warn":
		return Warn, nil
	case "error":
		return Error, nil
	case "fatal":
		return Fatal, nil
	case "silent":
		return Silent, nil
	default:
		return Silent, fmt.Errorf("invalid log level %q (want one of: debug, info, warn, error, fatal, silent)", value)
	}
}

// Logger writes leveled, mutex-protected messages to an io.Writer.
type Logger struct {
	level Level
	out   io.Writer
	mu    sync.Mutex
}

// New returns a Logger that writes to out and drops messages below level.
func New(level Level, out io.Writer) *Logger {
	return &Logger{level: level, out: out}
}

// Debugf logs a formatted debug message.
func (l *Logger) Debugf(format string, args ...any) {
	l.logf(Debug, format, args...)
}

// Infof logs a formatted info message.
func (l *Logger) Infof(format string, args ...any) {
	l.logf(Info, format, args...)
}

// Warnf logs a formatted warning message.
func (l *Logger) Warnf(format string, args ...any) {
	l.logf(Warn, format, args...)
}

// Errorf logs a formatted error message.
func (l *Logger) Errorf(format string, args ...any) {
	l.logf(Error, format, args...)
}

// Fatalf logs a formatted fatal message when the level permits it, then exits
// with status 1.
func (l *Logger) Fatalf(format string, args ...any) {
	l.logf(Fatal, format, args...)
	os.Exit(1)
}

// Printf writes an unprefixed line regardless of the configured level. It is
// used for startup output that should not be suppressed by --log-level.
func (l *Logger) Printf(format string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	_, _ = fmt.Fprintf(l.out, format+"\n", args...)
}

func (l *Logger) logf(level Level, format string, args ...any) {
	if level < l.level {
		return
	}

	label, ok := levelLabels[level]
	if !ok {
		label = "unknown"
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	_, _ = fmt.Fprintf(l.out, "[%s] %s\n", label, fmt.Sprintf(format, args...))
}
