package logging

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

type Level int

const (
	Debug Level = iota
	Info
	Warn
	Error
	Fatal
	Silent
)

var levelLabels = map[Level]string{
	Debug: "debug",
	Info:  "info",
	Warn:  "warn",
	Error: "error",
	Fatal: "fatal",
}

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

type Logger struct {
	level Level
	out   io.Writer
	mu    sync.Mutex
}

func New(level Level, out io.Writer) *Logger {
	return &Logger{level: level, out: out}
}

func (l *Logger) Debugf(format string, args ...any) {
	l.logf(Debug, format, args...)
}

func (l *Logger) Infof(format string, args ...any) {
	l.logf(Info, format, args...)
}

func (l *Logger) Warnf(format string, args ...any) {
	l.logf(Warn, format, args...)
}

func (l *Logger) Errorf(format string, args ...any) {
	l.logf(Error, format, args...)
}

func (l *Logger) Fatalf(format string, args ...any) {
	l.logf(Fatal, format, args...)
	os.Exit(1)
}

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
