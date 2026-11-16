package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseLevel(t *testing.T) {
	tests := []struct {
		input string
		want  Level
	}{
		{input: "debug", want: Debug},
		{input: "INFO", want: Info},
		{input: " warn ", want: Warn},
		{input: "error", want: Error},
		{input: "fatal", want: Fatal},
		{input: "silent", want: Silent},
	}

	for _, test := range tests {
		got, err := ParseLevel(test.input)
		if err != nil {
			t.Errorf("ParseLevel(%q) error = %v", test.input, err)
			continue
		}
		if got != test.want {
			t.Errorf("ParseLevel(%q) = %v, want %v", test.input, got, test.want)
		}
	}

	got, err := ParseLevel("verbose")
	if err == nil {
		t.Fatal("ParseLevel(invalid) error = nil, want an error")
	}
	if got != Silent {
		t.Fatalf("ParseLevel(invalid) = %v, want Silent", got)
	}
}

func TestLoggerFiltersBelowConfiguredLevel(t *testing.T) {
	var output bytes.Buffer
	logger := New(Warn, &output)

	logger.Debugf("debug message")
	logger.Infof("info message")
	logger.Warnf("warning %d", 7)
	logger.Errorf("error %s", "message")

	want := "[warn] warning 7\n[error] error message\n"
	if got := output.String(); got != want {
		t.Fatalf("log output = %q, want %q", got, want)
	}
}

func TestLoggerDebugIncludesAllLevels(t *testing.T) {
	var output bytes.Buffer
	logger := New(Debug, &output)

	logger.Debugf("debug")
	logger.Infof("info")
	logger.Warnf("warn")
	logger.Errorf("error")

	want := "[debug] debug\n[info] info\n[warn] warn\n[error] error\n"
	if got := output.String(); got != want {
		t.Fatalf("log output = %q, want %q", got, want)
	}
}

func TestPrintfIgnoresLevel(t *testing.T) {
	var output bytes.Buffer
	logger := New(Silent, &output)

	logger.Infof("discarded")
	logger.Printf("%s %d", "hello", 42)

	if got, want := output.String(), "hello 42\n"; got != want {
		t.Fatalf("log output = %q, want %q", got, want)
	}
}

func TestLoggerConcurrentWrites(t *testing.T) {
	var output bytes.Buffer
	logger := New(Info, &output)

	const writers = 20
	done := make(chan struct{}, writers)
	for i := 0; i < writers; i++ {
		go func() {
			logger.Infof("message")
			done <- struct{}{}
		}()
	}
	for i := 0; i < writers; i++ {
		<-done
	}

	if got := strings.Count(output.String(), "[info] message\n"); got != writers {
		t.Fatalf("logged %d complete lines, want %d", got, writers)
	}
}
