package blacklist

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadAndMatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "blacklist.txt")
	content := `
# This line is a comment.

Example.COM.
www.Example.org
example.com
x
duplicate.test
DUPLICATE.TEST
`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write blacklist: %v", err)
	}

	list, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got, want := list.Len(), 3; got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}

	tests := []struct {
		host string
		want bool
	}{
		{host: "example.com", want: true},
		{host: "a.b.example.com", want: true},
		{host: "www.example.com", want: true},
		{host: "example.org", want: true},
		{host: "sub.example.org", want: true},
		{host: "duplicate.test", want: true},
		{host: "notexample.com", want: false},
		{host: "example.net", want: false},
		{host: "", want: false},
	}

	for _, test := range tests {
		if got := list.IsBlocked(test.host); got != test.want {
			t.Errorf("IsBlocked(%q) = %v, want %v", test.host, got, test.want)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	t.Run("missing file", func(t *testing.T) {
		if _, err := Load(filepath.Join(t.TempDir(), "missing.txt")); err == nil {
			t.Fatal("Load() error = nil, want an error")
		}
	})

	t.Run("no domains", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "empty.txt")
		if err := os.WriteFile(path, []byte("\n# comment only\nx\n"), 0o600); err != nil {
			t.Fatalf("write blacklist: %v", err)
		}

		_, err := Load(path)
		if err == nil {
			t.Fatal("Load() error = nil, want an error")
		}
		if !strings.Contains(err.Error(), "contains no domains") {
			t.Fatalf("Load() error = %q, want a no-domains error", err)
		}
	})
}

func TestNilList(t *testing.T) {
	var list *List

	if list.IsBlocked("example.com") {
		t.Fatal("nil List should not block any host")
	}
	if got := list.Len(); got != 0 {
		t.Fatalf("nil List Len() = %d, want 0", got)
	}
}

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: " WWW.Example.COM. ", want: "example.com"},
		{input: "example.com.", want: "example.com"},
		{input: "sub.example.com", want: "sub.example.com"},
		{input: "", want: ""},
	}

	for _, test := range tests {
		if got := normalizeDomain(test.input); got != test.want {
			t.Errorf("normalizeDomain(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
