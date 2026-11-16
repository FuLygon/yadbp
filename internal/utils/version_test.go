package utils

import (
	"strings"
	"testing"
)

func TestVersionString(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	tests := []struct {
		version string
		want    string
	}{
		{version: "v1.2.3", want: "1.2.3"},
		{version: "1.2.3", want: "1.2.3"},
		{version: "  v2.0.0  ", want: "2.0.0"},
	}

	for _, test := range tests {
		Version = test.version
		if got := String(); got != test.want {
			t.Errorf("String() with Version=%q = %q, want %q", test.version, got, test.want)
		}
	}
}

func TestHeader(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })

	Version = "v1.2.3"
	if got, want := Header(), "yadbp 1.2.3"; got != want {
		t.Fatalf("Header() = %q, want %q", got, want)
	}
}

func TestCommitHashShape(t *testing.T) {
	hash := commitHash()
	if strings.TrimSpace(hash) != hash {
		t.Fatalf("commitHash() = %q, want no surrounding whitespace", hash)
	}
	if len(hash) > shortHashLength {
		t.Fatalf("commitHash() length = %d, want <= %d", len(hash), shortHashLength)
	}
}
