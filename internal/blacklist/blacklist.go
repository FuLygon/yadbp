package blacklist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// List is an immutable set of normalized domains. A List is safe for
// concurrent reads after Load returns.
type List struct {
	domains map[string]struct{}
}

// Load reads a blacklist file and returns its domains. Blank lines and lines
// beginning with "#" are ignored. It returns an error if the file cannot be
// read or contains no usable domains.
func Load(path string) (*List, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open blacklist %q: %w", path, err)
	}
	defer file.Close()

	list := &List{domains: make(map[string]struct{})}

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) < 2 || strings.HasPrefix(line, "#") {
			continue
		}

		domain := normalizeDomain(line)
		if domain == "" {
			continue
		}
		list.domains[domain] = struct{}{}
	}

	if err = scanner.Err(); err != nil {
		return nil, fmt.Errorf("read blacklist %q: %w", path, err)
	}

	if len(list.domains) == 0 {
		return nil, fmt.Errorf("blacklist %q contains no domains", path)
	}

	return list, nil
}

// IsBlocked reports whether domain or one of its parent domains is listed.
// A nil *List matches nothing, so callers can use nil to mean "no blacklist".
func (l *List) IsBlocked(domain string) bool {
	if l == nil {
		return false
	}

	domain = normalizeDomain(domain)
	if domain == "" {
		return false
	}

	for {
		if _, ok := l.domains[domain]; ok {
			return true
		}

		dot := strings.IndexByte(domain, '.')
		if dot < 0 {
			return false
		}
		domain = domain[dot+1:]
	}
}

// Len returns the number of listed domains. A nil *List has length zero.
func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.domains)
}

// normalizeDomain lowercases and trims a host for comparison, removes a
// trailing root dot, and drops "www." labels.
func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.ReplaceAll(domain, "www.", "")
	domain = strings.TrimSuffix(domain, ".")
	return domain
}
