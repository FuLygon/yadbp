package blacklist

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

type List struct {
	domains map[string]struct{}
}

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

func (l *List) Len() int {
	if l == nil {
		return 0
	}
	return len(l.domains)
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.ReplaceAll(domain, "www.", "")
	domain = strings.TrimSuffix(domain, ".")
	return domain
}
