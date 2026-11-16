package main

import (
	"flag"
	"os"
	"testing"

	"yadbp/internal/logging"
)

func setTestArgs(t *testing.T, args ...string) {
	t.Helper()

	oldArgs := os.Args
	oldCommandLine := flag.CommandLine
	oldUsage := flag.Usage

	flag.CommandLine = flag.NewFlagSet("yadbp", flag.ContinueOnError)
	os.Args = append([]string{"yadbp"}, args...)

	t.Cleanup(func() {
		flag.CommandLine = oldCommandLine
		flag.Usage = oldUsage
		os.Args = oldArgs
	})
}

func TestParseFlagsDefaults(t *testing.T) {
	setTestArgs(t)

	cfg := parseFlags()

	if cfg.host != defaultHost {
		t.Errorf("host = %q, want %q", cfg.host, defaultHost)
	}
	if cfg.port != defaultPort {
		t.Errorf("port = %d, want %d", cfg.port, defaultPort)
	}
	if cfg.blacklistPath != "" {
		t.Errorf("blacklistPath = %q, want empty", cfg.blacklistPath)
	}
	if cfg.logLevel != logging.Silent {
		t.Errorf("logLevel = %v, want Silent", cfg.logLevel)
	}
	if cfg.primaryDNS != "" || cfg.fallbackDNS != "" {
		t.Errorf("DNS config = %q/%q, want empty", cfg.primaryDNS, cfg.fallbackDNS)
	}
	if cfg.primaryDNSTimeout != defaultPrimaryDNSTimeout {
		t.Errorf("primaryDNSTimeout = %d, want %d", cfg.primaryDNSTimeout, defaultPrimaryDNSTimeout)
	}
	if cfg.primaryDNSHealthcheck != defaultPrimaryDNSHealthcheck {
		t.Errorf("primaryDNSHealthcheck = %d, want %d", cfg.primaryDNSHealthcheck, defaultPrimaryDNSHealthcheck)
	}
}

func TestParseFlagsCustomValues(t *testing.T) {
	setTestArgs(t,
		"-h", " 127.0.0.1 ",
		"-p", "9999",
		"-blacklist", "blocked.txt",
		"-log-level", "debug",
		"-dns-primary", " 1.1.1.1:53 ",
		"-dns-fallback", "8.8.8.8:53",
		"-dns-primary-timeout", "3",
		"-dns-primary-healthcheck", "4",
	)

	cfg := parseFlags()

	if cfg.host != "127.0.0.1" {
		t.Errorf("host = %q, want 127.0.0.1", cfg.host)
	}
	if cfg.port != 9999 {
		t.Errorf("port = %d, want 9999", cfg.port)
	}
	if cfg.blacklistPath != "blocked.txt" {
		t.Errorf("blacklistPath = %q, want blocked.txt", cfg.blacklistPath)
	}
	if cfg.logLevel != logging.Debug {
		t.Errorf("logLevel = %v, want Debug", cfg.logLevel)
	}
	if cfg.primaryDNS != "1.1.1.1:53" {
		t.Errorf("primaryDNS = %q, want 1.1.1.1:53", cfg.primaryDNS)
	}
	if cfg.fallbackDNS != "8.8.8.8:53" {
		t.Errorf("fallbackDNS = %q, want 8.8.8.8:53", cfg.fallbackDNS)
	}
	if cfg.primaryDNSTimeout != 3 {
		t.Errorf("primaryDNSTimeout = %d, want 3", cfg.primaryDNSTimeout)
	}
	if cfg.primaryDNSHealthcheck != 4 {
		t.Errorf("primaryDNSHealthcheck = %d, want 4", cfg.primaryDNSHealthcheck)
	}
}
