package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"yadbp/internal/blacklist"
	"yadbp/internal/logging"
	"yadbp/internal/proxy"
	"yadbp/internal/resolver"
)

// Defaults used when the corresponding command-line flags are omitted.
const (
	appName         = "yadbp"
	defaultHost     = "0.0.0.0"
	defaultPort     = 8888
	defaultLogLevel = "silent"

	defaultPrimaryDNSTimeout     = 2
	defaultPrimaryDNSHealthcheck = 30
)

// config is the validated command-line configuration used to build the proxy.
type config struct {
	host                  string
	port                  int
	blacklistPath         string
	logLevel              logging.Level
	primaryDNS            string
	fallbackDNS           string
	primaryDNSTimeout     int
	primaryDNSHealthcheck int
}

// main parses flags, loads the optional blacklist and resolver, and runs the
// proxy until it receives SIGINT or SIGTERM.
func main() {
	cfg := parseFlags()
	log := logging.New(cfg.logLevel, os.Stderr)

	var blocked *blacklist.List
	if cfg.blacklistPath != "" {
		var err error
		blocked, err = blacklist.Load(cfg.blacklistPath)
		if err != nil {
			log.Errorf("%v", err)
			log.Errorf("Use --blacklist <path> to select a blacklist file.")
			os.Exit(1)
		}
	}

	var dns *resolver.Resolver
	if cfg.primaryDNS != "" {
		var err error
		dns, err = resolver.New(resolver.Config{
			Primary:             cfg.primaryDNS,
			Fallback:            cfg.fallbackDNS,
			PrimaryTimeout:      time.Duration(cfg.primaryDNSTimeout) * time.Second,
			HealthcheckInterval: time.Duration(cfg.primaryDNSHealthcheck) * time.Second,
			Logger:              log,
		})
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		defer dns.Close()
	}

	server := proxy.New(proxy.Options{
		Host:          cfg.host,
		Port:          cfg.port,
		BlacklistPath: cfg.blacklistPath,
		DNS:           dns,
	}, blocked, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Serve(ctx); err != nil {
		log.Fatalf("%v", err)
	}

	log.Infof("Stopped.")
}

// parseFlags registers the command-line flags, validates the resulting
// configuration, and exits with status 2 when the input is invalid.
func parseFlags() *config {
	cfg := &config{}
	var logLevelName string

	flag.StringVar(&cfg.host, "h", defaultHost, "proxy listen host")
	flag.IntVar(&cfg.port, "p", defaultPort, "proxy listen port")
	flag.StringVar(&cfg.blacklistPath, "blacklist", "", "path to an optional domain blacklist file")
	flag.StringVar(&cfg.primaryDNS, "dns-primary", "", "primary DNS server in ip:port format, e.g. 1.1.1.1:53")
	flag.StringVar(&cfg.fallbackDNS, "dns-fallback", "", "fallback DNS server in ip:port format, used when the primary DNS fails")
	flag.IntVar(&cfg.primaryDNSTimeout, "dns-primary-timeout", defaultPrimaryDNSTimeout, "seconds before a primary DNS query counts as timed out and marked as down")
	flag.IntVar(&cfg.primaryDNSHealthcheck, "dns-primary-healthcheck", defaultPrimaryDNSHealthcheck, "seconds between primary DNS health checks while it is down")
	flag.StringVar(&logLevelName, "log-level", defaultLogLevel, "log level: debug, info, warn, error, fatal, or silent")

	flag.Usage = func() {
		out := flag.CommandLine.Output()
		_, _ = fmt.Fprintf(out, "Usage: %s [options]\n\nOptions:\n", appName)
		flag.PrintDefaults()
	}

	flag.Parse()

	if flag.NArg() > 0 {
		_, _ = fmt.Fprintf(os.Stderr, "error: unexpected argument %q\n", flag.Arg(0))
		flag.Usage()
		os.Exit(2)
	}

	level, err := logging.ParseLevel(logLevelName)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	cfg.logLevel = level

	cfg.host = strings.TrimSpace(cfg.host)
	if cfg.host == "" {
		_, _ = fmt.Fprintln(os.Stderr, "error: host must not be empty")
		os.Exit(2)
	}

	if cfg.port < 1 || cfg.port > 65535 {
		_, _ = fmt.Fprintf(os.Stderr, "error: invalid port %d\n", cfg.port)
		os.Exit(2)
	}

	cfg.primaryDNS = strings.TrimSpace(cfg.primaryDNS)
	cfg.fallbackDNS = strings.TrimSpace(cfg.fallbackDNS)

	if cfg.fallbackDNS != "" && cfg.primaryDNS == "" {
		_, _ = fmt.Fprintln(os.Stderr, "error: --dns-fallback requires --dns-primary")
		os.Exit(2)
	}

	if cfg.primaryDNS != "" {
		if cfg.primaryDNSTimeout < 1 {
			_, _ = fmt.Fprintln(os.Stderr, "error: --dns-primary-timeout must be at least 1 second")
			os.Exit(2)
		}
		if cfg.primaryDNSHealthcheck < 1 {
			_, _ = fmt.Fprintln(os.Stderr, "error: --dns-primary-healthcheck must be at least 1 second")
			os.Exit(2)
		}
	}

	return cfg
}
