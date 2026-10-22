package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"cloak-dpi/internal/blacklist"
	"cloak-dpi/internal/logging"
	"cloak-dpi/internal/proxy"
)

const (
	appName         = "cloak-dpi"
	defaultHost     = "0.0.0.0"
	defaultPort     = 8888
	defaultLogLevel = "silent"
)

type config struct {
	host          string
	port          int
	blacklistPath string
	logLevel      logging.Level
}

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

	server := proxy.New(proxy.Options{
		Host:          cfg.host,
		Port:          cfg.port,
		BlacklistPath: cfg.blacklistPath,
	}, blocked, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := server.Serve(ctx); err != nil {
		log.Fatalf("%v", err)
	}

	log.Infof("Stopped.")
}

func parseFlags() *config {
	cfg := &config{}
	var logLevelName string

	flag.StringVar(&cfg.host, "h", defaultHost, "proxy listen host")
	flag.IntVar(&cfg.port, "p", defaultPort, "proxy listen port")
	flag.StringVar(&cfg.blacklistPath, "blacklist", "", "path to an optional domain blacklist file")
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

	return cfg
}
