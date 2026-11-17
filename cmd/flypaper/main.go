// flypaper: turns honeypot ring-buffer captures into small, deduplicated,
// described PcapHub uploads.
//
//	flypaper run        process new ring files every interval (the service)
//	flypaper once       one pass, then exit
//	flypaper dry-run    one pass writing slices + metadata to the outbox, no upload
//	flypaper check      validate config, logs, ring dir and the PcapHub key
//	flypaper slice F    slice one pcap to stdout summary (debugging)
//	flypaper version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/pcaphub/flypaper/internal/classify"
	"github.com/pcaphub/flypaper/internal/config"
	"github.com/pcaphub/flypaper/internal/pcaphub"
	"github.com/pcaphub/flypaper/internal/pipeline"
	"github.com/pcaphub/flypaper/internal/session"
	"github.com/pcaphub/flypaper/internal/state"
)

func main() {
	fs := flag.NewFlagSet("flypaper", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/flypaper/config.yaml", "configuration file")
	interval := fs.Duration("interval", 2*time.Minute, "run: time between passes")
	jsonLog := fs.Bool("json", false, "log as JSON")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flypaper [-config FILE] run|once|dry-run|check|slice FILE|version")
		fs.PrintDefaults()
	}
	if len(os.Args) < 2 {
		fs.Usage()
		os.Exit(2)
	}
	// allow flags before or after the subcommand
	args := os.Args[1:]
	var cmd string
	var rest []string
	for i := 0; i < len(args); i++ {
		if len(args[i]) > 0 && args[i][0] != '-' && cmd == "" {
			cmd = args[i]
			rest = args[i+1:]
			_ = fs.Parse(append(args[:i:i], rest...))
			break
		}
	}
	if cmd == "" {
		_ = fs.Parse(args)
		cmd = fs.Arg(0)
	}
	rest = fs.Args()

	var h slog.Handler
	if *jsonLog {
		h = slog.NewJSONHandler(os.Stderr, nil)
	} else {
		h = slog.NewTextHandler(os.Stderr, nil)
	}
	log := slog.New(h)

	switch cmd {
	case "version":
		fmt.Println("flypaper", pcaphub.Version)
		return
	case "slice":
		if len(rest) < 1 {
			fatal(log, "slice needs a pcap file")
		}
		sliceCmd(log, rest[0])
		return
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		fatal(log, "config: "+err.Error())
	}
	if cmd == "dry-run" {
		cfg.DryRun = true
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "check":
		os.Exit(check(ctx, log, cfg))
	case "once", "dry-run":
		p, err := newPipeline(cfg, log)
		if err != nil {
			fatal(log, err.Error())
		}
		sum, err := p.Run(ctx)
		report(log, sum)
		if err != nil {
			fatal(log, err.Error())
		}
	case "run":
		p, err := newPipeline(cfg, log)
		if err != nil {
			fatal(log, err.Error())
		}
		log.Info("flypaper started", "collector", cfg.Name, "dry_run", cfg.DryRun, "interval", interval.String(), "ring", cfg.Capture.Dir)
		t := time.NewTicker(*interval)
		defer t.Stop()
		for {
			sum, err := p.Run(ctx)
			if err != nil && ctx.Err() == nil {
				log.Error("pass failed", "error", err)
			} else if sum != nil && (sum.Files > 0) {
				report(log, sum)
			}
			select {
			case <-ctx.Done():
				log.Info("flypaper stopping")
				return
			case <-t.C:
			}
		}
	default:
		fs.Usage()
		os.Exit(2)
	}
}

func newPipeline(cfg config.Config, log *slog.Logger) (*pipeline.Pipeline, error) {
	st, err := state.Open(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("state: %w", err)
	}
	p := &pipeline.Pipeline{Cfg: cfg, State: st, Log: log}
	if !cfg.DryRun {
		p.Client = pcaphub.New(cfg.PcapHub.URL, cfg.PcapHub.APIKey)
	}
	return p, nil
}

func report(log *slog.Logger, s *pipeline.Summary) {
	if s == nil {
		return
	}
	log.Info("pass complete", "files", s.Files, "sessions", s.Sessions, "uploaded", s.Uploaded, "baseline", s.Baseline, "skipped", s.Skipped)
}

// check validates the moving parts and prints one line each.
func check(ctx context.Context, log *slog.Logger, cfg config.Config) int {
	rc := 0
	ok := func(what string, err error) {
		if err != nil {
			fmt.Printf("FAIL  %-28s %v\n", what, err)
			rc = 1
			return
		}
		fmt.Printf("ok    %s\n", what)
	}
	_, err := os.Stat(cfg.Capture.Dir)
	ok("ring directory "+cfg.Capture.Dir, err)
	if cfg.Logs.Cowrie != "" {
		_, err = os.Stat(cfg.Logs.Cowrie)
		ok("cowrie log "+cfg.Logs.Cowrie, err)
	}
	if cfg.Logs.Honeypots != "" {
		_, err = os.Stat(cfg.Logs.Honeypots)
		ok("honeypots log "+cfg.Logs.Honeypots, err)
	}
	st, err := state.Open(cfg.StateDir)
	ok("state directory "+cfg.StateDir, err)
	if err == nil {
		ok("state file writable", st.Save())
	}
	if cfg.DryRun {
		ok("outbox "+cfg.Outbox, os.MkdirAll(cfg.Outbox, 0o750))
		fmt.Println("note  dry_run is set, PcapHub key not checked")
	} else {
		c := pcaphub.New(cfg.PcapHub.URL, cfg.PcapHub.APIKey)
		cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		ok("pcaphub reachable "+cfg.PcapHub.URL, c.Ping(cctx))
		if len(cfg.PcapHub.APIKey) < 8 {
			ok("api key present", fmt.Errorf("missing or too short"))
		} else {
			fmt.Println("ok    api key present (scope is verified on first upload)")
		}
	}
	return rc
}

// sliceCmd prints the sessions one pcap would produce, for tuning.
func sliceCmd(log *slog.Logger, path string) {
	cfg := config.Default()
	opt := session.Options{
		ExcludePorts: map[int]bool{}, IdleGap: cfg.Select.IdleGap,
		MaxPackets: cfg.Select.MaxPackets, MaxBytes: cfg.Select.MaxBytes, MinPackets: 1,
	}
	sessions, err := session.Slice(path, opt)
	if err != nil {
		fatal(log, err.Error())
	}
	fmt.Printf("%d sessions\n", len(sessions))
	for _, s := range sessions {
		r := classify.Run(s, nil)
		fmt.Printf("%-39s %s  %4d pkts %3d flows  ports=%v  %s score=%d fp=%s\n",
			s.Remote, s.Start.UTC().Format("15:04:05"), len(s.Packets), len(s.Flows), s.LocalPorts, r.Class, r.Score, r.Fingerprint)
	}
}

func fatal(log *slog.Logger, msg string) {
	log.Error(msg)
	os.Exit(1)
}
