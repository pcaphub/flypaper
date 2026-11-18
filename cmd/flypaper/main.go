// flypaper: turns honeypot ring-buffer captures into small, deduplicated,
// described PcapHub uploads.
//
//	flypaper run        process new ring files every interval (the service)
//	flypaper once       one pass, then exit
//	flypaper dry-run    one pass writing slices + metadata to the outbox, no upload
//	flypaper check      validate config, logs, ring dir and the PcapHub key
//	flypaper stats      sessions seen vs uploaded, per class, dedupe ratio
//	flypaper slice F    slice one pcap to stdout summary (debugging)
//	flypaper config     show the selection settings
//	flypaper config daily_cap=40 probe_cap=12   change settings in place and restart the service
//	flypaper upgrade    install the latest release (or -version vX.Y.Z) and restart the service
//	flypaper version
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/pcaphub/flypaper/internal/classify"
	"github.com/pcaphub/flypaper/internal/config"
	"github.com/pcaphub/flypaper/internal/pcaphub"
	"github.com/pcaphub/flypaper/internal/pipeline"
	"github.com/pcaphub/flypaper/internal/session"
	"github.com/pcaphub/flypaper/internal/state"
	"github.com/pcaphub/flypaper/internal/upgrade"
)

func main() {
	fs := flag.NewFlagSet("flypaper", flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/flypaper/config.yaml", "configuration file")
	interval := fs.Duration("interval", 2*time.Minute, "run: time between passes")
	jsonLog := fs.Bool("json", false, "log as JSON")
	upVersion := fs.String("version", "latest", "upgrade: release tag to install")
	upService := fs.String("service", "flypaper", "upgrade, config: systemd unit to restart, empty for none")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: flypaper [-config FILE] run|once|dry-run|check|stats|slice FILE|config [key=value ...]|upgrade|version")
		fs.PrintDefaults()
	}
	if len(os.Args) < 2 {
		fs.Usage()
		os.Exit(2)
	}
	// Flags may come before or after the subcommand: the flag package stops
	// at the first non-flag word, which is the command; parse what follows
	// it as flags again.
	_ = fs.Parse(os.Args[1:])
	cmd := fs.Arg(0)
	var rest []string
	if fs.NArg() > 1 {
		_ = fs.Parse(fs.Args()[1:])
		rest = fs.Args()
	}

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
	case "config":
		if len(rest) == 0 {
			cfg, err := config.Load(*cfgPath)
			if err != nil {
				fatal(log, err.Error())
			}
			showConfig(cfg)
			return
		}
		changed, err := config.Set(*cfgPath, rest)
		if err != nil {
			fatal(log, "config: "+err.Error())
		}
		for _, c := range changed {
			fmt.Println("set", c)
		}
		if *upService != "" {
			if out, err := exec.Command("systemctl", "restart", *upService).CombinedOutput(); err != nil {
				fatal(log, fmt.Sprintf("restart %s: %v: %s", *upService, err, strings.TrimSpace(string(out))))
			}
			fmt.Println("restarted", *upService)
		}
		return
	case "upgrade":
		tag, err := upgrade.Run(context.Background(), upgrade.Options{
			Version: *upVersion, Current: pcaphub.Version, Service: *upService,
			Log: func(f string, a ...any) { log.Info(fmt.Sprintf(f, a...)) },
		})
		if err != nil {
			fatal(log, "upgrade: "+err.Error())
		}
		fmt.Println("flypaper", tag)
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
	case "stats":
		st, err := state.Open(cfg.StateDir)
		if err != nil {
			fatal(log, err.Error())
		}
		printStats(st.Snapshot(time.Now()))
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
	if cfg.Logs.OpenCanary != "" {
		_, err = os.Stat(cfg.Logs.OpenCanary)
		ok("opencanary log "+cfg.Logs.OpenCanary, err)
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

func printStats(st state.Stats) {
	pct := func(up, seen int) string {
		if seen == 0 {
			return "n/a"
		}
		return fmt.Sprintf("%.2f%%", 100*float64(up)/float64(seen))
	}
	fmt.Printf("last 7 days:  %d sessions, %d uploads (%s)\n", st.Seen7, st.Uploaded7, pct(st.Uploaded7, st.Seen7))
	fmt.Printf("lifetime:     %d sessions, %d uploads (%s), %d scenarios, %d families\n", st.SeenAll, st.UploadedAll, pct(st.UploadedAll, st.SeenAll), st.Scenarios, st.Families)
	fmt.Printf("%-22s %8s %8s %8s\n", "class", "seen", "uploaded", "ratio")
	keys := make([]string, 0, len(st.ByClass))
	for k := range st.ByClass {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		c := st.ByClass[k]
		fmt.Printf("%-22s %8d %8d %8s\n", k, c.Seen, c.Uploaded, pct(c.Uploaded, c.Seen))
	}
}

func fatal(log *slog.Logger, msg string) {
	log.Error(msg)
	os.Exit(1)
}

// showConfig prints the values flypaper config can change.
func showConfig(cfg config.Config) {
	sel := cfg.Select
	rows := [][2]string{
		{"name", cfg.Name}, {"region", cfg.Region}, {"dry_run", fmt.Sprint(cfg.DryRun)},
		{"daily_cap", fmt.Sprint(sel.DailyCap)}, {"probe_cap", fmt.Sprint(sel.ProbeCap)},
		{"baseline_per_day", fmt.Sprint(sel.BaselinePerDay)}, {"min_score", fmt.Sprint(sel.MinScore)},
		{"family_cap", fmt.Sprint(sel.FamilyCap)}, {"repeat_after", sel.RepeatAfter.String()},
		{"novelty_bonus", fmt.Sprint(sel.NoveltyBonus)}, {"max_ratio", fmt.Sprint(sel.MaxRatio)},
		{"min_sessions_for_ratio", fmt.Sprint(sel.MinSessionsForRatio)},
		{"keep_attempts", fmt.Sprint(sel.KeepAttempts)}, {"max_packets", fmt.Sprint(sel.MaxPackets)},
		{"max_bytes", fmt.Sprint(sel.MaxBytes)}, {"idle_gap", sel.IdleGap.String()},
	}
	for _, r := range rows {
		fmt.Printf("%-24s %s\n", r[0], r[1])
	}
	fmt.Println("\nchange with: flypaper config daily_cap=40 probe_cap=12   (restarts the service)")
}
