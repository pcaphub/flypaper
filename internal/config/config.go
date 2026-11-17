// Package config loads the collector configuration (/etc/flypaper/config.yaml).
package config

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the whole agent configuration. Durations are written as Go
// durations in YAML ("5m", "24h").
type Config struct {
	// Name of this collector, used in tags and titles (e.g. "hel-1").
	Name string `yaml:"name"`
	// Region label for tags and descriptions (free text, e.g. "eu-north").
	Region string `yaml:"region"`

	PcapHub  PcapHub `yaml:"pcaphub"`
	Capture  Capture `yaml:"capture"`
	Logs     Logs    `yaml:"logs"`
	Select   Select  `yaml:"select"`
	StateDir string  `yaml:"state_dir"`
	Outbox   string  `yaml:"outbox"` // dry-run output directory
	DryRun   bool    `yaml:"dry_run"`
}

type PcapHub struct {
	URL        string `yaml:"url"`
	APIKey     string `yaml:"api_key"`
	APIKeyFile string `yaml:"api_key_file"`
	// Collection to add every uploaded capture to (optional).
	CollectionID string `yaml:"collection_id"`
	// Extra tags added to every capture.
	Tags []string `yaml:"tags"`
}

type Capture struct {
	// Directory the ring buffer writes to (dumpcap -b). Only files not written
	// to for MinAge are processed, so the open file is left alone.
	Dir     string        `yaml:"dir"`
	Pattern string        `yaml:"pattern"` // glob, default "*.pcap*"
	MinAge  time.Duration `yaml:"min_age"`
	// IPs of the honeypot itself. Empty: this host's interface addresses.
	LocalIPs []string `yaml:"local_ips"`
	// KeepOutbound keeps connections the honeypot opened itself (updates,
	// DNS, Cowrie's emulated downloads). Off: one capture = one attacker.
	KeepOutbound bool `yaml:"keep_outbound"`
	// Traffic to leave out of every slice (management SSH port, WireGuard,
	// provider metadata). Ports apply to either end.
	ExcludePorts []int    `yaml:"exclude_ports"`
	ExcludeIPs   []string `yaml:"exclude_ips"`
	// Delete processed ring files older than this (0 = never delete).
	Retention time.Duration `yaml:"retention"`
}

type Logs struct {
	// Cowrie JSON log (cowrie.json, rotated copies with a date suffix are
	// read too).
	Cowrie string `yaml:"cowrie"`
	// OpenCanary JSON log (optional).
	OpenCanary string `yaml:"opencanary"`
}

type Select struct {
	IdleGap        time.Duration `yaml:"idle_gap"`
	MaxPackets     int           `yaml:"max_packets"`
	MaxBytes       int64         `yaml:"max_bytes"`
	MinPackets     int           `yaml:"min_packets"`
	KeepAttempts   int           `yaml:"keep_attempts"` // brute-force connections kept per slice
	MinScore       int           `yaml:"min_score"`
	DailyCap       int           `yaml:"daily_cap"`
	BaselinePerDay int           `yaml:"baseline_per_day"`
	RepeatAfter    time.Duration `yaml:"repeat_after"` // same scenario uploads again after this
	// FamilyCap: uploads allowed per coarse family (class + services + verbs
	// or path set) inside RepeatAfter, so variants of one campaign stop early.
	FamilyCap int `yaml:"family_cap"`
	// NoveltyBonus is added to the score when a request path, command or
	// payload template has never been seen on this collector.
	NoveltyBonus int `yaml:"novelty_bonus"`
	// MaxRatio: if uploads / sessions over the last 7 days exceeds this (and
	// at least MinSessionsForRatio sessions were seen), the pass only accepts
	// scores >= MinScore+20 and logs a warning. 0.05 = 5 percent.
	MaxRatio            float64 `yaml:"max_ratio"`
	MinSessionsForRatio int     `yaml:"min_sessions_for_ratio"`
	// ExploitPatterns are extra regular expressions (RE2 syntax) matched
	// against request lines, payloads, commands and URLs.
	ExploitPatterns []string `yaml:"exploit_patterns"`
}

// Default returns the configuration with every default filled in.
func Default() Config {
	return Config{
		Name: "flypaper",
		PcapHub: PcapHub{
			URL:  "https://pcaphub.com",
			Tags: []string{"honeypot"},
		},
		Capture: Capture{
			Dir:       "/var/lib/flypaper/ring",
			Pattern:   "*.pcap*",
			MinAge:    2 * time.Minute,
			Retention: 7 * 24 * time.Hour,
		},
		Logs: Logs{
			Cowrie:     "/var/log/cowrie/cowrie.json",
			OpenCanary: "/var/log/opencanary/opencanary.log",
		},
		Select: Select{
			IdleGap:             5 * time.Minute,
			MaxPackets:          2000,
			MaxBytes:            2 << 20,
			MinPackets:          6,
			KeepAttempts:        20,
			MinScore:            40,
			DailyCap:            20,
			BaselinePerDay:      1,
			RepeatAfter:         30 * 24 * time.Hour,
			FamilyCap:           3,
			NoveltyBonus:        25,
			MaxRatio:            0.05,
			MinSessionsForRatio: 200,
		},
		StateDir: "/var/lib/flypaper/state",
		Outbox:   "/var/lib/flypaper/outbox",
	}
}

// Load reads the YAML file at path over the defaults and validates it.
func Load(path string) (Config, error) {
	cfg := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&cfg); err != nil && !errors.Is(err, io.EOF) {
		return cfg, fmt.Errorf("%s: %w", path, err)
	}
	if cfg.PcapHub.APIKey == "" && cfg.PcapHub.APIKeyFile != "" {
		kb, err := os.ReadFile(cfg.PcapHub.APIKeyFile)
		switch {
		case err == nil:
			cfg.PcapHub.APIKey = strings.TrimSpace(string(kb))
		case os.IsNotExist(err) && cfg.DryRun:
			// a dry-run install has no key yet; the file appears when it goes live
		default:
			return cfg, fmt.Errorf("api_key_file: %w", err)
		}
	}
	if cfg.PcapHub.APIKey == "" {
		cfg.PcapHub.APIKey = os.Getenv("PCAPHUB_API_KEY")
	}
	return cfg, cfg.Validate()
}

// Validate checks the values that would otherwise fail late.
func (c Config) Validate() error {
	if c.Name == "" {
		return errors.New("name is required")
	}
	if !c.DryRun && c.PcapHub.APIKey == "" {
		return errors.New("pcaphub.api_key (or api_key_file, or PCAPHUB_API_KEY) is required unless dry_run is set")
	}
	if !strings.HasPrefix(c.PcapHub.URL, "https://") && !strings.HasPrefix(c.PcapHub.URL, "http://") {
		return errors.New("pcaphub.url must be an http(s) URL")
	}
	for _, ip := range append(append([]string{}, c.Capture.LocalIPs...), c.Capture.ExcludeIPs...) {
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("invalid IP %q", ip)
		}
	}
	for _, p := range c.Capture.ExcludePorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("invalid port %d", p)
		}
	}
	if c.Select.MaxPackets < 10 || c.Select.MaxBytes < 4096 {
		return errors.New("select.max_packets must be >= 10 and max_bytes >= 4096")
	}
	if c.Select.IdleGap <= 0 {
		return errors.New("select.idle_gap must be positive")
	}
	for _, p := range c.Select.ExploitPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("select.exploit_patterns %q: %w", p, err)
		}
	}
	return nil
}
