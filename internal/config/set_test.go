package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The installer's file, comments included.
const installed = `# flypaper collector configuration (written by install.sh; edit freely, the
# installer does not overwrite an existing file)
name: do-sfo2
region: "us-west"

pcaphub:
  url: https://pcaphub.com
  api_key: phk_test_not_a_real_key
  collection_id: ""
  tags: [honeypot, flypaper]

capture:
  dir: /var/lib/flypaper/ring
  exclude_ports: [22222]

select:
  idle_gap: 5m
  min_score: 40
  daily_cap: 20       # uploads per day
  baseline_per_day: 1

dry_run: false
`

func TestSetKeepsCommentsAndValidates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(installed), 0o640)

	changed, err := Set(path, []string{"daily_cap=40", "probe_cap=12", "select.min_score=35", "dry_run=true", "region=us-west-2"})
	if err != nil {
		t.Fatal(err)
	}
	if len(changed) != 5 || changed[0] != "select.daily_cap=40" || changed[1] != "select.probe_cap=12" {
		t.Errorf("changed = %v", changed)
	}
	b, _ := os.ReadFile(path)
	s := string(b)
	for _, want := range []string{"# installer does not overwrite", "daily_cap: 40 # uploads per day", "probe_cap: 12", "min_score: 35", "dry_run: true", "region: us-west-2", "exclude_ports: [22222]"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in:\n%s", want, s)
		}
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Select.DailyCap != 40 || cfg.Select.ProbeCap != 12 || cfg.Select.MinScore != 35 || !cfg.DryRun || cfg.Region != "us-west-2" {
		t.Errorf("loaded: %+v dry=%v region=%s", cfg.Select, cfg.DryRun, cfg.Region)
	}
	// the untouched keys kept their defaults from Default(), not zero
	if cfg.Select.FamilyCap != Default().Select.FamilyCap {
		t.Errorf("family_cap = %d", cfg.Select.FamilyCap)
	}
}

func TestSetRejectsBadInputAndLeavesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(installed), 0o640)
	for _, bad := range []string{"daily_cap", "nonsense=1", "select.daily_cap=lots", "pcaphub.tags=x"} {
		if _, err := Set(path, []string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	b, _ := os.ReadFile(path)
	if string(b) != installed {
		t.Error("file changed after a rejected assignment")
	}
}
