package pipeline

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/pcaphub/flypaper/internal/classify"
	"github.com/pcaphub/flypaper/internal/config"
	"github.com/pcaphub/flypaper/internal/honeylog"
	"github.com/pcaphub/flypaper/internal/session"
	"github.com/pcaphub/flypaper/internal/state"
)

func newTestPipeline(t *testing.T) *Pipeline {
	t.Helper()
	cfg := config.Default()
	cfg.Name = "pol"
	cfg.DryRun = true
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	cfg.Outbox = filepath.Join(t.TempDir(), "outbox")
	st, err := state.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	return &Pipeline{Cfg: cfg, State: st, Log: slog.New(slog.NewTextHandler(os.Stderr, nil)), Now: func() time.Time { return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }}
}

// telnetSession fabricates a session plus Cowrie events for the given commands.
func telnetSession(ip string, at time.Time, cmds ...string) (*session.Session, []honeylog.Event) {
	s := &session.Session{Remote: net.ParseIP(ip), LinkType: layers.LinkTypeEthernet, Start: at, End: at.Add(10 * time.Second), LocalPorts: []int{23}}
	for i := 0; i < 20; i++ {
		s.Packets = append(s.Packets, session.Packet{CI: gopacket.CaptureInfo{Timestamp: at.Add(time.Duration(i) * 100 * time.Millisecond), CaptureLength: 60, Length: 60}, Data: make([]byte, 60), Remote: s.Remote, Proto: layers.IPProtocolTCP, RemPort: 50000, LocPort: 23, ToLocal: i%2 == 0})
	}
	s.Flows = []session.Flow{{Proto: layers.IPProtocolTCP, RemPort: 50000, LocPort: 23, Pkts: 20}}
	s.TotalPkts = 20
	evs := []honeylog.Event{
		{Time: at, Kind: "connect", Service: "telnet", SrcIP: s.Remote, SrcPort: 50000, Session: "x"},
		{Time: at.Add(time.Second), Kind: "login_success", Service: "telnet", SrcIP: s.Remote, SrcPort: 50000, Session: "x", Username: "admin", Password: "admin"},
	}
	for i, c := range cmds {
		evs = append(evs, honeylog.Event{Time: at.Add(time.Duration(2+i) * time.Second), Kind: "command", Service: "telnet", SrcIP: s.Remote, SrcPort: 50000, Session: "x", Input: c})
	}
	return s, evs
}

func TestFamilyCapStopsVariantsOfOneCampaign(t *testing.T) {
	p := newTestPipeline(t)
	p.Cfg.Select.FamilyCap = 3
	var decisions []string
	fams := map[string]bool{}
	fps := map[string]bool{}
	for i := 0; i < 6; i++ {
		// same verbs (enable, sh, cat, /bin/busybox), different arguments each time
		s, evs := telnetSession(fmt.Sprintf("198.51.100.%d", 10+i), p.Now().Add(time.Duration(i)*time.Minute),
			"enable", "sh", fmt.Sprintf("cat /proc/mounts; /bin/busybox VAR%d", i), fmt.Sprintf("cat /tmp/.f%dx%d", i, i*7))
		res := classify.Run(s, evs)
		fams[res.Family] = true
		fps[res.Fingerprint] = true
		c := &Candidate{Session: s, Result: res}
		p.decide(c)
		decisions = append(decisions, c.Decision)
		if c.Decision == "upload" {
			p.State.RecordUpload(res.Fingerprint, res.Family, fmt.Sprint("cap", i), p.Now(), false)
		}
	}
	if len(fams) != 1 {
		t.Fatalf("expected one family, got %d", len(fams))
	}
	if len(fps) < 2 {
		t.Fatalf("expected distinct exact fingerprints (busybox token is not masked), got %d", len(fps))
	}
	want := []string{"upload", "upload", "upload", "family-cap", "family-cap", "family-cap"}
	if fmt.Sprint(decisions) != fmt.Sprint(want) {
		t.Errorf("decisions = %v, want %v", decisions, want)
	}
}

func TestRatioGuardRaisesThreshold(t *testing.T) {
	p := newTestPipeline(t)
	p.Cfg.Select.MinSessionsForRatio = 10
	p.Cfg.Select.MaxRatio = 0.05
	p.Cfg.Select.FamilyCap = 0
	// 10 sessions seen, 3 uploaded today = 30%: the guard must engage on the next pass
	for i := 0; i < 10; i++ {
		p.State.Observe(fmt.Sprint("fp", i), classify.ScanOnly, fmt.Sprint("10.0.0.", i), p.Now())
	}
	for i := 0; i < 3; i++ {
		p.State.RecordUpload(fmt.Sprint("fp", i), fmt.Sprint("fam", i), "x", p.Now(), false)
	}
	seen, up := p.State.Ratio(p.Now(), 7)
	if seen != 10 || up != 3 {
		t.Fatalf("ratio counters = %d/%d", seen, up)
	}
	p.guard = float64(up)/float64(seen) > p.Cfg.Select.MaxRatio // what Run computes
	if !p.guard {
		t.Fatal("guard should be on")
	}
	// a commands-executed session scores 80 (+25 novelty) and still uploads
	s, evs := telnetSession("198.51.100.50", p.Now(), "uname -a", "cat /etc/passwd")
	c := &Candidate{Session: s, Result: classify.Run(s, evs)}
	p.decide(c)
	if c.Decision != "upload" {
		t.Errorf("high score under guard: %s (score %d)", c.Decision, c.Result.Score)
	}
	// a plain brute force (score ~33, no novelty) is below min_score+20 and gets no baseline slot under the guard
	s2 := &session.Session{Remote: net.ParseIP("198.51.100.51"), Start: p.Now(), End: p.Now().Add(time.Minute), LocalPorts: []int{22}, TotalPkts: 60}
	for i := 0; i < 60; i++ {
		s2.Packets = append(s2.Packets, session.Packet{Data: make([]byte, 60), Remote: s2.Remote, Proto: layers.IPProtocolTCP, RemPort: 40000 + i/6, LocPort: 22, ToLocal: true})
	}
	var evs2 []honeylog.Event
	for i := 0; i < 10; i++ {
		evs2 = append(evs2, honeylog.Event{Time: p.Now(), Kind: "login_failed", Service: "ssh", SrcIP: s2.Remote, Username: "root", Password: fmt.Sprint("p", i)})
	}
	c2 := &Candidate{Session: s2, Result: classify.Run(s2, evs2)}
	p.decide(c2)
	if c2.Decision != "below-threshold" {
		t.Errorf("brute force under guard: %s (score %d)", c2.Decision, c2.Result.Score)
	}
}

func TestNoveltyBonusOnlyOnce(t *testing.T) {
	p := newTestPipeline(t)
	a, evA := telnetSession("198.51.100.60", p.Now(), "enable", "sh", "cat /proc/mounts")
	ca := &Candidate{Session: a, Result: classify.Run(a, evA)}
	base := ca.Result.Score
	p.decide(ca)
	if len(ca.Novel) == 0 || ca.Result.Score != min(100, base+p.Cfg.Select.NoveltyBonus) {
		t.Errorf("first sighting: novel=%v score=%d base=%d", ca.Novel, ca.Result.Score, base)
	}
	b, evB := telnetSession("198.51.100.61", p.Now().Add(time.Hour), "enable", "sh", "cat /proc/mounts")
	cb := &Candidate{Session: b, Result: classify.Run(b, evB)}
	p.decide(cb)
	if len(cb.Novel) != 0 || cb.Result.Score != base {
		t.Errorf("second sighting: novel=%v score=%d base=%d", cb.Novel, cb.Result.Score, base)
	}
}

func TestNoNoveltyBonusForSprays(t *testing.T) {
	r := classify.Result{Class: classify.LoginBruteforce, Score: 30}
	r.Facts.Payloads = []string{"RFB 003.008"}
	if noveltyApplies(r.Class) || noveltyApplies(classify.ScanOnly) || noveltyApplies(classify.SSHBruteforce) {
		t.Error("novelty bonus must not apply to scans and password sprays")
	}
	if !noveltyApplies(classify.ServiceProbe) || !noveltyApplies(classify.WebExploit) || !noveltyApplies(classify.CommandsRun) {
		t.Error("novelty bonus must apply to probes, exploits and shells")
	}
}
