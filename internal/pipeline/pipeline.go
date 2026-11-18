// Package pipeline runs one pass: find closed ring files, slice them into
// attacker sessions, join with the honeypot logs, classify, decide what is
// worth uploading, upload (or write to the outbox in dry-run), enrich the
// description with PcapHub's Suricata results, and refresh prevalence counts
// on representative captures.
package pipeline

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/pcaphub/flypaper/internal/classify"
	"github.com/pcaphub/flypaper/internal/config"
	"github.com/pcaphub/flypaper/internal/describe"
	"github.com/pcaphub/flypaper/internal/honeylog"
	"github.com/pcaphub/flypaper/internal/pcaphub"
	"github.com/pcaphub/flypaper/internal/session"
	"github.com/pcaphub/flypaper/internal/state"
)

// Pipeline holds the pieces for one collector.
type Pipeline struct {
	Cfg    config.Config
	State  *state.Store
	Client *pcaphub.Client // nil in dry-run
	Log    *slog.Logger
	Now    func() time.Time

	patterns []*regexp.Regexp
	guard    bool // ratio guard active this pass
}

func (p *Pipeline) classifyOptions() classify.Options {
	if p.patterns == nil {
		for _, pat := range p.Cfg.Select.ExploitPatterns {
			if re, err := regexp.Compile(pat); err == nil {
				p.patterns = append(p.patterns, re)
			}
		}
	}
	return classify.Options{ExploitPatterns: p.patterns}
}

// Candidate is a slice with its classification and the decision taken.
type Candidate struct {
	File        string
	Session     *session.Session
	Result      classify.Result
	Meta        describe.Meta
	Decision    string // upload, baseline, repeat, family-cap, below-threshold, daily-cap, too-small
	Novel       []string
	Baseline    bool
	CaptureID   string
	ExistingURL string
}

// Summary is what one pass did.
type Summary struct {
	Files      int
	Sessions   int
	Uploaded   int
	Baseline   int
	Skipped    map[string]int
	Candidates []Candidate
}

// Run executes one pass.
func (p *Pipeline) Run(ctx context.Context) (*Summary, error) {
	if p.Now == nil {
		p.Now = time.Now
	}
	sum := &Summary{Skipped: map[string]int{}}

	files, err := p.closedRingFiles()
	if err != nil {
		return sum, err
	}
	if len(files) == 0 {
		return sum, nil
	}

	events, err := honeylog.ReadCowrieFiles(p.Cfg.Logs.Cowrie)
	if err != nil {
		p.Log.Warn("reading cowrie log", "error", err)
	}
	if p.Cfg.Logs.OpenCanary != "" {
		more, err := honeylog.ReadOpenCanaryFiles(p.Cfg.Logs.OpenCanary)
		if err != nil {
			p.Log.Warn("reading opencanary log", "error", err)
		}
		events = append(events, more...)
		sort.SliceStable(events, func(i, j int) bool { return events[i].Time.Before(events[j].Time) })
	}
	index := honeylog.NewIndex(events)

	// Dedupe guard: if this collector uploaded more than max_ratio of the
	// sessions it saw over the last 7 days, demand a higher score this pass.
	p.guard = false
	if seen, up := p.State.Ratio(p.Now(), 7); seen >= p.Cfg.Select.MinSessionsForRatio && p.Cfg.Select.MaxRatio > 0 &&
		float64(up)/float64(seen) > p.Cfg.Select.MaxRatio {
		p.guard = true
		p.Log.Warn("upload ratio above limit, raising threshold for this pass", "sessions_7d", seen, "uploads_7d", up, "max_ratio", p.Cfg.Select.MaxRatio)
	}

	opt := p.sliceOptions()
	copt := p.classifyOptions()
	for _, f := range files {
		if ctx.Err() != nil {
			return sum, ctx.Err()
		}
		sessions, err := session.Slice(f, opt)
		if err != nil {
			p.Log.Error("slicing", "file", filepath.Base(f), "error", err)
			// a corrupt file is marked processed so it is not retried forever
			p.State.MarkProcessed(filepath.Base(f))
			continue
		}
		sum.Files++
		for _, s := range sessions {
			sum.Sessions++
			evs := index.Between(s.Remote, s.Start, s.End, 45*time.Second)
			res := classify.RunWith(s, evs, copt)
			p.trimBruteforce(s, evs, res)
			if len(s.Packets) < p.Cfg.Select.MinPackets {
				sum.Skipped["too-small"]++
				continue
			}
			c := Candidate{File: filepath.Base(f), Session: s, Result: res}
			p.decide(&c)
			if c.Decision == "upload" || c.Decision == "baseline" {
				if err := p.publish(ctx, &c); err != nil {
					p.Log.Error("upload", "file", c.File, "remote", s.Remote, "error", err)
					c.Decision = "failed"
				} else if c.Baseline {
					sum.Baseline++
				} else {
					sum.Uploaded++
				}
			}
			if c.Decision != "upload" && c.Decision != "baseline" {
				sum.Skipped[c.Decision]++
			}
			sum.Candidates = append(sum.Candidates, c)
		}
		p.State.MarkProcessed(filepath.Base(f))
		if err := p.State.Save(); err != nil {
			return sum, err
		}
	}

	if p.Client != nil {
		p.refreshPrevalence(ctx)
	}
	p.expireRing()
	return sum, p.State.Save()
}

// closedRingFiles lists ring files old enough to be closed and not yet processed.
func (p *Pipeline) closedRingFiles() ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(p.Cfg.Capture.Dir, p.Cfg.Capture.Pattern))
	if err != nil {
		return nil, err
	}
	var out []string
	cut := p.Now().Add(-p.Cfg.Capture.MinAge)
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil || st.IsDir() || st.Size() < 24 {
			continue
		}
		if st.ModTime().After(cut) {
			continue
		}
		if p.State.IsProcessed(filepath.Base(m)) {
			continue
		}
		out = append(out, m)
	}
	sort.Strings(out)
	return out, nil
}

func (p *Pipeline) sliceOptions() session.Options {
	opt := session.Options{
		ExcludePorts:      map[int]bool{},
		UseInterfaceAddrs: len(p.Cfg.Capture.LocalIPs) == 0,
		KeepOutbound:      p.Cfg.Capture.KeepOutbound,
		IdleGap:           p.Cfg.Select.IdleGap,
		MaxPackets:        p.Cfg.Select.MaxPackets,
		MaxBytes:          p.Cfg.Select.MaxBytes,
		MinPackets:        1, // the pipeline applies MinPackets after trimming
	}
	for _, ip := range p.Cfg.Capture.LocalIPs {
		opt.LocalIPs = append(opt.LocalIPs, net.ParseIP(ip))
	}
	for _, ip := range p.Cfg.Capture.ExcludeIPs {
		opt.ExcludeIPs = append(opt.ExcludeIPs, net.ParseIP(ip))
	}
	for _, port := range p.Cfg.Capture.ExcludePorts {
		opt.ExcludePorts[port] = true
	}
	return opt
}

// trimBruteforce keeps the first KeepAttempts connections of a brute force
// plus every connection that logged in or ran commands (Cowrie gives the
// attacker's source port per session), so the technique and the outcome stay
// while hundreds of identical failures go.
func (p *Pipeline) trimBruteforce(s *session.Session, evs []honeylog.Event, res classify.Result) {
	keepN := p.Cfg.Select.KeepAttempts
	if keepN <= 0 || len(s.Flows) <= keepN {
		return
	}
	switch res.Class {
	case classify.SSHBruteforce, classify.LoginBruteforce, classify.TelnetIoT, classify.SSHLoginSuccess, classify.CommandsRun, classify.MalwareDownload, classify.PortForward:
	default:
		return
	}
	interesting := map[string]bool{} // cowrie session ids worth keeping
	for _, e := range evs {
		switch e.Kind {
		case "login_success", "command", "download", "upload", "forward":
			interesting[e.Session] = true
		}
	}
	keepPorts := map[int]bool{}
	for _, e := range evs {
		if e.Kind == "connect" && interesting[e.Session] && e.SrcPort > 0 {
			keepPorts[e.SrcPort] = true
		}
	}
	s.Trim(keepN, keepPorts)
}

// decide applies the selection policy and sets c.Decision.
//
// Order: count the sighting; novelty bonus for templates never seen here;
// daily cap; exact scenario (one upload per repeat_after); coarse family
// (family_cap uploads per repeat_after); score threshold (raised by 20 while
// the ratio guard is on); one baseline sample a day for the rest.
func (p *Pipeline) decide(c *Candidate) {
	now := p.Now()
	s := c.Session
	sc := p.State.Observe(c.Result.Fingerprint, c.Result.Class, s.Remote.String(), s.Start)
	c.Novel = p.State.NoteTemplates(c.Result.Templates(), s.Start)
	// The bonus rewards a request, command or payload nobody has sent this
	// collector before. A scan or a password spray has none of those worth
	// rewarding: its "payload" is the protocol handshake (RFB 003.008, a TDS
	// prelogin), new to a fresh collector once and never interesting.
	if len(c.Novel) > 0 && noveltyApplies(c.Result.Class) {
		c.Result.Novel = c.Novel
		if p.Cfg.Select.NoveltyBonus > 0 {
			c.Result.Score = min(100, c.Result.Score+p.Cfg.Select.NoveltyBonus)
		}
	}

	stats := p.State.Snapshot(now)
	in := describe.Input{
		Session: s, Result: c.Result, Collector: p.Cfg.Name, Region: p.Cfg.Region,
		ExtraTags:  p.Cfg.PcapHub.Tags,
		SeenBefore: sc.Seen - 1, SeenIPs: sc.IPCount, FirstSeen: sc.FirstSeen,
		SessionsSeen: stats.SeenAll, Uploaded: stats.UploadedAll,
	}
	c.Meta = describe.Build(in)

	if p.State.UploadsToday(now) >= p.Cfg.Select.DailyCap {
		c.Decision = "daily-cap"
		return
	}
	firstTime := sc.LastUpload.IsZero()
	stale := !firstTime && now.Sub(sc.LastUpload) >= p.Cfg.Select.RepeatAfter
	if !firstTime && !stale {
		c.Decision = "repeat"
		return
	}
	if p.Cfg.Select.FamilyCap > 0 && p.State.FamilyUploads(c.Result.Family, now, p.Cfg.Select.RepeatAfter) >= p.Cfg.Select.FamilyCap {
		c.Decision = "family-cap"
		return
	}
	threshold := p.Cfg.Select.MinScore
	if p.guard {
		threshold += 20
	}
	if c.Result.Score >= threshold {
		c.Decision = "upload"
		return
	}
	// Below threshold: one baseline sample a day keeps the boring majority
	// represented, but never the same scenario twice and never under the guard.
	if !p.guard && p.State.BaselineToday(now) < p.Cfg.Select.BaselinePerDay {
		c.Decision, c.Baseline = "baseline", true
		return
	}
	c.Decision = "below-threshold"
}

func noveltyApplies(class string) bool {
	switch class {
	case classify.ScanOnly, classify.SSHBruteforce, classify.LoginBruteforce:
		return false
	}
	return true
}

// publish writes the slice and either uploads it or drops it in the outbox.
func (p *Pipeline) publish(ctx context.Context, c *Candidate) error {
	dir := p.Cfg.Outbox
	if p.Client != nil {
		dir = filepath.Join(p.Cfg.StateDir, "spool")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	base := fmt.Sprintf("%s_%s_%s_%s", p.Cfg.Name, c.Session.Start.UTC().Format("20060102T150405Z"),
		strings.ReplaceAll(c.Session.Remote.String(), ":", "-"), c.Result.Fingerprint)
	pcapPath := filepath.Join(dir, base+".pcap")
	size, err := c.Session.Write(pcapPath)
	if err != nil {
		return err
	}

	if p.Client == nil { // dry run: pcap + metadata next to it
		meta := map[string]any{
			"title": c.Meta.Title, "tags": c.Meta.Tags, "description": c.Meta.Description,
			"class": c.Result.Class, "score": c.Result.Score, "fingerprint": c.Result.Fingerprint, "family": c.Result.Family, "novel": c.Novel,
			"decision": c.Decision, "packets": len(c.Session.Packets), "bytes": size,
			"remote": c.Session.Remote.String(), "start": c.Session.Start.UTC(), "end": c.Session.End.UTC(),
			"facts": c.Result.Facts,
		}
		b, _ := json.MarshalIndent(meta, "", " ")
		if err := os.WriteFile(filepath.Join(dir, base+".json"), b, 0o640); err != nil {
			return err
		}
		p.State.RecordUpload(c.Result.Fingerprint, c.Result.Family, "dry-run:"+base, p.Now(), c.Baseline)
		p.Log.Info("would upload", "class", c.Result.Class, "score", c.Result.Score, "remote", c.Session.Remote, "packets", len(c.Session.Packets), "bytes", size, "file", base+".pcap")
		return nil
	}

	defer os.Remove(pcapPath)
	cap, err := p.Client.Upload(ctx, pcaphub.UploadRequest{
		Path: pcapPath, Title: c.Meta.Title, Description: c.Meta.Description, Tags: c.Meta.Tags,
	})
	if errors.Is(err, pcaphub.ErrDuplicate) {
		// identical bytes already uploaded (ring overlap, restart): done
		c.Decision = "duplicate"
		p.State.RecordUpload(c.Result.Fingerprint, c.Result.Family, "", p.Now(), c.Baseline)
		return nil
	}
	if err != nil {
		return err
	}
	c.CaptureID = cap.ID
	p.State.RecordUpload(c.Result.Fingerprint, c.Result.Family, cap.ID, p.Now(), c.Baseline)
	p.Log.Info("uploaded", "id", cap.ID, "class", c.Result.Class, "score", c.Result.Score, "remote", c.Session.Remote, "packets", len(c.Session.Packets), "bytes", size)
	if err := p.State.Save(); err != nil {
		return err
	}

	if p.Cfg.PcapHub.CollectionID != "" {
		if err := p.Client.AddToCollection(ctx, p.Cfg.PcapHub.CollectionID, cap.ID); err != nil {
			p.Log.Warn("add to collection", "id", cap.ID, "error", err)
		}
	}

	// Enrich with Suricata results once processing finishes (a few seconds to
	// a minute); give up quietly after 10 minutes and leave the description.
	wctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	ready, err := p.Client.WaitReady(wctx, cap.ID, 5*time.Second)
	if err != nil || ready.Status != "ready" {
		return nil
	}
	alerts, err := p.Client.Alerts(ctx, cap.ID)
	if err != nil {
		return nil
	}
	var sids []string
	for _, a := range alerts {
		sids = append(sids, fmt.Sprint(a.SignatureID))
	}
	fresh := p.State.NewSignatures(c.Result.Fingerprint, sids)
	desc := c.Meta.Description + alertSection(alerts, fresh)
	if err := p.Client.Patch(ctx, cap.ID, &desc, nil); err != nil {
		p.Log.Warn("patch description", "id", cap.ID, "error", err)
	}
	return nil
}

func alertSection(alerts []pcaphub.Alert, fresh []string) string {
	if len(alerts) == 0 {
		return "\n## Suricata\n\nNo signatures fired on this capture (ET Open ruleset at upload time).\n"
	}
	freshSet := map[string]bool{}
	for _, s := range fresh {
		freshSet[s] = true
	}
	var b strings.Builder
	fmt.Fprintf(&b, "\n## Suricata\n\n%d signature(s) fired (ET Open ruleset at upload time):\n\n", len(alerts))
	sort.Slice(alerts, func(i, j int) bool {
		if alerts[i].Severity != alerts[j].Severity {
			return alerts[i].Severity < alerts[j].Severity
		}
		return alerts[i].Count > alerts[j].Count
	})
	for i, a := range alerts {
		if i >= 25 {
			fmt.Fprintf(&b, "- and %d more\n", len(alerts)-i)
			break
		}
		mark := ""
		if freshSet[fmt.Sprint(a.SignatureID)] {
			mark = " (first time from this collector)"
		}
		fmt.Fprintf(&b, "- %d x SID %d: %s [%s, severity %d]%s\n", a.Count, a.SignatureID, strings.ReplaceAll(a.Signature, "<", "&lt;"), a.Category, a.Severity, mark)
	}
	return b.String()
}

// refreshPrevalence updates the "seen N times" line on representative
// captures whose counts moved, at most once per pass per scenario.
func (p *Pipeline) refreshPrevalence(ctx context.Context) {
	reps := p.State.Representatives()
	n := 0
	for fp, sc := range reps {
		if n >= 20 { // keep PATCH traffic small per pass
			break
		}
		if sc.Seen-sc.LastReported < 5 && p.Now().Sub(sc.LastUpload) < 24*time.Hour {
			continue // not worth a request yet
		}
		cap, err := p.Client.Get(ctx, sc.CaptureID)
		if err != nil {
			continue
		}
		desc := replacePrevalence(cap.Description, describe.Prevalence(sc.Seen, sc.IPCount, sc.FirstSeen))
		if desc == cap.Description {
			p.State.MarkReported(fp)
			continue
		}
		if err := p.Client.Patch(ctx, sc.CaptureID, &desc, nil); err == nil {
			p.State.MarkReported(fp)
			n++
		}
	}
}

// replacePrevalence swaps the prevalence sentence, or the "first sighting"
// sentence, for the new one.
func replacePrevalence(desc, line string) string {
	const first = "First sighting of this scenario on this collector."
	if i := strings.Index(desc, first); i >= 0 {
		return desc[:i] + line + desc[i+len(first):]
	}
	if i := strings.Index(desc, "This scenario has been seen "); i >= 0 {
		j := strings.Index(desc[i:], "representative copy.")
		if j >= 0 {
			return desc[:i] + line + desc[i+j+len("representative copy."):]
		}
	}
	return desc
}

// expireRing deletes processed ring files past the retention window.
func (p *Pipeline) expireRing() {
	if p.Cfg.Capture.Retention <= 0 {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(p.Cfg.Capture.Dir, p.Cfg.Capture.Pattern))
	cut := p.Now().Add(-p.Cfg.Capture.Retention)
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil || !st.ModTime().Before(cut) {
			continue
		}
		if p.State.IsProcessed(filepath.Base(m)) {
			_ = os.Remove(m)
		}
	}
}
