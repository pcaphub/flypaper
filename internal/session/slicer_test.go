package session

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

type rs struct{ *bytes.Reader }

func writePcap(t *testing.T, flows func(w *pcapgo.Writer)) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	w := pcapgo.NewWriter(&buf)
	if err := w.WriteFileHeader(262144, layers.LinkTypeEthernet); err != nil {
		t.Fatal(err)
	}
	flows(w)
	return bytes.NewReader(buf.Bytes())
}

func tcpFlow(t *testing.T, w *pcapgo.Writer, at time.Time, src net.IP, sport int, dst net.IP, dport int, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		eth := &layers.Ethernet{SrcMAC: net.HardwareAddr{0, 1, 2, 3, 4, 5}, DstMAC: net.HardwareAddr{6, 7, 8, 9, 10, 11}, EthernetType: layers.EthernetTypeIPv4}
		ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
		tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), SYN: i == 0, ACK: i > 0, Window: 1000}
		if i%2 == 1 {
			ip.SrcIP, ip.DstIP = dst, src
			tcp.SrcPort, tcp.DstPort = layers.TCPPort(dport), layers.TCPPort(sport)
		}
		_ = tcp.SetNetworkLayerForChecksum(ip)
		b := gopacket.NewSerializeBuffer()
		if err := gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, eth, ip, tcp, gopacket.Payload([]byte(fmt.Sprintf("data%d", i)))); err != nil {
			t.Fatal(err)
		}
		if err := w.WritePacket(gopacket.CaptureInfo{Timestamp: at.Add(time.Duration(i) * 10 * time.Millisecond), CaptureLength: len(b.Bytes()), Length: len(b.Bytes())}, b.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOutboundFlowsDroppedAndLocalDetected(t *testing.T) {
	hp := net.ParseIP("203.0.113.10")
	att := net.ParseIP("198.51.100.7")
	archive := net.ParseIP("91.189.91.83")
	dns := net.ParseIP("1.1.1.1")
	t0 := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	r := writePcap(t, func(w *pcapgo.Writer) {
		tcpFlow(t, w, t0, att, 40000, hp, 22, 8)              // attacker -> honeypot
		tcpFlow(t, w, t0.Add(time.Second), hp, 50000, archive, 80, 8) // honeypot -> apt mirror
		tcpFlow(t, w, t0.Add(2*time.Second), hp, 50001, dns, 53, 4)    // honeypot -> dns (tcp for simplicity)
	})
	opt := Options{ExcludePorts: map[int]bool{}, IdleGap: 5 * time.Minute, MaxPackets: 2000, MaxBytes: 1 << 20, MinPackets: 1}
	sessions, err := SliceReader(r, opt)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		var got []string
		for _, s := range sessions {
			got = append(got, s.Remote.String())
		}
		t.Fatalf("sessions = %v, want only the attacker", got)
	}
	if !sessions[0].Remote.Equal(att) || len(sessions[0].Packets) != 8 {
		t.Errorf("session remote=%s packets=%d", sessions[0].Remote, len(sessions[0].Packets))
	}

	// with KeepOutbound the mirror and dns peers appear too
	r.Seek(0, 0)
	opt.KeepOutbound = true
	sessions, _ = SliceReader(r, opt)
	if len(sessions) != 3 {
		t.Errorf("KeepOutbound sessions = %d, want 3", len(sessions))
	}
}

func TestConfiguredLocalWinsOverHeuristic(t *testing.T) {
	hp := net.ParseIP("203.0.113.10")
	att := net.ParseIP("198.51.100.7")
	t0 := time.Date(2026, 11, 17, 9, 0, 0, 0, time.UTC)
	// one attacker only: the peer-count heuristic cannot tell the two apart
	r := writePcap(t, func(w *pcapgo.Writer) { tcpFlow(t, w, t0, att, 40000, hp, 22, 6) })
	opt := Options{LocalIPs: []net.IP{hp}, ExcludePorts: map[int]bool{}, IdleGap: time.Minute, MaxPackets: 100, MaxBytes: 1 << 20, MinPackets: 1}
	sessions, err := SliceReader(r, opt)
	if err != nil || len(sessions) != 1 || !sessions[0].Remote.Equal(att) {
		t.Fatalf("err=%v sessions=%+v", err, sessions)
	}
	if sessions[0].LocalPorts[0] != 22 {
		t.Errorf("local ports = %v", sessions[0].LocalPorts)
	}
}
