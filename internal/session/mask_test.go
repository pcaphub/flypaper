package session

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

var (
	hpIP  = net.ParseIP("143.198.12.34").To4() // 13 characters of text
	atkIP = net.ParseIP("203.0.113.77").To4()
	hpMAC = net.HardwareAddr{0, 1, 2, 3, 4, 5}
	atMAC = net.HardwareAddr{6, 7, 8, 9, 10, 11}
)

func serialize(t *testing.T, ls ...gopacket.SerializableLayer) []byte {
	t.Helper()
	buf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ls...); err != nil {
		t.Fatal(err)
	}
	return append([]byte(nil), buf.Bytes()...)
}

func tcpFrame(t *testing.T, src, dst net.IP, sport, dport uint16, payload []byte) []byte {
	eth := &layers.Ethernet{SrcMAC: atMAC, DstMAC: hpMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: src, DstIP: dst}
	tcp := &layers.TCP{SrcPort: layers.TCPPort(sport), DstPort: layers.TCPPort(dport), Seq: 1, Ack: 1, PSH: true, ACK: true, Window: 65535}
	tcp.SetNetworkLayerForChecksum(ip)
	return serialize(t, eth, ip, tcp, gopacket.Payload(payload))
}

// full recomputation of the IPv4 header and TCP/UDP checksums of a frame
func checksumsOK(t *testing.T, data []byte) {
	t.Helper()
	pkt := gopacket.NewPacket(data, layers.LinkTypeEthernet, gopacket.Default)
	ip, _ := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if ip == nil {
		t.Fatal("no IPv4 layer")
	}
	hdr := ip.Contents
	if got := onesComplement(sum16(hdr, 0)); got != 0 {
		t.Errorf("IPv4 header checksum wrong (residual %#x)", got)
	}
	l4 := ip.Payload
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], ip.SrcIP.To4())
	copy(pseudo[4:8], ip.DstIP.To4())
	pseudo[9] = byte(ip.Protocol)
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(l4)))
	switch ip.Protocol {
	case layers.IPProtocolTCP, layers.IPProtocolUDP:
		if ip.Protocol == layers.IPProtocolUDP && binary.BigEndian.Uint16(l4[6:8]) == 0 {
			return
		}
		if got := onesComplement(sum16(l4, sum16(pseudo, 0))); got != 0 {
			t.Errorf("%s checksum wrong (residual %#x)", ip.Protocol, got)
		}
	case layers.IPProtocolICMPv4:
		if got := onesComplement(sum16(l4, 0)); got != 0 {
			t.Errorf("ICMP checksum wrong (residual %#x)", got)
		}
	}
}

func sessionOf(t *testing.T, frames ...[]byte) *Session {
	s := &Session{Remote: atkIP, LinkType: layers.LinkTypeEthernet}
	for i, f := range frames {
		pkt := gopacket.NewPacket(f, layers.LinkTypeEthernet, gopacket.Default)
		var payload []byte
		if tl := pkt.TransportLayer(); tl != nil {
			payload = tl.LayerPayload()
		}
		s.Packets = append(s.Packets, Packet{
			CI:      gopacket.CaptureInfo{Timestamp: time.Unix(1_700_000_000+int64(i), 0), CaptureLength: len(f), Length: len(f)},
			Data:    f,
			Payload: payload,
			Remote:  atkIP, Local: hpIP,
		})
	}
	return s
}

func TestMaskLocalRewritesHeadersAndPayloadText(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: 143.198.12.34\r\nUser-Agent: x\r\n\r\n")
	in := tcpFrame(t, atkIP, hpIP, 40000, 80, req)
	out := tcpFrame(t, hpIP, atkIP, 80, 40000, []byte("HTTP/1.1 200 OK\r\nServer: 143.198.12.34:80\r\n\r\n"))
	s := sessionOf(t, in, out)

	res := s.MaskLocal()
	if res.Headers != 2 || res.Payloads != 2 || res.Unmasked != 0 {
		t.Fatalf("result = %+v", res)
	}
	repl := res.Mapping[hpIP.String()]
	if repl == "" || len(repl) != len(hpIP.String()) || net.ParseIP(repl) == nil {
		t.Fatalf("replacement %q should be a same-length documentation address", repl)
	}
	for i, pk := range s.Packets {
		pkt := gopacket.NewPacket(pk.Data, layers.LinkTypeEthernet, gopacket.Default)
		ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		if ip.SrcIP.Equal(hpIP) || ip.DstIP.Equal(hpIP) {
			t.Errorf("packet %d still carries the honeypot address", i)
		}
		if !(ip.SrcIP.Equal(atkIP) || ip.DstIP.Equal(atkIP)) {
			t.Errorf("packet %d lost the attacker address", i)
		}
		if !pk.Local.Equal(net.ParseIP(repl)) {
			t.Errorf("packet %d Local = %s", i, pk.Local)
		}
		checksumsOK(t, pk.Data)
		body := string(pkt.TransportLayer().LayerPayload())
		if len(body) != len(pk.Payload) || string(pk.Payload) != body {
			t.Errorf("packet %d Payload slice out of sync", i)
		}
		if contains(body, hpIP.String()) || !contains(body, repl) {
			t.Errorf("packet %d payload text not swapped: %q", i, body)
		}
	}
	if string(s.Packets[0].Payload[:16]) != "GET / HTTP/1.1\r\n" {
		t.Errorf("request line damaged: %q", s.Packets[0].Payload[:16])
	}
}

// A 15-character honeypot address has no documentation address of the same
// length; the payload text is swapped for a zero-padded spelling instead so
// nothing of the real address survives in a Host header.
func TestMaskLocalPadsLongAddressText(t *testing.T) {
	long := net.ParseIP("157.245.170.238").To4()
	req := []byte("GET /wp-login.php HTTP/1.1\r\nHost: 157.245.170.238:8080\r\n\r\n")
	in := tcpFrame(t, atkIP, long, 40000, 8080, req)
	s := sessionOf(t, in)
	s.Packets[0].Local = long

	res := s.MaskLocal()
	if res.Headers != 1 || res.Payloads != 1 || res.Unmasked != 0 {
		t.Fatalf("result = %+v", res)
	}
	repl := res.Mapping[long.String()]
	if net.ParseIP(repl) == nil || !strings.HasPrefix(repl, "192.0.2.") {
		t.Fatalf("replacement %q should be the 192.0.2.x fallback", repl)
	}
	pk := s.Packets[0]
	checksumsOK(t, pk.Data)
	pkt := gopacket.NewPacket(pk.Data, layers.LinkTypeEthernet, gopacket.Default)
	ip := pkt.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
	if !ip.DstIP.Equal(net.ParseIP(repl)) || !ip.SrcIP.Equal(atkIP) {
		t.Errorf("header addresses %s -> %s", ip.SrcIP, ip.DstIP)
	}
	body := string(pkt.TransportLayer().LayerPayload())
	if len(body) != len(req) || contains(body, "157.245") || contains(body, "170.238") {
		t.Errorf("payload text not swapped: %q", body)
	}
	want := "Host: " + string(padV4Text(net.ParseIP(repl), 15)) + ":8080"
	if !contains(body, want) {
		t.Errorf("payload %q lacks %q", body, want)
	}
	if string(pk.Payload) != body {
		t.Errorf("Payload slice out of sync")
	}
}

func TestPadV4Text(t *testing.T) {
	ip := net.ParseIP("203.0.113.1")
	cases := map[int]string{
		11: "203.0.113.1", 12: "203.0.113.01", 13: "203.0.113.001",
		14: "203.00.113.001", 15: "203.000.113.001",
	}
	for n, want := range cases {
		if got := string(padV4Text(ip, n)); got != want {
			t.Errorf("pad to %d = %q, want %q", n, got, want)
		}
	}
	if padV4Text(ip, 10) != nil || padV4Text(ip, 16) != nil {
		t.Error("impossible lengths should give nil")
	}
	if padV4Text(net.ParseIP("192.0.2.1"), 8) != nil {
		t.Error("8 characters cannot hold a documentation address")
	}
}

func TestMaskLocalLeavesPartialMatchesAndOtherHosts(t *testing.T) {
	// 143.198.12.345 is a different (nonsense) address; 1.143.198.12.34 too
	body := []byte("a=143.198.12.345&b=1.143.198.12.34&c=10.0.0.1")
	s := sessionOf(t, tcpFrame(t, atkIP, hpIP, 40000, 80, body))
	res := s.MaskLocal()
	if res.Payloads != 0 || res.Unmasked != 0 {
		t.Fatalf("partial matches were touched: %+v", res)
	}
	if string(s.Packets[0].Payload) != string(body) {
		t.Errorf("payload changed: %q", s.Packets[0].Payload)
	}
	checksumsOK(t, s.Packets[0].Data)
}

func TestMaskLocalUDPZeroChecksumAndICMPQuote(t *testing.T) {
	eth := &layers.Ethernet{SrcMAC: atMAC, DstMAC: hpMAC, EthernetType: layers.EthernetTypeIPv4}
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: atkIP, DstIP: hpIP}
	udp := &layers.UDP{SrcPort: 5000, DstPort: 161}
	udp.SetNetworkLayerForChecksum(ip)
	udpFrame := serialize(t, eth, ip, udp, gopacket.Payload([]byte("snmp 143.198.12.34")))
	// zero the UDP checksum (allowed for IPv4)
	udpFrame[14+20+6], udpFrame[14+20+7] = 0, 0

	// ICMP port unreachable from the honeypot quoting the attacker's datagram
	quoted := append([]byte(nil), udpFrame[14:14+28]...)
	eth2 := &layers.Ethernet{SrcMAC: hpMAC, DstMAC: atMAC, EthernetType: layers.EthernetTypeIPv4}
	ip2 := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolICMPv4, SrcIP: hpIP, DstIP: atkIP}
	icmp := &layers.ICMPv4{TypeCode: layers.CreateICMPv4TypeCode(3, 3)}
	icmpFrame := serialize(t, eth2, ip2, icmp, gopacket.Payload(quoted))

	s := sessionOf(t, udpFrame, icmpFrame)
	res := s.MaskLocal()
	if res.Headers != 3 || res.Payloads != 1 { // udp header, icmp outer, icmp quoted; one text
		t.Fatalf("result = %+v", res)
	}
	for i, pk := range s.Packets {
		checksumsOK(t, pk.Data)
		if idx := indexOf(pk.Data, hpIP); idx >= 0 {
			t.Errorf("packet %d still holds the honeypot address bytes at %d", i, idx)
		}
	}
	if binary.BigEndian.Uint16(s.Packets[0].Data[14+20+6:]) != 0 {
		t.Error("zero UDP checksum must stay zero")
	}
}

func TestMaskLocalARPAndIPv6(t *testing.T) {
	arp := serialize(t,
		&layers.Ethernet{SrcMAC: hpMAC, DstMAC: atMAC, EthernetType: layers.EthernetTypeARP},
		&layers.ARP{AddrType: layers.LinkTypeEthernet, Protocol: layers.EthernetTypeIPv4, HwAddressSize: 6, ProtAddressSize: 4, Operation: 2,
			SourceHwAddress: hpMAC, SourceProtAddress: hpIP, DstHwAddress: atMAC, DstProtAddress: atkIP})
	hp6 := net.ParseIP("2604:a880:2:d0::1234:1")
	at6 := net.ParseIP("2001:4860::8888")
	ip6 := &layers.IPv6{Version: 6, NextHeader: layers.IPProtocolTCP, HopLimit: 64, SrcIP: at6, DstIP: hp6}
	tcp := &layers.TCP{SrcPort: 1234, DstPort: 22, SYN: true, Window: 1000}
	tcp.SetNetworkLayerForChecksum(ip6)
	v6 := serialize(t, &layers.Ethernet{SrcMAC: atMAC, DstMAC: hpMAC, EthernetType: layers.EthernetTypeIPv6}, ip6, tcp)

	s := sessionOf(t, arp, v6)
	s.Packets[1].Local = hp6
	res := s.MaskLocal()
	if res.Headers != 2 {
		t.Fatalf("result = %+v", res)
	}
	a := gopacket.NewPacket(s.Packets[0].Data, layers.LinkTypeEthernet, gopacket.Default).Layer(layers.LayerTypeARP).(*layers.ARP)
	if net.IP(a.SourceProtAddress).Equal(hpIP) || !net.IP(a.DstProtAddress).Equal(atkIP) {
		t.Errorf("ARP: sender %v target %v", net.IP(a.SourceProtAddress), net.IP(a.DstProtAddress))
	}
	p6 := gopacket.NewPacket(s.Packets[1].Data, layers.LinkTypeEthernet, gopacket.Default)
	l6 := p6.Layer(layers.LayerTypeIPv6).(*layers.IPv6)
	if !l6.DstIP.Equal(net.ParseIP("2001:db8::2")) || !l6.SrcIP.Equal(at6) {
		t.Errorf("IPv6 addresses: %s -> %s", l6.SrcIP, l6.DstIP)
	}
	// TCP over IPv6 checksum: recompute with the pseudo header
	t6 := p6.Layer(layers.LayerTypeTCP).(*layers.TCP)
	pseudo := make([]byte, 40)
	copy(pseudo[0:16], l6.SrcIP)
	copy(pseudo[16:32], l6.DstIP)
	binary.BigEndian.PutUint32(pseudo[32:36], uint32(len(t6.Contents)+len(t6.Payload)))
	pseudo[39] = byte(layers.IPProtocolTCP)
	if got := onesComplement(sum16(append(append([]byte(nil), t6.Contents...), t6.Payload...), sum16(pseudo, 0))); got != 0 {
		t.Errorf("TCP/IPv6 checksum wrong (residual %#x)", got)
	}
}

func contains(s, sub string) bool { return indexOfStr(s, sub) >= 0 }

func indexOfStr(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func indexOf(b []byte, ip net.IP) int {
	v4 := ip.To4()
	for i := 0; i+4 <= len(b); i++ {
		if b[i] == v4[0] && b[i+1] == v4[1] && b[i+2] == v4[2] && b[i+3] == v4[3] {
			return i
		}
	}
	return -1
}
