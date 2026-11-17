// Package session cuts a ring-buffer pcap into one small capture per attacker
// session: all packets exchanged with one remote address, split where the
// remote goes quiet for longer than the idle gap. Pure Go (gopacket/pcapgo),
// so the honeypot host needs no libpcap or Wireshark.
package session

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"
)

// Options control slicing.
type Options struct {
	LocalIPs []net.IP // the honeypot's own addresses; empty = auto-detect
	// UseInterfaceAddrs adds this host's own interface addresses to LocalIPs
	// (the collector runs on the honeypot, so that is the right default).
	UseInterfaceAddrs bool
	// KeepOutbound keeps flows the honeypot itself opened (apt, DNS, Cowrie's
	// emulated wget). Off by default: a capture is one attacker's session.
	KeepOutbound bool
	ExcludePorts map[int]bool  // management ports, dropped at either end
	ExcludeIPs   []net.IP      // management peers, dropped
	IdleGap      time.Duration // new session after this much silence from one remote
	MaxPackets   int           // per slice
	MaxBytes     int64         // per slice (captured bytes)
	MinPackets   int           // slices smaller than this are dropped
	// KeepFlows, when > 0, trims a slice with many short TCP connections (a
	// brute force) to its first KeepFlows connections plus every flow listed in
	// KeepPorts (the remote source ports of connections worth keeping, e.g. the
	// one that logged in). 0 keeps everything up to the caps.
	KeepFlows int
}

// Packet is one captured frame with the fields the slicer needs.
type Packet struct {
	CI      gopacket.CaptureInfo
	Data    []byte
	Payload []byte // transport payload (TCP/UDP), nil when none
	Remote  net.IP
	Local   net.IP
	Proto   layers.IPProtocol
	RemPort int
	LocPort int
	ToLocal bool // remote -> honeypot
}

// Session is one attacker's activity window.
type Session struct {
	Remote     net.IP
	Start, End time.Time
	Packets    []Packet
	LinkType   layers.LinkType
	// Local ports the remote touched, in first-seen order, and TCP flows
	// (remote source ports) in first-seen order.
	LocalPorts []int
	Flows      []Flow
	Truncated  bool // caps applied
	TotalPkts  int  // before caps
}

// Flow is one TCP/UDP connection from the remote's point of view.
type Flow struct {
	Proto   layers.IPProtocol
	RemPort int
	LocPort int
	First   time.Time
	Pkts    int
}

// Key identifies a flow within a session.
func (f Flow) Key() string { return fmt.Sprintf("%d/%d>%d", f.Proto, f.RemPort, f.LocPort) }

// Slice reads the pcap or pcapng at path and returns its sessions in start order.
func Slice(path string, opt Options) ([]*Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return SliceReader(f, opt)
}

// SliceReader is Slice over an open file.
func SliceReader(r io.ReadSeeker, opt Options) ([]*Session, error) {
	var magic [4]byte
	if _, err := io.ReadFull(r, magic[:]); err != nil {
		return nil, fmt.Errorf("reading magic: %w", err)
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	var (
		src      gopacket.PacketDataSource
		linkType layers.LinkType
	)
	if magic == [4]byte{0x0a, 0x0d, 0x0d, 0x0a} {
		ng, err := pcapgo.NewNgReader(r, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			return nil, fmt.Errorf("pcapng: %w", err)
		}
		src, linkType = ng, ng.LinkType()
	} else {
		pr, err := pcapgo.NewReader(r)
		if err != nil {
			return nil, fmt.Errorf("pcap: %w", err)
		}
		src, linkType = pr, pr.LinkType()
	}

	// First pass: decode what we need from every packet. Ring files are an
	// hour of honeypot traffic (tens of MB at most), so holding them is fine.
	var pkts []parsed
	counts := map[string]int{}
	parser := newParser(linkType)
	for {
		data, ci, err := src.ReadPacketData()
		if err == io.EOF {
			break
		}
		if err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				break // ring file cut mid-packet; keep what we have
			}
			return nil, fmt.Errorf("reading packet: %w", err)
		}
		p, ok := parser.parse(data, ci)
		if !ok {
			continue
		}
		counts[p.srcIP.String()]++
		counts[p.dstIP.String()]++
		pkts = append(pkts, p)
	}
	if len(pkts) == 0 {
		return nil, nil
	}

	local := localSet(opt, pkts, counts)
	excludeIP := map[string]bool{}
	for _, ip := range opt.ExcludeIPs {
		excludeIP[ip.String()] = true
	}

	// Second pass: orient each packet (remote vs local), drop management
	// traffic and flows the honeypot opened itself, group by remote.
	byRemote := map[string][]Packet{}
	outbound := map[string]bool{} // flow key -> first packet went local -> remote
	flowSeen := map[string]bool{}
	for _, p := range pkts {
		var pk Packet
		switch {
		case local[p.dstIP.String()] && !local[p.srcIP.String()]:
			pk = Packet{CI: p.ci, Data: p.data, Payload: p.payload, Remote: p.srcIP, Local: p.dstIP, Proto: p.proto, RemPort: p.srcPort, LocPort: p.dstPort, ToLocal: true}
		case local[p.srcIP.String()] && !local[p.dstIP.String()]:
			pk = Packet{CI: p.ci, Data: p.data, Payload: p.payload, Remote: p.dstIP, Local: p.srcIP, Proto: p.proto, RemPort: p.dstPort, LocPort: p.srcPort}
		default:
			continue // local-local or unrelated
		}
		if excludeIP[pk.Remote.String()] || opt.ExcludePorts[pk.RemPort] || opt.ExcludePorts[pk.LocPort] {
			continue
		}
		if pk.Remote.IsLoopback() || pk.Remote.IsLinkLocalUnicast() || pk.Remote.IsMulticast() || pk.Remote.IsUnspecified() {
			continue
		}
		fk := pk.Remote.String() + "/" + Flow{Proto: pk.Proto, RemPort: pk.RemPort, LocPort: pk.LocPort}.Key()
		if !flowSeen[fk] {
			flowSeen[fk] = true
			outbound[fk] = !pk.ToLocal
		}
		if outbound[fk] && !opt.KeepOutbound {
			continue
		}
		byRemote[pk.Remote.String()] = append(byRemote[pk.Remote.String()], pk)
	}

	var out []*Session
	for _, list := range byRemote {
		sort.SliceStable(list, func(i, j int) bool { return list[i].CI.Timestamp.Before(list[j].CI.Timestamp) })
		cur := &Session{Remote: list[0].Remote, LinkType: linkType}
		for _, pk := range list {
			if len(cur.Packets) > 0 && pk.CI.Timestamp.Sub(cur.End) > opt.IdleGap {
				out = append(out, cur)
				cur = &Session{Remote: pk.Remote, LinkType: linkType}
			}
			cur.add(pk)
		}
		out = append(out, cur)
	}

	var kept []*Session
	for _, s := range out {
		s.TotalPkts = len(s.Packets)
		s.applyCaps(opt)
		if len(s.Packets) >= opt.MinPackets {
			kept = append(kept, s)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool { return kept[i].Start.Before(kept[j].Start) })
	return kept, nil
}

func (s *Session) add(pk Packet) {
	if len(s.Packets) == 0 {
		s.Start = pk.CI.Timestamp
	}
	s.End = pk.CI.Timestamp
	s.Packets = append(s.Packets, pk)
	seen := false
	for _, p := range s.LocalPorts {
		if p == pk.LocPort {
			seen = true
			break
		}
	}
	if !seen && pk.LocPort > 0 {
		s.LocalPorts = append(s.LocalPorts, pk.LocPort)
	}
	fk := Flow{Proto: pk.Proto, RemPort: pk.RemPort, LocPort: pk.LocPort}.Key()
	for i := range s.Flows {
		if s.Flows[i].Key() == fk {
			s.Flows[i].Pkts++
			return
		}
	}
	s.Flows = append(s.Flows, Flow{Proto: pk.Proto, RemPort: pk.RemPort, LocPort: pk.LocPort, First: pk.CI.Timestamp, Pkts: 1})
}

// Duration of the session.
func (s *Session) Duration() time.Duration { return s.End.Sub(s.Start) }

// applyCaps enforces the packet and byte caps. With KeepFlows set and more
// TCP flows than that, the slice keeps the first KeepFlows flows (and the
// flows marked in KeepPorts via Trim) so a long brute force stays small but
// still shows the technique.
func (s *Session) applyCaps(opt Options) {
	if opt.KeepFlows > 0 && len(s.Flows) > opt.KeepFlows {
		s.Trim(opt.KeepFlows, nil)
	}
	var bytes int64
	for i, pk := range s.Packets {
		bytes += int64(len(pk.Data))
		if i >= opt.MaxPackets || bytes > opt.MaxBytes {
			s.Packets = s.Packets[:i]
			s.Truncated = true
			break
		}
	}
	if len(s.Packets) > 0 {
		s.End = s.Packets[len(s.Packets)-1].CI.Timestamp
	}
}

// Trim keeps the first n flows plus any flow whose remote port is in keep.
func (s *Session) Trim(n int, keep map[int]bool) {
	allowed := map[string]bool{}
	for i, f := range s.Flows {
		if i < n || keep[f.RemPort] {
			allowed[f.Key()] = true
		}
	}
	var pk []Packet
	for _, p := range s.Packets {
		if allowed[Flow{Proto: p.Proto, RemPort: p.RemPort, LocPort: p.LocPort}.Key()] {
			pk = append(pk, p)
		}
	}
	if len(pk) < len(s.Packets) {
		s.Truncated = true
	}
	s.Packets = pk
}

// Write stores the session as a classic pcap file.
func (s *Session) Write(path string) (int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(262144, s.LinkType); err != nil {
		return 0, err
	}
	for _, pk := range s.Packets {
		ci := pk.CI
		ci.CaptureLength = len(pk.Data)
		if ci.Length < ci.CaptureLength {
			ci.Length = ci.CaptureLength
		}
		if err := w.WritePacket(ci, pk.Data); err != nil {
			return 0, err
		}
	}
	st, err := f.Stat()
	if err != nil {
		return 0, err
	}
	return st.Size(), nil
}

// localSet picks the honeypot's addresses: the configured ones, plus this
// host's interface addresses when asked, else a heuristic: the address that
// talks to the most distinct peers (the honeypot is one end of everything,
// an attacker talks to one host), with packet count as the tie-break.
func localSet(opt Options, pkts []parsed, counts map[string]int) map[string]bool {
	local := map[string]bool{}
	for _, ip := range opt.LocalIPs {
		local[ip.String()] = true
	}
	if opt.UseInterfaceAddrs {
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && !ipn.IP.IsLinkLocalUnicast() {
					local[ipn.IP.String()] = true
				}
			}
		}
	}
	if len(local) > 0 {
		return local
	}
	peers := map[string]map[string]bool{}
	for _, p := range pkts {
		a, b := p.srcIP.String(), p.dstIP.String()
		if peers[a] == nil {
			peers[a] = map[string]bool{}
		}
		if peers[b] == nil {
			peers[b] = map[string]bool{}
		}
		peers[a][b] = true
		peers[b][a] = true
	}
	best, bestPeers, bestN := "", -1, 0
	for ip, set := range peers {
		if len(set) > bestPeers || (len(set) == bestPeers && counts[ip] > bestN) || (len(set) == bestPeers && counts[ip] == bestN && ip < best) {
			best, bestPeers, bestN = ip, len(set), counts[ip]
		}
	}
	if best != "" {
		local[best] = true
	}
	return local
}

// ---- decoding -------------------------------------------------------------

type parsed struct {
	ci               gopacket.CaptureInfo
	data             []byte
	srcIP, dstIP     net.IP
	proto            layers.IPProtocol
	srcPort, dstPort int
	payload          []byte
}

type parser struct {
	dlp  *gopacket.DecodingLayerParser
	eth  layers.Ethernet
	sll  layers.LinuxSLL
	ip4  layers.IPv4
	ip6  layers.IPv6
	tcp  layers.TCP
	udp  layers.UDP
	icmp layers.ICMPv4
	icm6 layers.ICMPv6
	pay  gopacket.Payload
	dec  []gopacket.LayerType
}

func newParser(lt layers.LinkType) *parser {
	p := &parser{}
	first := gopacket.LayerType(layers.LayerTypeEthernet)
	switch lt {
	case layers.LinkTypeLinuxSLL:
		first = layers.LayerTypeLinuxSLL
	case layers.LinkTypeRaw, layers.LinkType(12), layers.LinkType(14):
		first = layers.LayerTypeIPv4 // DLT_RAW variants; v6 handled by failure fallback below
	}
	p.dlp = gopacket.NewDecodingLayerParser(first, &p.eth, &p.sll, &p.ip4, &p.ip6, &p.tcp, &p.udp, &p.icmp, &p.icm6, &p.pay)
	p.dlp.IgnoreUnsupported = true
	return p
}

func (p *parser) parse(data []byte, ci gopacket.CaptureInfo) (parsed, bool) {
	p.dec = p.dec[:0]
	_ = p.dlp.DecodeLayers(data, &p.dec) // partial decodes are fine
	out := parsed{ci: ci, data: data}
	haveIP := false
	for _, lt := range p.dec {
		switch lt {
		case layers.LayerTypeIPv4:
			out.srcIP, out.dstIP, out.proto, haveIP = p.ip4.SrcIP, p.ip4.DstIP, p.ip4.Protocol, true
		case layers.LayerTypeIPv6:
			out.srcIP, out.dstIP, out.proto, haveIP = p.ip6.SrcIP, p.ip6.DstIP, p.ip6.NextHeader, true
		case layers.LayerTypeTCP:
			out.srcPort, out.dstPort = int(p.tcp.SrcPort), int(p.tcp.DstPort)
			out.payload = p.tcp.Payload
		case layers.LayerTypeUDP:
			out.srcPort, out.dstPort = int(p.udp.SrcPort), int(p.udp.DstPort)
			out.payload = p.udp.Payload
		}
	}
	if !haveIP {
		return out, false
	}
	// Copy the addresses: the decoder reuses its buffers.
	out.srcIP = append(net.IP(nil), out.srcIP...)
	out.dstIP = append(net.IP(nil), out.dstIP...)
	return out, true
}
