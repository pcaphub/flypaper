package session

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"sort"

	"github.com/gopacket/gopacket/layers"
)

// MaskLocal rewrites the honeypot's own addresses in every packet of the
// session to addresses from the documentation ranges (RFC 5737 and RFC 3849),
// so a published capture does not tell scanners where the honeypot is.
// Attacker addresses are left alone.
//
// What is rewritten: the IPv4 and IPv6 headers (checksums fixed, TCP, UDP
// and ICMPv6 pseudo-header checksums adjusted), the IPv4 header quoted inside
// ICMP error messages, ARP sender and target addresses, and the dotted
// decimal text of the address inside TCP and UDP payloads (a scanner's
// "Host:" header, a banner) when a replacement of the same length exists, so
// segment sizes and sequence numbers stay valid. Payload text with no
// same-length replacement is left as it was and reported in the result.
//
// This is a byte-for-byte substitution with checksum arithmetic, nothing is
// reassembled or interpreted beyond the headers needed to find the fields.
func (s *Session) MaskLocal() MaskResult {
	locals := map[string]net.IP{}
	avoid := map[string]bool{} // every address already in the capture
	for _, pk := range s.Packets {
		if pk.Local != nil {
			locals[pk.Local.String()] = pk.Local
			avoid[pk.Local.String()] = true
		}
		if pk.Remote != nil {
			avoid[pk.Remote.String()] = true
		}
	}
	if len(locals) == 0 {
		return MaskResult{}
	}
	keys := make([]string, 0, len(locals))
	for k := range locals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	m := newMasker()
	for i, k := range keys {
		m.add(locals[k], i, avoid)
	}
	res := MaskResult{Mapping: map[string]string{}}
	for k, v := range m.byText {
		res.Mapping[k] = v.repl.String()
	}
	for i := range s.Packets {
		pk := &s.Packets[i]
		// Payload is a window into Data for packets the parser produced;
		// find it before the bytes change and point it at the new bytes after
		payloadAt := -1
		if len(pk.Payload) > 0 {
			payloadAt = bytes.Index(pk.Data, pk.Payload)
		}
		r := m.packet(s.LinkType, pk.Data)
		res.Headers += r.Headers
		res.Payloads += r.Payloads
		res.Unmasked += r.Unmasked
		if pk.Local != nil {
			if e, ok := m.byText[pk.Local.String()]; ok {
				pk.Local = e.repl
			}
		}
		if payloadAt >= 0 {
			pk.Payload = pk.Data[payloadAt : payloadAt+len(pk.Payload)]
		}
	}
	return res
}

// MaskResult counts what MaskLocal changed.
type MaskResult struct {
	Mapping  map[string]string // real address -> replacement
	Headers  int               // IP, ARP and ICMP-quoted headers rewritten
	Payloads int               // payload text occurrences rewritten
	Unmasked int               // payload text occurrences left (no same-length replacement)
}

type maskEntry struct {
	real, repl net.IP
	text       []byte // dotted/colon text of the real address
	replText   []byte // same-length replacement text, nil when none
}

type masker struct {
	byText map[string]*maskEntry
	v4     map[[4]byte]*maskEntry
	v6     map[[16]byte]*maskEntry
}

func newMasker() *masker {
	return &masker{byText: map[string]*maskEntry{}, v4: map[[4]byte]*maskEntry{}, v6: map[[16]byte]*maskEntry{}}
}

// add picks the replacement for one honeypot address. The i-th address of
// the session gets the i-th candidate, so the mapping is stable within a
// capture. IPv4 candidates are chosen by text length first, so the dotted
// text in payloads can be swapped in place.
func (m *masker) add(ip net.IP, i int, avoid map[string]bool) {
	e := &maskEntry{real: ip, text: []byte(ip.String())}
	if v4 := ip.To4(); v4 != nil {
		e.repl = docV4(len(e.text), i, avoid)
		if len(e.repl.String()) == len(e.text) {
			e.replText = []byte(e.repl.String())
		}
		var k [4]byte
		copy(k[:], v4)
		m.v4[k] = e
	} else {
		r := make(net.IP, 16)
		copy(r, net.ParseIP("2001:db8::"))
		binary.BigEndian.PutUint16(r[14:], uint16(i+1))
		e.repl = r
		// IPv6 text has too many spellings to swap in place; headers only
		var k [16]byte
		copy(k[:], ip.To16())
		m.v6[k] = e
	}
	m.byText[ip.String()] = e
}

// docV4 returns the i-th documentation address whose dotted text has length n
// when one exists (lengths 9 to 14), else the i-th 192.0.2.x. Addresses in
// avoid (anything already in the capture) are skipped so the rewrite never
// merges two hosts.
func docV4(n, i int, avoid map[string]bool) net.IP {
	var cands, fallback []net.IP
	for _, pfx := range []string{"192.0.2.", "203.0.113.", "198.51.100."} {
		for h := 1; h <= 254; h++ {
			ip := net.ParseIP(fmt.Sprintf("%s%d", pfx, h)).To4()
			if avoid[ip.String()] {
				continue
			}
			fallback = append(fallback, ip)
			if len(ip.String()) == n {
				cands = append(cands, ip)
			}
		}
	}
	if len(cands) == 0 {
		cands = fallback
	}
	return cands[i%len(cands)]
}

// packet rewrites one frame in place.
func (m *masker) packet(lt layers.LinkType, data []byte) MaskResult {
	var r MaskResult
	off, etype, ok := l3Offset(lt, data)
	if !ok {
		return r
	}
	switch etype {
	case 0x0800:
		m.ipv4(data, off, &r, true)
	case 0x86DD:
		m.ipv6(data, off, &r)
	case 0x0806:
		m.arp(data, off, &r)
	}
	return r
}

// l3Offset finds the network layer header and its EtherType-style protocol.
func l3Offset(lt layers.LinkType, data []byte) (int, uint16, bool) {
	switch lt {
	case layers.LinkTypeEthernet:
		off := 14
		if len(data) < off {
			return 0, 0, false
		}
		et := binary.BigEndian.Uint16(data[12:14])
		for et == 0x8100 || et == 0x88a8 {
			if len(data) < off+4 {
				return 0, 0, false
			}
			et = binary.BigEndian.Uint16(data[off+2 : off+4])
			off += 4
		}
		return off, et, true
	case layers.LinkTypeLinuxSLL:
		if len(data) < 16 {
			return 0, 0, false
		}
		return 16, binary.BigEndian.Uint16(data[14:16]), true
	case layers.LinkTypeLinuxSLL2:
		if len(data) < 20 {
			return 0, 0, false
		}
		return 20, binary.BigEndian.Uint16(data[0:2]), true
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
		if len(data) < 1 {
			return 0, 0, false
		}
		if data[0]>>4 == 6 {
			return 0, 0x86DD, true
		}
		return 0, 0x0800, true
	case layers.LinkTypeIPv6:
		return 0, 0x86DD, true
	case layers.LinkTypeNull, layers.LinkTypeLoop:
		if len(data) < 5 {
			return 0, 0, false
		}
		if data[4]>>4 == 6 {
			return 4, 0x86DD, true
		}
		return 4, 0x0800, true
	}
	return 0, 0, false
}

// ipv4 rewrites the addresses of the header at off and fixes the checksums
// that cover them. withL4 is false for the header quoted inside an ICMP
// error, whose transport header is incomplete.
func (m *masker) ipv4(data []byte, off int, r *MaskResult, withL4 bool) {
	if len(data) < off+20 || data[off]>>4 != 4 {
		return
	}
	ihl := int(data[off]&0x0f) * 4
	if ihl < 20 || len(data) < off+ihl {
		return
	}
	hdr := data[off : off+ihl]
	changed := false
	var oldAddrs, newAddrs []byte
	for _, p := range []int{12, 16} {
		var k [4]byte
		copy(k[:], hdr[p:p+4])
		if e, ok := m.v4[k]; ok {
			oldAddrs = append(oldAddrs, hdr[p:p+4]...)
			copy(hdr[p:p+4], e.repl.To4())
			newAddrs = append(newAddrs, hdr[p:p+4]...)
			changed = true
		}
	}
	if !changed {
		if withL4 {
			m.payloadText(data, off, ihl, r)
		}
		return
	}
	r.Headers++
	// header checksum: recompute over the header
	binary.BigEndian.PutUint16(hdr[10:12], 0)
	binary.BigEndian.PutUint16(hdr[10:12], onesComplement(sum16(hdr, 0)))
	if !withL4 {
		return
	}
	frag := binary.BigEndian.Uint16(hdr[6:8]) & 0x1fff
	if frag != 0 {
		return // not the first fragment: no transport header here
	}
	l4 := off + ihl
	switch layers.IPProtocol(hdr[9]) {
	case layers.IPProtocolTCP:
		if len(data) >= l4+18 {
			adjustField(data, l4+16, oldAddrs, newAddrs)
		}
	case layers.IPProtocolUDP:
		if len(data) >= l4+8 && binary.BigEndian.Uint16(data[l4+6:l4+8]) != 0 {
			adjustField(data, l4+6, oldAddrs, newAddrs)
		}
	case layers.IPProtocolICMPv4:
		m.icmpQuoted(data, l4, r)
		return
	default:
		return
	}
	m.payloadText(data, off, ihl, r)
}

// icmpQuoted rewrites the IPv4 header an ICMP error message quotes and
// adjusts the ICMP checksum, which covers the quote.
func (m *masker) icmpQuoted(data []byte, l4 int, r *MaskResult) {
	if len(data) < l4+8+20 {
		return
	}
	switch data[l4] {
	case 3, 4, 5, 11, 12: // unreachable, source quench, redirect, time exceeded, parameter problem
	default:
		return
	}
	inner := l4 + 8
	ihl := int(data[inner]&0x0f) * 4
	if data[inner]>>4 != 4 || ihl < 20 || len(data) < inner+ihl {
		return
	}
	before := append([]byte(nil), data[inner:inner+ihl]...)
	m.ipv4(data, inner, r, false)
	after := data[inner : inner+ihl]
	if !bytes.Equal(before, after) {
		adjustField(data, l4+2, before, after)
	}
}

// ipv6 rewrites the addresses of the header at off and adjusts the transport
// checksum (the IPv6 header itself has none).
func (m *masker) ipv6(data []byte, off int, r *MaskResult) {
	if len(data) < off+40 || data[off]>>4 != 6 {
		return
	}
	hdr := data[off : off+40]
	var oldAddrs, newAddrs []byte
	for _, p := range []int{8, 24} {
		var k [16]byte
		copy(k[:], hdr[p:p+16])
		if e, ok := m.v6[k]; ok {
			oldAddrs = append(oldAddrs, hdr[p:p+16]...)
			copy(hdr[p:p+16], e.repl.To16())
			newAddrs = append(newAddrs, hdr[p:p+16]...)
		}
	}
	if oldAddrs == nil {
		return
	}
	r.Headers++
	next := hdr[6]
	l4 := off + 40
	for {
		switch next {
		case 0, 43, 60: // hop-by-hop, routing, destination options
			if len(data) < l4+2 {
				return
			}
			next, l4 = data[l4], l4+int(data[l4+1])*8+8
		case 44: // fragment
			if len(data) < l4+8 {
				return
			}
			if binary.BigEndian.Uint16(data[l4+2:l4+4])&0xfff8 != 0 {
				return // not the first fragment
			}
			next, l4 = data[l4], l4+8
		default:
			goto transport
		}
	}
transport:
	switch layers.IPProtocol(next) {
	case layers.IPProtocolTCP:
		if len(data) >= l4+18 {
			adjustField(data, l4+16, oldAddrs, newAddrs)
		}
	case layers.IPProtocolUDP:
		if len(data) >= l4+8 {
			adjustField(data, l4+6, oldAddrs, newAddrs)
		}
	case layers.IPProtocolICMPv6:
		if len(data) >= l4+4 {
			adjustField(data, l4+2, oldAddrs, newAddrs)
		}
	}
}

// arp rewrites the sender and target protocol addresses of an IPv4 ARP frame.
func (m *masker) arp(data []byte, off int, r *MaskResult) {
	if len(data) < off+8 {
		return
	}
	hlen, plen := int(data[off+4]), int(data[off+5])
	if binary.BigEndian.Uint16(data[off+2:off+4]) != 0x0800 || plen != 4 || len(data) < off+8+2*hlen+2*plen {
		return
	}
	changed := false
	for _, p := range []int{off + 8 + hlen, off + 8 + 2*hlen + plen} {
		var k [4]byte
		copy(k[:], data[p:p+4])
		if e, ok := m.v4[k]; ok {
			copy(data[p:p+4], e.repl.To4())
			changed = true
		}
	}
	if changed {
		r.Headers++
	}
}

// payloadText swaps the dotted text of a masked address inside a TCP or UDP
// payload for its same-length replacement and adjusts the transport checksum.
func (m *masker) payloadText(data []byte, off, ihl int, r *MaskResult) {
	l4 := off + ihl
	var csumAt, hdrLen int
	switch layers.IPProtocol(data[off+9]) {
	case layers.IPProtocolTCP:
		if len(data) < l4+20 {
			return
		}
		hdrLen, csumAt = int(data[l4+12]>>4)*4, l4+16
	case layers.IPProtocolUDP:
		if len(data) < l4+8 {
			return
		}
		hdrLen, csumAt = 8, l4+6
		if binary.BigEndian.Uint16(data[csumAt:csumAt+2]) == 0 {
			csumAt = -1 // no checksum to maintain
		}
	default:
		return
	}
	payload := l4 + hdrLen
	if payload >= len(data) {
		return
	}
	for _, e := range m.v4 {
		for from := payload; ; {
			i := bytes.Index(data[from:], e.text)
			if i < 0 {
				break
			}
			at := from + i
			end := at + len(e.text)
			// whole address only: not a prefix of a longer dotted string
			if (at > payload && isDigitOrDot(data[at-1])) || (end < len(data) && isDigitOrDot(data[end])) {
				from = at + 1
				continue
			}
			if e.replText == nil {
				r.Unmasked++
				from = end
				continue
			}
			// align the changed span to the 16-bit words the checksum sums
			a, b := at, end
			if (a-l4)%2 == 1 {
				a--
			}
			if (b-l4)%2 == 1 && b < len(data) {
				b++
			}
			before := append([]byte(nil), data[a:b]...)
			copy(data[at:end], e.replText)
			if csumAt >= 0 {
				adjustField(data, csumAt, before, data[a:b])
			}
			r.Payloads++
			from = end
		}
	}
}

func isDigitOrDot(c byte) bool { return c == '.' || (c >= '0' && c <= '9') }

// adjustField updates the ones-complement checksum stored at data[at:at+2]
// after the bytes old were replaced by new (same length, RFC 1624 eqn 3):
// HC' = ~(~HC + ~m + m').
func adjustField(data []byte, at int, old, new []byte) {
	hc := binary.BigEndian.Uint16(data[at : at+2])
	acc := uint32(^hc)
	acc += sum16(old, 0) ^ 0xffff
	acc += sum16(new, 0)
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + acc>>16
	}
	binary.BigEndian.PutUint16(data[at:at+2], ^uint16(acc))
}

// sum16 folds b into a 16-bit ones-complement sum (odd trailing byte padded).
func sum16(b []byte, acc uint32) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		acc += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		acc += uint32(b[len(b)-1]) << 8
	}
	for acc>>16 != 0 {
		acc = (acc & 0xffff) + acc>>16
	}
	return acc
}

func onesComplement(acc uint32) uint16 { return ^uint16(acc) }
