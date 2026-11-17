// Package honeylog reads the structured logs the honeypots write (Cowrie JSON
// first) and groups events by attacker address so a pcap slice can be joined
// with what the attacker actually did.
package honeylog

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Event is one honeypot log line reduced to what the classifier uses.
type Event struct {
	Time     time.Time
	Kind     string // connect, login_failed, login_success, command, download, upload, forward, closed, client, other
	Source   string // cowrie, honeypots
	Service  string // ssh, telnet, http, ...
	SrcIP    net.IP
	SrcPort  int
	DstPort  int
	Session  string
	Username string
	Password string
	Input    string // command line, HTTP request line, ...
	URL      string
	Hash     string // sha256 of a downloaded file when known
	Message  string
}

// cowrieLine is the subset of Cowrie's JSON fields that matter here.
type cowrieLine struct {
	EventID   string  `json:"eventid"`
	Timestamp string  `json:"timestamp"`
	SrcIP     string  `json:"src_ip"`
	SrcPort   int     `json:"src_port"`
	DstPort   int     `json:"dst_port"`
	Session   string  `json:"session"`
	Protocol  string  `json:"protocol"`
	Username  string  `json:"username"`
	Password  string  `json:"password"`
	Input     string  `json:"input"`
	URL       string  `json:"url"`
	Shasum    string  `json:"shasum"`
	Message   string  `json:"message"`
	Version   string  `json:"version"`
	DstIPFwd  string  `json:"dst_ip"`
	Duration  float64 `json:"duration"`
}

// ReadCowrie parses one Cowrie JSON log file (one JSON object per line).
// Malformed lines are skipped; Cowrie occasionally writes a partial last line
// while running.
func ReadCowrie(r io.Reader) ([]Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Event
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var c cowrieLine
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			continue
		}
		if ev, err := cowrieEvent(c); err == nil {
			out = append(out, ev)
		}
	}
	return out, sc.Err()
}

func cowrieEvent(c cowrieLine) (Event, error) {
	ts, err := parseCowrieTime(c.Timestamp)
	if err != nil {
		return Event{}, err
	}
	ev := Event{
		Time: ts, Source: "cowrie", Service: c.Protocol,
		SrcIP: net.ParseIP(c.SrcIP), SrcPort: c.SrcPort, DstPort: c.DstPort,
		Session: c.Session, Username: c.Username, Password: c.Password,
		Input: c.Input, URL: c.URL, Hash: c.Shasum, Message: c.Message,
	}
	if ev.SrcIP == nil {
		return Event{}, errors.New("no src_ip")
	}
	switch c.EventID {
	case "cowrie.session.connect":
		ev.Kind = "connect"
	case "cowrie.login.failed":
		ev.Kind = "login_failed"
	case "cowrie.login.success":
		ev.Kind = "login_success"
	case "cowrie.command.input":
		ev.Kind = "command"
	case "cowrie.session.file_download", "cowrie.session.file_download.failed":
		ev.Kind = "download"
	case "cowrie.session.file_upload":
		ev.Kind = "upload"
	case "cowrie.direct-tcpip.request", "cowrie.direct-tcpip.data":
		ev.Kind = "forward"
		if ev.Input == "" {
			ev.Input = c.DstIPFwd
		}
	case "cowrie.session.closed":
		ev.Kind = "closed"
	case "cowrie.client.version", "cowrie.client.kex":
		ev.Kind = "client"
		if ev.Input == "" {
			ev.Input = c.Version
		}
	default:
		ev.Kind = "other"
	}
	if ev.Service == "" {
		switch ev.DstPort {
		case 23, 2223:
			ev.Service = "telnet"
		default:
			ev.Service = "ssh"
		}
	}
	return ev, nil
}

func parseCowrieTime(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, errors.New("bad timestamp " + s)
}

// ReadCowrieFiles reads the live log and its rotated siblings (cowrie.json,
// cowrie.json.2026-11-17, ...) and returns events sorted by time.
func ReadCowrieFiles(live string) ([]Event, error) {
	matches, _ := filepath.Glob(live + "*")
	if len(matches) == 0 {
		return nil, nil
	}
	var all []Event
	for _, m := range matches {
		f, err := os.Open(m)
		if err != nil {
			continue
		}
		evs, err := ReadCowrie(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, evs...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	return all, nil
}

// Index groups events by source address for fast lookup per slice.
type Index struct {
	byIP map[string][]Event
}

// NewIndex builds the lookup; events must be time-sorted.
func NewIndex(evs []Event) *Index {
	ix := &Index{byIP: map[string][]Event{}}
	for _, e := range evs {
		k := e.SrcIP.String()
		ix.byIP[k] = append(ix.byIP[k], e)
	}
	return ix
}

// Between returns the events from ip inside [from-slack, to+slack]. The slack
// covers clock skew between the capture process and the honeypot.
func (ix *Index) Between(ip net.IP, from, to time.Time, slack time.Duration) []Event {
	if ix == nil {
		return nil
	}
	list := ix.byIP[ip.String()]
	lo, hi := from.Add(-slack), to.Add(slack)
	i := sort.Search(len(list), func(i int) bool { return !list[i].Time.Before(lo) })
	var out []Event
	for ; i < len(list) && !list[i].Time.After(hi); i++ {
		out = append(out, list[i])
	}
	return out
}
