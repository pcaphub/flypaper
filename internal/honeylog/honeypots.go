package honeylog

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// honeypotsLine is the JSON the `honeypots` package writes (one object per
// line). Field names vary a little between servers, so everything optional is
// read loosely from "data".
type honeypotsLine struct {
	Timestamp string         `json:"timestamp"`
	Action    string         `json:"action"`
	Server    string         `json:"server"`
	SrcIP     string         `json:"src_ip"`
	SrcPort   int            `json:"src_port"`
	DestPort  int            `json:"dest_port"`
	Username  string         `json:"username"`
	Password  string         `json:"password"`
	Status    string         `json:"status"`
	Data      map[string]any `json:"data"`
}

// ReadHoneypots parses a honeypots package JSON log.
func ReadHoneypots(r io.Reader) ([]Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Event
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var h honeypotsLine
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			continue
		}
		ip := net.ParseIP(h.SrcIP)
		if ip == nil {
			continue
		}
		ts, err := parseCowrieTime(h.Timestamp)
		if err != nil {
			continue
		}
		ev := Event{
			Time: ts, Source: "honeypots", SrcIP: ip, SrcPort: h.SrcPort, DstPort: h.DestPort,
			Service: strings.TrimSuffix(strings.ToLower(h.Server), "_server"),
			Username: h.Username, Password: h.Password,
		}
		switch strings.ToLower(h.Action) {
		case "connection":
			ev.Kind = "connect"
		case "login":
			if strings.EqualFold(h.Status, "success") {
				ev.Kind = "login_success"
			} else {
				ev.Kind = "login_failed"
			}
		case "query", "command", "request":
			ev.Kind = "command"
			ev.Input = requestLine(h.Data)
		default:
			ev.Kind = "other"
			ev.Input = requestLine(h.Data)
		}
		if ev.Service == "http" || ev.Service == "https" {
			// HTTP requests are what the web-exploit matcher reads
			if ev.Kind == "connect" && ev.Input == "" {
				ev.Input = requestLine(h.Data)
			}
			if ev.Input != "" {
				ev.Kind = "command"
			}
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}

// requestLine assembles "METHOD path" plus a body snippet from the data map.
func requestLine(d map[string]any) string {
	if d == nil {
		return ""
	}
	var parts []string
	for _, k := range []string{"method", "uri", "path", "url", "command", "query", "payload", "body", "data"} {
		if v, ok := d[k]; ok {
			s := strings.TrimSpace(toString(v))
			if s != "" {
				if len(s) > 400 {
					s = s[:400]
				}
				parts = append(parts, s)
			}
		}
	}
	return strings.Join(parts, " ")
}

func toString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// ReadHoneypotsFiles reads the live log and rotated siblings.
func ReadHoneypotsFiles(live string) ([]Event, error) {
	matches, _ := filepath.Glob(live + "*")
	var all []Event
	for _, m := range matches {
		f, err := os.Open(m)
		if err != nil {
			continue
		}
		evs, err := ReadHoneypots(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, evs...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	return all, nil
}
