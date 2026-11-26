package honeylog

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// beelzebubLine is the subset of a Beelzebub event log line that matters:
// logrus JSON with the event nested under "event".
type beelzebubLine struct {
	Event struct {
		DateTime        string `json:"DateTime"` // RFC3339, second precision
		Protocol        string `json:"Protocol"`
		SourceIP        string `json:"SourceIp"`
		SourcePort      string `json:"SourcePort"`
		RemoteAddr      string `json:"RemoteAddr"`
		HTTPMethod      string `json:"HTTPMethod"`
		RequestURI      string `json:"RequestURI"`
		Body            string `json:"Body"`
		UserAgent       string `json:"UserAgent"`
		HostHTTPRequest string `json:"HostHTTPRequest"`
		Description     string `json:"Description"`
	} `json:"event"`
}

// maxBeelzebubBody bounds what is kept of a request body; the capture has
// the rest.
const maxBeelzebubBody = 4096

// ReadBeelzebub parses Beelzebub's event log. Each HTTP request becomes one
// Event of Kind "request" with Input "METHOD URI" and Message the body; the
// classifier merges these with what it reads from the wire, which only sees
// the first segment of a body.
func ReadBeelzebub(r io.Reader) ([]Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Event
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' || !strings.Contains(line, `"event"`) {
			continue
		}
		var l beelzebubLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		e := l.Event
		if !strings.EqualFold(e.Protocol, "http") || e.RequestURI == "" {
			continue
		}
		ipStr := e.SourceIP
		if ipStr == "" {
			ipStr, _, _ = net.SplitHostPort(e.RemoteAddr)
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		ts, err := time.Parse(time.RFC3339, e.DateTime)
		if err != nil {
			continue
		}
		port, _ := strconv.Atoi(e.SourcePort)
		body := e.Body
		if len(body) > maxBeelzebubBody {
			body = body[:maxBeelzebubBody]
		}
		method := e.HTTPMethod
		if method == "" {
			method = "GET"
		}
		out = append(out, Event{
			Time: ts.UTC(), Kind: "request", Source: "beelzebub", Service: "http",
			SrcIP: ip, SrcPort: port,
			Input:   method + " " + e.RequestURI,
			Message: body,
		})
	}
	return out, sc.Err()
}
