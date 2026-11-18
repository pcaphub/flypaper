package honeylog

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// opencanaryLine is one OpenCanary JSON log record (opencanary.log).
type opencanaryLine struct {
	LogType int             `json:"logtype"`
	SrcHost string          `json:"src_host"`
	SrcPort int             `json:"src_port"`
	DstPort int             `json:"dst_port"`
	UTCTime string          `json:"utc_time"`
	LogData json.RawMessage `json:"logdata"`
}

// OpenCanary logtype codes used here (opencanary/logger.py).
const (
	ocFTPLogin      = 2000
	ocHTTPGet       = 3000
	ocHTTPPostLogin = 3001
	ocHTTPOther     = 3002
	ocSSHConnect    = 4000
	ocSSHLogin      = 4002
	ocSMBFileOpen   = 5000
	ocTelnetLogin   = 6001
	ocTelnetConnect = 6002
	ocProxyLogin    = 7001
	ocMySQLLogin    = 8001
	ocMSSQLLogin    = 9001
	ocMSSQLWinAuth  = 9002
	ocMySQLConnect  = 9003
	ocTFTP          = 10001
	ocVNC           = 12001
	ocSNMP          = 13001
	ocRDP           = 14001
	ocSIP           = 15001
	ocGit           = 16001
	ocRedis         = 17001
	ocBannerConnect = 18001
	ocBannerData    = 18005
	ocMongoLogin    = 20001
)

// ReadOpenCanary parses an OpenCanary log (one JSON object per line).
func ReadOpenCanary(r io.Reader) ([]Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var out []Event
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] != '{' {
			continue
		}
		var l opencanaryLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			continue
		}
		ip := net.ParseIP(l.SrcHost)
		if ip == nil || l.LogType < 2000 {
			continue // boot, ping, config messages
		}
		ts, err := time.Parse("2006-01-02 15:04:05.999999", l.UTCTime)
		if err != nil {
			continue
		}
		var data map[string]any
		_ = json.Unmarshal(l.LogData, &data) // logdata is sometimes a string
		ev := Event{
			Time: ts.UTC(), Source: "opencanary", SrcIP: ip, SrcPort: l.SrcPort, DstPort: l.DstPort,
			Username: str(data, "USERNAME"), Password: str(data, "PASSWORD"),
		}
		switch l.LogType {
		case ocHTTPGet, ocHTTPOther:
			ev.Service, ev.Kind = "http", "command"
			ev.Input = strings.TrimSpace("GET " + str(data, "PATH") + " " + str(data, "USERAGENT"))
		case ocHTTPPostLogin:
			ev.Service, ev.Kind = "http", "login_failed"
			ev.Input = strings.TrimSpace("POST " + str(data, "PATH"))
		case ocFTPLogin:
			ev.Service, ev.Kind = "ftp", "login_failed"
		case ocSSHConnect:
			ev.Service, ev.Kind = "ssh", "connect"
		case ocSSHLogin:
			ev.Service, ev.Kind = "ssh", "login_failed"
		case ocTelnetConnect:
			ev.Service, ev.Kind = "telnet", "connect"
		case ocTelnetLogin:
			ev.Service, ev.Kind = "telnet", "login_failed"
		case ocProxyLogin:
			ev.Service, ev.Kind = "http-proxy", "login_failed"
		case ocMySQLConnect:
			ev.Service, ev.Kind = "mysql", "connect"
		case ocMySQLLogin:
			ev.Service, ev.Kind = "mysql", "login_failed"
		case ocMSSQLLogin:
			// TDS login: OpenCanary logs the client's self-description in
			// CamelCase keys (UserName, AppName, HostName, CltIntName), unlike
			// every other service. The client description is worth keeping:
			// "Nmap NSE / mssql.lua" and "Microl office / ODBC" are different
			// actors behind the same "sa" login.
			ev.Service, ev.Kind = "mssql", "login_failed"
			ev.Username = str(data, "UserName")
			if client := strings.TrimSpace(strings.Join(nonEmpty(str(data, "AppName"), str(data, "CltIntName"), str(data, "HostName")), " / ")); client != "" {
				out = append(out, Event{Time: ev.Time, Source: ev.Source, Service: "mssql", Kind: "client",
					SrcIP: ev.SrcIP, SrcPort: ev.SrcPort, DstPort: ev.DstPort, Input: client})
			}
		case ocMSSQLWinAuth:
			ev.Service, ev.Kind = "mssql", "login_failed"
		case ocMongoLogin:
			ev.Service, ev.Kind = "mongodb", "login_failed"
		case ocRDP:
			ev.Service, ev.Kind = "rdp", "login_failed"
		case ocVNC:
			ev.Service, ev.Kind = "vnc", "login_failed"
		case ocSMBFileOpen:
			ev.Service, ev.Kind = "smb", "command"
			ev.Input = str(data, "FILENAME")
		case ocRedis:
			ev.Service, ev.Kind = "redis", "command"
			ev.Input = strings.TrimSpace(str(data, "CMD") + " " + str(data, "ARGS"))
		case ocSNMP:
			ev.Service, ev.Kind = "snmp", "command"
			ev.Input = fmt.Sprint(data)
		case ocSIP:
			ev.Service, ev.Kind = "sip", "command"
			ev.Input = fmt.Sprint(data)
		case ocTFTP:
			ev.Service, ev.Kind = "tftp", "command"
			ev.Input = str(data, "FILENAME")
		case ocGit:
			ev.Service, ev.Kind = "git", "command"
			ev.Input = str(data, "REPO")
		case ocBannerConnect:
			ev.Service, ev.Kind = "tcp", "connect"
		case ocBannerData:
			ev.Service, ev.Kind = "tcp", "command"
			ev.Input = str(data, "DATA")
		default:
			ev.Kind = "other"
		}
		out = append(out, ev)
	}
	return out, sc.Err()
}

func str(m map[string]any, k string) string {
	if m == nil {
		return ""
	}
	switch v := m[k].(type) {
	case string:
		if len(v) > 400 {
			return v[:400]
		}
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func nonEmpty(parts ...string) []string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ReadOpenCanaryFiles reads the live log and rotated siblings.
func ReadOpenCanaryFiles(live string) ([]Event, error) {
	matches, _ := filepath.Glob(live + "*")
	var all []Event
	for _, m := range matches {
		f, err := os.Open(m)
		if err != nil {
			continue
		}
		evs, err := ReadOpenCanary(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, evs...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	return all, nil
}
