// Package classify turns a pcap slice plus the honeypot events for the same
// attacker into a class, a score and a scenario fingerprint. The fingerprint
// is built from the normalised content of the session, never from the source
// address, so the same campaign from a thousand bots has one fingerprint.
package classify

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/pcaphub/flypaper/internal/honeylog"
	"github.com/pcaphub/flypaper/internal/session"
)

// Class labels, from least to most interesting.
const (
	ScanOnly        = "scan-only"
	SSHBruteforce   = "ssh-bruteforce"
	TelnetIoT       = "telnet-iot"
	SSHLoginSuccess = "ssh-login-success"
	CommandsRun     = "commands-executed"
	MalwareDownload = "malware-download"
	WebExploit      = "web-exploit-attempt"
	PortForward     = "ssh-port-forward"
	ServiceProbe    = "service-probe"
)

// Result is what the selector and the describer consume.
type Result struct {
	Class       string
	Score       int      // 0-100
	Fingerprint string   // hex sha256 prefix, 16 chars
	Tags        []string // protocol and behaviour tags, lowercase-hyphen
	Facts       Facts
}

// Facts are the human-readable ingredients for the description.
type Facts struct {
	Services      []string // ssh, telnet, http, redis...
	LocalPorts    []int
	Flows         int
	LoginAttempts int
	LoginSuccess  []string // "user:pass" (attacker supplied, safe to show)
	TopCreds      []string // most tried "user:pass", up to 5
	Commands      []string // in order, deduplicated consecutive repeats
	URLs          []string // raw, caller defangs
	Hashes        []string
	ClientVersion string
	Forwards      []string
}

var (
	reIPv4     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reHex      = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	reNum      = regexp.MustCompile(`\b\d{3,}\b`)
	reRandName = regexp.MustCompile(`\b[A-Za-z0-9_.-]*[0-9]{2,}[A-Za-z0-9_.-]*\b`)
	reSpaces   = regexp.MustCompile(`\s+`)
	reExploit  = regexp.MustCompile(`(?i)(\.\./|%2e%2e|/etc/passwd|cgi-bin|\$\{jndi:|<\?php|eval\(|base64_decode|wget\s|curl\s|/bin/sh|cmd=|exec\(|union\s+select|sleep\(\d|/shell|/boaform|/GponForm|/HNAP1|/setup\.cgi|/manager/html|/wp-login|/xmlrpc\.php|/\.env|/\.git/|/actuator|/solr/|/jmx|/console/|/_ignition)`)
)

// Run classifies one slice given the honeypot events for its remote address.
func Run(s *session.Session, evs []honeylog.Event) Result {
	f := Facts{LocalPorts: s.LocalPorts, Flows: len(s.Flows)}
	svc := map[string]bool{}
	for _, p := range s.LocalPorts {
		svc[serviceName(p)] = true
	}
	credCount := map[string]int{}
	var lastCmd string
	seenURL := map[string]bool{}
	for _, e := range evs {
		if e.Service != "" {
			svc[e.Service] = true
		}
		switch e.Kind {
		case "login_failed":
			f.LoginAttempts++
			credCount[e.Username+":"+e.Password]++
		case "login_success":
			f.LoginAttempts++
			f.LoginSuccess = append(f.LoginSuccess, e.Username+":"+e.Password)
		case "command":
			cmd := strings.TrimSpace(e.Input)
			if cmd != "" && cmd != lastCmd {
				f.Commands = append(f.Commands, cmd)
				lastCmd = cmd
			}
		case "download":
			if e.URL != "" && !seenURL[e.URL] {
				f.URLs = append(f.URLs, e.URL)
				seenURL[e.URL] = true
			}
			if e.Hash != "" {
				f.Hashes = append(f.Hashes, e.Hash)
			}
		case "forward":
			if e.Input != "" {
				f.Forwards = append(f.Forwards, e.Input)
			}
		case "client":
			if f.ClientVersion == "" {
				f.ClientVersion = e.Input
			}
		}
		// URLs typed in commands count as downloads too (wget/curl/tftp).
		if e.Kind == "command" {
			for _, u := range urlsIn(e.Input) {
				if !seenURL[u] {
					f.URLs = append(f.URLs, u)
					seenURL[u] = true
				}
			}
		}
	}
	for s := range svc {
		if s != "" {
			f.Services = append(f.Services, s)
		}
	}
	sort.Strings(f.Services)
	f.TopCreds = topN(credCount, 5)

	r := Result{Facts: f}
	r.Class, r.Score = classify(s, f)
	r.Tags = tags(r.Class, f)
	r.Fingerprint = fingerprint(r.Class, f)
	return r
}

func classify(s *session.Session, f Facts) (string, int) {
	hasShell := len(f.Commands) > 0
	hasTelnet := contains(f.Services, "telnet")
	hasSSH := contains(f.Services, "ssh")
	switch {
	case len(f.URLs) > 0 && hasShell:
		return MalwareDownload, 95
	case webExploit(f):
		return WebExploit, 85
	case hasShell:
		if hasTelnet && !hasSSH {
			return TelnetIoT, 80
		}
		return CommandsRun, 80
	case len(f.Forwards) > 0:
		return PortForward, 70
	case len(f.LoginSuccess) > 0:
		return SSHLoginSuccess, 60
	case f.LoginAttempts >= 3:
		if hasTelnet && !hasSSH {
			return TelnetIoT, 35
		}
		return SSHBruteforce, 30 + min(f.LoginAttempts/20, 10)
	case len(s.LocalPorts) == 1 && s.TotalPkts >= 8 && !hasSSH && !hasTelnet:
		// one service, real payload exchanged, no honeypot log: a probe of
		// a service we only capture (redis, mysql, smb...)
		return ServiceProbe, 45
	default:
		// score scans by breadth: 1 port = noise, 20 ports = a proper sweep
		return ScanOnly, min(10+len(s.LocalPorts)*2, 30)
	}
}

func webExploit(f Facts) bool {
	if !contains(f.Services, "http") && !contains(f.Services, "http-alt") {
		return false
	}
	for _, c := range f.Commands {
		if reExploit.MatchString(c) {
			return true
		}
	}
	for _, u := range f.URLs {
		if reExploit.MatchString(u) {
			return true
		}
	}
	return false
}

func tags(class string, f Facts) []string {
	seen := map[string]bool{"honeypot": true, class: true}
	out := []string{"honeypot", class}
	for _, s := range f.Services {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(f.URLs) > 0 && !seen["malware-download"] {
		out = append(out, "malware-download")
	}
	return out
}

// fingerprint hashes the normalised scenario: class, service set, command
// sequence with volatile tokens masked, credential set, URL hosts and
// normalised paths, HTTP request templates. No addresses, no timestamps.
func fingerprint(class string, f Facts) string {
	var b strings.Builder
	b.WriteString(class)
	b.WriteString("|")
	b.WriteString(strings.Join(f.Services, ","))
	b.WriteString("|")
	for _, c := range f.Commands {
		b.WriteString(Normalise(c))
		b.WriteString(";")
	}
	b.WriteString("|")
	creds := append([]string{}, f.TopCreds...)
	creds = append(creds, f.LoginSuccess...)
	sort.Strings(creds)
	b.WriteString(strings.Join(creds, ","))
	b.WriteString("|")
	for _, u := range f.URLs {
		b.WriteString(normaliseURL(u))
		b.WriteString(";")
	}
	if class == ScanOnly || class == ServiceProbe {
		// scans are the same scenario when they hit the same port set
		ports := append([]int{}, f.LocalPorts...)
		sort.Ints(ports)
		b.WriteString(fmt.Sprint(ports))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:8])
}

// Normalise masks the parts of a command line that change per victim or per
// run: IP addresses, long hex strings (hashes, random names), long numbers,
// and names with embedded digits (/tmp/x8f2k, bot.x86_64 stays because the
// digit run is kept when it is part of a known arch token).
func Normalise(s string) string {
	s = strings.TrimSpace(s)
	s = reSpaces.ReplaceAllString(s, " ")
	s = reIPv4.ReplaceAllString(s, "IP")
	s = reHex.ReplaceAllString(s, "HEX")
	for _, arch := range []string{"x86_64", "i686", "i386", "arm7", "armv7l", "aarch64", "mips64"} {
		s = strings.ReplaceAll(s, arch, strings.ToUpper(arch))
	}
	s = reNum.ReplaceAllString(s, "N")
	s = reRandName.ReplaceAllString(s, "RND")
	return strings.ToLower(s)
}

func normaliseURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return Normalise(raw)
	}
	host := u.Hostname()
	if reIPv4.MatchString(host) {
		host = "IP"
	}
	return host + Normalise(u.Path)
}

func urlsIn(cmd string) []string {
	var out []string
	for _, tok := range strings.Fields(cmd) {
		tok = strings.Trim(tok, `"';` + "`")
		if strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") || strings.HasPrefix(tok, "ftp://") || strings.HasPrefix(tok, "tftp://") {
			out = append(out, tok)
		}
	}
	return out
}

func serviceName(port int) string {
	switch port {
	case 22, 2222:
		return "ssh"
	case 23, 2223:
		return "telnet"
	case 80, 8080, 8000, 8888, 443, 8443:
		return "http"
	case 21:
		return "ftp"
	case 25, 587:
		return "smtp"
	case 445, 139:
		return "smb"
	case 3306:
		return "mysql"
	case 5432:
		return "postgres"
	case 6379:
		return "redis"
	case 3389:
		return "rdp"
	case 5900:
		return "vnc"
	case 1433:
		return "mssql"
	case 27017:
		return "mongodb"
	case 161:
		return "snmp"
	case 53:
		return "dns"
	case 1900:
		return "upnp"
	case 5060:
		return "sip"
	case 11211:
		return "memcached"
	case 9200:
		return "elasticsearch"
	case 502:
		return "modbus"
	}
	return ""
}

func topN(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	var all []kv
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].v != all[j].v {
			return all[i].v > all[j].v
		}
		return all[i].k < all[j].k
	})
	var out []string
	for i := 0; i < len(all) && i < n; i++ {
		out = append(out, all[i].k)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
