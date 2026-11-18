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
	LoginBruteforce = "login-bruteforce" // password spray against vnc, mssql, mysql, ftp, rdp...
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
	Fingerprint string   // hex sha256 prefix, 16 chars: the exact scenario
	Family      string   // coarser hash: class + services + command verbs / path set
	Novel       []string // request paths or command templates not in the known set (filled by the caller)
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
	HTTPRequests  []string // "METHOD path" read from the packets themselves
	Payloads      []string // first bytes of POST bodies and of non-HTTP service payloads (printable)
	Hashes        []string
	ClientVersion string
	Forwards      []string
}

var (
	reIPv4    = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reHex     = regexp.MustCompile(`\b[0-9a-fA-F]{8,}\b`)
	reNum     = regexp.MustCompile(`\b\d{3,}\b`)
	reSpaces  = regexp.MustCompile(`\s+`)
	reHTTPReq = regexp.MustCompile(`^(GET|POST|HEAD|PUT|DELETE|OPTIONS|PATCH|PROPFIND|CONNECT|TRACE) (\S{1,400}) HTTP/1\.[01]\r?\n`)
	reExploit = regexp.MustCompile(`(?i)(\.\./|%2e%2e|/etc/passwd|cgi-bin|\$\{jndi:|<\?php|eval\(|base64_decode|php://input|allow_url_include|auto_prepend_file|system\(|passthru\(|shell_exec\(|assert\(|\bphpinfo\(|/vendor/phpunit|/eval-stdin\.php|/think/app|invokefunction|wget\s|curl\s|/bin/sh|cmd=|exec\(|union\s+select|sleep\(\d|/shell|/boaform|/GponForm|/HNAP1|/setup\.cgi|/manager/html|/wp-login|/xmlrpc\.php|/\.env|/\.git/|/actuator|/solr/|/jmx|/console/|/_ignition)`)
)

// Options tune classification.
type Options struct {
	// ExploitPatterns are extra regexes (from config) matched against HTTP
	// request lines, payloads, commands and URLs in addition to the built-in list.
	ExploitPatterns []*regexp.Regexp
}

// Run classifies one slice given the honeypot events for its remote address.
func Run(s *session.Session, evs []honeylog.Event) Result { return RunWith(s, evs, Options{}) }

// RunWith is Run with options.
func RunWith(s *session.Session, evs []honeylog.Event, opt Options) Result {
	f := Facts{LocalPorts: s.LocalPorts, Flows: len(s.Flows)}
	svc := map[string]bool{}
	for _, p := range s.LocalPorts {
		svc[serviceName(p)] = true
	}
	credCount := map[string]int{}
	var lastCmd string
	seenURL := map[string]bool{}
	seenReq := map[string]bool{}
	seenPayload := map[string]bool{}
	firstPayload := map[string]bool{} // one raw sample per non-HTTP flow
	for _, pk := range s.Packets {
		if !pk.ToLocal || len(pk.Payload) == 0 {
			continue
		}
		if httpPort(pk.LocPort) && len(pk.Payload) >= 14 {
			if m := reHTTPReq.FindSubmatch(pk.Payload[:min(len(pk.Payload), 512)]); m != nil {
				req := string(m[1]) + " " + string(m[2])
				if !seenReq[req] && len(f.HTTPRequests) < 100 {
					seenReq[req] = true
					f.HTTPRequests = append(f.HTTPRequests, req)
				}
				svc["http"] = true
				// body after the header block: where PHP and command-injection payloads live
				if i := strings.Index(string(pk.Payload), "\r\n\r\n"); i >= 0 && i+4 < len(pk.Payload) {
					if body := printable(pk.Payload[i+4:], 300); body != "" && !seenPayload[body] && len(f.Payloads) < 50 {
						seenPayload[body] = true
						f.Payloads = append(f.Payloads, body)
					}
				}
				continue
			}
		}
		// non-HTTP (or non-request) payload: keep the first sample per flow
		fk := fmt.Sprintf("%d/%d>%d", pk.Proto, pk.RemPort, pk.LocPort)
		if firstPayload[fk] || pk.LocPort == 22 || pk.LocPort == 2222 {
			continue // SSH is encrypted after the banner; Cowrie's log covers it
		}
		firstPayload[fk] = true
		if p := printable(pk.Payload, 200); p != "" && !seenPayload[p] && len(f.Payloads) < 50 {
			seenPayload[p] = true
			f.Payloads = append(f.Payloads, p)
		}
	}
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
	delete(credCount, ":") // VNC and NTLM logins carry no username or password
	f.TopCreds = topN(credCount, 5)

	r := Result{Facts: f}
	r.Class, r.Score = classify(s, f, opt)
	r.Tags = tags(r.Class, f)
	r.Fingerprint = fingerprint(r.Class, f)
	r.Family = family(r.Class, f)
	return r
}

func classify(s *session.Session, f Facts, opt Options) (string, int) {
	hasShell := len(f.Commands) > 0
	hasTelnet := contains(f.Services, "telnet")
	hasSSH := contains(f.Services, "ssh")
	switch {
	case len(f.URLs) > 0 && hasShell:
		return MalwareDownload, 95
	case webExploit(f, opt):
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
	case len(f.HTTPRequests) > 0:
		return ServiceProbe, 40 + min(len(f.HTTPRequests), 10)
	case f.LoginAttempts >= 3:
		if hasTelnet && !hasSSH {
			return TelnetIoT, 35
		}
		if !hasSSH {
			return LoginBruteforce, 30 + min(f.LoginAttempts/20, 10)
		}
		return SSHBruteforce, 30 + min(f.LoginAttempts/20, 10)
	case len(s.LocalPorts) == 1 && s.TotalPkts >= 8 && !hasSSH && !hasTelnet:
		// one service, real payload exchanged, no honeypot log: a probe of
		// a service we only capture (redis, mysql, smb...). With nothing
		// readable in it (an SMB negotiate, a TDS prelogin) it is a scanner
		// and scores below min_score: the baseline and new families keep it
		// represented.
		if len(f.Payloads) == 0 {
			return ServiceProbe, 35
		}
		return ServiceProbe, 45
	default:
		// score scans by breadth: 1 port = noise, 20 ports = a proper sweep
		return ScanOnly, min(10+len(s.LocalPorts)*2, 30)
	}
}

func webExploit(f Facts, opt Options) bool {
	if !contains(f.Services, "http") && !contains(f.Services, "http-alt") {
		return false
	}
	match := func(s string) bool {
		if reExploit.MatchString(s) {
			return true
		}
		for _, re := range opt.ExploitPatterns {
			if re.MatchString(s) {
				return true
			}
		}
		return false
	}
	for _, list := range [][]string{f.Commands, f.HTTPRequests, f.Payloads, f.URLs} {
		for _, s := range list {
			if match(s) {
				return true
			}
		}
	}
	return false
}

// family is the coarse scenario key: class, service set, and only the
// command verbs (first word of each command) or the set of request paths
// without query strings. Variants of one campaign that differ in arguments,
// file names or parameters share a family.
func family(class string, f Facts) string {
	var b strings.Builder
	b.WriteString(class)
	b.WriteString("|")
	b.WriteString(strings.Join(f.Services, ","))
	b.WriteString("|")
	verbs := map[string]bool{}
	for _, c := range f.Commands {
		for _, part := range strings.FieldsFunc(c, func(r rune) bool { return r == ';' || r == '|' || r == '&' }) {
			fs := strings.Fields(part)
			if len(fs) > 0 {
				verbs[strings.ToLower(fs[0])] = true
			}
		}
	}
	paths := map[string]bool{}
	for _, r := range f.HTTPRequests {
		fs := strings.Fields(r)
		if len(fs) == 2 {
			path := fs[1]
			if i := strings.IndexByte(path, '?'); i >= 0 {
				path = path[:i]
			}
			paths[Normalise(path)] = true
		}
	}
	b.WriteString(strings.Join(sortedKeys(verbs), ","))
	b.WriteString("|")
	b.WriteString(strings.Join(sortedKeys(paths), ","))
	if class == ScanOnly || class == ServiceProbe {
		ports := append([]int{}, f.LocalPorts...)
		sort.Ints(ports)
		b.WriteString(fmt.Sprint(ports))
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:6])
}

// Templates returns the normalised request paths and command templates of a
// result, the units the novelty check works on.
func (r Result) Templates() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, req := range r.Facts.HTTPRequests {
		fs := strings.Fields(req)
		if len(fs) == 2 {
			path := fs[1]
			if i := strings.IndexByte(path, '?'); i >= 0 {
				path = path[:i]
			}
			add("http:" + Normalise(path))
		}
	}
	for _, c := range r.Facts.Commands {
		add("cmd:" + Normalise(c))
	}
	if payloadsIdentify(r.Facts) {
		for _, p := range r.Facts.Payloads {
			add("payload:" + Normalise(p))
		}
	}
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// printable returns the payload as text if it is mostly printable, cut to n
// bytes, else "" (binary protocols are left to PcapHub's dissector).
func printable(b []byte, n int) string {
	if len(b) > n {
		b = b[:n]
	}
	good := 0
	for _, c := range b {
		if (c >= 0x20 && c < 0x7f) || c == '\n' || c == '\r' || c == '\t' {
			good++
		}
	}
	if len(b) == 0 || good*10 < len(b)*8 {
		return ""
	}
	var sb strings.Builder
	for _, c := range b {
		if c >= 0x20 && c < 0x7f {
			sb.WriteByte(c)
		} else {
			sb.WriteByte(' ')
		}
	}
	return strings.TrimSpace(reSpaces.ReplaceAllString(sb.String(), " "))
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
	b.WriteString("|")
	reqs := make([]string, 0, len(f.HTTPRequests))
	for _, r := range f.HTTPRequests {
		reqs = append(reqs, Normalise(r))
	}
	sort.Strings(reqs)
	b.WriteString(strings.Join(reqs, ";"))
	b.WriteString("|")
	if payloadsIdentify(f) {
		pays := make([]string, 0, len(f.Payloads))
		for _, p := range f.Payloads {
			pays = append(pays, Normalise(p))
		}
		sort.Strings(pays)
		b.WriteString(strings.Join(pays, ";"))
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

// payloadsIdentify reports whether the printable payload samples say
// something about the attacker's intent. They do when the session carries
// requests or commands (HTTP paths, Redis or shell commands and their POST
// bodies). A bare connect to RDP, MSSQL or SMB has only the protocol
// handshake: a client cookie or prelogin that changes with every tool and
// run, which would make one probe look like a dozen scenarios.
func payloadsIdentify(f Facts) bool {
	return len(f.HTTPRequests) > 0 || len(f.Commands) > 0
}

// Normalise masks the parts of a command line that change per victim or per
// run: IP addresses, long hex strings (hashes), long numbers, and any token
// carrying two or more digits (random file names like .x8f2k1, PIDs, ports).
// Architecture tokens (x86_64, aarch64, mips64...) are kept because they
// distinguish bot variants.
func Normalise(s string) string {
	s = strings.TrimSpace(s)
	s = reSpaces.ReplaceAllString(s, " ")
	for i, arch := range archTokens {
		s = strings.ReplaceAll(s, arch, archPlaceholders[i])
	}
	s = reIPv4.ReplaceAllString(s, "IP")
	s = reHex.ReplaceAllString(s, "HEX")
	s = reNum.ReplaceAllString(s, "N")
	s = reToken.ReplaceAllStringFunc(s, func(tok string) string {
		digits := 0
		for _, r := range tok {
			if r >= '0' && r <= '9' {
				digits++
			}
		}
		if digits >= 2 {
			return "RND"
		}
		return tok
	})
	for i, arch := range archTokens {
		s = strings.ReplaceAll(s, archPlaceholders[i], arch)
	}
	return strings.ToLower(s)
}

var (
	archTokens       = []string{"x86_64", "aarch64", "armv7l", "armv6l", "armv5l", "mips64el", "mips64", "mipsel", "i686", "i586", "i386", "arm7", "arm6", "arm5", "arm4", "sh4", "m68k", "ppc", "spc"}
	archPlaceholders = func() []string {
		out := make([]string, len(archTokens))
		for i := range archTokens {
			out[i] = fmt.Sprintf("\x00ARCH%c\x00", 'A'+i)
		}
		return out
	}()
	reToken = regexp.MustCompile(`[A-Za-z0-9_.-]+`)
)

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
		tok = strings.Trim(tok, `"';`+"`")
		if strings.HasPrefix(tok, "http://") || strings.HasPrefix(tok, "https://") || strings.HasPrefix(tok, "ftp://") || strings.HasPrefix(tok, "tftp://") {
			out = append(out, tok)
		}
	}
	return out
}

func httpPort(p int) bool {
	switch p {
	case 80, 81, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 7547, 2375, 9200, 5601:
		return true
	}
	return false
}

// ServiceName is the honeypot service usually behind a port, "" if unknown.
func ServiceName(port int) string { return serviceName(port) }

func serviceName(port int) string {
	switch port {
	case 22, 2222:
		return "ssh"
	case 23, 2223:
		return "telnet"
	case 80, 81, 8080, 8000, 8008, 8081, 8088, 8888, 9000, 9090, 443, 8443, 7547:
		return "http"
	case 2375:
		return "docker"
	case 5601:
		return "kibana"
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
