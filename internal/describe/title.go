package describe

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	"github.com/pcaphub/flypaper/internal/classify"
	"github.com/pcaphub/flypaper/internal/session"
)

// maxTitle keeps titles readable in PcapHub's cards and search results.
const maxTitle = 120

// Title says what the attacker did in the words a visitor would search for:
// the technique, the credentials, the paths, the tool. The collector, the
// date and the address are tags and the first line of the description, not
// the title.
func Title(r classify.Result, s *session.Session) string {
	f := r.Facts
	var t string
	switch r.Class {
	case classify.MalwareDownload:
		t = malwareTitle(f)
	case classify.WebExploit:
		t = exploitTitle(f)
	case classify.CommandsRun:
		t = fmt.Sprintf("%s session%s: %s", serviceLabel(primaryService(f, "ssh")), asUser(f), commandSummary(f.Commands, 3))
	case classify.ServiceExploit:
		t = fmt.Sprintf("%s exploit attempt: %s", serviceLabel(primaryService(f, "")), commandSummary(f.Commands, 3))
	case classify.TelnetIoT:
		switch {
		case len(f.Commands) > 0:
			t = fmt.Sprintf("Telnet IoT bot%s: %s", asUser(f), commandSummary(f.Commands, 3))
		case len(f.LoginSuccess) > 0:
			t = "Telnet login accepted" + asUser(f) + ", no commands"
		default:
			t = sprayTitle("Telnet", f)
		}
	case classify.PortForward:
		t = "SSH port forwarding attempt" + asUser(f)
		if len(f.Forwards) > 0 {
			t += " to " + Defang(f.Forwards[0])
		}
	case classify.SSHLoginSuccess:
		t = "SSH login accepted" + asUser(f) + ", no commands"
		if f.ClientVersion != "" {
			t += " (" + shortClient(f.ClientVersion) + ")"
		}
	case classify.SSHBruteforce:
		t = sprayTitle("SSH", f)
	case classify.LoginBruteforce:
		t = sprayTitle(serviceLabel(primaryService(f, "")), f)
	case classify.ServiceProbe:
		t = probeTitle(f)
	default: // scan-only
		t = scanTitle(f, s)
	}
	t = titleSafe(clean(t))
	if len(t) > maxTitle {
		cut := strings.LastIndexByte(t[:maxTitle-3], ' ')
		if cut < maxTitle/2 {
			cut = maxTitle - 3
		}
		t = t[:cut] + "..."
	}
	return t
}

// knownExploits names the technique behind a request path or payload so the
// title reads "PHPUnit eval-stdin RCE" instead of a 90-character URL. Only
// signatures that identify one thing are listed; everything else falls back
// to the request line itself.
var knownExploits = []struct {
	re   *regexp.Regexp
	name string
}{
	{regexp.MustCompile(`(?i)\$\{jndi:`), "Log4Shell JNDI injection (CVE-2021-44228)"},
	{regexp.MustCompile(`(?i)/SDK/webLanguage`), "Hikvision camera command injection (CVE-2021-36260)"},
	{regexp.MustCompile(`(?i)%2577eb%2575i|webui_wsma`), "Cisco IOS XE web UI authentication bypass (CVE-2023-20198)"},
	{regexp.MustCompile(`(?i)/\.well-known/pki-validation/`), "Webshell upload via pki-validation path"},
	// Cacti 1.2.31 "4HTTP2SHELL" (ek0ms savi0r, 2026-11-26, no CVE at the
	// time of writing): guest profile update stores SQL in
	// preview_graphs_per_page, graph preview runs it into poller_item.arg1,
	// graph_realtime pops the command. Step 1 is a plain GET of
	// auth_profile.php, listed last so a later step names the chain first.
	{regexp.MustCompile(`(?i)preview_graphs_per_page|UPDATE\s+poller_item|/graph_realtime\.php\?[^ ]*action=init`), "Cacti guest profile SQL injection to RCE (4HTTP2SHELL, Cacti 1.2.31)"},
	{regexp.MustCompile(`(?i)/auth_profile\.php`), "Cacti auth_profile.php guest access probe (4HTTP2SHELL step 1)"},
	{regexp.MustCompile(`(?i)/vendor/phpunit|/eval-stdin\.php`), "PHPUnit eval-stdin RCE (CVE-2017-9841)"},
	{regexp.MustCompile(`(?i)/think/app|invokefunction`), "ThinkPHP invokefunction RCE"},
	{regexp.MustCompile(`(?i)allow_url_include|auto_prepend_file|php://input`), "PHP-CGI argument injection to shell (CVE-2012-1823 / CVE-2024-4577)"},
	{regexp.MustCompile(`(?i)/GponForm/diag_Form`), "GPON router command injection (CVE-2018-10561)"},
	{regexp.MustCompile(`(?i)/boaform/admin/formLogin`), "Boa/Netlink router login probe (Mirai variant)"},
	{regexp.MustCompile(`(?i)/HNAP1`), "D-Link HNAP1 command injection"},
	{regexp.MustCompile(`(?i)/setup\.cgi\?`), "Netgear setup.cgi command injection"},
	{regexp.MustCompile(`(?i)/shell\?cd\+/tmp|/shell\?cd%20/tmp`), "JAWS webserver shell command injection"},
	{regexp.MustCompile(`(?i)/cgi-bin/luci`), "OpenWrt LuCI probe"},
	{regexp.MustCompile(`(?i)/manager/html`), "Tomcat manager login probe"},
	{regexp.MustCompile(`(?i)/actuator`), "Spring Boot Actuator exposure probe"},
	{regexp.MustCompile(`(?i)/_ignition/execute-solution`), "Laravel Ignition RCE (CVE-2021-3129)"},
	{regexp.MustCompile(`(?i)/solr/admin`), "Apache Solr admin probe"},
	{regexp.MustCompile(`(?i)/xmlrpc\.php`), "WordPress xmlrpc.php abuse"},
	{regexp.MustCompile(`(?i)/wp-login\.php|/wp-admin`), "WordPress login probe"},
	{regexp.MustCompile(`(?i)/\.git/`), "Exposed .git directory probe"},
	{regexp.MustCompile(`(?i)/\.env`), "Exposed .env secrets probe"},
	{regexp.MustCompile(`(?i)/etc/passwd|\.\./|%2e%2e`), "Path traversal attempt"},
	{regexp.MustCompile(`(?i)union\s+select|sleep\(\d`), "SQL injection attempt"},
	{regexp.MustCompile(`(?i)<\?php|eval\(|base64_decode|system\(|passthru\(|shell_exec\(`), "PHP code injection attempt"},
}

func exploitTitle(f classify.Facts) string {
	port := httpPortOf(f)
	for _, k := range knownExploits {
		for _, s := range append(append([]string{}, f.HTTPRequests...), f.Payloads...) {
			if k.re.MatchString(s) {
				return fmt.Sprintf("Web exploit attempt%s: %s", port, k.name)
			}
		}
	}
	if len(f.HTTPRequests) > 0 {
		return fmt.Sprintf("Web exploit attempt%s: %s", port, shortRequest(f.HTTPRequests[0], 70))
	}
	return "Web exploit attempt" + port
}

func malwareTitle(f classify.Facts) string {
	tool := "download"
	for _, c := range f.Commands {
		for _, t := range []string{"wget", "curl", "tftp", "ftpget"} {
			if strings.Contains(c, t+" ") || strings.HasPrefix(c, t) {
				tool = t
			}
		}
		if tool != "download" {
			break
		}
	}
	arch := archOf(append(append([]string{}, f.URLs...), f.Commands...))
	via := strings.ToUpper(primaryService(f, "ssh"))
	what := "payload"
	if arch != "" {
		what = arch + " binary"
	}
	t := fmt.Sprintf("%s bot drops %s via %s", via, what, tool)
	if len(f.URLs) > 0 {
		if h := hostOf(f.URLs[0]); h != "" {
			t += " from " + Defang(h)
		}
	}
	return t + asUser(f)
}

func probeTitle(f classify.Facts) string {
	svc := primaryService(f, "")
	port := ""
	if len(f.LocalPorts) == 1 {
		port = fmt.Sprintf(" on :%d", f.LocalPorts[0])
	}
	switch {
	case len(f.HTTPRequests) > 0 && isProxyRequest(f.HTTPRequests[0]):
		return fmt.Sprintf("Open proxy probe%s: %s", port, requestPaths(f.HTTPRequests, 1)[0])
	case len(f.HTTPRequests) > 0:
		paths := requestPaths(f.HTTPRequests, 3)
		more := ""
		if n := len(f.HTTPRequests) - 3; n > 0 {
			more = fmt.Sprintf(" (+%d)", n)
		}
		return fmt.Sprintf("HTTP probe%s: %s%s", port, strings.Join(paths, ", "), more)
	case len(f.Commands) > 0:
		return fmt.Sprintf("%s probe%s: %s", serviceLabel(svc), port, commandSummary(f.Commands, 3))
	}
	// handshake only: say which one, with the one readable detail if any
	switch svc {
	case "rdp":
		if c := cookieOf(f.Payloads, "mstshash="); c != "" {
			return fmt.Sprintf("RDP probe%s, connection cookie %q", port, c)
		}
		return "RDP connection probe" + port
	case "mssql":
		return "MSSQL TDS prelogin probe" + port
	case "smb":
		return "SMB negotiate probe" + port
	case "mysql":
		return "MySQL handshake probe" + port
	case "vnc":
		return "VNC RFB handshake probe" + port
	case "redis":
		return "Redis probe" + port
	case "":
		return "Service probe" + port
	}
	return serviceLabel(svc) + " probe" + port
}

// serviceLabel is the service name as people write it.
func serviceLabel(svc string) string {
	switch svc {
	case "ssh", "ftp", "vnc", "rdp", "http", "smb", "tftp", "snmp", "sip", "tcp", "dns", "sftp", "mssql", "upnp":
		return strings.ToUpper(svc)
	case "telnet":
		return "Telnet"
	case "redis":
		return "Redis"
	case "mysql":
		return "MySQL"
	case "mongodb":
		return "MongoDB"
	case "postgres":
		return "PostgreSQL"
	case "git":
		return "Git"
	case "docker":
		return "Docker API"
	case "kibana":
		return "Kibana"
	case "elasticsearch":
		return "Elasticsearch"
	case "memcached":
		return "Memcached"
	case "http-proxy":
		return "HTTP proxy"
	case "":
		return "Service"
	}
	return svc
}

// titleSafe keeps a title to printable ASCII: a run of anything else (raw
// protocol bytes in a Redis command, a NUL in a Telnet login) becomes one
// "?", and Cowrie's own backslash-x escapes are dropped.
func titleSafe(s string) string {
	s = reCowrieEscape.ReplaceAllString(s, "")
	var b strings.Builder
	junk := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f {
			b.WriteByte(c)
			junk = false
		} else if c == '\t' || c == '\n' || c == '\r' {
			b.WriteByte(' ')
		} else if !junk {
			b.WriteByte('?')
			junk = true
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

var reCowrieEscape = regexp.MustCompile(`\\x[0-9a-fA-F]{2}`)

func scanTitle(f classify.Facts, s *session.Session) string {
	ports := append([]int{}, f.LocalPorts...)
	sort.Ints(ports)
	switch {
	case len(ports) == 0:
		return "Connection attempts, no payload"
	case len(ports) == 1:
		name := classify.ServiceName(ports[0])
		if name != "" {
			name = " (" + strings.ToUpper(name) + ")"
		}
		n := len(s.Flows)
		if n <= 1 {
			return fmt.Sprintf("Single connection attempt to port %d%s", ports[0], name)
		}
		return fmt.Sprintf("%d connection attempts to port %d%s", n, ports[0], name)
	case len(ports) <= 6:
		return "Port sweep: " + joinInts(ports)
	}
	return fmt.Sprintf("Port sweep across %d ports (%s, ...)", len(ports), joinInts(ports[:5]))
}

func sprayTitle(svc string, f classify.Facts) string {
	if svc == "" {
		svc = "Credential"
	}
	t := fmt.Sprintf("%s brute force: %d login attempts", svc, f.LoginAttempts)
	if len(f.TopCreds) > 0 {
		creds := make([]string, 0, 2)
		for _, c := range f.TopCreds[:min(2, len(f.TopCreds))] {
			if strings.HasSuffix(c, ":") {
				c += "(empty)"
			}
			creds = append(creds, c)
		}
		t += ", " + strings.Join(creds, ", ")
	}
	if f.ClientVersion != "" {
		t += " (" + shortClient(f.ClientVersion) + ")"
	}
	return t
}

// asUser renders " as root:admin" from the accepted login, if any.
func asUser(f classify.Facts) string {
	if len(f.LoginSuccess) > 0 {
		return " as " + f.LoginSuccess[0]
	}
	return ""
}

// commandSummary lists the first n distinctive commands by their verb and
// first argument ("cat /proc/cpuinfo"), then "+k more".
func commandSummary(cmds []string, n int) string {
	var parts []string
	seen := map[string]bool{}
	for _, c := range cmds {
		fs := strings.Fields(c)
		if len(fs) == 0 {
			continue
		}
		p := fs[0]
		if i := strings.LastIndexByte(p, '/'); i >= 0 {
			p = p[i+1:]
		}
		if len(fs) > 1 && len(fs[1]) <= 24 && !strings.ContainsAny(fs[1], "|;&><") {
			p += " " + fs[1]
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		parts = append(parts, Defang(p))
		if len(parts) == n {
			break
		}
	}
	if len(cmds) > n {
		parts = append(parts, fmt.Sprintf("+%d more", len(cmds)-n))
	}
	return strings.Join(parts, ", ")
}

// primaryService picks the service the title should name, preferring the
// honeypot services over the bare "tcp" banner.
func primaryService(f classify.Facts, fallback string) string {
	for _, s := range f.Services {
		if s != "tcp" && s != "" {
			return s
		}
	}
	if len(f.Services) > 0 {
		return f.Services[0]
	}
	return fallback
}

func httpPortOf(f classify.Facts) string {
	if len(f.LocalPorts) == 1 && f.LocalPorts[0] != 80 {
		return fmt.Sprintf(" on :%d", f.LocalPorts[0])
	}
	return ""
}

// isProxyRequest: an absolute URL as the request target is a client asking
// us to fetch it, i.e. a check for an open proxy.
func isProxyRequest(req string) bool {
	fs := strings.Fields(req)
	return len(fs) >= 2 && (strings.HasPrefix(fs[1], "http://") || strings.HasPrefix(fs[1], "https://"))
}

func requestPaths(reqs []string, n int) []string {
	var out []string
	for _, r := range reqs {
		fs := strings.Fields(r)
		if len(fs) < 2 {
			continue
		}
		p := fs[1]
		if len(p) > 40 {
			p = p[:37] + "..."
		}
		out = append(out, p)
		if len(out) == n {
			break
		}
	}
	return out
}

func shortRequest(r string, n int) string {
	if len(r) > n {
		return r[:n-3] + "..."
	}
	return r
}

func shortClient(v string) string {
	v = strings.TrimPrefix(v, "SSH-2.0-")
	if len(v) > 30 {
		v = v[:27] + "..."
	}
	return v
}

var reArch = regexp.MustCompile(`(?i)\b(x86_64|x86|i[3-6]86|amd64|aarch64|arm64|armv[4-8]l?|arm[4-8]?|mips(?:el|64|64el)?|mpsl|m68k|sh4|sparc|ppc|powerpc|riscv64)\b`)

func archOf(strs []string) string {
	for _, s := range strs {
		if m := reArch.FindString(s); m != "" {
			return strings.ToLower(m)
		}
	}
	return ""
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Hostname()
}

// cookieOf extracts the value after a marker in the first payload holding it
// ("Cookie: mstshash=hello" -> "hello").
func cookieOf(payloads []string, marker string) string {
	for _, p := range payloads {
		if i := strings.Index(p, marker); i >= 0 {
			v := p[i+len(marker):]
			if j := strings.IndexAny(v, " \r\n\t;"); j >= 0 {
				v = v[:j]
			}
			if len(v) > 24 {
				v = v[:24]
			}
			return v
		}
	}
	return ""
}

func joinInts(ns []int) string {
	parts := make([]string, len(ns))
	for i, n := range ns {
		parts[i] = fmt.Sprint(n)
	}
	return strings.Join(parts, ", ")
}
