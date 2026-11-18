package honeylog

import (
	"strings"
	"testing"
)

// Two lines as written by Beelzebub v3.10.0 (logrus JSON, event nested).
const bzSample = `{"commands":23,"level":"info","msg":"Init service: WordPress 6.9.4","port":":80"}
{"event":{"DateTime":"2026-11-18T10:57:54Z","RemoteAddr":"198.51.100.7:47096","Protocol":"HTTP","Command":"","Status":"Stateless","Msg":"HTTP New request","ID":"798ecb49","Headers":"[Key: Content-Type, values: application/x-www-form-urlencoded],","HeadersMap":{"Content-Length":["15"]},"UserAgent":"curl/8.5.0","HostHTTPRequest":"203.0.113.10","Body":"log=admin&pwd=x","HTTPMethod":"POST","RequestURI":"/wp-login.php","Description":"WordPress 6.9.4","SourceIp":"198.51.100.7","SourcePort":"47096"},"level":"info","msg":"New Event","status":"Stateless"}
{"event":{"DateTime":"2026-11-18T10:57:55Z","RemoteAddr":"198.51.100.7:47104","Protocol":"HTTP","Body":"a=1&b=<?php echo 1; ?>","HTTPMethod":"POST","RequestURI":"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php","Description":"WordPress 6.9.4","SourceIp":"198.51.100.7","SourcePort":"47104"},"level":"info","msg":"New Event","status":"Stateless"}
`

func TestReadBeelzebub(t *testing.T) {
	evs, err := ReadBeelzebub(strings.NewReader(bzSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("got %d events: %+v", len(evs), evs)
	}
	e := evs[1]
	if e.Kind != "request" || e.Service != "http" || e.Source != "beelzebub" {
		t.Errorf("kind/service/source: %+v", e)
	}
	if e.Input != "POST /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php" {
		t.Errorf("input %q", e.Input)
	}
	if e.Message != "a=1&b=<?php echo 1; ?>" {
		t.Errorf("body %q", e.Message)
	}
	if e.SrcIP.String() != "198.51.100.7" || e.SrcPort != 47104 || e.Time.Format("15:04:05") != "10:57:55" {
		t.Errorf("source/time: %+v", e)
	}
}
