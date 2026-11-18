package describe

import (
	"testing"

	"github.com/pcaphub/flypaper/internal/classify"
)

func TestHumanClassNamesTheSprayedService(t *testing.T) {
	cases := map[string][]string{
		"VNC password spray":   {"tcp", "vnc"},
		"MSSQL password spray": {"mssql"},
		"password spray":       {"tcp"},
		"SSH brute force":      nil,
	}
	for want, services := range cases {
		class := classify.LoginBruteforce
		if want == "SSH brute force" {
			class = classify.SSHBruteforce
		}
		if got := humanClass(class, services); got != want {
			t.Errorf("humanClass(%s, %v) = %q, want %q", class, services, got, want)
		}
	}
}
