package honeylog

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func cowrieLineAt(ts time.Time, ip string) string {
	return fmt.Sprintf(`{"eventid":"cowrie.session.connect","timestamp":"%s","src_ip":"%s","src_port":4000,"dst_port":22,"session":"s","protocol":"ssh"}`+"\n",
		ts.UTC().Format("2006-01-02T15:04:05.000000Z"), ip)
}

// Rotated files last written before the window are not opened and events
// before the window are dropped; a zero window reads everything.
func TestReadFilesSinceSkipsOldRotations(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "cowrie.json")
	now := time.Date(2026, 11, 26, 10, 0, 0, 0, time.UTC)

	// an old rotated day: one line, mtime a week ago
	old := live + ".2026-11-18"
	os.WriteFile(old, []byte(cowrieLineAt(now.Add(-8*24*time.Hour), "198.51.100.1")), 0o600)
	os.Chtimes(old, now.Add(-7*24*time.Hour), now.Add(-7*24*time.Hour))
	// yesterday's rotation, written until midnight: one event each side of the window
	yday := live + ".2026-11-25"
	os.WriteFile(yday, []byte(cowrieLineAt(now.Add(-20*time.Hour), "198.51.100.2")+cowrieLineAt(now.Add(-30*time.Minute), "198.51.100.3")), 0o600)
	os.Chtimes(yday, now.Add(-10*time.Minute), now.Add(-10*time.Minute))
	// the live file: one event inside the window, mtime far in the past
	// (it must be read regardless)
	os.WriteFile(live, []byte(cowrieLineAt(now.Add(-time.Minute), "198.51.100.4")), 0o600)
	os.Chtimes(live, now.Add(-7*24*time.Hour), now.Add(-7*24*time.Hour))

	all, err := ReadCowrieFiles(live)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 4 {
		t.Fatalf("unbounded read: %d events, want 4", len(all))
	}

	evs, err := ReadCowrieFilesSince(live, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 {
		t.Fatalf("windowed read: %d events, want 2: %+v", len(evs), evs)
	}
	if evs[0].SrcIP.String() != "198.51.100.3" || evs[1].SrcIP.String() != "198.51.100.4" {
		t.Fatalf("wrong events kept or order: %s, %s", evs[0].SrcIP, evs[1].SrcIP)
	}
}
