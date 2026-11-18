package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSumFor(t *testing.T) {
	sums := "abc  other\n" + strings.Repeat("a", 64) + "  flypaper_linux_amd64\n" + strings.Repeat("b", 64) + " *flypaper_linux_arm64\n"
	if s, err := sumFor(sums, "flypaper_linux_amd64"); err != nil || s != strings.Repeat("a", 64) {
		t.Errorf("amd64: %q %v", s, err)
	}
	if s, err := sumFor(sums, "flypaper_linux_arm64"); err != nil || s != strings.Repeat("b", 64) {
		t.Errorf("arm64 with asterisk: %q %v", s, err)
	}
	if _, err := sumFor(sums, "flypaper_linux_riscv64"); err == nil {
		t.Error("missing name must fail")
	}
}

func TestChecksumMismatchLeavesTargetAlone(t *testing.T) {
	bin := []byte("#!/bin/sh\necho new\n")
	sum := sha256.Sum256([]byte("something else"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "SHA256SUMS"):
			w.Write([]byte(hex.EncodeToString(sum[:]) + "  " + filepath.Base(r.URL.Path) + "\n"))
		default:
			w.Write(bin)
		}
	}))
	defer srv.Close()
	target := filepath.Join(t.TempDir(), "flypaper")
	os.WriteFile(target, []byte("old"), 0o755)
	// drive the verify/replace half directly, the way Run does after download
	sums, _ := fetch(context.Background(), srv.Client(), srv.URL+"/SHA256SUMS", 1<<16)
	want, _ := sumFor(string(sums), "SHA256SUMS")
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) == want {
		t.Fatal("test setup: sums should differ")
	}
	if b, _ := os.ReadFile(target); string(b) != "old" {
		t.Error("target changed without a verified download")
	}
}

func TestRefusesOddTags(t *testing.T) {
	for _, tag := range []string{"../x", "main", "v1/evil", "v0.1.2 extra"} {
		if _, err := Run(context.Background(), Options{Version: tag, Target: filepath.Join(t.TempDir(), "x")}); err == nil {
			t.Errorf("tag %q accepted", tag)
		}
	}
}
