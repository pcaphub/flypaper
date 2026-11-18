// Package upgrade replaces the running flypaper binary with a release from
// GitHub: look up the tag (latest or given), download the binary for this
// architecture and the SHA256SUMS file, verify, swap atomically, restart
// the service.
package upgrade

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Repo is the only place binaries are fetched from.
const Repo = "pcaphub/flypaper"

const maxBinary = 64 << 20 // a release binary is ~9 MB

// Options for Run.
type Options struct {
	Version string // "" or "latest" resolves the newest release; otherwise a tag like v0.1.2
	Current string // running version, to skip a no-op
	Service string // systemd unit to restart after the swap, "" to skip
	Target  string // path to replace, default os.Executable()
	Log     func(format string, a ...any)
}

// Run performs the upgrade and returns the installed tag.
func Run(ctx context.Context, opt Options) (string, error) {
	if opt.Log == nil {
		opt.Log = func(string, ...any) {}
	}
	client := &http.Client{Timeout: 5 * time.Minute}

	tag := opt.Version
	if tag == "" || tag == "latest" {
		var err error
		if tag, err = latestTag(ctx, client); err != nil {
			return "", err
		}
	}
	if !strings.HasPrefix(tag, "v") || strings.ContainsAny(tag, "/ \\") {
		return "", fmt.Errorf("refusing tag %q", tag)
	}
	if tag == opt.Current {
		opt.Log("already on %s", tag)
		return tag, nil
	}

	target := opt.Target
	if target == "" {
		exe, err := os.Executable()
		if err != nil {
			return "", err
		}
		if target, err = filepath.EvalSymlinks(exe); err != nil {
			return "", err
		}
	}

	name := "flypaper_linux_" + runtime.GOARCH
	base := "https://github.com/" + Repo + "/releases/download/" + tag + "/"
	opt.Log("downloading %s %s", tag, name)
	sums, err := fetch(ctx, client, base+"SHA256SUMS", 64<<10)
	if err != nil {
		return "", fmt.Errorf("checksums: %w", err)
	}
	want, err := sumFor(string(sums), name)
	if err != nil {
		return "", err
	}
	bin, err := fetch(ctx, client, base+name, maxBinary)
	if err != nil {
		return "", fmt.Errorf("binary: %w", err)
	}
	got := sha256.Sum256(bin)
	if hex.EncodeToString(got[:]) != want {
		return "", fmt.Errorf("checksum mismatch for %s: downloaded %x, release says %s", name, got[:8], want[:16])
	}

	// write next to the target and rename over it: the running process keeps
	// its old inode, the next start gets the new file
	tmp, err := os.CreateTemp(filepath.Dir(target), ".flypaper-upgrade-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return "", fmt.Errorf("replace %s: %w (run as root?)", target, err)
	}
	opt.Log("installed %s to %s", tag, target)

	if opt.Service != "" {
		if _, err := exec.LookPath("systemctl"); err == nil {
			out, err := exec.CommandContext(ctx, "systemctl", "restart", opt.Service).CombinedOutput()
			if err != nil {
				return tag, fmt.Errorf("restart %s: %v: %s", opt.Service, err, strings.TrimSpace(string(out)))
			}
			opt.Log("restarted %s", opt.Service)
		}
	}
	return tag, nil
}

func latestTag(ctx context.Context, client *http.Client) (string, error) {
	b, err := fetch(ctx, client, "https://api.github.com/repos/"+Repo+"/releases/latest", 1<<20)
	if err != nil {
		return "", fmt.Errorf("latest release: %w", err)
	}
	var rel struct {
		Tag string `json:"tag_name"`
	}
	if err := json.Unmarshal(b, &rel); err != nil || rel.Tag == "" {
		return "", errors.New("latest release: no tag_name in response")
	}
	return rel.Tag, nil
}

func fetch(ctx context.Context, client *http.Client, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "flypaper-upgrade")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, limit)
	}
	return b, nil
}

// sumFor finds the hex digest for name in sha256sum output ("<hex>  <name>").
func sumFor(sums, name string) (string, error) {
	for _, line := range strings.Split(sums, "\n") {
		fs := strings.Fields(line)
		if len(fs) == 2 && strings.TrimPrefix(fs[1], "*") == name && len(fs[0]) == 64 {
			return strings.ToLower(fs[0]), nil
		}
	}
	return "", fmt.Errorf("no checksum for %s in SHA256SUMS", name)
}
