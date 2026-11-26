package main

import (
	"log/slog"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

// applyMemoryLimit points the Go garbage collector at the unit's cgroup
// memory cap (MemoryMax in the service file) so it collects hard as the cap
// nears instead of letting the heap grow into an OOM kill. GOMEMLIMIT in the
// environment wins, the runtime already honours it.
func applyMemoryLimit(log *slog.Logger) {
	if os.Getenv("GOMEMLIMIT") != "" {
		return
	}
	limit := cgroupMemoryMax()
	if limit <= 0 {
		return
	}
	soft := limit / 10 * 8
	debug.SetMemoryLimit(soft)
	log.Info("memory limit from cgroup", "cgroup_bytes", limit, "go_limit_bytes", soft)
}

// cgroupMemoryMax reads memory.max of this process's cgroup (v2). 0 when there
// is none or it is "max".
func cgroupMemoryMax() int64 {
	self, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return 0
	}
	var path string
	for _, line := range strings.Split(string(self), "\n") {
		// "0::/system.slice/flypaper.service"
		if rest, ok := strings.CutPrefix(line, "0::"); ok {
			path = rest
			break
		}
	}
	if path == "" {
		return 0
	}
	b, err := os.ReadFile("/sys/fs/cgroup" + path + "/memory.max")
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
