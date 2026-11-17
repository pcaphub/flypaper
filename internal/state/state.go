// Package state remembers what the collector has already done: which ring
// files were processed, which scenario fingerprints were uploaded and when,
// and how many uploads happened today. One JSON file, rewritten atomically.
package state

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Scenario is the record kept per fingerprint.
type Scenario struct {
	Class        string    `json:"class"`
	FirstSeen    time.Time `json:"first_seen"`
	LastSeen     time.Time `json:"last_seen"`
	Seen         int       `json:"seen"`
	IPs          []string  `json:"ips,omitempty"` // capped, for the distinct count
	IPCount      int       `json:"ip_count"`
	LastUpload   time.Time `json:"last_upload,omitempty"`
	CaptureID    string    `json:"capture_id,omitempty"` // representative on PcapHub
	Signatures   []string  `json:"signatures,omitempty"` // Suricata SIDs seen on uploads
	LastReported int       `json:"last_reported"`        // seen count at the last prevalence PATCH
}

// File is the persisted document.
type File struct {
	Version   int                  `json:"version"`
	Processed map[string]time.Time `json:"processed"` // ring file name -> when
	Scenarios map[string]*Scenario `json:"scenarios"` // fingerprint -> record
	Uploads   map[string]int       `json:"uploads"`   // "2006-01-02" -> count
	Baseline  map[string]int       `json:"baseline"`  // day -> baseline samples uploaded
	Sigs      map[string]bool      `json:"sigs"`      // Suricata SIDs ever seen from this collector
}

// Store is the in-memory copy with a path to save to.
type Store struct {
	mu   sync.Mutex
	path string
	F    File
}

const maxIPsPerScenario = 2000

// Open loads the store, creating an empty one if the file does not exist.
func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "state.json")}
	b, err := os.ReadFile(s.path)
	if err == nil {
		if err := json.Unmarshal(b, &s.F); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if s.F.Processed == nil {
		s.F.Processed = map[string]time.Time{}
	}
	if s.F.Scenarios == nil {
		s.F.Scenarios = map[string]*Scenario{}
	}
	if s.F.Uploads == nil {
		s.F.Uploads = map[string]int{}
	}
	if s.F.Baseline == nil {
		s.F.Baseline = map[string]int{}
	}
	if s.F.Sigs == nil {
		s.F.Sigs = map[string]bool{}
	}
	s.F.Version = 1
	return s, nil
}

// Save writes the file atomically (tmp + rename).
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// forget processed files older than 30 days so the map does not grow forever
	cut := time.Now().Add(-30 * 24 * time.Hour)
	for k, t := range s.F.Processed {
		if t.Before(cut) {
			delete(s.F.Processed, k)
		}
	}
	for k := range s.F.Uploads {
		if d, err := time.Parse("2006-01-02", k); err == nil && d.Before(cut) {
			delete(s.F.Uploads, k)
			delete(s.F.Baseline, k)
		}
	}
	b, err := json.MarshalIndent(&s.F, "", " ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// IsProcessed reports whether a ring file was handled already.
func (s *Store) IsProcessed(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.F.Processed[name]
	return ok
}

// MarkProcessed records a ring file as done.
func (s *Store) MarkProcessed(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.F.Processed[name] = time.Now()
}

// Observe records one sighting of a scenario and returns the record.
func (s *Store) Observe(fp, class, ip string, at time.Time) *Scenario {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc := s.F.Scenarios[fp]
	if sc == nil {
		sc = &Scenario{Class: class, FirstSeen: at}
		s.F.Scenarios[fp] = sc
	}
	sc.Seen++
	sc.LastSeen = at
	known := false
	for _, x := range sc.IPs {
		if x == ip {
			known = true
			break
		}
	}
	if !known {
		sc.IPCount++
		if len(sc.IPs) < maxIPsPerScenario {
			sc.IPs = append(sc.IPs, ip)
		}
	}
	return sc
}

// Scenario returns the record for a fingerprint, or nil.
func (s *Store) Scenario(fp string) *Scenario {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.F.Scenarios[fp]
}

// UploadsToday returns how many uploads were made on the given day.
func (s *Store) UploadsToday(day time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.F.Uploads[day.UTC().Format("2006-01-02")]
}

// BaselineToday returns how many baseline samples were uploaded that day.
func (s *Store) BaselineToday(day time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.F.Baseline[day.UTC().Format("2006-01-02")]
}

// RecordUpload stores a successful upload of a scenario.
func (s *Store) RecordUpload(fp, captureID string, at time.Time, baseline bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	day := at.UTC().Format("2006-01-02")
	s.F.Uploads[day]++
	if baseline {
		s.F.Baseline[day]++
	}
	if sc := s.F.Scenarios[fp]; sc != nil {
		sc.LastUpload = at
		sc.CaptureID = captureID
		sc.LastReported = sc.Seen
	}
}

// NewSignatures returns the SIDs not seen before from this collector and
// records them.
func (s *Store) NewSignatures(fp string, sids []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var fresh []string
	for _, sid := range sids {
		if !s.F.Sigs[sid] {
			s.F.Sigs[sid] = true
			fresh = append(fresh, sid)
		}
	}
	if sc := s.F.Scenarios[fp]; sc != nil {
		sc.Signatures = appendUnique(sc.Signatures, sids...)
	}
	return fresh
}

// Representatives returns scenarios whose seen count moved since the last
// prevalence update and that have a capture to update.
func (s *Store) Representatives() map[string]*Scenario {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]*Scenario{}
	for fp, sc := range s.F.Scenarios {
		if sc.CaptureID != "" && sc.Seen > sc.LastReported {
			out[fp] = sc
		}
	}
	return out
}

// MarkReported records that the prevalence line was refreshed.
func (s *Store) MarkReported(fp string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sc := s.F.Scenarios[fp]; sc != nil {
		sc.LastReported = sc.Seen
	}
}

func appendUnique(list []string, add ...string) []string {
	seen := map[string]bool{}
	for _, s := range list {
		seen[s] = true
	}
	for _, s := range add {
		if !seen[s] {
			seen[s] = true
			list = append(list, s)
		}
	}
	return list
}
