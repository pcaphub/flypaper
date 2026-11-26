package honeylog

import (
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// readFiles reads the live log and its rotated siblings (cowrie.json,
// cowrie.json.2026-11-17, beelzebub.log.1.gz, ...) with one parser and
// returns the events at or after from, sorted by time.
//
// A rotated file whose last write predates from is not opened at all, and
// events before from are dropped file by file, so a pass holds only the
// events of the hours it is about to slice. Reading every file since install
// is what took the collector past its memory limit after a week (Cowrie keeps
// its daily files forever and writes one line per password guess). A zero
// from reads everything.
func readFiles(live string, from time.Time, parse func(io.Reader) ([]Event, error)) ([]Event, error) {
	matches, _ := filepath.Glob(live + "*")
	var all []Event
	for _, m := range matches {
		if !from.IsZero() && m != live {
			st, err := os.Stat(m)
			if err != nil || st.ModTime().Before(from) {
				continue
			}
		}
		f, err := os.Open(m)
		if err != nil {
			continue
		}
		var r io.Reader = f
		if strings.HasSuffix(m, ".gz") {
			gz, err := gzip.NewReader(f)
			if err != nil {
				f.Close()
				continue
			}
			r = gz
		}
		evs, err := parse(r)
		f.Close()
		if err != nil {
			return nil, err
		}
		all = append(all, since(evs, from)...)
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	return all, nil
}

// since keeps the events at or after from, in place.
func since(evs []Event, from time.Time) []Event {
	if from.IsZero() {
		return evs
	}
	kept := evs[:0]
	for _, e := range evs {
		if !e.Time.Before(from) {
			kept = append(kept, e)
		}
	}
	// let the dropped tail be collected
	for i := len(kept); i < len(evs); i++ {
		evs[i] = Event{}
	}
	return kept
}

// ReadCowrieFiles reads the live Cowrie log and its rotated siblings.
func ReadCowrieFiles(live string) ([]Event, error) { return ReadCowrieFilesSince(live, time.Time{}) }

// ReadCowrieFilesSince reads the Cowrie events at or after from.
func ReadCowrieFilesSince(live string, from time.Time) ([]Event, error) {
	return readFiles(live, from, ReadCowrie)
}

// ReadOpenCanaryFiles reads the live OpenCanary log and its rotated siblings.
func ReadOpenCanaryFiles(live string) ([]Event, error) {
	return ReadOpenCanaryFilesSince(live, time.Time{})
}

// ReadOpenCanaryFilesSince reads the OpenCanary events at or after from.
func ReadOpenCanaryFilesSince(live string, from time.Time) ([]Event, error) {
	return readFiles(live, from, ReadOpenCanary)
}

// ReadBeelzebubFiles reads the live Beelzebub log and its rotated siblings,
// gzip-compressed ones included.
func ReadBeelzebubFiles(live string) ([]Event, error) {
	return ReadBeelzebubFilesSince(live, time.Time{})
}

// ReadBeelzebubFilesSince reads the Beelzebub events at or after from.
func ReadBeelzebubFilesSince(live string, from time.Time) ([]Event, error) {
	return readFiles(live, from, ReadBeelzebub)
}
