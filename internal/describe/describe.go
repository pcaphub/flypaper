// Package describe builds the title, tags and description of an uploaded
// capture from the classification facts. Every sentence comes from something
// observed; nothing is guessed. URLs and IPs an attacker supplied are
// defanged (hxxp, [.]) so the description is safe to paste anywhere.
package describe

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pcaphub/flypaper/internal/classify"
	"github.com/pcaphub/flypaper/internal/session"
)

// Meta is what goes to PcapHub.
type Meta struct {
	Title       string
	Description string
	Tags        []string
}

// Input bundles what the describer needs.
type Input struct {
	Session   *session.Session
	Result    classify.Result
	Collector string // config name
	Region    string
	ExtraTags []string
	// Seen counts for the prevalence line (0 = first sighting).
	SeenBefore int
	SeenIPs    int
	FirstSeen  time.Time
	// Collector-wide counters for the dedupe footer.
	SessionsSeen int
	Uploaded     int
}

const maxTags = 10

// Build renders the metadata.
func Build(in Input) Meta {
	s, r, f := in.Session, in.Result, in.Result.Facts

	title := Title(r, s)

	var b strings.Builder
	// The collector's name stays out of public text (it maps to one host);
	// the region is coarse enough to keep.
	b.WriteString("Honeypot session captured by a flypaper collector")
	if in.Region != "" {
		fmt.Fprintf(&b, " (%s)", in.Region)
	}
	fmt.Fprintf(&b, " on %s UTC.\n\n", s.Start.UTC().Format("2006-01-02 15:04:05"))

	fmt.Fprintf(&b, "Attacker %s, %d packets over %s", Defang(s.Remote.String()), len(s.Packets), humanDuration(s.Duration()))
	if s.Truncated {
		fmt.Fprintf(&b, " (trimmed from %d packets to keep the capture small)", s.TotalPkts)
	}
	b.WriteString(".\n")
	if len(f.LocalPorts) > 0 {
		fmt.Fprintf(&b, "Ports touched: %s.\n", portList(f.LocalPorts))
	}
	if len(f.Services) > 0 {
		fmt.Fprintf(&b, "Services: %s.\n", strings.Join(f.Services, ", "))
	}
	if f.ClientVersion != "" {
		fmt.Fprintf(&b, "Client banner: %s\n", clean(f.ClientVersion))
	}

	b.WriteString("\n## What happened\n\n")
	switch r.Class {
	case classify.ScanOnly:
		b.WriteString("Connection attempts only, no login or payload recorded by the honeypots. ")
		if len(f.LocalPorts) > 3 {
			b.WriteString("Several ports in one window, consistent with a port sweep.")
		}
		b.WriteString("\n")
	case classify.ServiceProbe:
		fmt.Fprintf(&b, "A probe of %s with payload exchanged; see the stream for the protocol handshake and any commands.\n", strings.Join(f.Services, ", "))
	case classify.ServiceExploit:
		fmt.Fprintf(&b, "Commands sent to %s match a known abuse pattern (for example writing files through the service's configuration or loading a module); the honeypot emulates the service and executed nothing.\n", strings.Join(f.Services, ", "))
	}
	if f.LoginAttempts > 0 {
		fmt.Fprintf(&b, "%d login attempts", f.LoginAttempts)
		if len(f.LoginSuccess) > 0 {
			fmt.Fprintf(&b, ", %d accepted by the honeypot", len(f.LoginSuccess))
		}
		b.WriteString(".\n")
	}
	if len(f.TopCreds) > 0 {
		fmt.Fprintf(&b, "Most tried credentials: %s.\n", strings.Join(quoteAll(f.TopCreds), ", "))
	}
	if len(f.LoginSuccess) > 0 {
		fmt.Fprintf(&b, "Accepted credentials: %s.\n", strings.Join(quoteAll(f.LoginSuccess), ", "))
	}
	if len(f.Commands) > 0 {
		fmt.Fprintf(&b, "\n%d command(s) or queries recorded by the honeypots:\n\n```\n", len(f.Commands))
		for i, c := range f.Commands {
			if i >= 40 {
				fmt.Fprintf(&b, "... %d more\n", len(f.Commands)-i)
				break
			}
			b.WriteString(clean(Defang(c)))
			b.WriteString("\n")
		}
		b.WriteString("```\n")
	}
	if len(f.HTTPRequests) > 0 {
		fmt.Fprintf(&b, "\n%d HTTP request(s) seen on the wire:\n\n```\n", len(f.HTTPRequests))
		for i, r := range f.HTTPRequests {
			if i >= 30 {
				fmt.Fprintf(&b, "... %d more\n", len(f.HTTPRequests)-i)
				break
			}
			b.WriteString(clean(r))
			b.WriteString("\n")
		}
		b.WriteString("```\n")
	}
	if len(f.Payloads) > 0 {
		fmt.Fprintf(&b, "\n%d payload sample(s) (first bytes, printable only):\n\n```\n", len(f.Payloads))
		for i, p := range f.Payloads {
			if i >= 10 {
				fmt.Fprintf(&b, "... %d more\n", len(f.Payloads)-i)
				break
			}
			b.WriteString(clean(Defang(p)))
			b.WriteString("\n")
		}
		b.WriteString("```\n")
	}
	if len(f.URLs) > 0 {
		b.WriteString("\nDownload URLs (defanged):\n")
		for _, u := range f.URLs {
			fmt.Fprintf(&b, "- %s\n", clean(Defang(u)))
		}
	}
	if len(f.Hashes) > 0 {
		b.WriteString("\nSHA-256 of fetched files:\n")
		for _, h := range dedupe(f.Hashes) {
			fmt.Fprintf(&b, "- %s\n", clean(h))
		}
	}
	if len(f.Forwards) > 0 {
		fmt.Fprintf(&b, "\nSSH port-forward requests to: %s.\n", strings.Join(defangAll(dedupe(f.Forwards)), ", "))
	}

	b.WriteString("\n## Scenario\n\n")
	fmt.Fprintf(&b, "Class %s, score %d/100, scenario fingerprint %s, family %s. ", r.Class, r.Score, r.Fingerprint, r.Family)
	if len(r.Novel) > 0 {
		fmt.Fprintf(&b, "%d request or command template(s) never seen on this collector before. ", len(r.Novel))
	}
	if in.SeenBefore > 0 {
		fmt.Fprintf(&b, "This scenario has been seen %d times from %d addresses since %s; this capture is the representative copy.\n",
			in.SeenBefore+1, in.SeenIPs, in.FirstSeen.UTC().Format("2006-01-02"))
	} else {
		b.WriteString("First sighting of this scenario on this collector.\n")
	}
	if in.SessionsSeen >= ratioAfterSessions {
		fmt.Fprintf(&b, "Collector totals: %d sessions seen, %d uploaded (%.1f%%).\n", in.SessionsSeen, in.Uploaded+1, 100*float64(in.Uploaded+1)/float64(in.SessionsSeen))
	} else if in.SessionsSeen > 0 {
		// a fresh collector uploads most of what it sees; the ratio means
		// nothing until the scenario store has filled
		fmt.Fprintf(&b, "Collector totals: %d sessions seen, %d uploaded.\n", in.SessionsSeen, in.Uploaded+1)
	}
	b.WriteString("\nCollected on a low-interaction honeypot (Cowrie and OpenCanary); the attacker never reached a real system. Credentials shown were supplied by the attacker. Uploaded automatically by flypaper, reviewed before any public release.\n")

	desc := b.String()
	if len(desc) > 10000 {
		desc = desc[:9990] + "\n..."
	}

	tags := mergeTags(r.Tags, in.ExtraTags, in.Region)
	return Meta{Title: title, Description: desc, Tags: tags}
}

// Prevalence renders the one-line update used when a representative capture
// is refreshed with new counts.
func Prevalence(seen, ips int, first time.Time) string {
	return fmt.Sprintf("This scenario has been seen %d times from %d addresses since %s; this capture is the representative copy.",
		seen, ips, first.UTC().Format("2006-01-02"))
}

// Defang makes URLs and IP addresses unclickable: hxxp://, [.] in hosts and IPs.
func Defang(s string) string {
	s = strings.ReplaceAll(s, "http://", "hxxp://")
	s = strings.ReplaceAll(s, "https://", "hxxps://")
	s = strings.ReplaceAll(s, "ftp://", "fxp://")
	s = strings.ReplaceAll(s, "tftp://", "tfxp://")
	// dots inside IPv4 addresses and hostnames following a scheme or in a
	// bare address; keep it simple: every dot between alphanumerics in tokens
	// that look like hosts.
	out := make([]string, 0, 8)
	for _, tok := range strings.Split(s, " ") {
		if i := strings.Index(tok, "://"); i >= 0 {
			// scheme://host[:port]/path : bracket the host's dots only
			rest := tok[i+3:]
			end := strings.IndexAny(rest, "/?#")
			if end < 0 {
				end = len(rest)
			}
			tok = tok[:i+3] + strings.ReplaceAll(rest[:end], ".", "[.]") + rest[end:]
		} else if looksLikeHost(tok) {
			tok = strings.ReplaceAll(tok, ".", "[.]")
		}
		out = append(out, tok)
	}
	return strings.Join(out, " ")
}

func looksLikeHost(tok string) bool {
	digits, dots := 0, 0
	for _, r := range tok {
		switch {
		case r >= '0' && r <= '9':
			digits++
		case r == '.':
			dots++
		case r == ':' || r == '/' || r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z'):
		default:
			return false
		}
	}
	return dots >= 3 && digits >= 4 // IPv4-like
}

func defangAll(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = Defang(s)
	}
	return out
}

func quoteAll(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = "`" + clean(s) + "`"
	}
	return out
}

// clean strips control characters and anything that could be read as markup.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '<':
			b.WriteString("&lt;")
		case r == '>':
			b.WriteString("&gt;")
		case r < 0x20 || r == 0x7f:
			b.WriteByte(' ')
		default:
			b.WriteRune(r)
		}
	}
	if b.Len() > 500 {
		return b.String()[:500] + "..."
	}
	return b.String()
}

// ratioAfterSessions: show the upload percentage only once this many
// sessions were seen, same threshold as the pipeline's ratio guard.
const ratioAfterSessions = 200

func humanDuration(d time.Duration) string {
	switch {
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	case d < time.Minute:
		return fmt.Sprintf("%.0f s", d.Seconds())
	default:
		return fmt.Sprintf("%d min %d s", int(d.Minutes()), int(d.Seconds())%60)
	}
}

func portList(ports []int) string {
	p := append([]int{}, ports...)
	sort.Ints(p)
	parts := make([]string, 0, len(p))
	for i, x := range p {
		if i >= 20 {
			parts = append(parts, fmt.Sprintf("and %d more", len(p)-i))
			break
		}
		parts = append(parts, fmt.Sprint(x))
	}
	return strings.Join(parts, ", ")
}

func dedupe(list []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range list {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// mergeTags keeps PcapHub's rules: lowercase, hyphens, at most 10.
func mergeTags(base, extra []string, region string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(t string) {
		t = strings.ToLower(strings.TrimSpace(t))
		t = strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
				return r
			}
			return '-'
		}, t)
		t = strings.Trim(t, "-")
		if t == "" || seen[t] || len(out) >= maxTags {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	for _, t := range base {
		add(t)
	}
	for _, t := range extra {
		add(t)
	}
	if region != "" {
		add(region)
	}
	return out
}
