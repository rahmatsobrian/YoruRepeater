// Package traffic turns monotonic kernel counters into rates.
//
// Rates come from /sys/class/net/<if>/statistics deltas only. Two rules matter
// for correctness on Android: counters can reset (interface re-created after a
// Wi-Fi toggle) and the first sample after a restart is not a real measurement,
// so the tracker emits "unknown" for one tick rather than inventing a number.
package traffic

import (
	"sort"
	"sync"
	"time"

	"yoru.dev/yorud/internal/netinfo"
)

// Rate is one interface's derived throughput.
type Rate struct {
	Iface     string  `json:"iface"`
	RxBytes   uint64  `json:"rxBytesTotal"`
	TxBytes   uint64  `json:"txBytesTotal"`
	RxRate    float64 `json:"rxBytesPerSec"`
	TxRate    float64 `json:"txBytesPerSec"`
	RxPackets uint64  `json:"rxPacketsTotal"`
	TxPackets uint64  `json:"txPacketsTotal"`
	RxPPS     float64 `json:"rxPacketsPerSec"`
	TxPPS     float64 `json:"txPacketsPerSec"`
	RxErrors  uint64  `json:"rxErrors"`
	TxErrors  uint64  `json:"txErrors"`
	RxDropped uint64  `json:"rxDropped"`
	TxDropped uint64  `json:"txDropped"`
	Elapsed   float64 `json:"sampleWindowSec"`
	Valid     bool    `json:"valid"`
	Reset     bool    `json:"counterReset,omitempty"`
	SeenAt    int64   `json:"-"`
}

type sample struct {
	st   *netinfo.Stats
	at   time.Time
	gone bool
}

// Tracker keeps previous counters per interface.
type Tracker struct {
	mu    sync.Mutex
	prev  map[string]*sample
	dev   *netinfo.Device
	order []string
}

// NewTracker binds the rate tracker to a network device source.
func NewTracker(dev *netinfo.Device) *Tracker {
	return &Tracker{prev: map[string]*sample{}, dev: dev}
}

// Sample advances all counters and returns current rates.
func (t *Tracker) Sample(interfaces []string) map[string]Rate {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := map[string]Rate{}
	seen := map[string]bool{}
	for _, iface := range interfaces {
		seen[iface] = true
		st := netinfo.ReadStats(iface)
		if st == nil {
			continue
		}
		now := time.Now()
		r := Rate{
			Iface: iface, RxBytes: st.RxBytes, TxBytes: st.TxBytes,
			RxPackets: st.RxPackets, TxPackets: st.TxPackets,
			RxErrors: st.RxErrors, TxErrors: st.TxErrors,
			RxDropped: st.RxDropped, TxDropped: st.TxDropped,
		}
		p := t.prev[iface]
		if p != nil && p.st != nil {
			dt := now.Sub(p.at).Seconds()
			if dt > 0.05 {
				r.Elapsed = dt
				switch {
				case st.RxBytes < p.st.RxBytes || st.TxBytes < p.st.TxBytes:
					// Counter wrap or interface renumbering: report totals but no
					// rate, and tell the UI why.
					r.Reset = true
					r.Valid = false
				default:
					r.RxRate = float64(st.RxBytes-p.st.RxBytes) / dt
					r.TxRate = float64(st.TxBytes-p.st.TxBytes) / dt
					r.RxPPS = float64(st.RxPackets-p.st.RxPackets) / dt
					r.TxPPS = float64(st.TxPackets-p.st.TxPackets) / dt
					r.Valid = true
				}
			}
		}
		out[iface] = r
		t.prev[iface] = &sample{st: st, at: now}
	}
	// Forget interfaces that disappeared so a reappearing name never reports a
	// stale window.
	for name := range t.prev {
		if !seen[name] {
			delete(t.prev, name)
		}
	}
	t.order = t.order[:0]
	for k := range out {
		t.order = append(t.order, k)
	}
	sort.Strings(t.order)
	return out
}

// Aggregate sums rates across the given interfaces.
func Aggregate(rates map[string]Rate, interfaces ...string) Rate {
	var a Rate
	for _, i := range interfaces {
		r, ok := rates[i]
		if !ok {
			continue
		}
		a.RxBytes += r.RxBytes
		a.TxBytes += r.TxBytes
		a.RxPackets += r.RxPackets
		a.TxPackets += r.TxPackets
		a.RxErrors += r.RxErrors
		a.TxErrors += r.TxErrors
		a.RxDropped += r.RxDropped
		a.TxDropped += r.TxDropped
		if r.Valid {
			a.RxRate += r.RxRate
			a.TxRate += r.TxRate
			a.RxPPS += r.RxPPS
			a.TxPPS += r.TxPPS
			a.Valid = true
			if r.Elapsed > a.Elapsed {
				a.Elapsed = r.Elapsed
			}
		}
		a.Iface = i
	}
	if len(interfaces) == 1 {
		a.Iface = interfaces[0]
	} else if len(interfaces) > 1 {
		a.Iface = "aggregate"
	}
	return a
}

// FormatBytes renders a byte count with the unit that fits its magnitude.
func FormatBytes(b float64) string {
	switch {
	case b >= 1e12:
		return trim(b/1e12) + " TB"
	case b >= 1e9:
		return trim(b/1e9) + " GB"
	case b >= 1e6:
		return trim(b/1e6) + " MB"
	case b >= 1e3:
		return trim(b/1e3) + " kB"
	}
	return trim(b) + " B"
}

// FormatRate renders a bytes-per-second value.
func FormatRate(bps float64) string { return FormatBytes(bps) + "/s" }

// FormatBits renders a value in bits/s, the convention for link speed.
func FormatBits(bps float64) string {
	b := bps * 8
	switch {
	case b >= 1e9:
		return trim(b/1e9) + " Gbit/s"
	case b >= 1e6:
		return trim(b/1e6) + " Mbit/s"
	case b >= 1e3:
		return trim(b/1e3) + " kbit/s"
	}
	return trim(b) + " bit/s"
}

func trim(f float64) string {
	s := strconvFormat(f)
	if len(s) > 6 {
		s = s[:6]
	}
	return trimZero(s)
}

func trimZero(s string) string {
	if !containsDot(s) {
		return s
	}
	for len(s) > 1 && (s[len(s)-1] == '0' || s[len(s)-1] == '.') {
		s = s[:len(s)-1]
	}
	return s
}

func containsDot(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			return true
		}
	}
	return false
}
