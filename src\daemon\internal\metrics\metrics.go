// Package metrics keeps bounded in-memory histories for the charts.
//
// Two things matter here: memory must be fixed regardless of uptime (a phone
// left tethering for a week cannot leak), and a gap must never be smoothed over
// with invented data - if samples stop, the chart shows a gap.
package metrics

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Sample is one timestamped measurement series point.
type Sample struct {
	T int64              `json:"t"`
	V map[string]float64 `json:"v"`
}

// Series is a ring buffer of samples plus the key order for stable JSON.
type Series struct {
	mu    sync.Mutex
	name  string
	buf   []Sample
	pos   int
	full  bool
	cap   int
	keys  []string
	gapAt int64
}

// NewSeries allocates a ring of capacity n.
func NewSeries(name string, n int) *Series {
	if n < 2 {
		n = 60
	}
	return &Series{name: name, buf: make([]Sample, n), cap: n}
}

// Add appends one sample. Keys are tracked so the UI can draw a legend without
// guessing the shape of the data.
func (s *Series) Add(v map[string]float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixMilli()
	if !s.bufIsZero() && s.bufLatest().T > 0 && now-s.bufLatest().T > int64(s.interval()*2.5) {
		s.gapAt = now
	}
	cp := make(map[string]float64, len(v))
	for k, x := range v {
		if math.IsNaN(x) || math.IsInf(x, 0) {
			continue
		}
		cp[k] = x
	}
	for k := range cp {
		if !containsKey(s.keys, k) {
			s.keys = append(s.keys, k)
			sort.Strings(s.keys)
		}
	}
	s.buf[s.pos] = Sample{T: now, V: cp}
	s.pos++
	if s.pos >= s.cap {
		s.pos = 0
		s.full = true
	}
}

// interval is a nominal sampling period used only for gap detection.
func (s *Series) interval() float64 { return 2000 }

func (s *Series) bufIsZero() bool { return s.bufLatest().T == 0 }

func (s *Series) bufLatest() Sample {
	if s.pos == 0 && !s.full {
		return Sample{}
	}
	i := s.pos - 1
	if i < 0 {
		i = s.cap - 1
	}
	return s.buf[i]
}

// Range returns up to n most recent samples, oldest first, in seconds-relative
// form suitable for charting.
func (s *Series) Range(n int) []Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	count := s.pos
	if s.full {
		count = s.cap
	}
	if n <= 0 || n > count {
		n = count
	}
	out := make([]Sample, 0, n)
	start := count - n
	for i := start; i < count; i++ {
		idx := i
		if s.full {
			idx = (i + s.cap) % s.cap
		}
		out = append(out, s.buf[idx])
	}
	return out
}

// Keys lists every field name ever recorded.
func (s *Series) Keys() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.keys...)
}

// Last returns the newest sample.
func (s *Series) Last() (Sample, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.bufLatest()
	if l.T == 0 {
		return Sample{}, false
	}
	return l, true
}

// Summary is the compact form for the dashboard.
func (s *Series) Summary() map[string]any {
	l, ok := s.Last()
	m := map[string]any{"name": s.name, "points": len(s.Range(0)), "keys": s.Keys()}
	if ok {
		m["last"] = l
		m["ageMs"] = time.Now().UnixMilli() - l.T
	}
	s.mu.Lock()
	if s.gapAt > 0 {
		m["gapAtMs"] = s.gapAt
	}
	s.mu.Unlock()
	return m
}

// Clear empties the buffer (used when the user changes the history length).
func (s *Series) Clear() {
	s.mu.Lock()
	s.buf = make([]Sample, s.cap)
	s.pos, s.full = 0, false
	s.mu.Unlock()
}

func containsKey(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// Store is the collection of every history the dashboard charts.
type Store struct {
	CPU      *Series
	Memory   *Series
	Traffic  *Series
	Battery  *Series
	Thermal  *Series
	Clients  *Series
	Load     *Series
	Freq     *Series
	CPUPerC  *Series
	Upstream *Series
}

// NewStore allocates all histories with the configured depth.
func NewStore(points int) *Store {
	return &Store{
		CPU: NewSeries("cpu", points), Memory: NewSeries("memory", points),
		Traffic: NewSeries("traffic", points), Battery: NewSeries("battery", points),
		Thermal: NewSeries("thermal", points), Clients: NewSeries("clients", points),
		Load: NewSeries("load", points), Freq: NewSeries("cpuFreq", points),
		CPUPerC: NewSeries("cpuPerCore", points), Upstream: NewSeries("upstream", points),
	}
}

// All returns the histories by name for the /api/v1/history endpoint.
func (s *Store) All() map[string]*Series {
	return map[string]*Series{
		"cpu": s.CPU, "memory": s.Memory, "traffic": s.Traffic, "battery": s.Battery,
		"thermal": s.Thermal, "clients": s.Clients, "load": s.Load, "cpuFreq": s.Freq,
		"cpuPerCore": s.CPUPerC, "upstream": s.Upstream,
	}
}

// Range packs several series for one API response.
func (s *Store) Range(n int) map[string][]Sample {
	out := map[string][]Sample{}
	for k, v := range s.All() {
		out[k] = v.Range(n)
	}
	return out
}

// Resize rebuilds every history with a new depth.
func (s *Store) Resize(points int) {
	for _, v := range s.All() {
		v.mu.Lock()
		v.buf = make([]Sample, points)
		v.cap = points
		v.pos, v.full = 0, false
		v.mu.Unlock()
	}
}
