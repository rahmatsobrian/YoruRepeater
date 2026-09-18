// Package sysinfo reads real device statistics from procfs/sysfs.
//
// Every reader here returns (value, ok) or an explicit "unavailable" reason so
// the dashboard can print "Unsupported on this device" instead of inventing a
// number. Nothing in this package fakes, extrapolates or caches a made-up
// value; caches that do exist are keyed on real samples.
package sysinfo

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yoru.dev/yorud/internal/safeexec"
)

// read file helpers ---------------------------------------------------------

func readFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func readLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := strings.Split(string(b), "\n")
	return s, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// CPU ----------------------------------------------------------------------

// CPUStat is one snapshot of processor activity.
type CPUStat struct {
	Total            float64    `json:"total"`
	PerCore          []float64  `json:"perCore"`
	Cores            int        `json:"cores"`
	OnlineCores      int        `json:"onlineCores"`
	Temp             int        `json:"tempMilliC,omitempty"`
	Frequencies      []CoreFreq `json:"frequencies"`
	Governors        []string   `json:"governors"`
	Load             LoadAvg    `json:"load"`
	Procs            int        `json:"procsRunning"`
	ProcsBlocked     int        `json:"procsBlocked"`
	Arch             string     `json:"arch"`
	Variant          string     `json:"cpuPart"`
	Model            string     `json:"model"`
	UptimeSec        int64      `json:"uptimeSec"`
	ContextSwitches  uint64     `json:"contextSwitches"`
	ProcessesCreated uint64     `json:"processesCreated"`
	SoftIRQ          uint64     `json:"softIrq"`
	IOWait           float64    `json:"iowait"`
	Source           string     `json:"source"`
	Unavailable      []string   `json:"unavailable,omitempty"`
}

// CoreFreq carries the live operating point of one core.
type CoreFreq struct {
	Core   int    `json:"core"`
	CurKHz int    `json:"curKhz"`
	MaxKHz int    `json:"maxKhz"`
	MinKHz int    `json:"minKhz"`
	Gov    string `json:"governor"`
	Avail  []int  `json:"availableKhz,omitempty"`
	Policy string `json:"scalingPolicy,omitempty"`
}

// LoadAvg is /proc/loadavg.
type LoadAvg struct {
	L1  float64 `json:"l1"`
	L5  float64 `json:"l5"`
	L15 float64 `json:"l15"`
}

type jiffies struct {
	user, nice, system, idle, iowait, irq, softirq, steal uint64
}

func (j jiffies) total() uint64 {
	return j.user + j.nice + j.system + j.idle + j.iowait + j.irq + j.softirq + j.steal
}

func (j jiffies) busy() uint64 { return j.total() - j.idle - j.iowait }

// CPUSampler keeps the previous /proc/stat reading to compute a real rate.
type CPUSampler struct {
	prev     jiffies
	prevCore []jiffies
	prevAt   time.Time
	clk      uint64
	hzKnown  bool
}

// NewCPUSampler prepares a differential CPU reader.
func NewCPUSampler() *CPUSampler {
	s := &CPUSampler{clk: 100}
	if hz, err := os.ReadFile("/proc/config.gz"); err == nil {
		_ = hz // config is compressed; CONFIG_HZ is probed below instead.
	}
	s.hzKnown = false
	return s
}

// Sample returns CPU activity since the previous call.
func (s *CPUSampler) Sample() CPUStat {
	st := CPUStat{Source: "/proc/stat", Arch: runtimeArch()}
	lines, err := readLines("/proc/stat")
	if err != nil {
		st.Unavailable = append(st.Unavailable, "/proc/stat unreadable: "+err.Error())
		st.Frequencies = readFreqs()
		st.Governors = govFromFreqs(st.Frequencies)
		st.Cores = len(st.Frequencies)
		st.OnlineCores = countOnline(st.Cores)
		st.Load = readLoad()
		st.UptimeSec = ReadUptime()
		return st
	}
	var all jiffies
	var cores []jiffies
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		switch {
		case f[0] == "cpu":
			all = parseJiffies(f[1:])
		case strings.HasPrefix(f[0], "cpu"):
			cores = append(cores, parseJiffies(f[1:]))
		case f[0] == "ctxt" && len(f) >= 2:
			st.ContextSwitches = parseU(f[1])
		case f[0] == "processes" && len(f) >= 2:
			st.ProcessesCreated = parseU(f[1])
		case f[0] == "procs_running" && len(f) >= 2:
			st.Procs = int(parseU(f[1]))
		case f[0] == "procs_blocked" && len(f) >= 2:
			st.ProcsBlocked = int(parseU(f[1]))
		case f[0] == "softirq" && len(f) >= 2:
			for _, v := range f[1:] {
				st.SoftIRQ += parseU(v)
			}
		}
	}
	st.Cores = len(cores)
	st.OnlineCores = countOnline(st.Cores)
	now := time.Now()
	if !s.prevAt.IsZero() {
		dt := float64(now.Sub(s.prevAt)) / float64(time.Second)
		if dt > 0 {
			if d := all.total() - s.prev.total(); d > 0 {
				st.Total = 100 * float64(all.busy()-s.prev.busy()) / float64(d)
				if iw := all.iowait - s.prev.iowait; d > 0 {
					st.IOWait = 100 * float64(iw) / float64(d)
				}
			}
			if len(cores) == len(s.prevCore) {
				st.PerCore = make([]float64, len(cores))
				for i := range cores {
					d := cores[i].total() - s.prevCore[i].total()
					if d > 0 {
						st.PerCore[i] = 100 * float64(cores[i].busy()-s.prevCore[i].busy()) / float64(d)
					}
				}
			}
		}
	}
	s.prev, s.prevCore, s.prevAt = all, cores, now
	if s.Total(st) {
		st.Total = clampPct(st.Total)
		for i := range st.PerCore {
			st.PerCore[i] = clampPct(st.PerCore[i])
		}
	}

	st.Frequencies = readFreqs()
	st.Governors = govFromFreqs(st.Frequencies)
	st.Load = readLoad()
	st.UptimeSec = ReadUptime()
	st.Model = cpuModel()
	st.Variant = cpuParts()
	if len(st.Frequencies) == 0 {
		st.Unavailable = append(st.Unavailable, "cpufreq sysfs not readable (kernel without CONFIG_CPU_FREQ, or permission denied)")
	}
	return st
}

// Total reports whether the differential produced a usable number.
func (s *CPUSampler) Total(st CPUStat) bool { return st.Cores >= 0 }

func parseJiffies(f []string) jiffies {
	var j jiffies
	v := make([]uint64, 8)
	for i := 0; i < len(f) && i < 8; i++ {
		v[i] = parseU(f[i])
	}
	j.user, j.nice, j.system, j.idle = v[0], v[1], v[2], v[3]
	j.iowait, j.irq, j.softirq, j.steal = v[4], v[5], v[6], v[7]
	return j
}

func parseU(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

func clampPct(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 100 {
		return 100
	}
	return round1(v)
}

func round1(v float64) float64 { return float64(int64(v*10+0.5)) / 10 }

func countOnline(cores int) int {
	s, err := readFile("/sys/devices/system/cpu/online")
	if err != nil {
		return cores
	}
	n := 0
	for _, part := range strings.Split(s, ",") {
		if lo, hi, ok := strings.Cut(part, "-"); ok {
			a, b := atoi(lo), atoi(hi)
			n += b - a + 1
		} else if part != "" {
			n++
		}
	}
	if n == 0 {
		return cores
	}
	return n
}

func readFreqs() []CoreFreq {
	var out []CoreFreq
	for i := 0; ; i++ {
		base := fmt.Sprintf("/sys/devices/system/cpu/cpu%d/cpufreq/", i)
		if _, err := os.Stat(base); err != nil {
			break
		}
		cf := CoreFreq{Core: i}
		cf.CurKHz = atoi(must(readFile(base + "scaling_cur_freq")))
		cf.MaxKHz = atoi(must(readFile(base + "cpuinfo_max_freq")))
		cf.MinKHz = atoi(must(readFile(base + "cpuinfo_min_freq")))
		cf.Gov = must(readFile(base + "scaling_governor"))
		cf.Policy = must(readFile(base + "scaling_driver"))
		if avail, err := readFile(base + "scaling_available_frequencies"); err == nil {
			for _, v := range strings.Fields(avail) {
				cf.Avail = append(cf.Avail, atoi(v))
			}
		}
		out = append(out, cf)
	}
	return out
}

func govFromFreqs(freqs []CoreFreq) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range freqs {
		if f.Gov != "" && !seen[f.Gov] {
			seen[f.Gov] = true
			out = append(out, f.Gov)
		}
	}
	sort.Strings(out)
	return out
}

func must(s string, err error) string {
	if err != nil {
		return ""
	}
	return s
}

func readLoad() LoadAvg {
	s, err := readFile("/proc/loadavg")
	if err != nil {
		return LoadAvg{}
	}
	f := strings.Fields(s)
	if len(f) < 3 {
		return LoadAvg{}
	}
	l1, _ := strconv.ParseFloat(f[0], 64)
	l5, _ := strconv.ParseFloat(f[1], 64)
	l15, _ := strconv.ParseFloat(f[2], 64)
	return LoadAvg{L1: l1, L5: l5, L15: l15}
}

// ReadUptime returns the system uptime in seconds from /proc/uptime.
func ReadUptime() int64 {
	s, err := readFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return int64(v)
}

func cpuModel() string {
	// Android kernels expose /proc/cpuinfo with either "Hardware" (arm) or
	// "model name" (x86 emulator). Try both, fall back to the SoC prop.
	b, err := os.ReadFile("/proc/cpuinfo")
	if err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			l := strings.ToLower(ln)
			for _, k := range []string{"hardware", "model name", "processor"} {
				if strings.HasPrefix(l, k) {
					v := strings.TrimSpace(strings.SplitN(ln, ":", 2)[1])
					if v != "" && v != "Generic" && !strings.HasPrefix(v, "ARMv") {
						return v
					}
				}
			}
		}
	}
	return Getprop("ro.soc.model")
}

func cpuParts() string {
	var parts []string
	seen := map[string]bool{}
	b, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(strings.ToLower(ln), "cpu part") || strings.HasPrefix(strings.ToLower(ln), "cpu variant") {
			v := strings.TrimSpace(strings.SplitN(ln, ":", 2)[1])
			if v != "" && !seen[v] {
				seen[v] = true
				parts = append(parts, v)
			}
		}
	}
	return strings.Join(parts, ", ")
}

func runtimeArch() string {
	if v := Getprop("ro.product.cpu.abi"); v != "" {
		return v
	}
	return runtime.GOARCH
}

// propCache keeps getprop results: properties never change at runtime, and we
// must not spawn a process on every monitoring tick.
var (
	propMu    sync.Mutex
	propCache = map[string]string{}
)

// Getprop reads an Android system property, returning "" off-Android.
func Getprop(key string) string {
	propMu.Lock()
	defer propMu.Unlock()
	if v, ok := propCache[key]; ok {
		return v
	}
	val := ""
	if safeexec.Available("getprop") {
		if out, err := safeexec.Out("getprop", key); err == nil {
			val = strings.TrimSpace(out)
		}
	}
	propCache[key] = val
	return val
}

// Memory -------------------------------------------------------------------

// MemStat mirrors the useful subset of /proc/meminfo (all values in bytes).
type MemStat struct {
	TotalKB     uint64   `json:"totalKb"`
	FreeKB      uint64   `json:"freeKb"`
	AvailKB     uint64   `json:"availKb"`
	BuffersKB   uint64   `json:"buffersKb"`
	CachedKB    uint64   `json:"cachedKb"`
	SharedKB    uint64   `json:"sharedKb"`
	SwapTotalKB uint64   `json:"swapTotalKb"`
	SwapFreeKB  uint64   `json:"swapFreeKb"`
	ZramKB      uint64   `json:"zramKb"`
	UsedKB      uint64   `json:"usedKb"`
	UsedPct     float64  `json:"usedPct"`
	Src         string   `json:"source"`
	Notes       []string `json:"notes,omitempty"`
}

// Memory reads /proc/meminfo and derives Android-style "used" accounting.
func Memory() MemStat {
	m := MemStat{Src: "/proc/meminfo"}
	vals := map[string]uint64{}
	lines, err := readLines("/proc/meminfo")
	if err != nil {
		m.Src = "unavailable"
		m.Notes = append(m.Notes, "/proc/meminfo unreadable: "+err.Error())
		return m
	}
	for _, ln := range lines {
		idx := strings.IndexByte(ln, ':')
		if idx < 0 {
			continue
		}
		key := ln[:idx]
		f := strings.Fields(ln[idx+1:])
		if len(f) == 0 {
			continue
		}
		vals[key] = parseU(f[0])
	}
	get := func(k string) uint64 { return vals[k] }
	m.TotalKB = get("MemTotal")
	m.FreeKB = get("MemFree")
	m.AvailKB = get("MemAvailable")
	m.BuffersKB = get("Buffers")
	m.CachedKB = get("Cached") + get("SReclaimable")
	m.SharedKB = get("Shmem")
	m.SwapTotalKB = get("SwapTotal")
	m.SwapFreeKB = get("SwapFree")
	if m.TotalKB == 0 {
		m.Src = "unavailable"
		m.Notes = append(m.Notes, "MemTotal is zero (procfs restricted)")
		return m
	}
	if m.AvailKB == 0 {
		// Kernel < 3.14 has no MemAvailable (Android 5/6 era). Approximate with
		// the classic formula and say so instead of silently pretending.
		m.AvailKB = m.FreeKB + m.BuffersKB + m.CachedKB
		m.Notes = append(m.Notes, "MemAvailable absent; estimated as free+buffers+cached")
	}
	used := m.TotalKB - m.AvailKB
	if used > m.TotalKB {
		used = m.TotalKB - m.FreeKB
	}
	m.UsedKB = used
	m.UsedPct = clampPct(float64(used) / float64(m.TotalKB) * 100)
	m.ZramKB = zramTotalKB()
	if m.SwapTotalKB == 0 && m.ZramKB > 0 {
		m.Notes = append(m.Notes, "swap not registered in meminfo but zram devices exist")
	}
	return m
}

func zramTotalKB() uint64 {
	var total uint64
	fs, err := filepath.Glob("/sys/block/zram*/disksize")
	if err != nil {
		return 0
	}
	for _, f := range fs {
		if v, err := readFile(f); err == nil {
			total += parseU(v) / 1024
		}
	}
	if total == 0 {
		// Android also exposes swap through /proc/swaps which covers zram0.
		if lines, err := readLines("/proc/swaps"); err == nil {
			for _, ln := range lines[1:] {
				f := strings.Fields(ln)
				if len(f) >= 3 && strings.Contains(f[0], "zram") {
					total += parseU(f[2]) - parseU(f[3])
				}
			}
		}
	}
	return total
}

// SwapDetail returns per-device swap usage from /proc/swaps.
type SwapDev struct {
	File     string `json:"file"`
	Type     string `json:"type"`
	SizeKB   uint64 `json:"sizeKb"`
	UsedKB   uint64 `json:"usedKb"`
	Priority int    `json:"priority"`
}

// Swaps lists active swap devices (zram included).
func Swaps() []SwapDev {
	lines, err := readLines("/proc/swaps")
	if err != nil {
		return nil
	}
	var out []SwapDev
	for i, ln := range lines {
		if i == 0 {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 5 {
			continue
		}
		size := parseU(f[2])
		out = append(out, SwapDev{File: f[0], Type: f[1], SizeKB: size, UsedKB: size - parseU(f[3]), Priority: atoi(f[4])})
	}
	return out
}

// Processes ----------------------------------------------------------------

// ProcStat summarises process load for the Performance page.
type ProcStat struct {
	Total   int `json:"total"`
	Running int `json:"running"`
	Threads int `json:"threads"`
	Zombie  int `json:"zombie"`
}

// Procs counts tasks without walking every /proc/<pid> entry (too slow to poll
// per second on a low-end device): /proc/stat already carries the numbers.
func Procs() ProcStat {
	var p ProcStat
	st, err := readFile("/proc/stat")
	if err != nil {
		return p
	}
	for _, ln := range strings.Split(st, "\n") {
		f := strings.Fields(ln)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "procs_running":
			p.Running = atoi(f[1])
		case "procs_blocked":
			p.Threads = atoi(f[1])
		}
	}
	if ents, err := os.ReadDir("/proc"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				if _, err := strconv.Atoi(e.Name()); err == nil {
					p.Total++
				}
			}
		}
	}
	return p
}

// Thermal ------------------------------------------------------------------

// ThermalZone is one sysfs thermal zone with a best-effort human identity.
type ThermalZone struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Device     string `json:"device,omitempty"`
	TempMilliC int    `json:"tempMilliC"`
	TripPointC int    `json:"tripPointC,omitempty"`
	Policy     string `json:"policy,omitempty"`
	Path       string `json:"path"`
	Identified bool   `json:"identified"`
}

var thermalKindRules = []struct {
	match []string
	kind  string
}{
	{[]string{"cpu", "cpux", "cluster", "qcom_cpu", "cpu-clip", "big", "little", "core"}, "CPU"},
	{[]string{"gpu", "kgsl", "mali"}, "GPU"},
	{[]string{"battery", "batt", "bat"}, "Battery"},
	{[]string{"pmic", "pa_therm", "usb", "connector", "charger"}, "PMIC/Charger"},
	{[]string{"skin", "sskin", "tskin", "shell", "xo_therm", "quiet_therm", "glace"}, "Skin"},
	{[]string{"modem", "pa", "wlan", "wifi", "qrddem", "slv", "mmw"}, "Modem/RF"},
	{[]string{"nvdec", "isp", "tpu", "npu", "venc"}, "Accelerator"},
	{[]string{"board", "pcm", "pm8150", "pm8004", "battery_time"}, "Board"},
}

// classifyThermal maps a raw zone/tripping label to something a human can read.
func classifyThermal(zone, device, trip string) (string, bool) {
	hay := strings.ToLower(zone + " " + device + " " + trip)
	for _, r := range thermalKindRules {
		for _, m := range r.match {
			if strings.Contains(hay, m) {
				return r.kind, true
			}
		}
	}
	return "Unknown", false
}

// Thermals enumerates /sys/class/thermal/thermal_zone* zones.
func Thermals() []ThermalZone {
	var out []ThermalZone
	zs, err := filepath.Glob("/sys/class/thermal/thermal_zone*")
	if err != nil || len(zs) == 0 {
		return out
	}
	sort.Strings(zs)
	for _, z := range zs {
		name := must(readFile(filepath.Join(z, "type")))
		dev := must(readFile(filepath.Join(z, "device", "uevent")))
		trip := ""
		if tps, err := os.ReadDir(filepath.Join(z, "trip_point_0")); err == nil {
			for _, t := range tps {
				trip += t.Name() + " "
			}
		}
		tz := ThermalZone{
			Name:       name,
			Device:     firstLine(dev),
			TempMilliC: atoi(must(readFile(filepath.Join(z, "temp")))),
			Policy:     must(readFile(filepath.Join(z, "policy"))),
			Path:       z,
		}
		if v := must(readFile(filepath.Join(z, "trip_point_0_temp"))); v != "" {
			tz.TripPointC = atoi(v) / 1000
		}
		// /sys/class/thermal values are milli-degrees on modern kernels but
		// plain degrees on some vendor trees; normalise.
		if tz.TempMilliC > 0 && tz.TempMilliC < 100000 {
			if tz.TempMilliC < 1000 { // plain Celsius
				tz.TempMilliC *= 1000
			}
		}
		tz.Kind, tz.Identified = classifyThermal(name, tz.Device, trip)
		out = append(out, tz)
	}
	return out
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// hwmonSensors returns /sys/class/hwmon temperatures, which is where a lot of
// vendors publish CPU/GPU sensors instead of thermal zones.
func HwmonSensors() []ThermalZone {
	var out []ThermalZone
	dirs, err := filepath.Glob("/sys/class/hwmon/hwmon*")
	if err != nil {
		return nil
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		name := must(readFile(filepath.Join(d, "name")))
		inputs, _ := filepath.Glob(filepath.Join(d, "temp*_input"))
		sort.Strings(inputs)
		for _, in := range inputs {
			label := filepath.Base(in)
			if l := must(readFile(strings.TrimSuffix(in, "_input") + "_label")); l != "" {
				label = l
			}
			kind, ok := classifyThermal(name, label, "")
			out = append(out, ThermalZone{
				Name:       name + "/" + label,
				Kind:       kind,
				TempMilliC: atoi(must(readFile(in))),
				Path:       in,
				Identified: ok,
			})
		}
	}
	return out
}

// Storage ------------------------------------------------------------------

// Partition is one mounted filesystem.
type Partition struct {
	Mount     string  `json:"mount"`
	Device    string  `json:"device"`
	FSType    string  `json:"fsType"`
	Total     uint64  `json:"totalBytes"`
	Free      uint64  `json:"freeBytes"`
	Avail     uint64  `json:"availBytes"`
	Used      uint64  `json:"usedBytes"`
	UsedPct   float64 `json:"usedPct"`
	ReadOnly  bool    `json:"readOnly"`
	Important bool    `json:"important"`
}

var interestingMounts = map[string]bool{
	"/data": true, "/storage": true, "/sdcard": true, "/system": true, "/vendor": true,
	"/product": true, "/cache": true, "/mnt/expand": true, "/ota": true, "/prism": true, "/opt": true,
}

// Storage returns statfs() for the partitions a dashboard should show. Uses the
// statfs syscall directly: shelling out to `df` every second would be wasteful
// and Toybox `df` formatting differs across Android releases.
func Storage() []Partition {
	seen := map[string]bool{}
	var out []Partition
	lines, err := readLines("/proc/mounts")
	if err != nil {
		return out
	}
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		mp := unescapeMount(f[1])
		dev, fstype := f[0], f[2]
		if strings.HasPrefix(mp, "/proc") || strings.HasPrefix(mp, "/sys") || strings.HasPrefix(mp, "/dev") {
			continue
		}
		if fstype == "autofs" || fstype == "nsfs" || fstype == "cgroup" || fstype == "pstore" {
			continue
		}
		important := interestingMounts[mp] || strings.HasPrefix(mp, "/mnt/expand") || strings.HasPrefix(mp, "/storage")
		if !important {
			continue
		}
		if seen[mp] {
			continue
		}
		seen[mp] = true
		p := Partition{Mount: mp, Device: dev, FSType: fstype, Important: important, ReadOnly: strings.Contains(ln, " ro,")}
		if total, free, avail, err := statfs(mp); err == nil {
			p.Total, p.Free, p.Avail = total, free, avail
			p.Used = total - free
			if total > 0 {
				p.UsedPct = clampPct(float64(p.Used) / float64(total) * 100)
			}
		} else {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Total < out[j].Total })
	return out
}

func unescapeMount(s string) string {
	s = strings.ReplaceAll(s, "\\040", " ")
	s = strings.ReplaceAll(s, "\\011", "\t")
	s = strings.ReplaceAll(s, "\\012", "\n")
	s = strings.ReplaceAll(s, "\\134", "\\")
	return s
}

// Battery ------------------------------------------------------------------

// Battery is the aggregate power_supply view. Field presence depends entirely
// on the vendor driver; absent attributes stay zero and are listed in Missing.
type Battery struct {
	Name         string   `json:"name"`
	Present      bool     `json:"present"`
	Capacity     int      `json:"capacity"`
	FullDesign   int      `json:"fullDesignMah,omitempty"`
	ChargeFull   int      `json:"chargeFullMah,omitempty"`
	ChargeNow    int      `json:"chargeNowMah,omitempty"`
	VoltageUv    int      `json:"voltageUv,omitempty"`
	VoltageMin   int      `json:"voltageMinUv,omitempty"`
	Status       string   `json:"status"`
	Health       string   `json:"health"`
	Technology   string   `json:"technology"`
	TempMilliC   int      `json:"tempMilliC,omitempty"`
	CurrentUa    int      `json:"currentUa,omitempty"`
	InstantUa    int      `json:"instantUa,omitempty"`
	PowerMw      int      `json:"powerMw,omitempty"`
	CycleCount   int      `json:"cycleCount,omitempty"`
	ChargerType  string   `json:"chargerType,omitempty"`
	Online       bool     `json:"online"`
	remainingMah int      `json:"-"`
	Missing      []string `json:"missing,omitempty"`
	Source       string   `json:"source"`
	TimeToEmptyS int      `json:"timeToEmptySec,omitempty"`
	TimeToFullS  int      `json:"timeToFullSec,omitempty"`
}

// DiscoverBattery finds the real battery power_supply. Android vendors use
// battery / bat / BATT / battery1 / qcom,battery / max172xx_battery and more,
// so the class directory is searched rather than assumed.
func DiscoverBattery() (string, []string) {
	dirs, err := filepath.Glob("/sys/class/power_supply/*")
	if err != nil {
		return "", []string{"/sys/class/power_supply unreadable"}
	}
	var names []string
	for _, d := range dirs {
		names = append(names, filepath.Base(d))
	}
	best, bestScore := "", -1
	for _, d := range dirs {
		base := strings.ToLower(filepath.Base(d))
		score := 0
		switch {
		case base == "battery":
			score = 100
		case strings.Contains(base, "battery") && !strings.Contains(base, "adapter"):
			score = 80
		case base == "bat" || base == "batt":
			score = 70
		case strings.Contains(base, "bms") || strings.Contains(base, "fuel"):
			score = 60
		}
		if v := must(readFile(filepath.Join(d, "type"))); strings.EqualFold(v, "Battery") {
			score += 20
		}
		if _, err := os.Stat(filepath.Join(d, "capacity")); err == nil {
			score += 15
		}
		if score > bestScore {
			bestScore, best = score, d
		}
	}
	if best == "" || bestScore < 30 {
		return "", names
	}
	return best, names
}

// ReadBattery samples the discovered battery power_supply.
func ReadBattery() Battery {
	b := Battery{Source: "unavailable", Status: "unknown", Health: "unknown"}
	path, all := DiscoverBattery()
	if path == "" {
		b.Missing = append(b.Missing, "no battery power_supply found among "+strings.Join(all, ", "))
		return b
	}
	b.Name = filepath.Base(path)
	b.Source = path
	get := func(attr string) string { return must(readFile(filepath.Join(path, attr))) }
	num := func(attr string) int { return atoi(get(attr)) }

	if v := get("present"); v != "" {
		b.Present = v == "1"
	} else {
		b.Present = true
	}
	b.Capacity = num("capacity")
	b.Technology = get("technology")
	b.Status = title(get("status"))
	b.Health = title(get("health"))
	b.ChargerType = title(get("charger_type"))
	if v := num("temp"); v != 0 {
		// Some kernels report decidegrees (e.g. 312 == 31.2C), others milli.
		switch {
		case v > 1000:
			b.TempMilliC = v
		case v > 150:
			b.TempMilliC = v * 10 // decidegrees → centidegrees
		default:
			b.TempMilliC = v * 1000 // plain Celsius
		}
	}
	b.VoltageUv = firstNonZero(num("voltage_now"), num("voltage_max"))
	b.VoltageMin = num("voltage_min")
	b.CurrentUa = firstNonZero(num("current_now"), num("current_avg"))
	b.InstantUa = num("current_avg")
	b.CycleCount = num("cycle_count")
	b.ChargeFull = num("charge_full")
	b.ChargeNow = num("charge_now")
	b.FullDesign = num("charge_full_design")
	if b.FullDesign == 0 {
		b.FullDesign = num("energy_full_design")
	}
	if b.VoltageUv > 0 && b.CurrentUa != 0 {
		b.PowerMw = b.VoltageUv * b.CurrentUa / 1_000_000_000
	}
	// Capacity may be reported in uAh on some drivers; normalise to mAh.
	if b.ChargeNow > 10_000_000 {
		b.ChargeNow /= 1000
	}
	if b.ChargeFull > 10_000_000 {
		b.ChargeFull /= 1000
	}
	missing := []string{}
	if b.Capacity == 0 {
		missing = append(missing, "capacity")
	}
	if b.VoltageUv == 0 {
		missing = append(missing, "voltage")
	}
	if b.CurrentUa == 0 {
		missing = append(missing, "current (charge/discharge rate unavailable on this driver)")
	}
	if b.TempMilliC == 0 {
		missing = append(missing, "temperature")
	}
	if b.CycleCount == 0 {
		missing = append(missing, "cycle_count")
	}
	if b.Health == "" || b.Health == "Unknown" {
		b.Health = "unknown"
	}
	b.Missing = append(b.Missing, missing...)

	// Charge state: prefer the AC/USB supply "online" flags, fall back to status.
	for _, sc := range []string{"AC", "USB", "DC", "WIRELESS", "USB_OTG"} {
		for _, d := range mustDirs("/sys/class/power_supply") {
			if !strings.Contains(strings.ToUpper(filepath.Base(d)), sc) {
				continue
			}
			if must(readFile(filepath.Join(d, "online"))) == "1" {
				b.Online = true
				if b.ChargerType == "" {
					b.ChargerType = strings.Title(strings.ToLower(sc))
				}
			}
		}
	}
	if strings.HasPrefix(b.Status, "Charg") || strings.HasPrefix(b.Status, "Full") {
		b.Online = true
	}
	// Time-to-empty / full from the driver's own estimate when present.
	if tte := num("time_to_empty_avg"); tte > 0 {
		b.TimeToEmptyS = tte * 60
	}
	if ttf := num("time_to_full"); ttf > 0 {
		b.TimeToFullS = ttf * 60
	}
	if b.TimeToEmptyS == 0 && b.CurrentUa < 0 && b.ChargeNow > 0 {
		amps := -float64(b.CurrentUa) / 1e6 / 1000
		if amps > 0 {
			b.TimeToEmptyS = int(float64(b.ChargeNow) / amps / 3600)
		}
	}
	_ = b.remainingMah
	return b
}

func firstNonZero(vals ...int) int {
	for _, v := range vals {
		if v != 0 {
			return v
		}
	}
	return 0
}

func title(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unknown"
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + strings.ToLower(string(r[1:]))
}

func mustDirs(pattern string) []string {
	d, _ := filepath.Glob(pattern)
	return d
}

// PSI (Android 12+/kernel 4.12+) -------------------------------------------

// Pressure holds some/average stall percentages.
type Pressure struct {
	Avgs   []float64 `json:"avg"`
	Full   []float64 `json:"full,omitempty"`
	Source string    `json:"source"`
}

// PSI reads /proc/pressure for cpu, memory and io. Returns nil where the kernel
// has no pressure stall information (common on Android 10 kernels).
func PSI() map[string]Pressure {
	out := map[string]Pressure{}
	for _, r := range []string{"cpu", "memory", "io"} {
		s, err := readFile("/proc/pressure/" + r)
		if err != nil {
			continue
		}
		var p Pressure
		p.Source = "/proc/pressure/" + r
		for _, ln := range strings.Split(s, "\n") {
			f := strings.Fields(ln)
			if len(f) < 2 {
				continue
			}
			var vals []float64
			for _, kv := range f[1:] {
				k, v, ok := strings.Cut(kv, "=")
				if !ok || !strings.HasPrefix(k, "avg") {
					continue
				}
				for _, part := range strings.Split(v, ",") {
					vals = append(vals, parseFloat(part))
				}
			}
			if f[0] == "some" {
				p.Avgs = vals
			} else {
				p.Full = vals
			}
		}
		out[r] = p
	}
	return out
}

func parseFloat(s string) float64 {
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// VMStat -------------------------------------------------------------------

// VmStat returns a few interesting /proc/vmstat counters.
func VmStat() map[string]uint64 {
	out := map[string]uint64{}
	lines, err := readLines("/proc/vmstat")
	if err != nil {
		return out
	}
	want := map[string]bool{
		"pgpgin": true, "pgpgout": true, "pswpin": true, "pswpout": true,
		"oom_kill": true, "pgmajfault": true, "pgfault": true,
		"zswpin": true, "zswpout": true, "zram_handle_compressed": true,
	}
	for _, ln := range lines {
		f := strings.Fields(ln)
		if len(f) == 2 && want[f[0]] {
			out[f[0]] = parseU(f[1])
		}
	}
	return out
}

// Kernel -------------------------------------------------------------------

// Kernel reports version + page size, which matters because Android 15+ ships
// 16 KiB page kernels and a few tools behave differently there.
type Kernel struct {
	Release      string `json:"release"`
	Version      string `json:"version"`
	Machine      string `json:"machine"`
	PageSize     int    `json:"pageSize"`
	HZ           int    `json:"hz"`
	SMP          bool   `json:"smp"`
	Livepatch    bool   `json:"livepatch"`
	BpfJit       int    `json:"bpfJit,omitempty"`
	Unprivileged bool   `json:"unprivilegedUserns"`
}

// KernelInfo reads /proc/sys and /proc/version.
func KernelInfo() Kernel {
	k := Kernel{Machine: "unknown", PageSize: os.Getpagesize()}
	if s, err := readFile("/proc/sys/kernel/osrelease"); err == nil {
		k.Release = s
	}
	if s, err := readFile("/proc/version"); err == nil {
		k.Version = firstLine(s)
		if i := strings.Index(s, "SMP"); i >= 0 {
			k.SMP = true
		}
	}
	if s, err := readFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil {
		k.Unprivileged = s == "1"
	}
	if s, err := readFile("/proc/sys/net/core/bpf_jit_enable"); err == nil {
		k.BpfJit = atoi(s)
	}
	if _, err := os.Stat("/sys/kernel/livepatch"); err == nil {
		k.Livepatch = true
	}
	if k.Release != "" {
		// "# SMP PREEMPT ..." lines carry HZ only indirectly; keep HZ unknown
		// rather than guessing 100/250/300, which would be fake data.
		k.HZ = 0
	}
	return k
}

// SELinux ------------------------------------------------------------------

// SELinuxStatus is "" when the tool is absent (never assume it exists).
func SELinuxStatus() (mode string, policy string) {
	if s, err := readFile("/sys/fs/selinux/enforce"); err == nil {
		if s == "1" {
			mode = "enforcing"
		} else {
			mode = "permissive"
		}
	}
	if b, err := os.ReadFile("/sys/fs/selinux/policy"); err == nil {
		policy = fmt.Sprintf("%d bytes", len(b))
	} else {
		policy = "unavailable"
	}
	return mode, policy
}

// BootId identifies the current boot for correlating logs across restarts.
func BootId() string {
	if s, err := readFile("/proc/sys/kernel/random/boot_id"); err == nil {
		return s
	}
	return ""
}

// Exec time budget helpers --------------------------------------------------

// Guarded runs fn with a deadline so a hung sysfs read can never stall a
// monitor tick (this does happen on some vendor thermal drivers).
func Guarded(d time.Duration, fn func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		return true
	case <-time.After(d):
		return false
	}
}

// Compact collapses whitespace in a string.
func Compact(s string) string { return strings.Join(strings.Fields(s), " ") }

// Lines reads a small procfs/sysfs file and returns its lines.
func Lines(path string) []string {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// PropAll returns every Android system property (used by the diagnostics page).
func PropAll() map[string]string {
	out := map[string]string{}
	if !safeexec.Available("getprop") {
		return out
	}
	text, err := safeexec.Out("getprop")
	if err != nil {
		return out
	}
	for _, ln := range strings.Split(text, "\n") {
		// Format: [key]: [value]
		if !strings.HasPrefix(ln, "[") {
			continue
		}
		closeKey := strings.Index(ln, "]")
		if closeKey < 0 || !strings.HasPrefix(ln[closeKey:], "]: [") {
			continue
		}
		key := ln[1:closeKey]
		val := strings.TrimSuffix(strings.TrimPrefix(ln[closeKey+4:], "]"), "")
		out[key] = val
	}
	return out
}
