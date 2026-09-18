// Package monitors samples the device and produces the API payloads.
//
// Two design rules shape everything here:
//   - Every subsystem has its own interval and its own goroutine, so a slow
//     thermal read cannot delay CPU. Polling is demand-driven too: if nobody is
//     watching (no SSE clients, no recent HTTP request), the loop slows down to
//     a background cadence so an idle phone is not burned by a root daemon.
//   - Nothing is smoothed, averaged or inferred. If a value is not readable it
//     is reported as missing, with the reason, and the UI says "Unavailable on
//     this device".
package monitors

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

	"yoru.dev/yorud/internal/caps"
	"yoru.dev/yorud/internal/clients"
	"yoru.dev/yorud/internal/config"
	"yoru.dev/yorud/internal/dnsd"
	"yoru.dev/yorud/internal/firewall"
	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/metrics"
	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/repeater"
	"yoru.dev/yorud/internal/safeexec"
	"yoru.dev/yorud/internal/sysinfo"
	"yoru.dev/yorud/internal/telegram"
	"yoru.dev/yorud/internal/traffic"
	"yoru.dev/yorud/internal/version"
	"yoru.dev/yorud/internal/wifistate"
)

// versionTag is the human-readable build identity reported in diagnostics.
var versionTag = version.String()

// Daemon holds the shared state every monitor reads.
type Daemon struct {
	Cfg     *config.Store
	Log     *logging.Logger
	Dev     *netinfo.Device
	Cap     *caps.Set
	Eng     *repeater.Engine
	Metrics *metrics.Store
	Clients *clients.Tracker
	Wifi    *wifistate.Reader
	Fire    *firewall.Manager
	DNS     func() *dnsd.Server

	cpu      *sysinfo.CPUSampler
	trk      *traffic.Tracker
	stop     chan struct{}
	done     []chan struct{}
	wg       sync.WaitGroup
	monot    sync.Mutex
	lastReq  time.Time
	watchers int

	mu      sync.RWMutex
	cache   map[string]cachedValue
	started time.Time
	tick    int64

	batNotify batNotifyState
}

type batNotifyState struct {
	lastCap      int
	lastCharging bool
	notified80   bool
	notified90   bool
	notified100  bool
	notifiedLow  bool
}

type cachedValue struct {
	at  time.Time
	val any
}

// NewDaemon wires the monitors.
func NewDaemon(cfg *config.Store, log *logging.Logger, dev *netinfo.Device, cs *caps.Set,
	eng *repeater.Engine, hist *metrics.Store, trk *clients.Tracker,
	wifi *wifistate.Reader, dnsFn func() *dnsd.Server) *Daemon {
	return &Daemon{
		Cfg: cfg, Log: log, Dev: dev, Cap: cs, Eng: eng, Metrics: hist, Clients: trk,
		Wifi: wifi, DNS: dnsFn, cache: map[string]cachedValue{},
		cpu: sysinfo.NewCPUSampler(), trk: traffic.NewTracker(dev),
		started: time.Now(),
	}
}

// NoteActivity is called by the API on every request so monitors can stay
// responsive while someone is looking and cheap when nobody is.
func (d *Daemon) NoteActivity() {
	d.monot.Lock()
	d.lastReq = time.Now()
	d.monot.Unlock()
}

// SetWatchers records how many SSE streams are open.
func (d *Daemon) SetWatchers(n int) {
	d.monot.Lock()
	d.watchers = n
	d.monot.Unlock()
}

func (d *Daemon) interested() bool {
	d.monot.Lock()
	defer d.monot.Unlock()
	return d.watchers > 0 || time.Since(d.lastReq) < 15*time.Second
}

// Start launches every monitor loop.
func (d *Daemon) Start() {
	cfg := d.Cfg.Get()
	d.stop = make(chan struct{})
	d.startLoop("cpu", time.Duration(cfg.Monitor.CPUIntervalMs)*time.Millisecond, d.tickCPU)
	d.startLoop("memory", time.Duration(cfg.Monitor.MemIntervalMs)*time.Millisecond, d.tickMem)
	d.startLoop("traffic", time.Duration(cfg.Monitor.TrafficIntervalMs)*time.Millisecond, d.tickTraffic)
	d.startLoop("thermal", time.Duration(cfg.Monitor.ThermalIntervalMs)*time.Millisecond, d.tickThermal)
	d.startLoop("battery", time.Duration(cfg.Monitor.BatteryIntervalMs)*time.Millisecond, d.tickBattery)
	d.startLoop("clients", time.Duration(cfg.Monitor.ClientsIntervalMs)*time.Millisecond, d.tickClients)
	d.startLoop("network", 4*time.Second, d.tickNetwork)
	d.startLoop("health", 10*time.Second, d.tickHealth)
	d.Log.Infof("monitor", "monitors started (cpu=%dms traffic=%dms battery=%dms thermal=%dms clients=%dms)",
		cfg.Monitor.CPUIntervalMs, cfg.Monitor.TrafficIntervalMs, cfg.Monitor.BatteryIntervalMs,
		cfg.Monitor.ThermalIntervalMs, cfg.Monitor.ClientsIntervalMs)
}

func (d *Daemon) startLoop(name string, interval time.Duration, fn func()) {
	if interval < 200*time.Millisecond {
		interval = 200 * time.Millisecond
	}
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-d.stop:
				return
			case <-t.C:
				// Idle mode: run at most one in eight ticks when nobody is
				// watching, so an unobserved daemon costs almost nothing.
				if !d.interested() {
					d.monot.Lock()
					d.tick++
					skip := d.tick%8 != 0
					d.monot.Unlock()
					if skip {
						continue
					}
				}
				start := time.Now()
				d.safeRun(name, fn)
				if cost := time.Since(start); cost > interval {
					d.Log.Debugf("monitor", "%s tick took %dms which exceeds its %s interval", name, cost.Milliseconds(), interval)
				}
			}
		}
	}()
}

// safeRun converts a monitor panic into a logged error. A bad vendor sysfs file
// must never take the daemon (and therefore the hotspot) down with it.
func (d *Daemon) safeRun(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			d.Log.Errorf("monitor", "%s panicked and was recovered: %v", name, r)
		}
	}()
	fn()
}

// Stop ends all loops.
func (d *Daemon) Stop() {
	if d.stop != nil {
		close(d.stop)
	}
	d.wg.Wait()
}

// ---------------------------------------------------------------------------
// ticks (refresh the cache + history)
// ---------------------------------------------------------------------------

func (d *Daemon) tickCPU() {
	st := d.cpu.Sample()
	d.put("cpu", st)
	v := map[string]float64{"total": st.Total}
	for i, c := range st.PerCore {
		v[strconv.Itoa(i)] = c
	}
	d.Metrics.CPU.Add(map[string]float64{"total": st.Total, "iowait": st.IOWait})
	d.Metrics.CPUPerC.Add(v)
	f := map[string]float64{}
	for _, cf := range st.Frequencies {
		f["core"+strconv.Itoa(cf.Core)] = float64(cf.CurKHz) / 1000.0
	}
	if len(f) > 0 {
		d.Metrics.Freq.Add(f)
	}
	d.Metrics.Load.Add(map[string]float64{"l1": st.Load.L1, "l5": st.Load.L5, "l15": st.Load.L15})
}

func (d *Daemon) tickMem() {
	m := sysinfo.Memory()
	d.put("memory", map[string]any{
		"mem": m, "swaps": sysinfo.Swaps(), "procs": sysinfo.Procs(), "vmstat": sysinfo.VmStat(),
		"psi": sysinfo.PSI(),
	})
	d.Metrics.Memory.Add(map[string]float64{
		"usedMb": float64(m.UsedKB) / 1024, "availableMb": float64(m.AvailKB) / 1024,
		"usedPct": m.UsedPct, "swapUsedMb": float64(m.SwapTotalKB-m.SwapFreeKB) / 1024,
	})
}

func (d *Daemon) tickTraffic() {
	ifaces := d.monitorInterfaces()
	rates := d.sampleTraffic(ifaces)
	d.put("traffic", map[string]any{"rates": rates, "interfaces": ifaces, "aggregate": rates["__agg"]})
	agg := rates["__agg"]
	d.Metrics.Traffic.Add(map[string]float64{
		"rxBps": agg.RxRate, "txBps": agg.TxRate,
		"rxKbps": agg.RxRate / 125, "txKbps": agg.TxRate / 125,
		"rxTotalMb": float64(agg.RxBytes) / 1e6, "txTotalMb": float64(agg.TxBytes) / 1e6,
	})
}

// trkSample keeps the traffic tracker accessor in one place.
func (d *Daemon) sampleTraffic(ifaces []string) map[string]traffic.Rate {
	rates := d.trk.Sample(ifaces)
	if len(ifaces) > 1 {
		agg := traffic.Aggregate(rates, ifaces...)
		agg.Iface = "aggregate"
		rates["__agg"] = agg
	} else if len(ifaces) == 1 {
		rates["__agg"] = rates[ifaces[0]]
	}
	return rates
}

func (d *Daemon) tickThermal() {
	zones := sysinfo.Thermals()
	hw := sysinfo.HwmonSensors()
	d.put("thermal", map[string]any{"zones": zones, "hwmon": hw, "count": len(zones) + len(hw)})
	v := map[string]float64{}
	for _, z := range zones {
		if z.TempMilliC > 0 && z.TempMilliC < 150000 {
			v[slug(z.Kind)+"/"+slug(z.Name)] = float64(z.TempMilliC) / 1000
		}
	}
	for _, z := range hw {
		if z.TempMilliC > 0 {
			v[slug(z.Name)] = float64(z.TempMilliC) / 1000
		}
	}
	if len(v) == 0 {
		return
	}
	d.Metrics.Thermal.Add(v)
}

func (d *Daemon) tickBattery() {
	b := sysinfo.ReadBattery()
	d.put("battery", b)
	if b.Present || b.Capacity > 0 {
		d.Metrics.Battery.Add(map[string]float64{
			"capacity": float64(b.Capacity), "powerMw": float64(b.PowerMw),
			"tempC": float64(b.TempMilliC) / 1000, "currentMa": float64(b.CurrentUa) / 1000,
		})
	}
	d.checkBatteryNotify(b)
}

func (d *Daemon) checkBatteryNotify(b sysinfo.Battery) {
	tg := d.Cfg.Get().Telegram
	if !tg.Enabled || tg.BotToken == "" || tg.ChatID == "" {
		return
	}
	if b.Capacity <= 0 {
		return
	}
	charging := b.Status == "Charging" || b.Status == "Full" || b.Online
	n := &d.batNotify

	if tg.NotifyLowBat && !charging && b.Capacity <= tg.LowBatPercent && !n.notifiedLow {
		temp := ""
		if b.TempMilliC > 0 {
			temp = fmt.Sprintf(" (temp %.1f°C)", float64(b.TempMilliC)/100)
		}
		msg := fmt.Sprintf("⚠️ <b>Low Battery</b>\nCapacity: %d%%%s\nStatus: %s", b.Capacity, temp, b.Status)
		if err := telegram.Send(tg.BotToken, tg.ChatID, msg); err != nil {
			d.Log.Warnf("telegram", "low battery notify failed: %v", err)
		} else {
			n.notifiedLow = true
			d.Log.Infof("telegram", "sent low battery notification (%d%%)", b.Capacity)
		}
	}

	if charging && !n.lastCharging {
		n.notified80 = false
		n.notified90 = false
		n.notified100 = false
	}

	if tg.NotifyCharge && charging {
		type milestone struct {
			threshold int
			flag      *bool
			enabled   bool
		}
		milestones := []milestone{
			{80, &n.notified80, tg.Charge80},
			{90, &n.notified90, tg.Charge90},
			{100, &n.notified100, tg.Charge100},
		}
		for _, m := range milestones {
			if m.enabled && !*m.flag && b.Capacity >= m.threshold {
				msg := fmt.Sprintf("🔋 <b>Charge %d%%</b>\nStatus: %s", b.Capacity, b.Status)
				if b.TempMilliC > 0 {
					msg += fmt.Sprintf(" (temp %.1f°C)", float64(b.TempMilliC)/100)
				}
				if err := telegram.Send(tg.BotToken, tg.ChatID, msg); err != nil {
					d.Log.Warnf("telegram", "charge %d%% notify failed: %v", m.threshold, err)
				} else {
					*m.flag = true
					d.Log.Infof("telegram", "sent charge %d%% notification", b.Capacity)
				}
			}
		}
	}

	n.lastCap = b.Capacity
	n.lastCharging = charging
	if !charging {
		n.notifiedLow = false
	}
}

func (d *Daemon) tickClients() {
	readers := d.leaseReaders()
	list := d.Clients.Scan(readers...)
	online := 0
	var rx, tx uint64
	for _, c := range list {
		if c.Online {
			online++
		}
		rx += c.RxBytes
		tx += c.TxBytes
	}
	d.Metrics.Clients.Add(map[string]float64{"online": float64(online), "total": float64(len(list))})
	d.put("clients", map[string]any{"count": online, "total": len(list), "bytes": rx + tx})
}

func (d *Daemon) tickNetwork() {
	snap := d.Dev.Snapshot(true)
	d.put("net", snap)
	es := d.Eng.Status()
	up := es.Upstream
	if up.Name != "" {
		if st := netinfo.ReadStats(up.Name); st != nil {
			d.Metrics.Upstream.Add(map[string]float64{"rxTotalMb": float64(st.RxBytes) / 1e6, "txTotalMb": float64(st.TxBytes) / 1e6})
		}
	}
	if es.State == repeater.Running && es.Downstream.Name != "" && es.Gateway != "" {
		if !d.Dev.HasAddr(es.Downstream.Name, es.Gateway) {
			d.Log.Warnf("monitor", "LAN address %s missing on %s, re-adding", es.Gateway, es.Downstream.Name)
			_ = d.Dev.AddAddr(es.Downstream.Name, es.Gateway+"/24")
		}
	}
}

func (d *Daemon) tickHealth() {
	// The engine self-monitors; this tick only refreshes cached capability data
	// so the diagnostics page stays current without a manual re-probe.
	d.Cap.Invalidate()
	d.Cap.All()
}

// leaseReaders returns the lease sources that exist right now.
func (d *Daemon) leaseReaders() []clients.LeaseReader {
	var out []clients.LeaseReader
	if p := d.Eng.LeaseFile(); p != "" {
		if _, err := os.Stat(p); err == nil {
			out = append(out, clients.DHCPLeases{Path: p})
		}
	}
	out = append(out, clients.DnsmasqLeases{Paths: []string{
		"/data/misc/dhcp/dnsmasq.leases",
		"/data/misc/apexdata/com.android.tethering/misc/dhcp/dnsmasq.leases",
		"/data/misc/dnsmasq.leases",
	}})
	out = append(out, clients.ARPFileLeases{})
	return out
}

// monitorInterfaces decides which interfaces' counters to sample: always the
// upstream and downstream, plus anything else with traffic.
func (d *Daemon) monitorInterfaces() []string {
	st := d.Eng.Status()
	set := map[string]bool{}
	var out []string
	add := func(n string) {
		if n != "" && !set[n] {
			set[n] = true
			out = append(out, n)
		}
	}
	add(st.Upstream.Name)
	add(st.Downstream.Name)
	if len(out) == 0 {
		if up, err := d.Dev.DefaultUpstream(); err == nil {
			add(up.Name)
		}
	}
	if links, err := d.Dev.Links(); err == nil {
		for _, l := range links {
			if l.Up && !l.Loopback && len(out) < 8 {
				add(l.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

// cache ---------------------------------------------------------------

func (d *Daemon) put(key string, v any) {
	d.mu.Lock()
	d.cache[key] = cachedValue{at: time.Now(), val: v}
	d.mu.Unlock()
}

// cached returns the freshest cached value, or falls back to reading directly
// the first time a monitor has not ticked yet. This means the dashboard always
// has data on first paint instead of spinning.
func (d *Daemon) cached(key string, fallback func() any) any {
	d.mu.RLock()
	v, ok := d.cache[key]
	d.mu.RUnlock()
	if ok {
		return v.val
	}
	f := fallback()
	d.put(key, f)
	return f
}

// ---------------------------------------------------------------------------
// api.Monitor implementation
// ---------------------------------------------------------------------------

// CPU returns processor state plus per-core detail.
func (d *Daemon) CPU() map[string]any {
	return cpuMap(d.cached("cpu", func() any { return d.cpu.Sample() }).(sysinfo.CPUStat), d)
}

// Memory returns RAM/swap detail.
func (d *Daemon) Memory() map[string]any {
	return d.cached("memory", func() any {
		m := sysinfo.Memory()
		return map[string]any{
			"mem": m, "swaps": sysinfo.Swaps(), "procs": sysinfo.Procs(),
			"vmstat": sysinfo.VmStat(), "psi": sysinfo.PSI(),
		}
	}).(map[string]any)
}

// Battery returns power state.
func (d *Daemon) Battery() map[string]any {
	b := d.cached("battery", func() any { return sysinfo.ReadBattery() }).(sysinfo.Battery)
	out := map[string]any{"battery": b}
	// Charging power is only meaningful with a current reading.
	if b.CurrentUa == 0 {
		out["note"] = "This battery driver does not expose current, so charge/discharge rate is unavailable."
	}
	if b.Capacity == 0 {
		out["note"] = "Battery capacity is not readable on this device."
	}
	return out
}

// Thermal returns sensor readings grouped by identified kind.
func (d *Daemon) Thermal() map[string]any {
	return d.cached("thermal", func() any {
		zones := sysinfo.Thermals()
		hw := sysinfo.HwmonSensors()
		grouped := map[string][]map[string]any{}
		add := func(kind string, name string, mc int, path string, identified bool) {
			if mc <= 0 {
				return
			}
			grouped[kind] = append(grouped[kind], map[string]any{
				"name": name, "tempC": float64(mc) / 1000, "path": path, "identified": identified,
			})
		}
		for _, z := range zones {
			add(z.Kind, z.Name, z.TempMilliC, z.Path, z.Identified)
		}
		for _, z := range hw {
			add(z.Kind, z.Name, z.TempMilliC, z.Path, z.Identified)
		}
		var maxT float64
		for _, list := range grouped {
			for _, e := range list {
				if v, ok := e["tempC"].(float64); ok && v > maxT {
					maxT = v
				}
			}
		}
		res := map[string]any{
			"zones": zones, "hwmon": hw, "grouped": grouped, "maxC": maxT,
			"count": len(zones) + len(hw),
		}
		if len(zones)+len(hw) == 0 {
			res["unavailable"] = "No thermal sensors are exposed by this kernel, so temperature cannot be measured."
		}
		return res
	}).(map[string]any)
}

// Storage returns filesystem usage.
func (d *Daemon) Storage() map[string]any {
	return d.cached("storage", func() any {
		parts := sysinfo.Storage()
		var total, free uint64
		for _, p := range parts {
			if p.Mount == "/data" {
				total, free = p.Total, p.Avail
			}
		}
		out := map[string]any{"partitions": parts, "log": d.Log.Stats()}
		if total > 0 {
			out["data"] = map[string]any{"total": total, "avail": free, "used": total - free}
		}
		return out
	}).(map[string]any)
}

// Traffic returns throughput with per-interface detail.
func (d *Daemon) Traffic() map[string]any {
	return d.cached("traffic", func() any {
		ifaces := d.monitorInterfaces()
		rates := d.sampleTraffic(ifaces)
		return map[string]any{"rates": rates, "interfaces": ifaces}
	}).(map[string]any)
}

// WiFi returns station + AP state and the radio inventory.
func (d *Daemon) WiFi() map[string]any {
	stations := d.Wifi.Stations()
	aps := d.Wifi.AccessPoints()
	out := map[string]any{
		"stations": stations, "accessPoints": aps,
		"radios": d.Cap.Radios(), "capabilities": d.Cap.All(),
	}
	if len(stations) == 0 && len(aps) == 0 {
		out["note"] = "No Wi-Fi interface is active. Yoru will report the exact reason once one exists."
	}
	for _, s := range stations {
		if s.RSSI != 0 {
			out["signalQuality"] = wifistate.SignalQuality(s.RSSI)
			break
		}
	}
	if e := d.Eng.Status(); e.Strategy != "" {
		out["strategy"] = e.Strategy
	}
	return out
}

// Network returns full routing/DHCP/DNS/neighbour state.
func (d *Daemon) Network() map[string]any {
	snap := d.cached("net", func() any { return d.Dev.Snapshot(true) }).(netinfo.Snapshot)
	st := d.Eng.Status()
	out := map[string]any{
		"snapshot": snap, "repeater": st,
		"firewall": d.Fire.Status(),
		"tunnel":   vpnReport(snap),
	}
	if s := d.DNS(); s != nil {
		out["dnsServer"] = s.Status()
	}
	if e := d.Eng.DHCP(); e != nil {
		out["dhcpServer"] = e.Status()
		out["leases"] = e.Leases()
	}
	return out
}

// System returns OS/kernel identity.
func (d *Daemon) System() map[string]any {
	k := sysinfo.KernelInfo()
	mem := sysinfo.Memory()
	cpu := d.cpu.Sample()
	return map[string]any{
		"kernel": k, "cpu": cpu, "memory": mem,
		"android": map[string]any{
			"release":      sysinfo.Getprop("ro.build.version.release"),
			"sdk":          atoi(sysinfo.Getprop("ro.build.version.sdk")),
			"model":        sysinfo.Getprop("ro.product.model"),
			"manufacturer": sysinfo.Getprop("ro.product.manufacturer"),
			"device":       sysinfo.Getprop("ro.product.device"),
			"abi":          sysinfo.Getprop("ro.product.cpu.abi"),
			"abilist":      sysinfo.Getprop("ro.product.cpu.abilist"),
			"board":        sysinfo.Getprop("ro.product.board"),
			"soc":          sysinfo.Getprop("ro.soc.model"),
			"display":      sysinfo.Getprop("ro.build.display.id"),
		},
		"uptimeSec": sysinfo.ReadUptime(),
		"procs":     sysinfo.Procs(),
		"runtime": map[string]any{
			"goroutines": runtime.NumGoroutine(), "goVersion": runtime.Version(),
			"allocBytes": memAlloc(), "sysBytes": memSys(), "gomaxprocs": runtime.GOMAXPROCS(0),
		},
		"bootId": sysinfo.BootId(),
		"pid":    os.Getpid(),
	}
}

// Health returns a compact liveness document.
func (d *Daemon) Health() map[string]any {
	st := d.Eng.Status()
	out := map[string]any{
		"state":      string(st.State),
		"mode":       st.Mode,
		"engine":     st,
		"uptimeSec":  int64(time.Since(d.started).Seconds()),
		"goroutines": runtime.NumGoroutine(),
		"logOk":      d.Log.FileErr() == nil,
		"clients":    d.Clients.Stats(),
		"dashboard":  map[string]any{"streams": d.watchers},
	}
	if err := d.Log.FileErr(); err != nil {
		out["logError"] = err.Error()
	}
	if st.LastError != "" {
		out["lastError"] = st.LastError
	}
	return out
}

// Diagnostics builds the full report the Diagnostics page shows and exports.
func (d *Daemon) Diagnostics() map[string]any {
	k := sysinfo.KernelInfo()
	mode, policy := sysinfo.SELinuxStatus()
	rep := map[string]any{
		"generated": time.Now().Format(time.RFC3339),
		"identity": map[string]any{
			"product": "Yoru Repeater", "version": versionTag, "pid": os.Getpid(),
			"uid": os.Getuid(), "bootId": sysinfo.BootId(),
		},
		"android": map[string]any{
			"release":      sysinfo.Getprop("ro.build.version.release"),
			"sdk":          atoi(sysinfo.Getprop("ro.build.version.sdk")),
			"abi":          sysinfo.Getprop("ro.product.cpu.abi"),
			"abilist":      sysinfo.Getprop("ro.product.cpu.abilist"),
			"board":        sysinfo.Getprop("ro.product.board"),
			"hardware":     sysinfo.Getprop("ro.hardware"),
			"bootHardware": sysinfo.Getprop("ro.boot.hardware"),
			"soc":          sysinfo.Getprop("ro.soc.model"),
			"model":        sysinfo.Getprop("ro.product.model"),
			"manufacturer": sysinfo.Getprop("ro.product.manufacturer"),
			"fingerprint":  sysinfo.Getprop("ro.build.fingerprint"),
			"buildType":    sysinfo.Getprop("ro.build.type"),
			"apiLevelName": apiLevelName(atoi(sysinfo.Getprop("ro.build.version.sdk"))),
		},
		"root":         rootReport(),
		"kernel":       k,
		"selinux":      map[string]any{"mode": orUnset(mode), "policy": policy},
		"capabilities": d.Cap.All(),
		"radios":       d.Cap.Radios(),
		"summary":      d.Cap.Summarise(),
		"tools":        safeexec.Tools(),
		"firewall": map[string]any{
			"backend": d.Fire.Backend(), "binary": d.Fire.Binary(),
			"status": d.Fire.Status(), "backends": d.Fire.AvailableBackends(),
		},
		"engine":     d.Eng.Status(),
		"strategies": d.Eng.Strategies(),
		"interfaces": nil,
		"log":        d.Log.Stats(),
		"runtime": map[string]any{
			"goroutines": runtime.NumGoroutine(), "goVersion": runtime.Version(),
			"allocBytes": memAlloc(), "uptimeSec": int64(time.Since(d.started).Seconds()),
		},
	}
	if links, err := d.Dev.Links(); err == nil {
		rep["interfaces"] = links
	}
	if addrs, err := d.Dev.Addrs(); err == nil {
		rep["addresses"] = addrs
	}
	if routes, err := d.Dev.Routes(); err == nil {
		rep["routes"] = compactRoutes(routes)
	}
	rep["dns"] = d.Dev.Resolvers()
	rep["sensors"] = map[string]any{
		"thermalZones": len(sysinfo.Thermals()), "hwmon": len(sysinfo.HwmonSensors()),
		"powerSupplies": powerSupplies(),
	}
	rep["battery"] = sysinfo.ReadBattery()
	rep["memory"] = sysinfo.Memory()
	rep["cpu"] = d.cpu.Sample()
	return rep
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// toMap adapts a CPUStat for the API, adding derived fields the UI needs.
func cpuMap(c sysinfo.CPUStat, d *Daemon) map[string]any {
	out := map[string]any{
		"cpu": c, "cores": c.Cores, "onlineCores": c.OnlineCores,
		"governors": c.Governors, "frequencies": c.Frequencies,
		"load": c.Load, "perCore": c.PerCore, "total": c.Total, "iowait": c.IOWait,
		"arch": c.Arch, "model": c.Model, "cpuPart": c.Variant,
		"uptimeSec": c.UptimeSec, "contextSwitches": c.ContextSwitches,
		"processes": sysinfo.Procs(),
	}
	if len(c.Frequencies) > 0 {
		var cur, max float64
		for _, f := range c.Frequencies {
			cur += float64(f.CurKHz)
			max += float64(f.MaxKHz)
		}
		out["avgCurMHz"] = cur / float64(len(c.Frequencies)) / 1000
		out["maxMHz"] = max / float64(len(c.Frequencies)) / 1000
	}
	// Cluster layout helps the UI label big/little cores honestly.
	var clusters []map[string]any
	seen := map[int]bool{}
	for _, f := range c.Frequencies {
		if f.MaxKHz == 0 || seen[f.MaxKHz] {
			continue
		}
		seen[f.MaxKHz] = true
		n := 0
		for _, g := range c.Frequencies {
			if g.MaxKHz == f.MaxKHz {
				n++
			}
		}
		clusters = append(clusters, map[string]any{"maxMHz": f.MaxKHz / 1000, "cores": n, "governor": f.Gov})
	}
	sort.Slice(clusters, func(i, j int) bool {
		return clusters[i]["maxMHz"].(int) > clusters[j]["maxMHz"].(int)
	})
	out["clusters"] = clusters
	return out
}

func compactRoutes(rs []netinfo.Route) []netinfo.Route {
	var out []netinfo.Route
	for _, r := range rs {
		if r.Family != "IPv4" && r.Family != "IPv6" {
			continue
		}
		out = append(out, r)
		if len(out) > 80 {
			break
		}
	}
	return out
}

func vpnReport(s netinfo.Snapshot) []map[string]any {
	var out []map[string]any
	for _, l := range s.Links {
		if netinfo.Classify(l) != netinfo.ClassVPN {
			continue
		}
		entry := map[string]any{"iface": l.Name, "up": l.Up, "running": l.Running || l.LowerUp}
		for _, a := range s.Addrs {
			if a.Iface == l.Name {
				entry["address"] = a.CIDR
			}
		}
		if l.Up && (l.Running || l.LowerUp) {
			entry["warning"] = "A VPN tunnel is active. Client traffic may leave through the tunnel instead of the " +
				"upstream interface Yoru selected, and the VPN's own routing rules take precedence. Yoru does not modify VPN configuration."
		}
		out = append(out, entry)
	}
	return out
}

func powerSupplies() []string {
	d, err := filepath.Glob("/sys/class/power_supply/*")
	if err != nil {
		return nil
	}
	var out []string
	for _, x := range d {
		name := filepath.Base(x)
		t, err := os.ReadFile(filepath.Join(x, "type"))
		if err == nil {
			name += "=" + strings.TrimSpace(string(t))
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func rootReport() map[string]any {
	out := map[string]any{}
	for _, kv := range [][3]string{
		{"KSU", "KernelSU", "/data/adb/ksu"},
		{"APATCH", "APatch", "/data/adb/ap"},
		{"MAGISKBLOCK", "Magisk(block)", "/data/adb/magisk"},
	} {
		if v := os.Getenv(kv[0]); v != "" {
			out["implementation"] = kv[1]
			out["env"] = v
		}
		if _, err := os.Stat(kv[2]); err == nil {
			out[kv[1]+"Dir"] = true
		}
	}
	if v := sysinfo.Getprop("ro.magisk.version"); v != "" {
		out["magiskVersion"] = v
	}
	out["uid"] = os.Getuid()
	out["euid"] = os.Geteuid()
	if out["uid"] == 0 {
		out["privileged"] = true
	} else {
		out["privileged"] = false
		out["warning"] = "yorud is not running as root; network changes will fail and are refused."
	}
	return out
}

func apiLevelName(sdk int) string {
	names := map[int]string{
		29: "Android 10 (Q)", 30: "Android 11 (R)", 31: "Android 12 (S)",
		32: "Android 12L", 33: "Android 13 (T)", 34: "Android 14 (U)",
		35: "Android 15 (V)", 36: "Android 16", 37: "Android 17",
	}
	if n, ok := names[sdk]; ok {
		return n
	}
	if sdk == 0 {
		return "unknown (not reading Android properties)"
	}
	return "unrecognised SDK level " + strconv.Itoa(sdk)
}

func slug(s string) string {
	var b strings.Builder
	prevSep := false
	for _, r := range strings.ToLower(s) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			prevSep = false
			continue
		}
		if !prevSep {
			b.WriteRune('_')
			prevSep = true
		}
	}
	return strings.Trim(b.String(), "_")
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func orUnset(s string) string {
	if s == "" {
		return "not exposed"
	}
	return s
}

func memAlloc() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Alloc
}

func memSys() uint64 {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.Sys
}
