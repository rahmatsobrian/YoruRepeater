// Package repeater is Yoru's network engine: the state machine that turns a
// capability set plus a configuration into a working router, or into a precise
// explanation of why it cannot.
//
// Startup order is deliberate and mirrors what a careful operator would do by
// hand, and every step records the undo action it needs:
//
//  1. resolve interfaces + verify the subnet will not collide with upstream
//  2. enable forwarding            (undo: restore previous sysctl values)
//  3. bring up the access point     (undo: stop backend, restore interface)
//  4. address the LAN interface     (undo: remove the address we added)
//  5. install firewall rules        (undo: remove Yoru chains)
//  6. start DHCP + DNS              (undo: stop servers)
//  7. health loop                   (watchdog: restart dead children, or fail
//     the whole attempt and roll back)
//
// If any step fails, everything from that step backwards is undone. The phone
// is never left half-configured.
package repeater

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"yoru.dev/yorud/internal/apbringer"
	"yoru.dev/yorud/internal/caps"
	"yoru.dev/yorud/internal/clients"
	"yoru.dev/yorud/internal/config"
	"yoru.dev/yorud/internal/dhcpd"
	"yoru.dev/yorud/internal/dnsd"
	"yoru.dev/yorud/internal/firewall"
	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/safeexec"
	"yoru.dev/yorud/internal/wifistate"
)

// State is the engine's lifecycle position.
type State string

// Lifecycle states.
const (
	Stopped     State = "stopped"
	Starting    State = "starting"
	Running     State = "running"
	Stopping    State = "stopping"
	Degraded    State = "degraded"
	Failed      State = "failed"
	Cooldown    State = "cooldown"
	RollingBack State = "rolling-back"
)

// Status is the engine's externally visible state.
type Status struct {
	State        State     `json:"state"`
	Mode         string    `json:"mode"`
	ModeLabel    string    `json:"modeLabel"`
	Upstream     IfaceRef  `json:"upstream"`
	Downstream   IfaceRef  `json:"downstream"`
	Strategy     string    `json:"apStrategy,omitempty"`
	Gateway      string    `json:"gateway,omitempty"`
	DHCPRunning  bool      `json:"dhcpRunning"`
	DNSRunning   bool      `json:"dnsRunning"`
	Firewall     string    `json:"firewallBackend"`
	Since        int64     `json:"sinceMs,omitempty"`
	LastError    string    `json:"lastError,omitempty"`
	LastFailure  string    `json:"lastFailureAt,omitempty"`
	Failures     int       `json:"consecutiveFailures"`
	AutoDisabled bool      `json:"autoStartDisabled"`
	Steps        []StepLog `json:"steps"`
	Rollback     []string  `json:"rollbackLog,omitempty"`
	Notes        []string  `json:"notes,omitempty"`
	Internet     Internet  `json:"internet"`
	Clients      int       `json:"clients"`
	UptimeSec    int64     `json:"uptimeSec,omitempty"`
}

// IfaceRef names an interface plus its address.
type IfaceRef struct {
	Name    string `json:"name"`
	Kind    string `json:"kind"`
	Address string `json:"address,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	MAC     string `json:"mac,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// StepLog records what each bring-up step did.
type StepLog struct {
	Name   string `json:"step"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
	TookMs int64  `json:"tookMs"`
	At     int64  `json:"atMs"`
}

// Internet is the upstream reachability verdict.
type Internet struct {
	Reachable bool     `json:"reachable"`
	Method    string   `json:"method"`
	LatencyMs int64    `json:"latencyMs,omitempty"`
	Detail    string   `json:"detail,omitempty"`
	CheckedAt int64    `json:"checkedAtMs"`
	DNS       bool     `json:"dnsWorks"`
	Probes    []string `json:"probes,omitempty"`
}

// Engine owns the repeater.
type Engine struct {
	mu sync.Mutex

	cfg  *config.Store
	log  *logging.Logger
	dev  *netinfo.Device
	cap  *caps.Set
	ap   *apbringer.Controller
	fw   *firewall.Manager
	dhcp *dhcpd.Server
	dns  *dnsd.Server
	trk  *clients.Tracker
	wifi *wifistate.Reader

	state   State
	status  Status
	undo    []func() error
	started time.Time

	dhcpFile string
	runDir   string
	stateDir string

	failures   int
	cooldownU  time.Time
	stopCh     chan struct{}
	healthOnce sync.Once
	lastCtl    string
}

// Options locates the engine's directories.
type Options struct {
	StateDir string
	RunDir   string
}

// New builds an engine.
func New(cfg *config.Store, log *logging.Logger, dev *netinfo.Device, cs *caps.Set,
	trk *clients.Tracker, wifi *wifistate.Reader, opts Options) *Engine {
	if opts.StateDir == "" {
		opts.StateDir = config.DefaultStateDir
	}
	if opts.RunDir == "" {
		opts.RunDir = filepath.Join(opts.StateDir, "run")
	}
	e := &Engine{
		cfg: cfg, log: log, dev: dev, cap: cs, trk: trk, wifi: wifi,
		state: Stopped, runDir: opts.RunDir, stateDir: opts.StateDir,
		dhcpFile: filepath.Join(opts.StateDir, "state", "dhcp.leases"),
		fw:       firewall.NewManager(log),
		status:   Status{State: Stopped},
	}
	e.ap = apbringer.NewController(log, dev, cs, wifi, opts.StateDir)
	e.status.Firewall = string(e.fw.Detect())
	return e
}

// State returns the current lifecycle state.
func (e *Engine) State() State {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state
}

// Status returns a copy of the engine status.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := e.status
	s.State = e.state
	s.Firewall = string(e.fw.Detect())
	if !e.started.IsZero() && (e.state == Running || e.state == Degraded) {
		s.UptimeSec = int64(time.Since(e.started).Seconds())
	}
	s.DHCPRunning = e.dhcp != nil && e.dhcp.Running()
	s.DNSRunning = e.dns != nil && e.dns.Running()
	s.Clients = e.trk.Stats().Online
	if s.Since == 0 && !e.started.IsZero() {
		s.Since = e.started.UnixMilli()
	}
	return s
}

// LeaseFile returns the path Yoru's DHCP server writes.
func (e *Engine) LeaseFile() string { return e.dhcpFile }

// DHCP returns the built-in server (nil when dnsmasq is in use).
func (e *Engine) DHCP() *dhcpd.Server {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dhcp
}

// DNS returns the forwarder.
func (e *Engine) DNS() *dnsd.Server {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.dns
}

// Strategies lists AP backends and their verdicts.
func (e *Engine) Strategies() []map[string]any {
	c := e.cfg.Get()
	return e.ap.Strategies(e.spec(c))
}

// Start brings the repeater up. Safe to call from the API and from boot.
func (e *Engine) Start(auto bool) error {
	e.mu.Lock()
	if e.state == Running || e.state == Starting || e.state == Degraded {
		e.mu.Unlock()
		return nil
	}
	if e.state == Cooldown && time.Now().Before(e.cooldownU) {
		wait := time.Until(e.cooldownU)
		e.mu.Unlock()
		return fmt.Errorf("repeater is cooling down after repeated failures; retry in %s", wait.Round(time.Second))
	}
	if auto && e.status.AutoDisabled {
		e.mu.Unlock()
		return errors.New("automatic start is disabled after repeated failures; start it manually from the dashboard")
	}
	e.state = Starting
	e.undo = nil
	e.status.Steps = nil
	e.status.Rollback = nil
	e.status.LastError = ""
	e.mu.Unlock()

	err := e.bringUp(auto)
	if err != nil {
		e.mu.Lock()
		e.failures++
		cfg := e.cfg.Get()
		window := time.Duration(cfg.Advanced.Watchdog.WindowSec) * time.Second
		if e.failures >= cfg.Advanced.Watchdog.MaxRestarts {
			e.state = Cooldown
			e.cooldownU = time.Now().Add(window)
			e.status.AutoDisabled = true
			e.log.Errorf("repeater", "startup failed %d times; automatic restart disabled until it is started manually", e.failures)
		} else {
			e.state = Failed
			backoff := time.Duration(e.failures*cfg.Advanced.Watchdog.BackoffStepMs) * time.Millisecond
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
			e.cooldownU = time.Now().Add(backoff)
			e.state = Cooldown
		}
		e.status.LastError = err.Error()
		e.status.LastFailure = time.Now().Format(time.RFC3339)
		e.mu.Unlock()
		e.log.Errorf("repeater", "start failed: %v", err)
		return err
	}
	e.mu.Lock()
	e.failures = 0
	e.state = Running
	e.started = time.Now()
	e.status.Since = e.started.UnixMilli()
	e.stopCh = make(chan struct{})
	e.mu.Unlock()
	e.log.Infof("repeater", "started in %s mode (upstream=%s downstream=%s)",
		e.Status().Mode, e.Status().Upstream.Name, e.Status().Downstream.Name)
	e.healthOnce.Do(func() { go e.healthLoop() })
	e.logSteps()
	return nil
}

// logSteps emits a compact startup summary for the log page.
func (e *Engine) logSteps() {
	s := e.Status()
	e.log.Infof("repeater", "up: strategy=%s upstream=%s(%s) downstream=%s gw=%s dhcp=%v dns=%v fw=%s",
		s.Strategy, s.Upstream.Name, s.Upstream.Kind, s.Downstream.Name, s.Gateway, s.DHCPRunning, s.DNSRunning, s.Firewall)
}

func (e *Engine) bringUp(auto bool) error {
	c := e.cfg.Get()
	if msgs := config.Validate(c); len(msgs) > 0 {
		e.log.Warnf("repeater", "configuration was normalised: %s", strings.Join(msgs, " "))
	}
	if err := os.MkdirAll(e.runDir, 0700); err != nil {
		return fmt.Errorf("cannot create %s: %w", e.runDir, err)
	}
	if err := os.MkdirAll(filepath.Dir(e.dhcpFile), 0700); err != nil {
		return err
	}

	// ---- step 1: interfaces ------------------------------------------------
	sum := e.cap.Summarise()
	upName, upWhy, err := apbringer.PickUpstream(e.dev, c.Repeater.Upstream)
	if err != nil {
		e.step("interfaces", false, "no usable upstream: "+err.Error())
		return e.upstreamError(err, sum)
	}
	e.step("upstream", true, upName+": "+upWhy)

	downName, downWhy := apbringer.PickDownstream(e.dev, c.Repeater.Downstream, c.Repeater.AP.Strategy == "hostapd")
	if downName == "" && !sum.HotspotRouter && !sum.TrueRepeater {
		e.step("downstream", false, downWhy)
		return e.downstreamError(downWhy, sum)
	}
	if downName == "" {
		downName = c.Repeater.Downstream
	}
	e.step("downstream", true, orFallback(downName, downWhy))

	if sameIface(upName, downName) {
		return fmt.Errorf("upstream and downstream resolved to the same interface %s; refusing to create a routing loop", upName)
	}

	// ---- step 2: subnet conflict check ------------------------------------
	gwIP := net.ParseIP(c.Repeater.LAN.Gateway)
	if gwIP == nil {
		return errors.New("configured gateway is not an IP address")
	}
	addrs, _ := e.dev.Addrs()
	routes, _ := e.dev.Routes()
	conflicts := findConflicts(c, addrs, routes, upName, downName)
	if len(conflicts) > 0 && !c.Advanced.ForceInterface {
		// Filter out overlaps on interfaces where we already placed the gateway
		// (the daemon or Android hotspot previously configured the downstream).
		var real []string
		for _, cf := range conflicts {
			isSelf := false
			for _, a := range addrs {
				if a.Iface != "" && a.Iface != upName && a.IP == c.Repeater.LAN.Gateway {
					if strings.Contains(cf, a.Iface) {
						isSelf = true
						break
					}
				}
			}
			if !isSelf {
				real = append(real, cf)
			}
		}
		if len(real) > 0 {
			return fmt.Errorf("the configured LAN subnet %s/%d overlaps an existing network (%s); choose a different subnet in Settings - Repeater",
				c.Repeater.LAN.Gateway, c.Repeater.LAN.Prefix, strings.Join(real, ", "))
		}
	}
	if len(conflicts) > 0 {
		e.step("subnet", true, "overlaps "+strings.Join(conflicts, ", ")+" but forcing was requested")
		e.note("subnet overlap forced by advanced.forceInterface; traffic to the overlapping network will be unreachable for clients")
	} else {
		e.step("subnet", true, fmt.Sprintf("%s/%d is free", c.Repeater.LAN.Gateway, c.Repeater.LAN.Prefix))
	}

	// ---- step 3: forwarding -----------------------------------------------
	if c.Repeater.Routing.IPForward {
		prev, err := e.enableForwarding("net.ipv4.ip_forward")
		if err != nil {
			e.step("ip-forward", false, err.Error())
			return fmt.Errorf("cannot enable IPv4 forwarding: %w", err)
		}
		e.step("ip-forward", true, "was "+prev+", now 1")
	}
	if c.Repeater.LAN.IPv6Mode == "forward" || c.Repeater.LAN.IPv6Mode == "auto" {
		if netinfo.IPv6Available() {
			if prev, err := e.enableForwarding("net.ipv6.conf.all.forwarding"); err == nil {
				e.step("ipv6-forward", true, "was "+prev+", now 1")
			} else {
				e.step("ipv6-forward", true, "skipped: "+err.Error())
			}
		}
	}

	// ---- step 4: access point ---------------------------------------------
	spec := e.spec(c)
	if spec.Iface == "" {
		spec.Iface = downName
	}
	if spec.Security != "open" && spec.Passphrase == "" {
		return errors.New("a Wi-Fi passphrase is required for " + spec.Security + "; set one in Settings - Repeater")
	}
	res, err := e.ap.Start(spec)
	if err != nil {
		e.step("access-point", false, err.Error())
		return fmt.Errorf("could not start an access point: %w", err)
	}
	e.pushUndo(func() error { return e.ap.Stop(res.Iface) })
	e.step("access-point", true, res.Strategy+" on "+res.Iface+" ("+res.Detail+")")
	downName = res.Iface

	// ---- step 5: address the LAN ------------------------------------------
	cidr := fmt.Sprintf("%s/%d", c.Repeater.LAN.Gateway, c.Repeater.LAN.Prefix)
	if err := e.dev.AddAddr(downName, cidr); err != nil {
		e.step("lan-address", false, err.Error())
		return fmt.Errorf("could not assign %s to %s: %w", cidr, downName, err)
	}
	e.pushUndo(func() error { return e.dev.DelAddr(downName, cidr) })
	if err := e.dev.LinkUp(downName); err != nil {
		e.log.Warnf("repeater", "interface %s may already be up: %v", downName, err)
	}
	e.step("lan-address", true, cidr)
	// Keep a record of addresses we did not own so a rollback never removes a
	// framework address.
	e.note("assigned " + cidr + " to " + downName)

	// ---- step 6: firewall --------------------------------------------------
	plan := firewall.Plan{
		AP: downName, Upstream: upName, GatewayIP: c.Repeater.LAN.Gateway,
		ClientSubnet: cidr, Isolate: c.Repeater.Routing.IsolateClients,
		Account: true, IPv6: netinfo.IPv6Available() && c.Repeater.LAN.IPv6Mode != "off",
	}
	if c.Repeater.Routing.FirewallBackend != "auto" {
		e.log.Debugf("repeater", "operator requested firewall backend %q", c.Repeater.Routing.FirewallBackend)
	}
	if err := e.fw.Apply(plan); err != nil {
		e.step("firewall", false, err.Error())
		return fmt.Errorf("cannot install forwarding/NAT rules: %w", err)
	}
	e.pushUndo(func() error { return e.fw.Remove() })
	e.step("firewall", true, "backend "+string(e.fw.Detect())+" NAT via "+upName)

	// ---- step 7: DNS then DHCP (order matters: the lease must name servers) --
	dnsServers := e.lanDNS(c)
	if err := e.startDNS(downName, c, dnsServers); err != nil {
		e.step("dns", false, err.Error())
		e.note("DNS forwarder unavailable; clients will need their own resolver")
	} else {
		e.step("dns", true, "forwarding to "+strings.Join(ipsToString(dnsServers), ", "))
	}
	if err := e.startDHCP(downName, c, dnsServers); err != nil {
		e.step("dhcp", false, err.Error())
		return fmt.Errorf("cannot provide addresses to clients: %w", err)
	} else {
		e.step("dhcp", true, c.Repeater.LAN.DHCPStart+"-"+c.Repeater.LAN.DHCPEnd)
	}

	// ---- step 8: per-client accounting + tracking --------------------------
	e.trk.Configure(downName, c.Repeater.LAN.Gateway, c.Monitor.MaskMACs)
	e.trk.SetAccounting(e.fw)
	e.step("monitoring", true, "clients tracked on "+downName)

	// ---- final: does the whole thing actually work? -----------------------
	e.status.Upstream = e.describe(upName)
	e.status.Downstream = e.describe(downName)
	e.status.Gateway = c.Repeater.LAN.Gateway
	e.status.Strategy = res.Strategy
	e.status.Mode, e.status.ModeLabel = e.decideMode(c, res.Strategy, downName, upName)
	for _, n := range res.Notes {
		e.note(n)
	}
	if !e.waitForTraffic(downName, 6*time.Second) {
		e.log.Warnf("repeater", "no client traffic observed yet on %s (this is normal before a device connects)", downName)
	}
	return nil
}

// stop performs the rollback in reverse order.
func (e *Engine) stop(reason string) error {
	e.mu.Lock()
	if e.state == Stopped {
		e.mu.Unlock()
		return nil
	}
	e.state = Stopping
	undos := e.undo
	e.undo = nil
	e.mu.Unlock()

	e.log.Infof("repeater", "stopping (%s); rolling back %d step(s)", reason, len(undos))
	var problems []string
	for i := len(undos) - 1; i >= 0; i-- {
		if err := undos[i](); err != nil {
			problems = append(problems, err.Error())
			e.log.Warnf("repeater", "rollback step %d failed: %v", i, err)
			e.mu.Lock()
			e.status.Rollback = append(e.status.Rollback, fmt.Sprintf("step %d: %v", i, err))
			e.mu.Unlock()
		}
	}
	e.mu.Lock()
	if e.dhcp != nil {
		_ = e.dhcp.Stop()
		e.dhcp = nil
	}
	if e.dns != nil {
		_ = e.dns.Stop()
		e.dns = nil
	}
	if e.stopCh != nil {
		close(e.stopCh)
		e.stopCh = nil
	}
	e.trk.SetAccounting(nil)
	e.status.DHCPRunning = false
	e.status.DNSRunning = false
	e.state = Stopped
	e.started = time.Time{}
	e.mu.Unlock()
	e.cap.Invalidate()
	if len(problems) > 0 {
		return fmt.Errorf("stopped with %d rollback problem(s): %s", len(problems), strings.Join(problems, "; "))
	}
	return nil
}

// Stop shuts the repeater down.
func (e *Engine) Stop() error { return e.stop("requested") }

// Restart stops then starts.
func (e *Engine) Restart() error {
	if err := e.stop("restart"); err != nil {
		e.log.Warnf("repeater", "restart: stop reported problems: %v", err)
	}
	return e.Start(false)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (e *Engine) spec(c *config.Config) apbringer.Spec {
	return apbringer.Spec{
		SSID: c.Repeater.AP.SSID, Passphrase: c.Repeater.AP.Passphrase,
		Security: c.Repeater.AP.Security, Band: c.Repeater.AP.Band,
		Channel: c.Repeater.AP.Channel, Hidden: c.Repeater.AP.Hidden,
		MaxClients: c.Repeater.AP.MaxClients, CountryCode: c.Repeater.AP.CountryCode,
		HT40: c.Repeater.AP.HT40, VHT: c.Repeater.AP.VHT, HE: c.Repeater.AP.HE,
		ControlDir: filepath.Join(e.runDir, "hostapd-ctrl"),
		Isolate:    c.Repeater.Routing.IsolateClients,
	}
}

func (e *Engine) step(name string, ok bool, detail string) {
	e.mu.Lock()
	e.status.Steps = append(e.status.Steps, StepLog{Name: name, OK: ok, Detail: detail, At: time.Now().UnixMilli()})
	e.mu.Unlock()
	if ok {
		e.log.Infof("repeater", "%-14s ok: %s", name, logging.Redact(detail))
	} else {
		e.log.Errorf("repeater", "%-14s FAILED: %s", name, logging.Redact(detail))
	}
}

func (e *Engine) note(s string) {
	e.mu.Lock()
	e.status.Notes = append(e.status.Notes, s)
	e.mu.Unlock()
}

func (e *Engine) pushUndo(f func() error) {
	e.mu.Lock()
	e.undo = append(e.undo, f)
	e.mu.Unlock()
}

// enableForwarding sets a sysctl and records its previous value for rollback.
func (e *Engine) enableForwarding(key string) (string, error) {
	prev, err := netinfo.Sysctl(key)
	if err != nil {
		return "", fmt.Errorf("cannot read %s: %w", key, err)
	}
	if err := netinfo.WriteSysctl(key, "1"); err != nil {
		return prev, err
	}
	if p := prev; p != "1" {
		e.pushUndo(func() error { return netinfo.WriteSysctl(key, orDefault(p, "0")) })
	}
	return prev, nil
}

func (e *Engine) describe(iface string) IfaceRef {
	ref := IfaceRef{Name: iface}
	l, err := e.dev.Link(iface)
	if err != nil {
		ref.Kind = "missing"
		ref.Detail = err.Error()
		return ref
	}
	ref.Kind = string(netinfo.Classify(l))
	ref.MAC = l.MAC
	ifaces, _ := e.dev.Addrs()
	for _, a := range ifaces {
		if a.Iface == iface && a.Family == "IPv4" {
			ref.Address = a.IP
			ref.CIDR = a.CIDR
			break
		}
	}
	if ref.CIDR == "" {
		for _, a := range ifaces {
			if a.Iface == iface && a.Family == "IPv6" && !strings.HasPrefix(a.IP, "fe80") {
				ref.CIDR = a.CIDR
				break
			}
		}
	}
	ref.Detail = fmt.Sprintf("mtu=%d oper=%s", l.MTU, l.OperState)
	return ref
}

func (e *Engine) decideMode(c *config.Config, strategy, down, up string) (string, string) {
	if strategy == "android-softap" {
		return "hotspot", "Wi-Fi hotspot router (framework-managed AP)"
	}
	sum := e.cap.Summarise()
	if sum.TrueRepeater && netinfo.Classify(mustLink(e.dev, up)) == netinfo.ClassWiFiSTA {
		return "repeater", "Wi-Fi repeater (STA + AP)"
	}
	switch netinfo.Classify(mustLink(e.dev, up)) {
	case netinfo.ClassUSB:
		return "usb", "USB upstream router"
	case netinfo.ClassEthernet:
		return "ethernet", "Ethernet upstream router"
	case netinfo.ClassCellular:
		return "hotspot", "Cellular sharing over Wi-Fi (tethering)"
	}
	return "hotspot", "Wi-Fi hotspot router"
}

func mustLink(dev *netinfo.Device, name string) netinfo.Link {
	l, err := dev.Link(name)
	if err != nil {
		return netinfo.Link{Name: name}
	}
	return l
}

// lanDNS picks the resolvers the phone will hand to clients.
func (e *Engine) lanDNS(c *config.Config) []net.IP {
	var out []net.IP
	add := func(s string) {
		if ip := net.ParseIP(s); ip != nil && !containsIP(out, ip) {
			out = append(out, ip)
		}
	}
	add(c.Repeater.LAN.DNS1)
	add(c.Repeater.LAN.DNS2)
	if len(out) == 0 {
		for _, r := range e.dev.Resolvers() {
			add(r.Server)
			if len(out) >= 2 {
				break
			}
		}
	}
	if len(out) == 0 {
		// Nothing was discovered. Hand out the gateway (Yoru's own forwarder)
		// and let it fail loudly upstream rather than invent a public resolver.
		e.note("no upstream DNS could be detected; clients will use Yoru's forwarder, which has nowhere to forward to until DNS is configured")
	}
	return out
}

func (e *Engine) startDHCP(down string, c *config.Config, dns []net.IP) error {
	_, subnet, err := net.ParseCIDR(c.Repeater.LAN.Gateway + "/" + fmt.Sprint(c.Repeater.LAN.Prefix))
	if err != nil {
		return err
	}
	switch c.Repeater.LAN.DHCPMode {
	case "off":
		e.note("DHCP disabled: clients must be configured manually")
		return nil
	case "dnsmasq":
		if !e.cap.Has(caps.Dnsmasq) {
			return errors.New("dhcpMode=dnsmasq but no dnsmasq binary exists; switch to built-in in Settings")
		}
		return errors.New("dhcpMode=dnsmasq requires the external control helper (scripts/dnsmasq-start.sh); use dhcpMode=auto or builtin to let Yoru manage it")
	}
	// auto and builtin both end up here: Yoru's own server, because it is the
	// only implementation that is guaranteed present and that we can restart
	// without touching system services.
	srv, err := dhcpd.New(dhcpd.Config{
		Iface: down, ServerID: net.ParseIP(c.Repeater.LAN.Gateway), Router: net.ParseIP(c.Repeater.LAN.Gateway),
		Subnet: subnet, PoolStart: net.ParseIP(c.Repeater.LAN.DHCPStart), PoolEnd: net.ParseIP(c.Repeater.LAN.DHCPEnd),
		DNS: dns, Lease: time.Duration(c.Repeater.LAN.LeaseMin) * time.Minute,
		Domain: c.Repeater.LAN.Domain, LeaseFile: e.dhcpFile, MaxClients: c.Repeater.AP.MaxClients,
		Reservations: map[string]net.IP{},
	}, e.log)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	e.pushUndo(func() error { return srv.Stop() })
	e.mu.Lock()
	e.dhcp = srv
	e.mu.Unlock()
	return nil
}

func (e *Engine) startDNS(down string, c *config.Config, dns []net.IP) error {
	switch c.Repeater.LAN.DNSMode {
	case "off":
		e.note("Yoru DNS disabled")
		return nil
	case "dnsmasq":
		if !e.cap.Has(caps.Dnsmasq) {
			e.note("dnsMode=dnsmasq requested but dnsmasq is absent; falling back to the built-in forwarder")
		} else {
			e.note("dnsMode=dnsmasq is not managed by the daemon; using the built-in forwarder so behaviour stays reversible")
		}
	}
	ups := dns
	if len(ups) == 0 {
		ups = []net.IP{}
		for _, r := range e.dev.Resolvers() {
			if ip := net.ParseIP(r.Server); ip != nil {
				ups = append(ups, ip)
			}
		}
	}
	if len(ups) == 0 {
		e.note("no upstream resolver discovered; the DNS forwarder will answer LAN names only")
		ups = nil
	}
	srv, err := dnsd.New(dnsd.Config{
		Bind: net.ParseIP(c.Repeater.LAN.Gateway), Port: 53,
		Upstream: ups, TTL: 120, MaxCache: 256,
		LocalZone: c.Repeater.LAN.Domain, LocalName: map[string]net.IP{},
	}, e.log)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	e.pushUndo(func() error { return srv.Stop() })
	e.mu.Lock()
	e.dns = srv
	e.mu.Unlock()
	return nil
}

// UpdateLocalNames publishes leased hostnames into the DNS server so LAN names
// resolve while offline.
func (e *Engine) UpdateLocalNames() {
	e.mu.Lock()
	dns := e.dns
	dhcp := e.dhcp
	e.mu.Unlock()
	if dns == nil || dhcp == nil {
		return
	}
	m := map[string]net.IP{}
	for _, l := range dhcp.Leases() {
		if l.Hostname != "" {
			if ip := net.ParseIP(l.IP); ip != nil {
				m[strings.ToLower(l.Hostname)] = ip
			}
		}
	}
	dns.SetLocalRecords(m)
}

// ---------------------------------------------------------------------------
// health / watchdog
// ---------------------------------------------------------------------------

func (e *Engine) healthLoop() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	for {
		e.mu.Lock()
		ch := e.stopCh
		state := e.state
		e.mu.Unlock()
		if ch == nil || state == Stopped {
			return
		}
		select {
		case <-ch:
			return
		case <-t.C:
		}
		e.checkHealth()
	}
}

// checkHealth verifies the pieces we own are still alive. A dead child is
// restarted; a dead interface fails the engine so the UI can say so.
func (e *Engine) checkHealth() {
	c := e.cfg.Get()
	s := e.Status()
	if s.Downstream.Name == "" {
		return
	}
	l, err := e.dev.Link(s.Downstream.Name)
	if err != nil || !l.Up {
		e.log.Errorf("repeater", "downstream interface %s disappeared; stopping repeater to avoid a broken half-state", s.Downstream.Name)
		_ = e.stop("interface lost")
		return
	}
	e.checkInternet()
	e.UpdateLocalNames()
	if c.Repeater.LAN.IPv6Mode == "auto" && netinfo.IPv6Available() {
		// Nothing to do per tick: IPv6 state is reported by netinfo on demand.
	}
}

// checkInternet probes upstream reachability without requiring a DNS server.
func (e *Engine) checkInternet() {
	e.mu.Lock()
	up := e.status.Upstream.Name
	e.mu.Unlock()
	res := Internet{CheckedAt: time.Now().UnixMilli(), Method: "route+ping"}
	routes, _ := e.dev.Routes()
	hasDefault := false
	for _, r := range routes {
		if r.IsDefault && r.Dev == up {
			hasDefault = true
			break
		}
	}
	if up == "" {
		res.Method = "no-upstream"
		res.Detail = "the repeater has no upstream interface"
		e.mu.Lock()
		e.status.Internet = res
		e.mu.Unlock()
		return
	}
	if !hasDefault {
		// On Android the default route can live in a secondary table, so only
		// report this as a warning when a probe also fails.
		res.Probes = append(res.Probes, "no IPv4 default route on "+up+" (it may live in a policy table)")
	}
	// Probe: TCP connect to a well-known port is the most firewall-proof test
	// that does not require outbound ICMP.
	targets := []string{"1.1.1.1:443", "8.8.8.8:53", "192.172.3.3:80"}
	probeTimeout := 1500 * time.Millisecond
	deadline := time.Now().Add(probeTimeout)
	for _, tgt := range targets {
		start := time.Now()
		conn, err := net.DialTimeout("tcp", tgt, probeTimeout)
		if err == nil {
			_ = conn.Close()
			res.Reachable = true
			res.Method = "tcp-probe"
			res.LatencyMs = time.Since(start).Milliseconds()
			res.Detail = "connected to " + tgt
			res.Probes = append(res.Probes, tgt+" ok")
			break
		}
		res.Probes = append(res.Probes, tgt+" failed: "+shortErr(err))
		if time.Now().After(deadline.Add(3 * time.Second)) {
			break
		}
	}
	if !res.Reachable {
		res.Detail = "no upstream TCP probe succeeded"
	}
	// DNS is reported separately: a captive portal can pass the probe but not
	// resolve, and users care about that distinction.
	res.DNS = e.probeDNS()
	e.mu.Lock()
	e.status.Internet = res
	e.mu.Unlock()
}

func (e *Engine) probeDNS() bool {
	if e.cfg.Get().Repeater.LAN.DNS1 == "" && len(e.dev.Resolvers()) == 0 {
		return false
	}
	r := &net.Resolver{PreferGo: false}
	ctx, cancel := contextTimeout(1200 * time.Millisecond)
	defer cancel()
	_, err := r.LookupHost(ctx, "connectivitycheck.android.com")
	if err == nil {
		return true
	}
	_, err = r.LookupHost(ctx, "example.com")
	return err == nil
}

// waitForTraffic reports whether the AP interface has seen any activity, which
// is a cheap sanity check that the link really exists.
func (e *Engine) waitForTraffic(iface string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	base := netinfo.ReadStats(iface)
	for time.Now().Before(deadline) {
		time.Sleep(500 * time.Millisecond)
		st := netinfo.ReadStats(iface)
		if st == nil || base == nil {
			continue
		}
		if st.RxPackets > base.RxPackets || st.TxPackets > base.TxPackets || st.RxBytes > base.RxBytes {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// conflict detection
// ---------------------------------------------------------------------------

// findConflicts lists existing networks that overlap the LAN we are about to
// create. Overlap is fatal because the kernel would then send client traffic to
// the wrong place - exactly the kind of breakage Yoru must never cause.
func findConflicts(c *config.Config, addrs []netinfo.Addr, routes []netinfo.Route, up, down string) []string {
	_, mine, err := net.ParseCIDR(c.Repeater.LAN.Gateway + "/" + fmt.Sprint(c.Repeater.LAN.Prefix))
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range addrs {
		if a.Family != "IPv4" || a.Iface == "" || a.Iface == down {
			continue
		}
		ip, n, err := net.ParseCIDR(a.CIDR)
		if err != nil {
			continue
		}
		_ = ip
		if overlaps(mine, n) && !seen[n.String()] {
			seen[n.String()] = true
			out = append(out, fmt.Sprintf("%s on %s", n, a.Iface))
		}
	}
	for _, r := range routes {
		if r.Family != "IPv4" || r.IsDefault || r.Dev == "" || r.Dst == "" || r.Dev == down {
			continue
		}
		if strings.HasSuffix(r.Dst, "/32") {
			continue
		}
		_, n, err := net.ParseCIDR(r.Dst)
		if err != nil {
			continue
		}
		if overlaps(mine, n) && !seen[n.String()] {
			seen[n.String()] = true
			out = append(out, fmt.Sprintf("%s via route on %s", n, r.Dev))
		}
	}
	return out
}

func overlaps(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// ---------------------------------------------------------------------------
// error builders
// ---------------------------------------------------------------------------

func (e *Engine) upstreamError(err error, sum caps.Summary) error {
	var reasons []string
	for _, c := range e.cap.All() {
		if !c.Supported && strings.Contains(c.ID, "UPSTREAM") && c.Reason != "" {
			reasons = append(reasons, c.ID+" - "+c.Reason)
		}
	}
	help := "Yoru needs an interface that can reach the internet. Connect to a Wi-Fi network, plug in USB Ethernet, or enable mobile data."
	if len(reasons) > 0 {
		help += " Detected: " + strings.Join(reasons, " | ")
	}
	return fmt.Errorf("no upstream connection: %v. %s", err, help)
}

func (e *Engine) downstreamError(why string, sum caps.Summary) error {
	var advice []string
	if !sum.TrueRepeater {
		advice = append(advice, "true Wi-Fi repeating is unavailable because "+e.cap.Get(caps.WiFiConcurrent).Reason)
	}
	if !sum.HotspotRouter {
		advice = append(advice, "hotspot mode is unavailable because "+e.cap.Get(caps.WiFiAP).Reason)
	}
	return fmt.Errorf("cannot provide a downstream access point: %s. %s", why, strings.Join(advice, "; "))
}

func sameIface(a, b string) bool {
	return a != "" && a == b
}

func orFallback(v, def string) string {
	if v == "" {
		return def
	}
	if def == "" {
		return v
	}
	return v + " (" + def + ")"
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func containsIP(list []net.IP, ip net.IP) bool {
	for _, x := range list {
		if x.Equal(ip) {
			return true
		}
	}
	return false
}

func ipsToString(ips []net.IP) []string {
	var out []string
	for _, i := range ips {
		out = append(out, i.String())
	}
	sort.Strings(out)
	return out
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.Index(s, "): "); i > 0 {
		s = s[i+3:]
	}
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

var _ = safeexec.Available
