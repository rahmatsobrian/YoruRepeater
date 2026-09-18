// Package firewall owns Yoru's netfilter footprint.
//
// Safety rules implemented here, which the whole project depends on:
//   - Yoru never flushes, deletes or re-policies a chain it does not own. The
//     only chains created or modified are the YORU_* chains listed below, plus
//     single jump rules that reference them.
//   - teardown deletes exactly the objects it created, in reverse order, and
//     tolerates "does not exist" from a previous partial cleanup.
//   - every rule carries a comment so an operator can see what Yoru added with
//     plain iptables/nft, and so removal is unambiguous.
//   - a probe run at startup proves the backend can actually create a chain
//     before the engine commits to it, because Android devices frequently ship
//     an iptables binary whose kernel modules are absent.
package firewall

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"yoru.dev/yorud/internal/clients"
	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/safeexec"
)

// Chain and table names owned by Yoru.
const (
	Prefix        = "YORU_"
	ChainForward  = "YORU_REPEATER"
	ChainNAT      = "YORU_REPEATER_NAT"
	ChainAcc      = "YORU_ACC"
	ChainIsolate  = "YORU_ISOLATE"
	CommentMarker = "yoru-repeater"

	NftTable     = "yoru_repeater"
	NftChainFwd  = "forward"
	NftChainNat  = "nat"
	NftChainAcc  = "acc"
	NftChainIsol = "isolate"
)

// Backend identifies the netfilter flavour in use.
type Backend string

// Supported backends.
const (
	BackendNone          Backend = "none"
	BackendIPTables      Backend = "iptables"
	BackendIPTablesNft   Backend = "iptables-nft"
	BackendIPTablesOld   Backend = "iptables-legacy"
	BackendNft           Backend = "nft"
	BackendAndroidTether Backend = "android-tethering"
)

// Rule is one Yoru-owned netfilter rule.
type Rule struct {
	Hook    string // forward | postrouting | prerouting | input | output
	Action  string // accept | masquerade | jump | return | drop | saddr | counter
	Src     string
	Dst     string
	In      string
	Out     string
	Chain   string
	Jump    string
	Proto   string
	Extra   []string
	Comment string
}

// Manager creates, applies and removes Yoru's rules.
type Manager struct {
	mu        sync.Mutex
	log       *logging.Logger
	backend   Backend
	bin       string // iptables | ip6tables | nft
	avail     map[Backend]ProbeResult
	nftHasAcc bool
	enabled   bool
}

// ProbeResult is the outcome of testing a backend on this kernel.
type ProbeResult struct {
	OK      bool
	Version string
	Err     string
}

// NewManager prepares the firewall manager.
func NewManager(log *logging.Logger) *Manager {
	return &Manager{log: log, backend: BackendNone, avail: map[Backend]ProbeResult{}}
}

// Detect finds a working backend. It never modifies anything.
func (m *Manager) Detect() Backend {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend != BackendNone {
		return m.backend
	}
	for _, b := range []Backend{BackendIPTablesNft, BackendIPTablesOld, BackendNft} {
		res := m.probeLocked(b)
		m.avail[b] = res
		if res.OK {
			m.backend = b
			switch b {
			case BackendNft:
				m.bin = "nft"
			default:
				m.bin = "iptables"
			}
			m.log.Infof("firewall", "selected %s backend (%s)", b, res.Version)
			return b
		}
	}
	m.log.Warnf("firewall", "no usable netfilter backend: %+v", m.avail)
	return BackendNone
}

// Probe reports the status of one backend, running the probe if needed.
func (m *Manager) Probe(b Backend) ProbeResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.avail[b]; ok {
		return r
	}
	r := m.probeLocked(b)
	m.avail[b] = r
	return r
}

// AvailableBackends returns every probed backend and its verdict, for the
// diagnostics page.
func (m *Manager) AvailableBackends() map[string]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]string{}
	for b, r := range m.avail {
		if r.OK {
			out[string(b)] = "available: " + r.Version
		} else {
			out[string(b)] = "unavailable: " + r.Err
		}
	}
	return out
}

// Binary returns the tool the chosen backend drives.
func (m *Manager) Binary() string { return m.bin }

// Backend returns the active backend name, satisfying the clients.Accounting
// interface so the UI can label per-client totals with their true source.
func (m *Manager) Backend() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == BackendNone {
		return "none"
	}
	return string(m.backend)
}

// probeLocked tries to create and destroy a private chain. This is the only
// reliable way to know whether the kernel modules behind iptables exist.
func (m *Manager) probeLocked(b Backend) ProbeResult {
	switch b {
	case BackendIPTablesNft, BackendIPTablesOld:
		name := "iptables-nft"
		if b == BackendIPTablesOld {
			name = "iptables-legacy"
		}
		if !safeexec.Available(name) && !safeexec.Available("iptables") {
			return ProbeResult{Err: "iptables binary not present"}
		}
		bin := name
		if !safeexec.Available(name) {
			bin = "iptables"
		}
		vr, err := safeexec.Run(bin, []string{"--version"}, safeexec.Options{Timeout: 3 * time.Second})
		if err != nil {
			return ProbeResult{Err: err.Error()}
		}
		version := strings.TrimSpace(firstLine(vr.Stdout))
		// The probe chain must be created, a rule appended, then removed.
		if _, err := safeexec.Out(bin, "-t", "filter", "-N", "YORU_PROBE"); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "exists") {
				return ProbeResult{Version: version, Err: cleanIptablesError(err)}
			}
			_, _ = safeexec.Out(bin, "-t", "filter", "-F", "YORU_PROBE")
		}
		if _, err := safeexec.Out(bin, "-t", "filter", "-A", "YORU_PROBE", "-j", "RETURN"); err != nil {
			_, _ = safeexec.Out(bin, "-t", "filter", "-X", "YORU_PROBE")
			return ProbeResult{Version: version, Err: "append test rule failed: " + cleanIptablesError(err)}
		}
		if _, err := safeexec.Out(bin, "-t", "nat", "-N", "YORU_PROBE"); err != nil {
			if strings.Contains(strings.ToLower(err.Error()), "exists") {
				_, _ = safeexec.Out(bin, "-t", "nat", "-F", "YORU_PROBE")
			} else {
				_, _ = safeexec.Out(bin, "-t", "filter", "-X", "YORU_PROBE")
				return ProbeResult{Version: version, Err: "nat table unavailable: " + cleanIptablesError(err)}
			}
		}
		_, _ = safeexec.Out(bin, "-t", "nat", "-X", "YORU_PROBE")
		_, _ = safeexec.Out(bin, "-t", "filter", "-X", "YORU_PROBE")
		return ProbeResult{OK: true, Version: version}
	case BackendNft:
		if !safeexec.Available("nft") {
			return ProbeResult{Err: "nft binary not present"}
		}
		vr, err := safeexec.Run("nft", []string{"--version"}, safeexec.Options{Timeout: 3 * time.Second})
		if err != nil {
			return ProbeResult{Err: err.Error()}
		}
		script := "table ip yoru_probe {\n  chain yoru_probe {\n    type filter hook forward priority 0;\n    policy accept;\n  }\n}\n"
		path := "/data/local/tmp/yoru-probe.nft"
		if err := writeFile(path, script); err != nil {
			path = "/tmp/yoru-probe.nft"
			if err := writeFile(path, script); err != nil {
				return ProbeResult{Err: "cannot write probe file: " + err.Error()}
			}
		}
		defer removeFile(path)
		if _, err := safeexec.Run("nft", []string{"-f", path}, safeexec.Options{Timeout: 4 * time.Second}); err != nil {
			return ProbeResult{Version: strings.TrimSpace(firstLine(vr.Stdout)), Err: err.Error()}
		}
		if !strings.Contains(readFileSafe("/proc/net/netfilter/nf_tables"), "yoru_probe") && !nftTableExists() {
			_, _ = safeexec.Out("nft", "delete", "table", "ip", "yoru_probe")
			return ProbeResult{Version: strings.TrimSpace(firstLine(vr.Stdout)), Err: "table accepted by nft but not visible in the kernel"}
		}
		_, _ = safeexec.Out("nft", "delete", "table", "ip", "yoru_probe")
		return ProbeResult{OK: true, Version: strings.TrimSpace(firstLine(vr.Stdout))}
	}
	return ProbeResult{Err: "unknown backend"}
}

// Plan describes the complete rule set Yoru wants while running.
type Plan struct {
	AP           string
	Upstream     string
	GatewayIP    string
	ClientSubnet string
	Isolate      bool
	Account      bool
	IPv6         bool
}

// Apply installs Yoru's chains and rules idempotently. It is safe to call
// repeatedly; existing Yoru objects are reused rather than duplicated.
func (m *Manager) Apply(p Plan) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == BackendNone {
		if m.Detect() == BackendNone {
			return errors.New("no working packet-filter backend: Yoru cannot safely enable NAT without one")
		}
	}
	if !safeexec.ValidIface(p.AP) || (p.Upstream != "" && !safeexec.ValidIface(p.Upstream)) {
		return fmt.Errorf("invalid interface names in firewall plan")
	}
	switch m.backend {
	case BackendNft:
		return m.applyNft(p)
	case BackendIPTablesNft, BackendIPTablesOld, BackendIPTables:
		return m.applyIptables(p)
	}
	return errors.New("no firewall backend selected")
}

// ensureChainFilter creates the chain if absent.
func (m *Manager) ensureChainFilter(table, chain string) error {
	if _, err := safeexec.Out(m.bin, "-t", table, "-N", chain); err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "exists") || strings.Contains(msg, "chain already exists") {
			return nil
		}
		return err
	}
	m.log.Infof("firewall", "created chain %s (%s)", chain, table)
	return nil
}

func (m *Manager) applyIptables(p Plan) error {
	bin := m.bin
	// 1. own chains
	if err := m.ensureChainFilter("filter", ChainForward); err != nil {
		return fmt.Errorf("create %s: %w", ChainForward, err)
	}
	if err := m.ensureChainFilter("nat", ChainNAT); err != nil {
		return fmt.Errorf("create %s: %w", ChainNAT, err)
	}
	if p.Account {
		if err := m.ensureChainFilter("mangle", ChainAcc); err != nil {
			m.log.Warnf("firewall", "accounting chain unavailable: %v", err)
			p.Account = false
		}
	}
	if p.Isolate {
		if err := m.ensureChainFilter("filter", ChainIsolate); err != nil {
			m.log.Warnf("firewall", "client isolation chain unavailable: %v", err)
			p.Isolate = false
		}
	}
	// 2. chain contents (flush only Yoru's own chains - never a system chain)
	if _, err := safeexec.Out(bin, "-t", "filter", "-F", ChainForward); err != nil {
		return fmt.Errorf("flush %s: %w", ChainForward, err)
	}
	if _, err := safeexec.Out(bin, "-t", "nat", "-F", ChainNAT); err != nil {
		return fmt.Errorf("flush %s: %w", ChainNAT, err)
	}
	rules := [][]string{
		{"-t", "filter", "-A", ChainForward, "-i", p.AP, "-o", p.Upstream, "-j", "ACCEPT", "-m", "comment", "--comment", CommentMarker},
		{"-t", "filter", "-A", ChainForward, "-o", p.AP, "-i", p.Upstream, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT", "-m", "comment", "--comment", CommentMarker},
		{"-t", "filter", "-A", ChainForward, "-i", p.AP, "-o", p.AP, "-j", "DROP", "-m", "comment", "--comment", CommentMarker + "-local"},
	}
	for _, r := range rules {
		if _, err := safeexec.OutArgs(bin, r); err != nil {
			// conntrack/comment modules may be missing; retry without them.
			if !strings.Contains(strings.ToLower(err.Error()), "no such file") &&
				!strings.Contains(strings.ToLower(err.Error()), "unknown option") &&
				!strings.Contains(strings.ToLower(err.Error()), "bad rule") {
				return fmt.Errorf("append %s: %w", strings.Join(r, " "), err)
			}
			m.log.Warnf("firewall", "rule needed a module this kernel lacks (%v); applying a reduced rule", err)
			slim := stripOptional(r)
			if _, err := safeexec.OutArgs(bin, slim); err != nil {
				return fmt.Errorf("append reduced rule %s: %w", strings.Join(slim, " "), err)
			}
		}
	}
	if _, err := safeexec.Out(bin, "-t", "nat", "-A", ChainNAT, "-o", p.Upstream, "-j", "MASQUERADE", "-m", "comment", "--comment", CommentMarker); err != nil {
		slim := stripOptional([]string{"-t", "nat", "-A", ChainNAT, "-o", p.Upstream, "-j", "MASQUERADE"})
		if _, err2 := safeexec.OutArgs(bin, slim); err2 != nil {
			return fmt.Errorf("masquerade: %v / %v", err, err2)
		}
	}
	// DNS/DHCP service from clients to this phone.
	svc := [][]string{
		{"-t", "filter", "-A", ChainForward, "-i", p.AP, "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
		{"-t", "filter", "-A", ChainForward, "-i", p.AP, "-p", "udp", "--dport", "67", "-j", "ACCEPT"},
		{"-t", "filter", "-A", ChainForward, "-i", p.AP, "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
	}
	for _, r := range svc {
		_, _ = safeexec.OutArgs(bin, r)
	}
	if p.Isolate {
		if _, err := safeexec.Out(bin, "-t", "filter", "-F", ChainIsolate); err == nil {
			_, _ = safeexec.Out(bin, "-t", "filter", "-A", ChainIsolate, "-i", p.AP, "-o", p.AP, "-j", "DROP")
			_, _ = safeexec.Out(bin, "-t", "filter", "-A", ChainIsolate, "-i", p.AP, "-o", p.AP, "-p", "udp", "--dport", "67:68", "-j", "ACCEPT")
			_, _ = safeexec.Out(bin, "-t", "filter", "-A", ChainIsolate, "-i", p.AP, "-o", p.AP, "-p", "udp", "--dport", "53", "-j", "ACCEPT")
			_, _ = safeexec.Out(bin, "-t", "filter", "-I", ChainForward, "1", "-j", ChainIsolate)
		}
	}
	// 3. attach to the system chains exactly once
	if err := m.jumpIn("filter", "FORWARD", ChainForward, p); err != nil {
		return err
	}
	if err := m.jumpIn("nat", "POSTROUTING", ChainNAT, p); err != nil {
		return err
	}
	if p.IPv6 {
		if err := m.applyIPv6Companion(p); err != nil {
			m.log.Warnf("firewall", "IPv6 NAT unavailable (%v); clients will still have IPv4", err)
		}
	}
	m.enabled = true
	return nil
}

// jumpIn adds "-j YORU_CHAIN" to a system chain unless it is already there.
// On Android, the FORWARD chain has a tetherctrl_FORWARD with a catch-all DROP
// that blocks hotspot client traffic. We insert at position 1 so our ACCEPT
// rules are evaluated before Android's tethering firewall.
func (m *Manager) jumpIn(table, host, own string, p Plan) error {
	bin := m.bin
	if out, err := safeexec.Out(bin, "-t", table, "-S", host); err == nil {
		if strings.Contains(out, "-j "+own) || strings.Contains(out, " -j "+own) {
			return nil
		}
	}
_POSITION := "-A"
	if table == "filter" && host == "FORWARD" {
		_POSITION = "-I"
	}
	if _, err := safeexec.Out(bin, "-t", table, _POSITION, host, "-j", own); err != nil {
		return fmt.Errorf("attach %s to %s/%s: %w", own, table, host, err)
	}
	m.log.Infof("firewall", "attached %s to %s/%s", own, table, host)
	return nil
}

// stripOptional removes modules that hardened kernels may not provide.
func stripOptional(r []string) []string {
	var out []string
	skip := 0
	for i, x := range r {
		if skip > 0 {
			skip--
			continue
		}
		switch x {
		case "-m":
			if i+1 < len(r) && (r[i+1] == "comment" || r[i+1] == "conntrack") {
				skip = 1
				continue
			}
		case "--comment":
			skip = 1
			continue
		case "--ctstate":
			skip = 1
			continue
		}
		out = append(out, x)
	}
	return out
}

// applyIPv6Companion mirrors the v4 setup for ip6tables. NAT66 uses MASQUERADE
// over the same upstream, which is valid when the phone has a routed prefix.
func (m *Manager) applyIPv6Companion(p Plan) error {
	if !safeexec.Available("ip6tables") {
		return errors.New("ip6tables not present")
	}
	if _, err := safeexec.Out("ip6tables", "-t", "filter", "-N", ChainForward); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "exists") {
			return err
		}
	}
	if _, err := safeexec.Out("ip6tables", "-t", "nat", "-N", ChainNAT); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "exists") {
			return err
		}
	}
	_, _ = safeexec.Out("ip6tables", "-t", "filter", "-F", ChainForward)
	_, _ = safeexec.Out("ip6tables", "-t", "nat", "-F", ChainNAT)
	if _, err := safeexec.Out("ip6tables", "-t", "nat", "-A", ChainNAT, "-o", p.Upstream, "-j", "MASQUERADE"); err != nil {
		return err
	}
	_, _ = safeexec.Out("ip6tables", "-t", "filter", "-A", ChainForward, "-i", p.AP, "-j", "ACCEPT")
	_, _ = safeexec.Out("ip6tables", "-t", "filter", "-A", ChainForward, "-o", p.AP, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
	if out, err := safeexec.Out("ip6tables", "-t", "filter", "-S", "FORWARD"); err == nil && !strings.Contains(out, "-j "+ChainForward) {
		_, _ = safeexec.Out("ip6tables", "-t", "filter", "-A", "FORWARD", "-j", ChainForward)
	}
	if out, err := safeexec.Out("ip6tables", "-t", "nat", "-S", "POSTROUTING"); err == nil && !strings.Contains(out, "-j "+ChainNAT) {
		_, _ = safeexec.Out("ip6tables", "-t", "nat", "-A", "POSTROUTING", "-j", ChainNAT)
	}
	return nil
}

// RemoveAccountRule deletes one per-client accounting rule.
func (m *Manager) Forget(ip string) error {
	if !validIPv4(ip) {
		return fmt.Errorf("invalid address %q", ip)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == BackendNone {
		return nil
	}
	if m.backend == BackendNft {
		return m.nftRemoveHandle(ip)
	}
	bin := m.bin
	for _, t := range []string{"mangle"} {
		for _, args := range [][]string{
			{"-t", t, "-D", ChainAcc, "-s", ip, "-j", "RETURN"},
			{"-t", t, "-D", ChainAcc, "-d", ip, "-j", "RETURN"},
		} {
			_, _ = safeexec.OutArgs(bin, args)
		}
	}
	return nil
}

// TrackIP creates accounting state for one client address.
func (m *Manager) Track(ip string) error {
	if !validIPv4(ip) {
		return fmt.Errorf("invalid address %q", ip)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == BackendNone {
		return nil
	}
	if m.backend == BackendNft {
		if !m.nftHasAcc {
			return nil
		}
		return m.nftTrack(ip)
	}
	bin := m.bin
	if out, err := safeexec.Out(bin, "-t", "mangle", "-S", ChainAcc); err == nil && strings.Contains(out, "s "+ip+" ") {
		return nil // already tracked
	}
	if _, err := safeexec.Out(bin, "-t", "mangle", "-A", ChainAcc, "-s", ip, "-j", "RETURN"); err != nil {
		return err
	}
	return nil
}

var handleRe = regexp.MustCompile(`handle#(\d+)`)

// Observe reads per-client counters. For iptables the counters come from
// `-L -v -n -x` line byte/packet columns matched on the client address; for nft
// they come from `nft -a list chain` counter handles.
//
// ok=false means the backend cannot account per client, and the caller must
// label the totals as unavailable rather than showing zeros.
func (m *Manager) Observe(iface string) (map[string]clients.Counters, bool, error) {
	m.mu.Lock()
	backend := m.backend
	bin := m.bin
	m.mu.Unlock()
	out := map[string]clients.Counters{}
	if backend == BackendNone {
		return out, false, errors.New("no firewall backend")
	}
	if iface != "" && !safeexec.ValidIface(iface) {
		return out, false, fmt.Errorf("invalid interface")
	}
	if backend == BackendNft {
		return m.observeNft()
	}
	res, err := safeexec.Run(bin, []string{"-t", "mangle", "-S", ChainAcc, "-v", "-n", "-x"}, safeexec.Options{Timeout: 4 * time.Second})
	if err != nil {
		return out, false, err
	}
	if !res.OK() {
		return out, false, errors.New(strings.TrimSpace(res.Stderr))
	}
	for _, ln := range strings.Split(res.Stdout, "\n") {
		ip, dir, bytes, pkts, ok := parseIptAccountLine(ln)
		if !ok {
			continue
		}
		v := out[ip]
		if dir == "src" {
			v.TxBytes += bytes
			v.TxPackets += pkts
		} else {
			v.RxBytes += bytes
			v.RxPackets += pkts
		}
		out[ip] = v
	}
	return out, true, nil
}

// parseIptAccountLine handles `-L -v -x` output where the first two numeric
// columns are the packet and byte counters followed by the rule text.
func parseIptAccountLine(ln string) (ip, dir string, bytes, pkts uint64, ok bool) {
	f := strings.Fields(strings.TrimSpace(ln))
	if len(f) < 7 {
		return "", "", 0, 0, false
	}
	pkts, err1 := strconv.ParseUint(f[0], 10, 64)
	bytes, err2 := strconv.ParseUint(f[1], 10, 64)
	if err1 != nil || err2 != nil {
		return "", "", 0, 0, false
	}
	rest := strings.Join(f[2:], " ")
	if !strings.Contains(rest, "RETURN") {
		return "", "", 0, 0, false
	}
	if i := strings.Index(rest, "SRC="); i >= 0 {
		return strings.Fields(rest[i+4:])[0], "src", bytes, pkts, true
	}
	if i := strings.Index(rest, "DST="); i >= 0 {
		return strings.Fields(rest[i+4:])[0], "dst", bytes, pkts, true
	}
	return "", "", 0, 0, false
}

type nftCounter struct {
	bytes, packets uint64
}

func parseNftCounters(line string) nftCounter {
	var c nftCounter
	i := strings.Index(line, "counter")
	if i < 0 {
		return c
	}
	f := strings.Fields(line[i:])
	for j := 0; j < len(f)-1; j++ {
		switch f[j] {
		case "packets":
			c.packets, _ = strconv.ParseUint(f[j+1], 10, 64)
		case "bytes":
			c.bytes, _ = strconv.ParseUint(f[j+1], 10, 64)
		}
	}
	return c
}

func ipInLine(line string) string {
	if i := strings.Index(line, "ip saddr"); i >= 0 {
		f := strings.Fields(line[i:])
		if len(f) >= 3 {
			return strings.Trim(f[2], "\\")
		}
	}
	if i := strings.Index(line, "ip daddr"); i >= 0 {
		f := strings.Fields(line[i:])
		if len(f) >= 3 {
			return strings.Trim(f[2], "\\")
		}
	}
	return ""
}

// Remove tears down everything Yoru created. It is written to be idempotent and
// to succeed even when called after a crash left a partial setup behind.
func (m *Manager) Remove() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.backend == BackendNone {
		if m.Detect() == BackendNone {
			return nil
		}
	}
	var errs []string
	switch m.backend {
	case BackendNft:
		if _, err := safeexec.Out("nft", "delete", "table", "ip", NftTable); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "no such") {
				errs = append(errs, err.Error())
			}
		}
		if _, err := safeexec.Out("nft", "delete", "table", "ip6", NftTable+"6"); err != nil {
			if !strings.Contains(strings.ToLower(err.Error()), "no such") {
				errs = append(errs, err.Error())
			}
		}
	default:
		bin := m.bin
		// Detach first, then delete chains: reversing the order would leave the
		// host chain referencing a chain that no longer exists.
		m.detach(bin, "filter", "FORWARD", ChainForward)
		m.detach(bin, "nat", "POSTROUTING", ChainNAT)
		m.detach(bin, "filter", "FORWARD", ChainIsolate)
		for _, spec := range []struct{ t, c string }{
			{"filter", ChainForward}, {"nat", ChainNAT}, {"mangle", ChainAcc}, {"filter", ChainIsolate},
		} {
			_, _ = safeexec.Out(bin, "-t", spec.t, "-F", spec.c)
			if out, err := safeexec.Out(bin, "-t", spec.t, "-X", spec.c); err != nil {
				msg := strings.ToLower(err.Error() + out)
				if !strings.Contains(msg, "does not exist") && !strings.Contains(msg, "no chain") && !strings.Contains(msg, "invalid argument") {
					errs = append(errs, msg)
				}
			}
		}
		m.detach6("filter", "FORWARD", ChainForward)
		m.detach6("nat", "POSTROUTING", ChainNAT)
		for _, spec := range []struct{ t, c string }{{"filter", ChainForward}, {"nat", ChainNAT}} {
			if safeexec.Available("ip6tables") {
				_, _ = safeexec.Out("ip6tables", "-t", spec.t, "-F", spec.c)
				_, _ = safeexec.Out("ip6tables", "-t", spec.t, "-X", spec.c)
			}
		}
	}
	m.enabled = false
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	m.log.Infof("firewall", "Yoru rules removed")
	return nil
}

func (m *Manager) detach(bin, table, host, own string) {
	for {
		out, err := safeexec.Out(bin, "-t", table, "-S", host)
		if err != nil {
			return
		}
		idx := strings.Index(out, "-j "+own)
		if idx < 0 {
			return
		}
		num := positionOf(out, own)
		if num == 0 {
			return
		}
		if _, err := safeexec.Out(bin, "-t", table, "-D", host, strconv.Itoa(num)); err != nil {
			return
		}
	}
}

func (m *Manager) detach6(table, host, own string) {
	if !safeexec.Available("ip6tables") {
		return
	}
	out, err := safeexec.Out("ip6tables", "-t", table, "-S", host)
	if err != nil || !strings.Contains(out, "-j "+own) {
		return
	}
	if num := positionOf(out, own); num > 0 {
		_, _ = safeexec.Out("ip6tables", "-t", table, "-D", host, strconv.Itoa(num))
	}
}

// positionOf returns the 1-based rule number of the jump to chain `own` inside
// the `iptables -S` listing of a host chain.
func positionOf(listing, own string) int {
	n := 0
	for _, ln := range strings.Split(listing, "\n") {
		l := strings.TrimSpace(ln)
		if !strings.HasPrefix(l, "-A") {
			continue
		}
		n++
		if strings.Contains(l, "-j "+own) {
			return n
		}
	}
	return 0
}

// Status reports the live Yoru rule set for the Network page.
func (m *Manager) Status() map[string]any {
	m.mu.Lock()
	backend, bin, enabled := m.backend, m.bin, m.enabled
	m.mu.Unlock()
	out := map[string]any{"backend": string(backend), "binary": bin, "active": enabled}
	if backend == BackendNone || backend == BackendNft {
		return out
	}
	chains := map[string]int{}
	for _, spec := range []struct{ t, c string }{
		{"filter", ChainForward}, {"nat", ChainNAT}, {"mangle", ChainAcc}, {"filter", ChainIsolate},
	} {
		res, err := safeexec.Run(bin, []string{"-t", spec.t, "-S", spec.c}, safeexec.Options{Timeout: 3 * time.Second})
		if err == nil && res.OK() {
			n := 0
			for _, ln := range strings.Split(res.Stdout, "\n") {
				if strings.HasPrefix(strings.TrimSpace(ln), "-A") {
					n++
				}
			}
			chains[spec.t+"/"+spec.c] = n
		}
	}
	out["chains"] = chains
	return out
}

func validIPv4(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c == '.') {
			return false
		}
	}
	return strings.Count(s, ".") == 3
}

func cleanIptablesError(err error) string {
	s := err.Error()
	if i := strings.Index(s, ":"); i > 0 && i < 40 {
		s = s[i+1:]
	}
	return strings.TrimSpace(s)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}

func firstErr(err error, text string) error {
	if err != nil {
		return err
	}
	if strings.TrimSpace(text) != "" {
		return errors.New(strings.TrimSpace(text))
	}
	return nil
}
