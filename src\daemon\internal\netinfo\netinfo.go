// Package netinfo discovers and manipulates network state.
//
// Reads go through netlink (syscall.NetlinkRIB) and sysfs so that Yoru works
// even when `ip`, `ifconfig` or `netstat` are missing or are Toybox variants
// with different output formats. Writes go through the `ip` binary, guarded by
// safeexec and by argument validation, because reimplementing RTM_NEWADDR/NEWROUTE
// encoding adds risk we do not want in a networking path.
package netinfo

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yoru.dev/yorud/internal/safeexec"
	"yoru.dev/yorud/internal/sysinfo"
)

// Link flags we care about (defined here because syscall exports only some).
const (
	ifFlagUp          = 1 << 0
	ifFlagBroadcast   = 1 << 1
	ifFlagLoopback    = 1 << 3
	ifFlagPointopoint = 1 << 5
	ifFlagRunning     = 1 << 6
	ifFlagMulticast   = 1 << 9
	ifFlagLowerUp     = 1 << 16
)

// Link is one network interface.
type Link struct {
	Name        string `json:"name"`
	Index       int    `json:"index"`
	MAC         string `json:"mac"`
	MTU         int    `json:"mtu"`
	Type        string `json:"type"`
	KernelType  uint16 `json:"kernelType"`
	OperState   string `json:"operState"`
	State       string `json:"state"`
	Up          bool   `json:"up"`
	Running     bool   `json:"running"`
	Loopback    bool   `json:"loopback"`
	LowerUp     bool   `json:"lowerUp"`
	Wireless    bool   `json:"wireless"`
	IsVirtual   bool   `json:"isVirtual"`
	Statistics  *Stats `json:"statistics,omitempty"`
	WirelessIdx int    `json:"wirelessIndex,omitempty"`
	Master      string `json:"master,omitempty"`
	Carrier     string `json:"carrier,omitempty"`
	Kind        string `json:"kind,omitempty"`
	SpeedMbps   int    `json:"speedMbps,omitempty"`
	TxQLen      int    `json:"txQueueLength,omitempty"`
}

// Stats are the sysfs interface counters (monotonic).
type Stats struct {
	RxBytes    uint64 `json:"rxBytes"`
	TxBytes    uint64 `json:"txBytes"`
	RxPackets  uint64 `json:"rxPackets"`
	TxPackets  uint64 `json:"txPackets"`
	RxErrors   uint64 `json:"rxErrors"`
	TxErrors   uint64 `json:"txErrors"`
	RxDropped  uint64 `json:"rxDropped"`
	TxDropped  uint64 `json:"txDropped"`
	Multicast  uint64 `json:"multicast"`
	Collisions uint64 `json:"collisions"`
	RxOver     uint64 `json:"rxOver"`
	Frame      uint64 `json:"frame"`
	TxCarrier  uint64 `json:"txCarrier"`
	TxAborted  uint64 `json:"txAborted"`
	BytePfx    string `json:"-"`
}

// Addr is one assigned address.
type Addr struct {
	Iface      string `json:"iface"`
	Family     string `json:"family"`
	IP         string `json:"ip"`
	CIDR       string `json:"cidr"`
	PrefixLen  int    `json:"prefixLen"`
	Scope      string `json:"scope"`
	Label      string `json:"label,omitempty"`
	Flags      string `json:"flags,omitempty"`
	Preferred  int    `json:"preferredLifetimeSec,omitempty"`
	Valid      int    `json:"validLifetimeSec,omitempty"`
	Tentative  bool   `json:"tentative,omitempty"`
	Deprecated bool   `json:"deprecated,omitempty"`
}

// Route is one FIB entry.
type Route struct {
	Family    string `json:"family"`
	Dst       string `json:"dst"`
	Gateway   string `json:"gateway,omitempty"`
	Dev       string `json:"dev,omitempty"`
	Metric    int    `json:"metric"`
	Table     string `json:"table"`
	Protocol  string `json:"protocol"`
	Scope     string `json:"scope"`
	Type      string `json:"type"`
	Prefsrc   string `json:"prefsrc,omitempty"`
	IsDefault bool   `json:"isDefault"`
}

// Neigh is an ARP/NDISC entry.
type Neigh struct {
	Iface   string `json:"iface"`
	IP      string `json:"ip"`
	MAC     string `json:"mac"`
	State   string `json:"state"`
	Manual  bool   `json:"manual"`
	Router  bool   `json:"router,omitempty"`
	Updated int64  `json:"-"`
}

// ARPHRD types used for interface classification.
const (
	arpRDNetrom   = 0
	arpRDEther    = 1
	arpRDLoop     = 771
	arpRDFDDI     = 776
	arpRDIPTunnel = 778
	arpRDIPLite   = 878
	arpRDIEEE1394 = 24
	arpRDRadiotap = 508
	arpRDARPRaw   = 65534
)

func typeName(t uint16) string {
	switch t {
	case arpRDEther:
		return "ethernet"
	case arpRDLoop:
		return "loopback"
	case arpRDIPTunnel, arpRDIPLite:
		return "tunnel"
	case arpRDNetrom:
		return "netrom"
	case arpRDFDDI:
		return "fddi"
	case arpRDIEEE1394:
		return "ieee1394"
	case arpRDRadiotap:
		return "radiotap"
	case arpRDARPRaw:
		return "arp-raw"
	}
	return fmt.Sprintf("type-%d", t)
}

// Device reads all interface state. It is deliberately cheap enough to call
// every second: one netlink dump per message type plus small sysfs reads.
type Device struct {
	mu       sync.Mutex
	lastLink map[string]Link
}

// NewDevice prepares the network information source.
func NewDevice() *Device { return &Device{} }

// Links returns every interface known to the kernel.
func (d *Device) Links() ([]Link, error) {
	msgs, err := netlinkDump(syscallRTMGetlink)
	if err != nil {
		return d.linksFromSysfs(err)
	}
	seen := map[string]bool{}
	var out []Link
	for _, m := range msgs {
		l, ok := parseIfInfo(m)
		if !ok {
			continue
		}
		d.enrich(&l)
		seen[l.Name] = true
		out = append(out, l)
	}
	// Interfaces can exist in sysfs before netlink shows them (hot-plug races).
	if ents, err := filepath.Glob("/sys/class/net/*"); err == nil {
		for _, e := range ents {
			name := filepath.Base(e)
			if seen[name] {
				continue
			}
			l := Link{Name: name}
			d.enrich(&l)
			out = append(out, l)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	d.mu.Lock()
	d.lastLink = map[string]Link{}
	for _, l := range out {
		d.lastLink[l.Name] = l
	}
	d.mu.Unlock()
	return out, nil
}

func (d *Device) enrich(l *Link) {
	base := filepath.Join("/sys/class/net", l.Name)
	if v, err := readTrim(filepath.Join(base, "operstate")); err == nil {
		l.OperState = v
	}
	if v, err := readTrim(filepath.Join(base, "address")); err == nil {
		if l.MAC == "" {
			l.MAC = normaliseMAC(v)
		}
	}
	if _, err := os.Stat(filepath.Join(base, "wireless")); err == nil {
		l.Wireless = true
	} else if _, err := os.Stat(filepath.Join(base, "phy80211")); err == nil {
		l.Wireless = true
	}
	if _, err := os.Stat(filepath.Join(base, "phy80211", "index")); err == nil {
		if v, err := readTrim(filepath.Join(base, "phy80211", "index")); err == nil {
			l.WirelessIdx, _ = strconv.Atoi(v)
		}
	}
	// An interface without a backing `device` symlink is a software device
	// (veth, bridge, tun, ...). Physical NICs always carry one.
	if _, err := os.Stat(filepath.Join(base, "device")); err != nil {
		l.IsVirtual = true
	}
	if v, err := readTrim(filepath.Join(base, "carrier")); err == nil {
		if v == "1" {
			l.Carrier = "on"
		} else {
			l.Carrier = "off"
		}
	}
	if v, err := readTrim(filepath.Join(base, "speed")); err == nil {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			l.SpeedMbps = n
		}
	}
	if v, err := readTrim(filepath.Join(base, "master")); err == nil && v != "" {
		l.Master = filepath.Base(v)
	}
	if v, err := readTrim(filepath.Join(base, "type")); err == nil && l.KernelType == 0 {
		n, _ := strconv.Atoi(v)
		l.KernelType = uint16(n)
		l.Type = typeName(l.KernelType)
	}
	if st := ReadStats(l.Name); st != nil {
		l.Statistics = st
	}
}

// linksFromSysfs is the netlink-less fallback.
func (d *Device) linksFromSysfs(cause error) ([]Link, error) {
	ents, err := filepath.Glob("/sys/class/net/*")
	if err != nil {
		return nil, fmt.Errorf("netlink unavailable (%v) and sysfs unreadable: %w", cause, err)
	}
	var out []Link
	for _, e := range ents {
		name := filepath.Base(e)
		l := Link{Name: name, Type: "unknown"}
		if v, err := readTrim(filepath.Join(e, "ifindex")); err == nil {
			l.Index, _ = strconv.Atoi(v)
		}
		if v, err := readTrim(filepath.Join(e, "mtu")); err == nil {
			l.MTU, _ = strconv.Atoi(v)
		}
		if v, err := readTrim(filepath.Join(e, "flags")); err == nil {
			// sysfs flags are a hex bitmask
			n, _ := strconv.ParseUint(strings.TrimPrefix(v, "0x"), 16, 64)
			l.Up = n&ifFlagUp != 0
			l.Running = n&ifFlagRunning != 0
			l.Loopback = n&ifFlagLoopback != 0
		}
		d.enrich(&l)
		if l.State == "" {
			l.State = deriveState(l)
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func deriveState(l Link) string {
	parts := []string{}
	if l.Up {
		parts = append(parts, "UP")
	}
	if l.Running || l.LowerUp {
		parts = append(parts, "LOWER_UP")
	}
	if l.Loopback {
		parts = append(parts, "LOOPBACK")
	}
	if len(parts) == 0 {
		parts = append(parts, "DOWN")
	}
	return strings.Join(parts, "<|>")
}

// ReadStats returns the sysfs counters for one interface.
func ReadStats(iface string) *Stats {
	if !safeexec.ValidIface(iface) {
		return nil
	}
	base := filepath.Join("/sys/class/net", iface, "statistics")
	ents, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	s := &Stats{}
	for _, e := range ents {
		v, err := readTrim(filepath.Join(base, e.Name()))
		if err != nil {
			continue
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			continue
		}
		switch e.Name() {
		case "rx_bytes":
			s.RxBytes = n
		case "tx_bytes":
			s.TxBytes = n
		case "rx_packets":
			s.RxPackets = n
		case "tx_packets":
			s.TxPackets = n
		case "rx_errors":
			s.RxErrors = n
		case "tx_errors":
			s.TxErrors = n
		case "rx_dropped":
			s.RxDropped = n
		case "tx_dropped":
			s.TxDropped = n
		case "multicast":
			s.Multicast = n
		case "collisions":
			s.Collisions = n
		case "rx_over_length":
			s.RxOver = n
		case "rx_frame":
			s.Frame = n
		case "tx_carrier_errors":
			s.TxCarrier = n
		case "tx_aborted_errors":
			s.TxAborted = n
		}
	}
	return s
}

// Addrs returns every assigned IPv4/IPv6 address.
func (d *Device) Addrs() ([]Addr, error) {
	msgs, err := netlinkDump(syscallRTMGetaddr)
	if err != nil {
		return d.addrsFallback()
	}
	var out []Addr
	for _, m := range msgs {
		a, ok := parseIfAddr(m)
		if !ok {
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return d.addrsFallback()
	}
	return out, nil
}

// addrsFallback parses `ip -f inet addr` style output from procfs when netlink
// is blocked by SELinux (rare, but observed on locked-down vendor kernels).
func (d *Device) addrsFallback() ([]Addr, error) {
	var out []Addr
	// `ip addr show` text parsing is the fallback when netlink is blocked. It is
	// format-sensitive, so it is only used when the primary path fails.
	for _, fam := range []string{"4", "6"} {
		args := []string{"-f", "inet" + fam, "addr", "show"}
		if !safeexec.Available("ip") {
			continue
		}
		res, err := safeexec.Run("ip", args, safeexec.Options{Timeout: 3 * time.Second})
		if err != nil || !res.OK() {
			continue
		}
		iface := ""
		for _, ln := range strings.Split(res.Stdout, "\n") {
			ln = strings.TrimRight(ln, "\r")
			t := strings.TrimSpace(ln)
			if t == "" {
				continue
			}
			if !strings.HasPrefix(ln, " ") {
				f := strings.Fields(t)
				if len(f) >= 2 {
					iface = strings.TrimSuffix(f[len(f)-1], ":")
				}
				continue
			}
			f := strings.Fields(t)
			if len(f) < 2 || (f[0] != "inet" && f[0] != "inet6") {
				continue
			}
			a := Addr{Iface: iface, Family: "IPv4"}
			if f[0] == "inet6" {
				a.Family = "IPv6"
			}
			if cidr, plen, err := net.ParseCIDR(f[1]); err == nil {
				a.IP = cidr.String()
				a.CIDR = f[1]
				a.PrefixLen, _ = plen.Mask.Size()
			} else {
				a.IP = f[1]
				a.CIDR = f[1]
			}
			for i := 2; i < len(f); i++ {
				switch f[i] {
				case "scope":
					if i+1 < len(f) {
						a.Scope = f[i+1]
					}
				case "label":
					if i+1 < len(f) {
						a.Label = f[i+1]
					}
				case "tentative":
					a.Tentative = true
				case "deprecated":
					a.Deprecated = true
				case "preferred_lft":
					if i+1 < len(f) {
						a.Preferred = atoiOr(f[i+1], -1)
					}
				case "valid_lft":
					if i+1 < len(f) {
						a.Valid = atoiOr(f[i+1], -1)
					}
				}
			}
			out = append(out, a)
		}
	}
	return out, nil
}

// atoi parses a decimal integer, returning 0 on error.
func atoi(s string) int {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0
	}
	return n
}

func atoiOr(s string, def int) int {
	if s == "forever" || s == "infinite" {
		return -1
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}

// Routes returns the main + default policy routing tables.
func (d *Device) Routes() ([]Route, error) {
	msgs, err := netlinkDump(syscallRTMGetroute)
	if err != nil {
		return d.routesFallback()
	}
	var out []Route
	for _, m := range msgs {
		r, ok := parseRoute(m)
		if !ok {
			continue
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return d.routesFallback()
	}
	return out, nil
}

// routesFallback reads /proc/net/route + /proc/net/ipv6_route.
func (d *Device) routesFallback() ([]Route, error) {
	var out []Route
	if lines := sysinfo.Lines("/proc/net/route"); len(lines) > 1 {
		nameByIndex := d.ifaceByIndex()
		for _, ln := range lines[1:] {
			f := strings.Fields(ln)
			if len(f) < 8 {
				continue
			}
			dev := nameByIndex[f[0]]
			if dev == "" {
				dev = f[0]
			}
			dst := reverseHexIP(f[1])
			mask := reverseHexIP(f[7])
			gw := reverseHexIP(f[2])
			pl := prefixLenFromMask(mask)
			r := Route{
				Family: "IPv4", Dev: dev, Gateway: gw, Metric: atoi(f[6]),
				Dst:       fmt.Sprintf("%s/%d", dst, pl),
				IsDefault: dst == "0.0.0.0" && pl == 0,
				Table:     "main", Protocol: "kernel", Scope: "universe", Type: "unicast",
			}
			out = append(out, r)
		}
	}
	if lines := sysinfo.Lines("/proc/net/ipv6_route"); len(lines) > 0 {
		for _, ln := range lines {
			f := strings.Fields(ln)
			if len(f) < 10 {
				continue
			}
			// /proc/net/ipv6_route columns:
			//   dest(32hex) dst-plen(hex) src(32hex) src-plen(hex) nh(32hex)
			//   metric(h) error(h) refcnt(h) use(h) flags(h) devname
			dst := parseHexIPv6(f[0])
			pl := hexAtoi(f[1])
			nh := parseHexIPv6(f[4])
			out = append(out, Route{
				Family: "IPv6", Dst: fmt.Sprintf("%s/%d", dst, pl),
				Gateway:   nonzeroIPv6(nh),
				Dev:       f[len(f)-1],
				Metric:    hexAtoi(f[5]),
				IsDefault: dst == "::" && pl == 0,
				Table:     "main", Protocol: "kernel", Scope: "universe", Type: "unicast",
			})
		}
	}
	return out, nil
}

// hexAtoi parses a hexadecimal column from /proc/net routing files.
func hexAtoi(s string) int {
	n, err := strconv.ParseInt(s, 16, 32)
	if err != nil {
		return 0
	}
	return int(n)
}

// nonzeroIPv6 suppresses the all-zero next hop that procfs reports for
// directly-connected routes.
func nonzeroIPv6(s string) string {
	if s == "" || s == "::" {
		return ""
	}
	return s
}

func (d *Device) ifaceByIndex() map[string]string {
	out := map[string]string{}
	if links, err := d.Links(); err == nil {
		for _, l := range links {
			out[strconv.Itoa(l.Index)] = l.Name
		}
	}
	return out
}

func reverseHexIP(s string) string {
	if len(s) != 8 {
		return "0.0.0.0"
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return "0.0.0.0"
	}
	return fmt.Sprintf("%d.%d.%d.%d", v&0xff, (v>>8)&0xff, (v>>16)&0xff, (v>>24)&0xff)
}

func prefixLenFromMask(mask string) int {
	ip := net.ParseIP(mask)
	if ip == nil {
		return 0
	}
	m := ip.To4()
	if m == nil {
		return 0
	}
	n := 0
	for _, b := range m {
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) != 0 {
				n++
			}
		}
	}
	return n
}

func parseHexIPv6(s string) string {
	if len(s) < 32 {
		return "::"
	}
	var b [16]byte
	for i := 0; i < 16; i++ {
		v, _ := strconv.ParseUint(s[i*2:i*2+2], 16, 8)
		b[i] = byte(v)
	}
	return net.IP(b[:]).String()
}

// Neigh returns ARP/NDISC neighbours, optionally limited to one interface.
func (d *Device) Neigh(iface string) ([]Neigh, error) {
	msgs, err := netlinkDump(syscallRTMGetneigh)
	if err == nil {
		var out []Neigh
		names := d.ifaceNameByIndex()
		for _, m := range msgs {
			n, ok := parseNeigh(m, names)
			if !ok {
				continue
			}
			if iface != "" && n.Iface != iface {
				continue
			}
			out = append(out, n)
		}
		if len(out) > 0 || iface == "" {
			return out, nil
		}
	}
	// procfs fallbacks
	var out []Neigh
	if lines := sysinfo.Lines("/proc/net/arp"); len(lines) > 1 {
		for _, ln := range lines[1:] {
			f := strings.Fields(ln)
			if len(f) < 6 {
				continue
			}
			n := Neigh{IP: f[0], MAC: normaliseMAC(f[3]), Iface: f[5], State: arpState(f[2])}
			if n.MAC == "00:00:00:00:00:00" {
				continue
			}
			if iface != "" && n.Iface != iface {
				continue
			}
			out = append(out, n)
		}
	}
	if len(out) == 0 && safeexec.Available("ip") {
		res, err := safeexec.Run("ip", []string{"-6", "neigh", "show"}, safeexec.Options{Timeout: 3 * time.Second})
		if err == nil && res.OK() {
			for _, ln := range strings.Split(res.Stdout, "\n") {
				f := strings.Fields(strings.TrimSpace(ln))
				if len(f) < 3 {
					continue
				}
				n := Neigh{IP: f[0], Iface: f[len(f)-1]}
				for i, x := range f {
					if x == "lladdr" && i+1 < len(f) {
						n.MAC = normaliseMAC(f[i+1])
					}
					if x == "router" {
						n.Router = true
					}
				}
				if n.MAC != "" {
					n.State = strings.Join(f[1:len(f)-1], " ")
					out = append(out, n)
				}
			}
		}
	}
	return out, nil
}

func arpState(s string) string {
	switch s {
	case "0x0":
		return "incomplete"
	case "0x2":
		return "reachable"
	case "0x4":
		return "stale"
	case "0x8":
		return "delay"
	case "0x10":
		return "probe"
	case "0x8000":
		return "permanent"
	}
	return s
}

func (d *Device) ifaceNameByIndex() map[int]string {
	out := map[int]string{}
	if links, err := d.Links(); err == nil {
		for _, l := range links {
			out[l.Index] = l.Name
		}
	}
	return out
}

// Link looks up one interface by name.
func (d *Device) Link(name string) (Link, error) {
	links, err := d.Links()
	if err != nil {
		return Link{}, err
	}
	for _, l := range links {
		if l.Name == name {
			return l, nil
		}
	}
	return Link{}, fmt.Errorf("interface %s does not exist", name)
}

// Index returns the kernel interface index.
func (d *Device) Index(name string) (int, error) {
	l, err := d.Link(name)
	if err != nil {
		return 0, err
	}
	if l.Index == 0 {
		if v, err := readTrim(filepath.Join("/sys/class/net", name, "ifindex")); err == nil {
			n, _ := strconv.Atoi(v)
			return n, nil
		}
	}
	return l.Index, nil
}

// Errors -------------------------------------------------------------------

// ErrNoCommand reports that a mutation could not run because the tool is gone.
var ErrNoCommand = errors.New("required network command is unavailable on this device")

// Bring commands -----------------------------------------------------------

// RunIP executes a validated `ip` sub-command.
func RunIP(args ...string) (string, error) {
	if !safeexec.Available("ip") {
		return "", fmt.Errorf("%w: ip", ErrNoCommand)
	}
	res, err := safeexec.Run("ip", args, safeexec.Options{Timeout: 6 * time.Second})
	if err != nil {
		return "", err
	}
	if !res.OK() {
		msg := strings.TrimSpace(res.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(res.Stdout)
		}
		if msg == "" {
			msg = fmt.Sprintf("exit %d", res.ExitCode)
		}
		return res.Stdout, fmt.Errorf("ip %s: %s", strings.Join(args, " "), msg)
	}
	return res.Stdout, nil
}

// LinkUp enables an interface.
func (d *Device) LinkUp(iface string) error {
	if !safeexec.ValidIface(iface) {
		return fmt.Errorf("invalid interface name")
	}
	_, err := RunIP("link", "set", iface, "up")
	return err
}

// LinkDown disables an interface.
func (d *Device) LinkDown(iface string) error {
	if !safeexec.ValidIface(iface) {
		return fmt.Errorf("invalid interface name")
	}
	_, err := RunIP("link", "set", iface, "down")
	return err
}

// SetMTU configures the link MTU.
func (d *Device) SetMTU(iface string, mtu int) error {
	if !safeexec.ValidIface(iface) || mtu < 128 || mtu > 9198 {
		return fmt.Errorf("invalid MTU request")
	}
	_, err := RunIP("link", "set", iface, "mtu", strconv.Itoa(mtu))
	return err
}

// AddAddr assigns cidr (e.g. 192.168.50.1/24) to iface. "add" is idempotent
// enough for our restart path: EEXIST is treated as success.
func (d *Device) AddAddr(iface, cidr string) error {
	if !safeexec.ValidIface(iface) || !validCIDR(cidr) {
		return fmt.Errorf("invalid address request")
	}
	out, err := RunIP("addr", "add", cidr, "dev", iface)
	if err != nil && !strings.Contains(strings.ToLower(out+err.Error()), "file exists") {
		return err
	}
	return nil
}

// DelAddr removes cidr from iface.
func (d *Device) DelAddr(iface, cidr string) error {
	if !safeexec.ValidIface(iface) || !validCIDR(cidr) {
		return fmt.Errorf("invalid address request")
	}
	out, err := RunIP("addr", "del", cidr, "dev", iface)
	if err != nil && !strings.Contains(strings.ToLower(out+err.Error()), "cannot assign") {
		return err
	}
	return nil
}

// HasAddr reports whether ip is currently assigned to iface.
func (d *Device) HasAddr(iface, ip string) bool {
	addrs, err := d.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if a.Iface == iface && a.IP == ip {
			return true
		}
	}
	return false
}

// AddRoute installs a unicast route.
func (d *Device) AddRoute(dstCIDR, via, dev string) error {
	if !validCIDR(dstCIDR) || (via != "" && net.ParseIP(via) == nil) || (dev != "" && !safeexec.ValidIface(dev)) {
		return fmt.Errorf("invalid route request")
	}
	args := []string{"route", "add", dstCIDR}
	if via != "" {
		args = append(args, "via", via)
	}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	_, err := RunIP(args...)
	return err
}

// DelRoute removes a unicast route.
func (d *Device) DelRoute(dstCIDR, dev string) error {
	if !validCIDR(dstCIDR) || (dev != "" && !safeexec.ValidIface(dev)) {
		return fmt.Errorf("invalid route request")
	}
	args := []string{"route", "del", dstCIDR}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	_, err := RunIP(args...)
	return err
}

func validCIDR(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	ip, n, err := net.ParseCIDR(s)
	if err != nil || ip == nil {
		return false
	}
	ones, bits := n.Mask.Size()
	if bits == 32 {
		return ones >= 0 && ones <= 32
	}
	return ones >= 0 && ones <= 128
}

// Sysctls ------------------------------------------------------------------

// Sysctl reads one /proc/sys value.
func Sysctl(key string) (string, error) {
	path := "/proc/sys/" + strings.ReplaceAll(strings.TrimPrefix(key, "/proc/sys/"), ".", "/")
	if !strings.HasPrefix(path, "/proc/sys/") {
		return "", fmt.Errorf("sysctl key outside /proc/sys")
	}
	if strings.Contains(path, "..") {
		return "", fmt.Errorf("invalid sysctl key")
	}
	return readTrim(path)
}

// WriteSysctl sets one /proc/sys value through the kernel path directly.
// Only keys on the internal allowlist can be written, so a bug elsewhere in
// Yoru can never write an arbitrary sysctl.
func WriteSysctl(key, value string) error {
	allowed := map[string]bool{
		"net.ipv4.ip_forward":                          true,
		"net.ipv4.conf.all.forwarding":                 true,
		"net.ipv4.conf.default.forwarding":             true,
		"net.ipv4.ip_no_pmtu_disc":                     true,
		"net.ipv4.conf.all.send_redirects":             true,
		"net.ipv4.ip_local_port_range":                 true,
		"net.ipv6.conf.all.forwarding":                 true,
		"net.ipv6.conf.default.forwarding":             true,
		"net.ipv6.conf.all.accept_ra":                  true,
		"net.ipv6.conf.all.accept_ra_rt_info_max_plen": true,
		"net.ipv6.conf.all.autoconf":                   true,
		"net.ipv4.conf.all.rp_filter":                  true,
	}
	if !allowed[key] {
		return fmt.Errorf("sysctl key %q is not managed by Yoru", key)
	}
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	if _, err := os.Stat(path); err != nil {
		return fmt.Errorf("sysctl %s unavailable: %w", key, err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.WriteString(value); err != nil {
		return err
	}
	return nil
}

// DNS ----------------------------------------------------------------------

// DNSServer is one resolver address with its origin.
type DNSServer struct {
	Server string `json:"server"`
	Iface  string `json:"iface,omitempty"`
	Source string `json:"source"`
}

// Resolvers collects DNS servers from every place Android may publish them.
// Android has no /etc/resolv.conf on most devices, so this walks properties,
// dumpsys netd and per-interface scripts.
func (d *Device) Resolvers() []DNSServer {
	seen := map[string]bool{}
	var out []DNSServer
	add := func(server, iface, src string) {
		server = strings.TrimSpace(server)
		if server == "" || net.ParseIP(server) == nil {
			return
		}
		k := server + "|" + iface
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, DNSServer{Server: server, Iface: iface, Source: src})
	}
	// 1. legacy net.dns properties (Android <= 11 era, still set by some RILs)
	for _, p := range []string{"net.dns1", "net.dns2", "net.dns3", "net.dns4", "net.dns5", "net.dns6"} {
		if v := sysinfo.Getprop(p); v != "" {
			add(v, "", "getprop:"+p)
		}
	}
	// 2. dumpsys netd / connectivity (AOSP publishes "Dns:" lists)
	if safeexec.Available("dumpsys") {
		for _, svc := range []string{"netd", "connectivity"} {
			res, err := safeexec.Run("dumpsys", []string{svc}, safeexec.Options{Timeout: 4 * time.Second, MaxOut: 2 << 20})
			if err != nil || !res.OK() {
				continue
			}
			for _, ln := range strings.Split(res.Stdout, "\n") {
				l := strings.ToLower(ln)
				if !strings.Contains(l, "dns") {
					continue
				}
				for _, f := range strings.Fields(ln) {
					if ip := net.ParseIP(strings.Trim(f, ",()[]")); ip != nil && ip.To4() != nil {
						add(ip.String(), "", "dumpsys:"+svc)
					}
				}
			}
		}
	}
	// 3. whatever the C library can see (works on devices that do expose one)
	if b, err := os.ReadFile("/etc/resolv.conf"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Fields(ln)
			if len(f) == 2 && f[0] == "nameserver" {
				add(f[1], "", "/etc/resolv.conf")
			}
		}
	}
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

// Classification -----------------------------------------------------------

// InterfaceClass labels an interface for the engine's mode selection.
type InterfaceClass string

// Interface roles.
const (
	ClassWiFiSTA    InterfaceClass = "wifi-sta"
	ClassWiFiAP     InterfaceClass = "wifi-ap"
	ClassWiFiP2P    InterfaceClass = "wifi-p2p"
	ClassWiFiDirect InterfaceClass = "wifi-direct"
	ClassCellular   InterfaceClass = "cellular"
	ClassUSB        InterfaceClass = "usb"
	ClassEthernet   InterfaceClass = "ethernet"
	ClassVPN        InterfaceClass = "vpn"
	ClassLoopback   InterfaceClass = "loopback"
	ClassBridge     InterfaceClass = "bridge"
	ClassVirtual    InterfaceClass = "virtual"
	ClassUnknown    InterfaceClass = "unknown"
)

var apNameHints = []string{"ap0", "swlan0", "softap", "wifi-ap", "athap", "p2p-ap", "sap0", "vap0", "wlan_ap", "wlan-ap"}
var staNameHints = []string{"wlan", "sta", "ath", "ra", "wl"}
var cellularHints = []string{"rmnet", "ccmni", "ipa", "qti", "wwan", "lte", "rndis", "mobile", "tun", "diag"}
var vpnHints = []string{"tun", "tap", "wg", "ppp", "sit", "ipsec", "dn42", "utun", "gtp", "v4-eth", "pdp"}
var usbHints = []string{"usb", "rndis", "ncm", "ecm", "g_"}
var ethHints = []string{"eth", "mgbe", "gmac", "lan", "dvbn", "enx"}

// Classify maps an interface to a role using name + driver hints.
func Classify(l Link) InterfaceClass {
	name := strings.ToLower(l.Name)
	driver := strings.ToLower(l.Type)
	switch {
	case l.Loopback:
		return ClassLoopback
	}
	for _, h := range apNameHints {
		if strings.Contains(name, h) {
			return ClassWiFiAP
		}
	}
	if strings.HasPrefix(name, "p2p") {
		return ClassWiFiP2P
	}
	if l.Wireless {
		for _, h := range cellularHints {
			if strings.HasPrefix(name, h) {
				return ClassCellular
			}
		}
		return ClassWiFiSTA
	}
	for _, h := range vpnHints {
		if strings.HasPrefix(name, h) {
			return ClassVPN
		}
	}
	for _, h := range cellularHints {
		if strings.HasPrefix(name, h) {
			return ClassCellular
		}
	}
	for _, h := range usbHints {
		if strings.HasPrefix(name, h) {
			return ClassUSB
		}
	}
	for _, h := range ethHints {
		if strings.HasPrefix(name, h) || strings.Contains(driver, "eth") {
			return ClassEthernet
		}
	}
	if strings.HasPrefix(name, "br") || strings.HasPrefix(name, "docker") || strings.HasPrefix(name, "virbr") {
		return ClassBridge
	}
	if l.IsVirtual {
		return ClassVirtual
	}
	return ClassUnknown
}

// IsUsableUpstream reports whether an interface can plausibly carry traffic out.
func IsUsableUpstream(l Link, addrs []Addr) bool {
	if !l.Up {
		return false
	}
	c := Classify(l)
	switch c {
	case ClassLoopback, ClassBridge, ClassVirtual, ClassWiFiAP, ClassWiFiP2P, ClassWiFiDirect:
		return false
	}
	for _, a := range addrs {
		if a.Iface != l.Name {
			continue
		}
		if a.Family != "IPv4" || a.IP == "" {
			continue
		}
		if strings.HasPrefix(a.Scope, "link") && !strings.Contains(a.IP, ".") {
			continue
		}
		ip := net.ParseIP(a.IP)
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		return true
	}
	// Some devices have IPv6-only upstreams (rare on cellular, common in lab).
	for _, a := range addrs {
		if a.Iface == l.Name && a.Family == "IPv6" {
			ip := net.ParseIP(a.IP)
			if ip != nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
				return true
			}
		}
	}
	return false
}

// IPv6Available reports whether the kernel has IPv6 enabled at all.
func IPv6Available() bool {
	if _, err := os.Stat("/proc/net/if_inet6"); err != nil {
		return false
	}
	if v, err := readTrim("/proc/sys/net/ipv6/conf/all/disable_ipv6"); err == nil && v == "1" {
		return false
	}
	return true
}

// Snapshot is the combined network view used by the API.
type Snapshot struct {
	Links     []Link      `json:"links"`
	Addrs     []Addr      `json:"addresses"`
	Routes    []Route     `json:"routes"`
	Neigh     []Neigh     `json:"-"`
	Resolvers []DNSServer `json:"dns"`
	IPv6      bool        `json:"ipv6Enabled"`
	Hostname  string      `json:"hostname"`
	ReadAt    int64       `json:"readAtMs"`
}

// Snapshot gathers everything in one call (shared by monitors and API).
func (d *Device) Snapshot(withNeigh bool) Snapshot {
	s := Snapshot{IPv6: IPv6Available()}
	if h, err := os.Hostname(); err == nil {
		s.Hostname = h
	}
	links, err := d.Links()
	if err == nil {
		s.Links = links
	}
	if addrs, err := d.Addrs(); err == nil {
		s.Addrs = addrs
	}
	if routes, err := d.Routes(); err == nil {
		s.Routes = routes
	}
	s.Resolvers = d.Resolvers()
	if withNeigh {
		if n, err := d.Neigh(""); err == nil {
			s.Neigh = n
		}
	}
	s.ReadAt = time.Now().UnixMilli()
	return s
}

// DefaultUpstream picks the interface that currently carries the default route.
func (d *Device) DefaultUpstream() (Link, error) {
	links, err := d.Links()
	if err != nil {
		return Link{}, err
	}
	addrs, _ := d.Addrs()
	routes, _ := d.Routes()
	byName := map[string]Link{}
	for _, l := range links {
		byName[l.Name] = l
	}
	// Prefer the route with the lowest metric that has a real gateway+dev.
	var best *Route
	for i := range routes {
		r := &routes[i]
		if !r.IsDefault || r.Dev == "" {
			continue
		}
		if best == nil || r.Metric < best.Metric {
			best = r
		}
	}
	if best != nil {
		if l, ok := byName[best.Dev]; ok && IsUsableUpstream(l, addrs) {
			return l, nil
		}
	}
	// No usable default route: return the first classed, running interface.
	var out []Link
	for _, l := range links {
		if IsUsableUpstream(l, addrs) {
			out = append(out, l)
		}
	}
	if len(out) > 0 {
		// Wi-Fi STA beats cellular for cost reasons; wired beats both.
		rank := func(l Link) int {
			switch Classify(l) {
			case ClassEthernet, ClassUSB:
				return 0
			case ClassWiFiSTA:
				return 1
			case ClassCellular:
				return 2
			case ClassVPN:
				return 4
			}
			return 3
		}
		sort.Slice(out, func(i, j int) bool {
			ri, rj := rank(out[i]), rank(out[j])
			if ri != rj {
				return ri < rj
			}
			return out[i].Name < out[j].Name
		})
		return out[0], nil
	}
	return Link{}, errors.New("no interface with a usable address was found")
}

// helpers ------------------------------------------------------------------

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func normaliseMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || s == "00:00:00:00:00:00" {
		return s
	}
	return s
}

// IsLocal returns true for interfaces that must never be used as downstream.
func IsLocal(l Link) bool {
	c := Classify(l)
	return c == ClassLoopback || strings.HasPrefix(l.Name, "lo")
}

var _ = sort.Strings
