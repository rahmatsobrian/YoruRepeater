// Package clients builds the connected-device list.
//
// A client is only reported when the kernel says something is on the local
// network segment: an ARP/NDISC entry on the access-point interface, or a live
// lease. Identity fields (hostname, IP) are joined from as many real sources as
// the device offers - built-in DHCP leases, dnsmasq.leases, static ARP, and
// hostapd's own station table - and per-client byte counts come from Yoru-owned
// netfilter accounting rules when the firewall supports them. Anything that
// cannot be determined stays empty, and `TrafficSource` says why.
package clients

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/traffic"
)

// Client is one connected device.
type Client struct {
	MAC           string   `json:"mac"`
	MACDisplay    string   `json:"macDisplay"`
	Hostname      string   `json:"hostname,omitempty"`
	HostnameSrc   string   `json:"hostnameSource,omitempty"`
	IPv4          string   `json:"ip,omitempty"`
	IPv6          []string `json:"ipv6,omitempty"`
	Iface         string   `json:"iface"`
	FirstSeen     int64    `json:"firstSeenMs"`
	LastSeen      int64    `json:"lastSeenMs"`
	Online        bool     `json:"online"`
	OfflineSec    int64    `json:"offlineSec,omitempty"`
	RxBytes       uint64   `json:"rxBytes"`
	TxBytes       uint64   `json:"txBytes"`
	RxPackets     uint64   `json:"rxPackets"`
	TxPackets     uint64   `json:"txPackets"`
	TrafficSource string   `json:"trafficSource"`
	Authenticated bool     `json:"authenticated,omitempty"`
	Vendor        string   `json:"ouiHint,omitempty"`
	DeviceGuess   string   `json:"deviceClass,omitempty"`
	Icon          string   `json:"icon"`
	AssocSec      int64    `json:"assocSec,omitempty"`
	Signals       int      `json:"rssi,omitempty"`
	InactiveSec   int64    `json:"inactiveSec,omitempty"`
	Manual        bool     `json:"manual,omitempty"`
	Sources       []string `json:"sources"`
}

// Lease is a DHCP binding.
type Lease struct {
	MAC       string    `json:"mac"`
	IP        string    `json:"ip"`
	Hostname  string    `json:"hostname"`
	Expiry    time.Time `json:"expiry"`
	Source    string    `json:"source"`
	Temporary bool      `json:"-"`
}

// Tracker keeps the device table across polls.
type Tracker struct {
	mu        sync.Mutex
	log       *logging.Logger
	dev       *netinfo.Device
	statePath string
	table     map[string]*entry
	iface     string // downstream AP interface
	gateway   string
	leases    []Lease
	acc       Accounting // per-client netfilter accounting (optional)
	maskMACs  bool
	lastScan  time.Time
}

type entry struct {
	MAC          string   `json:"mac"`
	IPv4         string   `json:"ipv4,omitempty"`
	IPv6         []string `json:"ipv6,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	HostnameSrc  string   `json:"hs,omitempty"`
	FirstSeen    int64    `json:"first"`
	LastSeen     int64    `json:"last"`
	Online       bool     `json:"online"`
	Iface        string   `json:"iface,omitempty"`
	RxBytes      uint64   `json:"rx"`
	TxBytes      uint64   `json:"tx"`
	RxPackets    uint64   `json:"rxp"`
	TxPackets    uint64   `json:"txp"`
	AccRxBytes   uint64   `json:"-"`
	AccTxBytes   uint64   `json:"-"`
	AssocAt      int64    `json:"assoc,omitempty"`
	OfflineSince int64    `json:"offsince,omitempty"`
	Sources      []string `json:"-"`
}

// NewTracker creates a client tracker persisting to statePath.
func NewTracker(log *logging.Logger, dev *netinfo.Device, statePath string) *Tracker {
	t := &Tracker{
		log: log, dev: dev, statePath: statePath,
		table: map[string]*entry{},
	}
	t.load()
	return t
}

// Configure sets the monitored downstream interface and privacy options.
func (t *Tracker) Configure(iface, gateway string, maskMACs bool) {
	t.mu.Lock()
	t.iface, t.gateway, t.maskMACs = iface, gateway, maskMACs
	t.mu.Unlock()
}

// SetAccounting attaches a netfilter per-client counter source.
func (t *Tracker) SetAccounting(a Accounting) {
	t.mu.Lock()
	t.acc = a
	t.mu.Unlock()
}

// Accounting is implemented by the firewall package.
type Accounting interface {
	// Observe refreshes per-IP counters. ok is false when the backend cannot
	// account per client, in which case totals stay zero and are labelled.
	Observe(iface string) (map[string]Counters, bool, error)
	// Track makes the backend create accounting state for a client IP.
	Track(ip string) error
	Forget(ip string) error
	Backend() string
}

// Counters is a per-client byte/packet reading.
type Counters struct {
	RxBytes   uint64
	TxBytes   uint64
	RxPackets uint64
	TxPackets uint64
}

// LeaseReader supplies DHCP bindings from whatever server is authoritative.
type LeaseReader interface {
	ReadLeaseFiles() []Lease
	SourceName() string
}

// Scan refreshes the client table and returns the current view.
func (t *Tracker) Scan(readers ...LeaseReader) []Client {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.lastScan = time.Now()
	now := time.Now().UnixMilli()

	var neigh []netinfo.Neigh
	ifaces := []string{t.iface}
	if t.iface == "" {
		ifaces = nil
	}
	for _, ifc := range ifaces {
		if n, err := t.dev.Neigh(ifc); err == nil {
			neigh = append(neigh, n...)
		}
	}
	if t.iface == "" {
		if all, err := t.dev.Neigh(""); err == nil {
			neigh = all
		}
	}

	// Leases from all readers, newest expiry wins.
	leaseByMAC := map[string]Lease{}
	var sources []string
	for _, r := range readers {
		for _, l := range r.ReadLeaseFiles() {
			if l.MAC == "" {
				continue
			}
			prev, ok := leaseByMAC[l.MAC]
			if !ok || l.Expiry.After(prev.Expiry) {
				l.Source = sourceOf(r)
				leaseByMAC[l.MAC] = l
			}
			sources = append(sources, sourceOf(r))
		}
	}

	seenMAC := map[string]bool{}
	for _, n := range neigh {
		mac := normaliseMAC(n.MAC)
		if mac == "" || isBroadcast(mac) {
			continue
		}
		if n.State == "failed" || n.State == "incomplete" {
			continue
		}
		if t.iface != "" && n.Iface != "" && n.Iface != t.iface {
			continue
		}
		seenMAC[mac] = true
		e := t.ensure(mac)
		if ip := net.ParseIP(n.IP); ip != nil {
			if ip.To4() != nil {
				e.IPv4 = ip.String()
			} else if !ip.IsLinkLocalUnicast() && !containsStr(e.IPv6, ip.String()) {
				e.IPv6 = append(e.IPv6, ip.String())
			}
		}
		e.Online = true
		e.LastSeen = now
		e.Iface = firstNonEmpty(n.Iface, e.Iface, t.iface)
		e.addSource("neigh:" + n.State)
	}

	for mac, l := range leaseByMAC {
		if time.Now().After(l.Expiry) {
			continue
		}
		seenMAC[mac] = true
		e := t.ensure(mac)
		if e.IPv4 == "" {
			e.IPv4 = l.IP
		}
		if l.Hostname != "" && (e.Hostname == "" || e.HostnameSrc == "lease" && l.Source != "lease") {
			e.Hostname = l.Hostname
			e.HostnameSrc = l.Source
		}
		e.Online = true
		e.LastSeen = now
		e.addSource("lease:" + l.Source)
	}

	// Offline bookkeeping: a device stops being reported as reachable when it is
	// neither in the neighbour table nor holds a live lease. Records are kept for
	// 30 minutes so a reconnect looks like the same device and the duration
	// history stays honest.
	for mac, e := range t.table {
		if seenMAC[mac] {
			if !e.Online {
				e.AssocAt = now // fresh association starts the clock
			}
			e.Online = true
			e.OfflineSince = 0
			e.LastSeen = now
			continue
		}
		if e.Online {
			e.Online = false
			e.OfflineSince = now
		}
		if now-e.LastSeen > int64(30*60*1000) {
			delete(t.table, mac)
		}
	}

	// Per-client accounting.
	backend := "none"
	if t.acc != nil {
		backend = t.acc.Backend()
	}
	counters, accOK, err := map[string]Counters{}, false, error(nil)
	if t.acc != nil {
		counters, accOK, err = t.acc.Observe(t.iface)
		if err != nil {
			t.log.Debugf("clients", "per-client accounting unavailable: %v", err)
		}
	}

	out := make([]Client, 0, len(t.table))
	for mac, e := range t.table {
		c := Client{
			MAC: mac, MACDisplay: t.macDisplay(mac), IPv4: e.IPv4, IPv6: e.IPv6,
			Hostname: e.Hostname, HostnameSrc: e.HostnameSrc,
			FirstSeen: e.FirstSeen, LastSeen: e.LastSeen, Online: e.Online,
			Iface: e.Iface, Sources: e.Sources,
		}
		if e.Online && e.AssocAt > 0 {
			c.AssocSec = (now - e.AssocAt) / 1000
		}
		if !e.Online && e.OfflineSince > 0 {
			c.OfflineSec = (now - e.OfflineSince) / 1000
			c.InactiveSec = c.OfflineSec
		}
		switch {
		case accOK:
			if ct, ok := counters[e.IPv4]; ok {
				c.RxBytes, c.TxBytes = ct.RxBytes, ct.TxBytes
				c.RxPackets, c.TxPackets = ct.RxPackets, ct.TxPackets
				c.TrafficSource = "accounting:" + backend
			} else {
				c.TrafficSource = "accounting:" + backend + " (no rule yet)"
			}
		case t.acc != nil:
			c.TrafficSource = "unavailable: " + backend + " cannot account per client"
			if err != nil {
				c.TrafficSource += " (" + err.Error() + ")"
			}
		default:
			c.TrafficSource = "unavailable: per-client accounting disabled"
		}
		c.DeviceGuess, c.Icon = guessDevice(c.Hostname, mac)
		c.Vendor = ouiHint(mac)
		if c.Online {
			out = append(out, c)
		} else {
			c.Online = false
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return out[i].FirstSeen < out[j].FirstSeen
	})
	t.persistLocked()
	return out
}

func sourceOf(r LeaseReader) string {
	switch x := r.(type) {
	case interface{ SourceName() string }:
		return x.SourceName()
	default:
		_ = r
		return "lease"
	}
}

func (t *Tracker) ensure(mac string) *entry {
	if e, ok := t.table[mac]; ok {
		return e
	}
	e := &entry{MAC: mac, FirstSeen: time.Now().UnixMilli(), Online: true, AssocAt: time.Now().UnixMilli()}
	t.table[mac] = e
	return e
}

func (e *entry) addSource(s string) {
	if len(e.Sources) > 6 {
		return
	}
	if !containsStr(e.Sources, s) {
		e.Sources = append(e.Sources, s)
	}
}

// OnlineCount reports how many devices are currently reachable.
func (t *Tracker) OnlineCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	n := 0
	for _, e := range t.table {
		if e.Online {
			n++
		}
	}
	return n
}

// KnownIPs returns every leased/seen IPv4 address on the downstream segment.
func (t *Tracker) KnownIPs() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for _, e := range t.table {
		if e.IPv4 != "" {
			out = append(out, e.IPv4)
		}
	}
	sort.Strings(out)
	return out
}

// macDisplay honours the privacy switch in Settings.
func (t *Tracker) macDisplay(mac string) string {
	if t.maskMACs {
		return logging.MaskMAC(mac)
	}
	return mac
}

// SetMaskMACs toggles MAC privacy at runtime.
func (t *Tracker) SetMaskMACs(on bool) {
	t.mu.Lock()
	t.maskMACs = on
	t.mu.Unlock()
}

// persistence ---------------------------------------------------------------

// Entry is the on-disk state file schema. It is versioned so a future Yoru can
// read an older table without guessing.
type Entry struct {
	MAC          string   `json:"mac"`
	IPv4         string   `json:"ipv4,omitempty"`
	IPv6         []string `json:"ipv6,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	HostnameSrc  string   `json:"hs,omitempty"`
	FirstSeen    int64    `json:"first"`
	LastSeen     int64    `json:"last"`
	OfflineSince int64    `json:"offsince,omitempty"`
	AssocAt      int64    `json:"assoc,omitempty"`
	Iface        string   `json:"iface,omitempty"`
}

func (t *Tracker) persistLocked() {
	if t.statePath == "" {
		return
	}
	list := make([]Entry, 0, len(t.table))
	for _, e := range t.table {
		list = append(list, Entry{
			MAC: e.MAC, IPv4: e.IPv4, IPv6: e.IPv6, Hostname: e.Hostname, HostnameSrc: e.HostnameSrc,
			FirstSeen: e.FirstSeen, LastSeen: e.LastSeen, OfflineSince: e.OfflineSince,
			AssocAt: e.AssocAt, Iface: e.Iface,
		})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].MAC < list[j].MAC })
	b, err := json.Marshal(map[string]any{"version": 1, "clients": list})
	if err != nil {
		return
	}
	dir := filepath.Dir(t.statePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return
	}
	tmp := t.statePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return
	}
	_ = os.Rename(tmp, t.statePath)
}

func (t *Tracker) load() {
	if t.statePath == "" {
		return
	}
	b, err := os.ReadFile(t.statePath)
	if err != nil {
		return
	}
	var doc struct {
		Version int     `json:"version"`
		List    []Entry `json:"clients"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.log.Warnf("clients", "client state file unreadable (%v); starting fresh", err)
		return
	}
	for _, e := range doc.List {
		mac := normaliseMAC(e.MAC)
		if mac == "" {
			continue
		}
		t.table[mac] = &entry{
			MAC: mac, IPv4: e.IPv4, IPv6: e.IPv6, Hostname: e.Hostname, HostnameSrc: e.HostnameSrc,
			FirstSeen: e.FirstSeen, LastSeen: e.LastSeen, Online: false, OfflineSince: e.OfflineSince,
			AssocAt: e.AssocAt, Iface: e.Iface,
		}
	}
	if len(t.table) > 0 {
		t.log.Infof("clients", "restored %d known devices from state", len(t.table))
	}
}

// Clear forgets all device history (Settings -> "reset device list").
func (t *Tracker) Clear() error {
	t.mu.Lock()
	t.table = map[string]*entry{}
	t.mu.Unlock()
	if t.statePath != "" {
		return os.Remove(t.statePath)
	}
	return nil
}

// Hostnames ----------------------------------------------------------------

// DnsmasqLeases reads /data/misc/dhcp/dnsmasq.leases and friends.
type DnsmasqLeases struct {
	Paths []string
}

// SourceName identifies the reader in the UI.
func (d DnsmasqLeases) SourceName() string { return "dnsmasq" }

// ReadLeaseFiles parses dnsmasq lease files (expires unix; hostname; mac; ip;
// cidr) tolerantly: some OEMs reorder fields or add a trailing FQDN.
func (d DnsmasqLeases) ReadLeaseFiles() []Lease {
	var out []Lease
	for _, p := range d.Paths {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			f := strings.Fields(ln)
			if len(f) < 4 {
				continue
			}
			exp, err := strconv.ParseInt(f[0], 10, 64)
			if err != nil {
				continue
			}
			l := Lease{Expiry: time.Unix(exp, 0), Source: "dnsmasq"}
			// Field 2 is MAC for the standard format; verify by shape.
			if isMAC(f[1]) {
				l.MAC = normaliseMAC(f[1])
				l.IP = f[2]
				l.Hostname = unquote(f[3])
			} else if isMAC(f[2]) {
				l.MAC = normaliseMAC(f[2])
				l.IP = f[1]
				l.Hostname = unquote(f[3])
			} else {
				continue
			}
			out = append(out, l)
		}
	}
	return out
}

// DHCPLeases reads the leases written by Yoru's own DHCP server.
type DHCPLeases struct {
	Path string
}

// SourceName identifies the reader.
func (d DHCPLeases) SourceName() string { return "dhcp-builtin" }

// ReadLeaseFiles returns the built-in server's bindings.
func (d DHCPLeases) ReadLeaseFiles() []Lease {
	b, err := os.ReadFile(d.Path)
	if err != nil {
		return nil
	}
	var doc struct {
		Leases []struct {
			MAC      string `json:"mac"`
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
			Expiry   int64  `json:"expiryMs"`
		} `json:"leases"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil
	}
	var out []Lease
	for _, l := range doc.Leases {
		out = append(out, Lease{
			MAC: normaliseMAC(l.MAC), IP: l.IP, Hostname: l.Hostname,
			Expiry: time.UnixMilli(l.Expiry), Source: "dhcp-builtin",
		})
	}
	return out
}

// ARPFileLeases reads the legacy /proc/net/arp as a fallback identity source.
type ARPFileLeases struct{}

// SourceName identifies the reader.
func (ARPFileLeases) SourceName() string { return "arp" }

// ReadLeaseFiles returns ARP entries without expiry information, marked
// temporary so they never override a real DHCP lease.
func (ARPFileLeases) ReadLeaseFiles() []Lease {
	b, err := os.ReadFile("/proc/net/arp")
	if err != nil {
		return nil
	}
	var out []Lease
	lines := strings.Split(string(b), "\n")
	for i, ln := range lines {
		if i == 0 {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 4 || !isMAC(f[3]) {
			continue
		}
		out = append(out, Lease{
			MAC: normaliseMAC(f[3]), IP: f[0],
			Expiry: time.Now().Add(2 * time.Minute), Temporary: true, Source: "arp",
		})
	}
	return out
}

func unquote(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "\"*")
	if s == "?" {
		return ""
	}
	return s
}

var macRe = regexp.MustCompile(`^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$`)

func isMAC(s string) bool { return macRe.MatchString(s) }

func normaliseMAC(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || !isMAC(s) {
		if s == "" {
			return ""
		}
	}
	return s
}

func isBroadcast(mac string) bool {
	return mac == "ff:ff:ff:ff:ff:ff" || mac == "01:00:5e:00:00:00" || strings.HasPrefix(mac, "01:80:c2")
}

func containsStr(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// guessDevice classifies a device from its DHCP hostname. Only patterns that
// are actually common in the wild are matched; anything else stays "device".
func guessDevice(hostname, mac string) (class, icon string) {
	h := strings.ToLower(hostname)
	switch {
	case h == "":
		return "unknown", "help"
	case containsAny(h, "iphone", "ipad", "ipod", "apple", "macbook", "imac", "airpods", "watch"):
		if containsAny(h, "ipad", "macbook", "imac") {
			return "apple-computer", "laptop_mac"
		}
		return "apple-device", "smartphone"
	case containsAny(h, "sm-", "samsung", "galaxy", "gt-"):
		return "android-phone", "smartphone"
	case containsAny(h, "redmi", "xiaomi", "poco", "mi-"):
		return "android-phone", "smartphone"
	case containsAny(h, "pixel", "a1[0-9]", "oneplus", "realmi", "oppo", "vivo", "motorola", "moto", "nokia", "sony", "huawei", "honor"):
		return "android-phone", "smartphone"
	case containsAny(h, "pc", "desktop", "laptop", "win", "thinkpad", "lenovo", "dell", "hp-", "asus", "notebook"):
		return "computer", "laptop"
	case containsAny(h, "tv", "bravia", "shield", "chromecast", "fire tv", "roku", "mi-box", "beelink"):
		return "tv", "tv"
	case containsAny(h, "watch", "band", "fitbit", "galaxy watch"):
		return "wearable", "watch"
	case containsAny(h, "speaker", "audio", "bose", "jbl", "sonos", "sound"):
		return "audio", "speaker"
	case containsAny(h, "print", "scanner", "epson", "canon", "hp"):
		return "printer", "print"
	case containsAny(h, "camera", "ipc", "dashcam", "gopro"):
		return "camera", "photo_camera"
	case containsAny(h, "vac", "roborock", "deebot", "ikea", "bulb", "plug", "sensor", "esp"):
		return "iot", "settings_remote"
	case containsAny(h, "car", "headunit", "android auto"):
		return "vehicle", "directions_car"
	case containsAny(h, "note", "tab", "pad"):
		return "tablet", "tablet"
	}
	return "device", "devices_other"
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// ouiHint returns the registered vendor prefix (first 3 octets) as text. No
// OUI database is shipped, so this is a prefix hint rather than a claim.
func ouiHint(mac string) string {
	if len(mac) < 8 {
		return ""
	}
	return strings.ToUpper(mac[:8])
}

// Stats summarises the table for the API.
type Stats struct {
	Online  int    `json:"online"`
	Offline int    `json:"offline"`
	Total   int    `json:"total"`
	Iface   string `json:"iface"`
	ScanAt  int64  `json:"scanAtMs"`
}

// Stats reports current counts.
func (t *Tracker) Stats() Stats {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Stats{Iface: t.iface, ScanAt: t.lastScan.UnixMilli()}
	for _, e := range t.table {
		if e.Online {
			s.Online++
		} else {
			s.Offline++
		}
	}
	s.Total = s.Online + s.Offline
	return s
}

var _ = traffic.FormatBytes
