// Package caps implements Yoru's capability engine.
//
// Nothing in Yoru assumes hardware exists. Every feature is the result of an
// active probe (sysfs, netlink, `iw`, `dumpsys`) that is verified before it is
// advertised, and each capability carries a human-readable reason when it is
// absent. This is what lets the dashboard say "unsupported on this device,
// because X" instead of showing a dead button or a fake number.
package caps

import (
	"fmt"
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
	"yoru.dev/yorud/internal/safeexec"
	"yoru.dev/yorud/internal/sysinfo"
)

// Capability identifiers (stable wire values; the WebUI keys off these).
const (
	WiFiSTA            = "WIFI_STA"
	WiFiAP             = "WIFI_AP"
	WiFiConcurrent     = "WIFI_STA_AP_CONCURRENT"
	WiFiP2P            = "WIFI_P2P"
	WiFi6              = "WIFI_6GHZ"
	WiFiHe             = "WIFI_HE"
	WiFiVht            = "WIFI_VHT"
	Iptables           = "IPTABLES"
	IptablesLegacy     = "IPTABLES_LEGACY"
	IptablesNft        = "IPTABLES_NFT"
	Nftables           = "NFTABLES"
	Dnsmasq            = "DNSMASQ"
	Hostapd            = "HOSTAPD"
	HostapdBundled     = "HOSTAPD_BUNDLED"
	IPCommand          = "IP_COMMAND"
	IWCommand          = "IW"
	IWConfig           = "IWCONFIG"
	AndroidTethering   = "ANDROID_TETHERING"
	AndroidSoftAP      = "ANDROID_SOFTAP"
	AndroidWifiCmd     = "ANDROID_WIFI_CMD"
	SELinuxPermissive  = "SELINUX_PERMISSIVE"
	NetlinkAccess      = "NETLINK_ACCESS"
	IPv6               = "IPV6"
	ProcfsReadable     = "PROCFS"
	SysfsThermal       = "SYSFS_THERMAL"
	SwapZram           = "ZRAM"
	CellularUpstream   = "CELLULAR_UPSTREAM"
	UsbUpstream        = "USB_UPSTREAM"
	EthernetUpstream   = "ETHERNET_UPSTREAM"
	VPNPresent         = "VPN_PRESENT"
	EthernetDownstream = "ETHERNET_DOWNSTREAM"
	MultiPHY           = "MULTI_PHY"
	RegDomain          = "REGDOMAIN"
	TCTrafficControl   = "TC"
	WpaCli             = "WPA_CLI"
	SSESupported       = "SSE"
	DumpsysAvailable   = "DUMPSYS"
)

// Capability is one probed feature.
type Capability struct {
	ID        string `json:"id"`
	Supported bool   `json:"supported"`
	State     string `json:"state"` // yes | no | unknown | degraded
	Reason    string `json:"reason,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Probed    int64  `json:"probedAtMs"`
	Source    string `json:"source"`
	Fixable   bool   `json:"fixable,omitempty"`
	FixHint   string `json:"fixHint,omitempty"`
}

// Radio describes one 802.11 physical device.
type Radio struct {
	PHY             string   `json:"phy"`
	MAC             string   `json:"mac"`
	Driver          string   `json:"driver"`
	Firmware        string   `json:"firmware,omitempty"`
	Interfaces      []string `json:"interfaces"`
	Modes           []string `json:"modes"`
	Channels2G      []int    `json:"channels2ghz"`
	Channels5G      []int    `json:"channels5ghz"`
	Channels6G      []int    `json:"channels6ghz"`
	SupportsAP      bool     `json:"supportsAp"`
	SupportsSTA     bool     `json:"supportsSta"`
	SupportsP2P     bool     `json:"supportsP2p"`
	MaxInterfaces   int      `json:"maxInterfaces"`
	Combos          []string `json:"interfaceCombos"`
	RegDomain       string   `json:"regdomain,omitempty"`
	He              bool     `json:"he"`
	Vht             bool     `json:"vht"`
	Ht40            bool     `json:"ht40"`
	NumBegunCombos  int      `json:"-"`
	ConcurrencyHint string   `json:"concurrencyHint,omitempty"`
}

// Set is a cached capability snapshot.
type Set struct {
	mu           sync.RWMutex
	log          *logging.Logger
	dev          *netinfo.Device
	items        map[string]Capability
	radios       []Radio
	probedAt     time.Time
	probing      bool
	ttl          time.Duration
	modpath      string
	bootComplete bool
}

// NewSet prepares the capability engine. modpath is the module directory, used
// to find a bundled hostapd if the operator supplied one.
func NewSet(log *logging.Logger, dev *netinfo.Device, modpath string) *Set {
	return &Set{
		log: log, dev: dev, items: map[string]Capability{},
		ttl:     30 * time.Second,
		modpath: modpath,
	}
}

// Get returns one capability, probing the world if the cache is stale.
func (s *Set) Get(id string) Capability {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c, ok := s.items[id]; ok {
		return c
	}
	return Capability{ID: id, State: "unknown", Reason: "not probed"}
}

// Has reports whether a capability is usable.
func (s *Set) Has(id string) bool { return s.Get(id).Supported }

// All returns every capability sorted by id.
func (s *Set) All() []Capability {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Capability, 0, len(s.items))
	for _, c := range s.items {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Radios returns the detected 802.11 physical devices.
func (s *Set) Radios() []Radio {
	s.refresh()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]Radio(nil), s.radios...)
}

// set records a probe result. A supported capability carries a detail (what
// was found) and no reason; an unsupported one carries the reason the user must
// see. Mixing them would put a failure message next to a green indicator.
func (s *Set) set(id string, ok bool, state, source, reason, detail string) {
	c := Capability{ID: id, State: state, Source: source, Probed: time.Now().UnixMilli()}
	if ok {
		c.Supported = true
		c.Detail = detail
	} else {
		c.Reason = reason
		c.Detail = detail
		if reason == "" {
			c.Reason = detail
		}
	}
	s.mu.Lock()
	s.items[id] = c
	s.mu.Unlock()
}

// refresh re-probes when the cache is older than the TTL. It must never
// re-enter Probe from inside a probe pass (probes read each other's results),
// so an in-flight probe short-circuits here.
func (s *Set) refresh() {
	s.mu.RLock()
	stale := time.Since(s.probedAt) > s.ttl || len(s.items) == 0
	probing := s.probing
	s.mu.RUnlock()
	if stale && !probing {
		s.Probe()
	}
}

// Probe runs every detection pass. Safe to call concurrently; serialised.
func (s *Set) Probe() {
	s.mu.Lock()
	if s.probing {
		s.mu.Unlock()
		return
	}
	if len(s.items) > 0 && time.Since(s.probedAt) < time.Second {
		s.mu.Unlock()
		return
	}
	// Claim probedAt up front: later passes read earlier capabilities through
	// Get(), and without this the freshness check would restart the probe.
	s.probing = true
	s.probedAt = time.Now()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.probing = false
		s.mu.Unlock()
	}()

	start := time.Now()
	s.log.Debugf("caps", "probing device capabilities")

	s.probeTools()
	s.probeKernel()
	s.probeSELinux()
	radios := s.probeWiFi()
	s.probeFirewall()
	s.probeDHCPDNS()
	s.probeAndroid()
	s.probeInterfaces()
	s.probeConcurrency(radios)

	s.mu.Lock()
	s.radios = radios
	s.probedAt = time.Now()
	s.mu.Unlock()
	s.log.Infof("caps", "capability probe finished in %dms (%d radios, %d capabilities)",
		time.Since(start).Milliseconds(), len(radios), len(s.items))
}

// probeTools checks for each helper binary without assuming any exist.
func (s *Set) probeTools() {
	type t struct{ id, bin, why string }
	list := []t{
		{IPCommand, "ip", "needed to configure addresses and routes"},
		{IWCommand, "iw", "needed to read Wi-Fi radio capabilities and station stats"},
		{IWConfig, "iwconfig", "legacy alternative to iw"},
		{Hostapd, "hostapd", "needed for software-managed access point"},
		{Dnsmasq, "dnsmasq", "optional: provides DHCP and DNS"},
		{TCTrafficControl, "tc", "optional: enables per-client shaping"},
		{WpaCli, "wpa_cli", "optional: reads upstream station state"},
	}
	for _, x := range list {
		if p, ok := safeexec.Resolve(x.bin); ok {
			s.set(x.id, true, "yes", "binary", "", p)
		} else {
			s.set(x.id, false, "no", "binary", x.why, "not found in /system/bin, /vendor/bin or /sbin")
		}
	}
	// A bundled hostapd shipped inside the module is a separate capability:
	// it exists even when the OS has none.
	for _, p := range []string{
		filepath.Join(s.modpath, "yoru", "bin", "hostapd"),
		"/data/adb/yoru-repeater/bin/hostapd",
	} {
		if st, err := os.Stat(p); err == nil && st.Mode().Perm()&0111 != 0 {
			s.set(HostapdBundled, true, "yes", "module", "", p)
			break
		}
	}
	s.flag(ProcfsReadable, readable("/proc/stat"), "procfs",
		"/proc must be readable to report CPU and memory", "")
	s.flag(SysfsThermal, len(sysinfo.Thermals()) > 0 || len(sysinfo.HwmonSensors()) > 0, "sysfs",
		"no thermal sensors are exposed, so temperature will be reported as unavailable", "")
	s.flag(SwapZram, len(zramDevices()) > 0, "sysfs", "no zram block device is present", strings.Join(zramDevices(), ","))
}

// flag records a boolean probe whose state is derived from the result.
func (s *Set) flag(id string, ok bool, source, reason, detail string) {
	state := "no"
	if ok {
		state = "yes"
	}
	s.set(id, ok, state, source, reason, detail)
}

func readable(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

func zramDevices() []string {
	d, _ := filepath.Glob("/sys/block/zram*")
	var out []string
	for _, x := range d {
		out = append(out, filepath.Base(x))
	}
	return out
}

func (s *Set) probeKernel() {
	if links, err := s.dev.Links(); err == nil && len(links) > 0 {
		s.flag(NetlinkAccess, true, "netlink", "", fmt.Sprintf("%d interfaces", len(links)))
	} else {
		s.set(NetlinkAccess, false, "no", "netlink",
			"Yoru cannot read interface state; the dashboard will show very little",
			fmt.Sprint(err))
	}
	s.flag(IPv6, netinfo.IPv6Available(), "sysfs",
		"IPv6 is disabled in the kernel; only IPv4 will be offered to clients", "")
}

func (s *Set) probeSELinux() {
	mode, _ := sysinfo.SELinuxStatus()
	switch mode {
	case "":
		s.set(SELinuxPermissive, true, "unknown", "selinux",
			"SELinux state is not readable; if a policy blocks a step Yoru will report it when it happens", "")
	case "permissive":
		s.set(SELinuxPermissive, true, "yes", "selinux", "", "permissive")
	default:
		s.set(SELinuxPermissive, false, "degraded", "selinux",
			"enforcing SELinux can block hostapd or dnsmasq; Yoru ships a sepolicy.rule to cover the common cases", mode)
	}
}

var (
	phyRe   = regexp.MustCompile(`phy\d+`)
	ifaceRe = regexp.MustCompile(`Interface (wlansvn|[a-z0-9_.\-]+)`)
	modeRe  = regexp.MustCompile(`(^\s*(managed|AP|P2P Client|P2P Device|monitor|wds|mesh point)\s*$)`)
	freqRe  = regexp.MustCompile(`^\s*\*\s+([\d.]+) MHz.*`)
	validRe = regexp.MustCompile(`valid interface combinations:`)
)

// probeWiFi enumerates 802.11 radios and extracts their abilities.
func (s *Set) probeWiFi() []Radio {
	var radios []Radio
	phys, _ := filepath.Glob("/sys/class/ieee80211/phy*")
	sort.Strings(phys)

	links, _ := s.dev.Links()
	ifToPhy := map[string]string{}
	for _, l := range links {
		if !l.Wireless && l.WirelessIdx == 0 {
			continue
		}
		idx := l.WirelessIdx
		if idx == 0 {
			if v, err := os.Readlink(filepath.Join("/sys/class/net", l.Name, "phy80211")); err == nil {
				if m := phyRe.FindString(v); m != "" {
					ifToPhy[l.Name] = m
					continue
				}
			}
			continue
		}
		for _, p := range phys {
			if filepath.Base(p) == "phy"+strconv.Itoa(idx) {
				ifToPhy[l.Name] = filepath.Base(p)
			}
		}
	}

	for _, p := range phys {
		phy := filepath.Base(p)
		r := Radio{PHY: phy}
		if v, err := readTrim(filepath.Join(p, "macaddress")); err == nil {
			r.MAC = v
		}
		if drv, err := os.Readlink(filepath.Join(p, "device", "driver")); err == nil {
			r.Driver = filepath.Base(drv)
		}
		for _, n := range links {
			if ifToPhy[n.Name] == phy {
				r.Interfaces = append(r.Interfaces, n.Name)
			}
		}
		r.Firmware = readFirmware(r.Driver)

		if safeexec.Available("iw") {
			res, err := safeexec.Run("iw", []string{"phy", phy, "info"}, safeexec.Options{Timeout: 6 * time.Second, MaxOut: 4 << 20})
			if err == nil && res.OK() {
				parsePhyInfo(res.Stdout, &r)
			} else if err != nil {
				s.log.Warnf("caps", "iw phy %s info failed: %v", phy, err)
			} else {
				s.log.Warnf("caps", "iw phy %s info exited %d: %s", phy, res.ExitCode, strings.TrimSpace(res.Stderr))
			}
		}
		if len(r.Modes) == 0 {
			// Without iw we can still infer STA from an associated interface.
			for _, n := range links {
				if ifToPhy[n.Name] == phy && strings.HasPrefix(n.Name, "wlan") {
					r.Modes = append(r.Modes, "managed")
					r.SupportsSTA = true
				}
			}
		}
		radios = append(radios, r)
	}

	// Capability publication.
	staCount, apCount := 0, 0
	for _, r := range radios {
		if r.SupportsSTA {
			staCount++
		}
		if r.SupportsAP {
			apCount++
		}
	}
	if len(radios) == 0 {
		s.set(WiFiSTA, false, "no", "sysfs", "no 802.11 radio found under /sys/class/ieee80211", "")
		s.set(WiFiAP, false, "no", "sysfs", "no 802.11 radio found, so an access point cannot be started", "")
		s.set(WiFiConcurrent, false, "no", "sysfs", "no Wi-Fi hardware detected", "")
		return radios
	}
	if staCount > 0 {
		s.set(WiFiSTA, true, "yes", "iw", "", phyList(radios, true, false))
	} else {
		s.set(WiFiSTA, false, "no", "iw", "the driver does not advertise managed (STA) mode", phyList(radios, false, false))
	}
	if apCount > 0 {
		s.set(WiFiAP, true, "yes", "iw", "", phyList(radios, false, true))
	} else {
		s.set(WiFiAP, false, "no", "iw",
			"the Wi-Fi driver does not advertise AP mode, so a software access point is impossible; Yoru can still route for an existing hotspot",
			phyList(radios, false, false))
	}
	if hasMode(radios, "P2P Client") || hasMode(radios, "P2P Device") {
		s.set(WiFiP2P, true, "yes", "iw", "", "")
	} else {
		s.set(WiFiP2P, false, "no", "iw", "P2P is not advertised; it is not used by Yoru but the OS may need it", "")
	}
	for _, r := range radios {
		if len(r.Channels6G) > 0 {
			s.set(WiFi6, true, "yes", "iw", "", fmt.Sprintf("%s: %d 6 GHz channels", r.PHY, len(r.Channels6G)))
			break
		}
	}
	if !s.Has(WiFi6) {
		s.set(WiFi6, false, "no", "iw", "no 6 GHz channels are permitted for this radio/regulatory domain", "")
	}
	for _, r := range radios {
		if r.RegDomain != "" {
			s.set(RegDomain, true, "yes", "iw", "", r.PHY+"="+r.RegDomain)
			break
		}
	}
	if !s.Has(RegDomain) {
		s.set(RegDomain, false, "unknown", "iw", "regulatory domain is not exposed; channel availability cannot be confirmed", "")
	}
	if len(radios) > 1 {
		s.set(MultiPHY, true, "yes", "sysfs", "", fmt.Sprintf("%d radios", len(radios)))
	}
	return radios
}

func phyList(rs []Radio, sta, ap bool) string {
	var out []string
	for _, r := range rs {
		if sta && !r.SupportsSTA {
			continue
		}
		if ap && !r.SupportsAP {
			continue
		}
		out = append(out, fmt.Sprintf("%s(%s) modes=%s", r.PHY, r.Driver, strings.Join(r.Modes, "+")))
	}
	return strings.Join(out, "; ")
}

func hasMode(rs []Radio, m string) bool {
	for _, r := range rs {
		for _, x := range r.Modes {
			if strings.EqualFold(x, m) {
				return true
			}
		}
	}
	return false
}

var bandFreq = map[string]bool{"2g": true, "5g": true, "6g": true}

// parsePhyInfo reads `iw phy X info` output. The format is stable across iw
// versions but indentation varies, so parsing is whitespace tolerant.
func parsePhyInfo(text string, r *Radio) {
	var curBand string
	inCombos := false
	heSeen := false
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "valid interface combinations:"):
			inCombos = true
			continue
		case strings.HasPrefix(t, "valid interface combination sets:"):
			inCombos = false
			continue
		case strings.HasPrefix(t, "Frequencies:"):
			continue
		case strings.HasPrefix(t, "Regdomain:") || strings.HasPrefix(t, "regdomain:"):
			r.RegDomain = strings.TrimSpace(t[strings.Index(t, ":")+1:])
		}
		if inCombos {
			if strings.HasPrefix(t, "*") {
				r.Combos = append(r.Combos, t)
				if n, ok := comboCount(t); ok && n > r.MaxInterfaces {
					r.MaxInterfaces = n
				}
				if strings.Contains(t, "AP") && strings.Contains(t, "managed") {
					r.SupportsSTA = true
					r.SupportsAP = true
				}
			} else if t != "" && !strings.HasPrefix(t, "\t") {
				inCombos = false
			}
		}
		if strings.HasPrefix(t, "band ") {
			switch {
			case strings.Contains(t, "Band 1"):
				curBand = "2g"
			case strings.Contains(t, "Band 2"):
				curBand = "5g"
			case strings.Contains(t, "Band 3") || strings.Contains(t, "Band 4"):
				curBand = "6g"
			default:
				curBand = ""
			}
			continue
		}
		if strings.HasPrefix(t, "HT Capabilities") || strings.Contains(t, "HT40") {
			r.Ht40 = true
		}
		if strings.HasPrefix(t, "VHT Capabilities") {
			r.Vht = true
		}
		if strings.HasPrefix(t, "HE Iftypes") || strings.HasPrefix(t, "HE PHY Capabilities") || strings.HasPrefix(t, "HE Capabilities") {
			r.He = true
			heSeen = true
		}
		if m := freqRe.FindStringSubmatch(t); m != nil && bandFreq[curBand] {
			f, _ := strconv.ParseFloat(m[1], 64)
			ch := freqToChannel(f)
			if ch <= 0 {
				continue
			}
			switch curBand {
			case "2g":
				r.Channels2G = append(r.Channels2G, ch)
			case "5g":
				r.Channels5G = append(r.Channels5G, ch)
			case "6g":
				r.Channels6G = append(r.Channels6G, ch)
			}
			continue
		}
		if modeRe.MatchString(t) {
			mode := strings.TrimSpace(modeRe.FindStringSubmatch(t)[1])
			seen := false
			for _, x := range r.Modes {
				if x == mode {
					seen = true
				}
			}
			if !seen {
				r.Modes = append(r.Modes, mode)
			}
			switch mode {
			case "managed":
				r.SupportsSTA = true
			case "AP":
				r.SupportsAP = true
			case "P2P Client", "P2P Device":
				r.SupportsP2P = true
			}
		}
	}
	if !heSeen && strings.Contains(text, "HE") {
		r.He = true
	}
	sort.Ints(r.Channels2G)
	sort.Ints(r.Channels5G)
	sort.Ints(r.Channels6G)
	r.Channels2G = uniq(r.Channels2G)
	r.Channels5G = uniq(r.Channels5G)
	r.Channels6G = uniq(r.Channels6G)
}

// comboCount parses "devices (up to N total)" out of an iw combination line.
func comboCount(line string) (int, bool) {
	re := regexp.MustCompile(`devices \(up to (\d+) total`)
	m := re.FindStringSubmatch(line)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

func uniq(in []int) []int {
	var out []int
	last := -1
	for _, v := range in {
		if v != last {
			out = append(out, v)
			last = v
		}
	}
	return out
}

// freqToChannel converts a MHz centre to a channel number using the standard
// 802.11 lettered tables.
func freqToChannel(mhz float64) int {
	switch {
	case mhz >= 2412 && mhz <= 2472:
		ch := int((mhz - 2407) / 5)
		if mhz == 2484 {
			return 14
		}
		if ch >= 1 && ch <= 13 {
			return ch
		}
	case mhz >= 5170 && mhz <= 5900:
		ch := int((mhz - 5000) / 5)
		if ch >= 32 && ch <= 233 {
			return ch
		}
	case mhz >= 5950 && mhz <= 7115: // Wi-Fi 6E/7
		ch := int((mhz-5950)/5) + 1
		if ch >= 1 && ch <= 233 {
			return ch
		}
	case mhz == 2484:
		return 14
	}
	return 0
}

// ChannelFrequency is the inverse mapping, used when the user picks a channel.
func ChannelFrequency(ch int, band string) int {
	switch band {
	case "2g":
		if ch >= 1 && ch <= 13 {
			return 2407 + ch*5
		}
		if ch == 14 {
			return 2484
		}
	case "5g":
		if ch >= 32 && ch <= 233 {
			return 5000 + ch*5
		}
	case "6g":
		if ch >= 1 && ch <= 233 {
			return 5950 + (ch-1)*5
		}
	}
	return 0
}

// probeFirewall determines which NAT mechanism is actually usable. Merely
// finding an iptables binary is not enough: on Android 13+ the binary may be a
// symlink to nft-compat while the legacy tables are unreachable, and a kernel
// without the match modules will fail at rule-insert time.
func (s *Set) probeFirewall() {
	if !s.Has(IPCommand) {
		s.set(Iptables, false, "no", "policy", "no ip command; cannot manage forwarding anyway", "")
		s.set(Nftables, false, "no", "policy", "no ip command", "")
		return
	}
	if res, err := safeexec.Run("iptables", []string{"--version"}, safeexec.Options{Timeout: 3 * time.Second}); err == nil && res.OK() {
		v := strings.TrimSpace(res.Stdout)
		backend := "legacy"
		if strings.Contains(v, "nf_tables") {
			backend = "nft"
			s.set(IptablesNft, true, "yes", "iptables --version", "", v)
		} else {
			s.set(IptablesLegacy, true, "yes", "iptables --version", "", v)
		}
		// Verify a real rule can be created and deleted in a private chain.
		if err := verifyIptables(); err != nil {
			s.set(Iptables, false, "degraded", "probe", "iptables exists but creating a test chain failed: "+err.Error(), v)
			s.log.Warnf("caps", "iptables probe failed: %v", err)
		} else {
			s.set(Iptables, true, "yes", "probe", "", fmt.Sprintf("%s (backend %s)", v, backend))
		}
	} else {
		msg := "iptables binary not found"
		if err != nil {
			msg = "iptables failed: " + err.Error()
		} else if res.Stderr != "" {
			msg = "iptables failed: " + strings.TrimSpace(res.Stderr)
		}
		s.set(Iptables, false, "no", "binary", msg, "")
	}
	if res, err := safeexec.Run("nft", []string{"--version"}, safeexec.Options{Timeout: 3 * time.Second}); err == nil && res.OK() {
		if err := verifyNft(); err != nil {
			s.set(Nftables, false, "degraded", "probe", "nft exists but a test table could not be created: "+err.Error(), strings.TrimSpace(res.Stdout))
		} else {
			s.set(Nftables, true, "yes", "probe", "", strings.TrimSpace(res.Stdout))
		}
	} else {
		s.set(Nftables, false, "no", "binary", "nft binary not found", "")
	}
}

const (
	probeChain   = "YORU_PROBE"
	probeTable   = "filter"
	probeNftName = "yoru_probe"
)

func verifyIptables() error {
	if _, err := safeexec.Out("iptables", "-t", probeTable, "-N", probeChain); err != nil {
		if !strings.Contains(strings.ToLower(err.Error()), "exists") {
			return err
		}
		_, _ = safeexec.Out("iptables", "-t", probeTable, "-F", probeChain)
	}
	defer func() { _, _ = safeexec.Out("iptables", "-t", probeTable, "-X", probeChain) }()
	if _, err := safeexec.Out("iptables", "-t", probeTable, "-A", probeChain, "-j", "RETURN"); err != nil {
		return fmt.Errorf("append test rule: %w", err)
	}
	_, _ = safeexec.Out("iptables", "-t", probeTable, "-F", probeChain)
	return nil
}

func verifyNft() error {
	script := "table ip " + probeNftName + " { chain yoru_probe { type filter hook forward priority 0; policy accept; } }"
	path := "/data/local/tmp/yoru-nft-probe.conf"
	if err := os.WriteFile(path, []byte(script), 0600); err != nil {
		return fmt.Errorf("write probe file: %w", err)
	}
	defer os.Remove(path)
	if _, err := safeexec.Out("nft", "-f", path); err != nil {
		return err
	}
	_, _ = safeexec.Out("nft", "delete", "table", "ip", probeNftName)
	return nil
}

func (s *Set) probeDHCPDNS() {
	if s.Has(Dnsmasq) {
		res, err := safeexec.Run("dnsmasq", []string{"--version"}, safeexec.Options{Timeout: 3 * time.Second})
		detail := ""
		if err == nil {
			detail = firstLine(res.Stdout)
		}
		s.set(Dnsmasq, true, "yes", "binary", "", detail)
	}
	// Yoru always has its own DHCP+DNS, so the built-in path is unconditionally
	// available; it is recorded as a capability because the UI offers a choice.
	s.flag("BUILTIN_DHCP", true, "internal", "", "compiled into yorud")
	s.flag("BUILTIN_DNS", true, "internal", "", "compiled into yorud")
}

// probeAndroid checks the framework services Yoru may delegate to. Detection
// is by capability, never by version number.
func (s *Set) probeAndroid() {
	if !safeexec.Available("cmd") {
		s.set(AndroidWifiCmd, false, "no", "binary", "cmd(1) is absent; this is not a normal Android system", "")
	} else {
		res, err := safeexec.Run("cmd", []string{"wifi", "status"}, safeexec.Options{Timeout: 5 * time.Second})
		switch {
		case err != nil:
			s.set(AndroidWifiCmd, false, "unknown", "probe", "cmd wifi status failed: "+err.Error(), "")
		case res.ExitCode != 0:
			s.set(AndroidWifiCmd, false, "degraded", "probe",
				"the Wi-Fi service refused the shell command (common on hardened OEM builds)", strings.TrimSpace(res.Combined()))
		default:
			s.set(AndroidWifiCmd, true, "yes", "probe", "", firstLine(res.Stdout))
		}
	}
	if safeexec.Available("dumpsys") {
		res, err := safeexec.Run("dumpsys", []string{"wifi"}, safeexec.Options{Timeout: 6 * time.Second, MaxOut: 8 << 20})
		if err == nil && res.OK() && strings.Contains(res.Stdout, "Wi-Fi is") || strings.Contains(res.Stdout, "mWifiStateMachine") {
			s.set(DumpsysAvailable, true, "yes", "dumpsys", "", "")
			// AndroidSoftAP: does the framework expose a usable hotspot? Look for
			// the objects that only exist when SoftAp is implemented.
			softAP := strings.Contains(res.Stdout, "SoftAp") || strings.Contains(res.Stdout, "mSoftApManager") ||
				strings.Contains(res.Stdout, "Tethering:")
			if softAP {
				s.set(AndroidSoftAP, true, "yes", "dumpsys", "", "framework SoftAp objects present")
			} else {
				s.set(AndroidSoftAP, false, "unknown", "dumpsys", "no SoftAp state found in dumpsys wifi output", "")
			}
		} else {
			s.set(DumpsysAvailable, false, "no", "dumpsys", "dumpsys wifi is not readable from this context", "")
		}
	} else {
		s.set(DumpsysAvailable, false, "no", "binary", "dumpsys not found", "")
	}
	if safeexec.Available("cmd") {
		res, err := safeexec.Run("cmd", []string{"tethering", "help"}, safeexec.Options{Timeout: 4 * time.Second})
		if err == nil && (res.OK() || strings.Contains(res.Combined(), "Usage")) {
			s.set(AndroidTethering, true, "yes", "cmd tethering", "", "tethering service reachable")
		} else {
			s.set(AndroidTethering, false, "no", "cmd tethering", "the tethering service is not reachable from the shell", "")
		}
	}
}

// probeInterfaces classifies what upstream and downstream options exist.
func (s *Set) probeInterfaces() {
	links, err := s.dev.Links()
	if err != nil {
		return
	}
	addrs, _ := s.dev.Addrs()
	var up, ap, vpn []string
	for _, l := range links {
		if l.Loopback || l.Name == "bonding_masters" {
			continue
		}
		switch netinfo.Classify(l) {
		case netinfo.ClassWiFiAP:
			ap = append(ap, l.Name)
		case netinfo.ClassVPN:
			// tunl0/sit0 exist as disabled stubs on virtually every kernel, so a
			// tunnel only counts as a real VPN when it is carried and addressable.
			if l.Up && (l.Running || l.LowerUp) {
				vpn = append(vpn, l.Name)
			}
		}
		if netinfo.IsUsableUpstream(l, addrs) {
			up = append(up, l.Name)
		}
	}
	if hasAnyPrefix(up, "rmnet", "ccmni", "ipa", "qti", "wwan", "rndis") {
		s.flag(CellularUpstream, true, "netlink", "", strings.Join(up, ","))
	}
	if hasAnyPrefix(up, "usb", "ncm", "ecm", "g_") {
		s.flag(UsbUpstream, true, "netlink", "", "")
	} else {
		s.set(UsbUpstream, false, "no", "netlink", "no active USB network interface (connect a USB Ethernet/rndis device)", "")
	}
	if hasAnyPrefix(up, "eth", "mgbe", "gmac", "enx", "lan") {
		s.flag(EthernetUpstream, true, "netlink", "", "")
	} else {
		s.set(EthernetUpstream, false, "no", "netlink", "no active wired Ethernet interface", "")
	}
	if len(vpn) > 0 {
		s.set(VPNPresent, true, "yes", "netlink",
			"a VPN is active; Yoru will not touch it, but traffic may still leave through the VPN tunnel instead of the repeater",
			strings.Join(vpn, ","))
	}
	down := ap
	for _, l := range links {
		if l.Wireless && netinfo.Classify(l) == netinfo.ClassWiFiSTA && contains(ap, l.Name) == false {
			// an idle second Wi-Fi interface can be converted into an AP
			down = append(down, l.Name)
		}
	}
	if len(down) > 0 {
		s.flag(EthernetDownstream, len(ap) > 0, "netlink", "no wireless access-point interface is available to reuse", strings.Join(down, ","))
	}
}

func (s *Set) probeConcurrency(rs []Radio) {
	// Three independent evidence paths, best first:
	//   1. two Wi-Fi radios  -> guaranteed STA+AP
	//   2. an AP iface and a STA iface both present right now
	//   3. a single radio advertising an interface combination with both types
	conc := false
	detail := ""
	switch {
	case countRadios(rs) >= 2 && allSupport(rs):
		conc = true
		detail = "two independent Wi-Fi radios"
	case runningSTAandAP(rs):
		conc = true
		detail = "a STA and an AP interface are both active"
	default:
		for _, r := range rs {
			for _, c := range r.Combos {
				if strings.Contains(c, "AP") && strings.Contains(c, "managed") {
					conc = true
					detail = r.PHY + " advertises a combined interface set: " + compact(c)
					break
				}
			}
			if conc {
				break
			}
		}
	}
	if conc {
		s.set(WiFiConcurrent, true, "yes", "iw", "", detail)
	} else {
		why := "the Wi-Fi driver does not advertise a simultaneous managed+AP interface combination"
		if len(rs) == 0 {
			why = "no Wi-Fi radio was detected"
		}
		s.set(WiFiConcurrent, false, "no", "iw",
			why+"; true repeating is impossible on this hardware, so Yoru will offer hotspot-router mode instead",
			combosOf(rs))
	}
}

func compact(s string) string { return strings.Join(strings.Fields(s), " ") }

func combosOf(rs []Radio) string {
	var out []string
	for _, r := range rs {
		for _, c := range r.Combos {
			out = append(out, r.PHY+": "+compact(c))
		}
		if len(out) > 6 {
			return strings.Join(out, " | ")
		}
	}
	return strings.Join(out, " | ")
}

func countRadios(rs []Radio) int { return len(rs) }

func allSupport(rs []Radio) bool {
	sta, ap := 0, 0
	for _, r := range rs {
		if r.SupportsSTA {
			sta++
		}
		if r.SupportsAP {
			ap++
		}
	}
	return sta > 0 && ap > 0
}

func runningSTAandAP(rs []Radio) bool {
	sta := false
	ap := false
	for _, r := range rs {
		if r.SupportsSTA && len(r.Interfaces) > 0 {
			sta = true
		}
	}
	for _, r := range rs {
		for _, i := range r.Interfaces {
			if strings.HasPrefix(strings.ToLower(i), "ap") || strings.Contains(strings.ToLower(i), "swlan") {
				ap = true
			}
		}
	}
	return sta && ap
}

func hasAnyPrefix(list []string, pfx ...string) bool {
	for _, v := range list {
		for _, p := range pfx {
			if strings.HasPrefix(v, p) {
				return true
			}
		}
	}
	return false
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func readTrim(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return strings.TrimSpace(s)
}

// readFirmware guesses the firmware revision from well-known sysfs locations.
func readFirmware(driver string) string {
	cands := []string{
		"/sys/module/" + driver + "/firmware_version",
		"/sys/module/" + driver + "/parameters/firmware_path",
	}
	for _, c := range cands {
		if v, err := readTrim(c); err == nil {
			return v
		}
	}
	if driver == "" {
		return ""
	}
	// Some vendors expose it through the device tree path instead.
	if matches, _ := filepath.Glob("/sys/devices/platform/*/" + driver + "/firmware*"); len(matches) > 0 {
		if v, err := readTrim(matches[0]); err == nil {
			return v
		}
	}
	return ""
}

// Summary is the compact form the dashboard shows on the Repeater page.
type Summary struct {
	TrueRepeater   bool     `json:"trueRepeater"`
	HotspotRouter  bool     `json:"hotspotRouter"`
	UsbRouter      bool     `json:"usbRouter"`
	EthernetRouter bool     `json:"ethernetRouter"`
	Reasons        []string `json:"reasons"`
	Radios         []Radio  `json:"radios"`
}

// Summarise converts the raw capability set into mode decisions.
func (s *Set) Summarise() Summary {
	sum := Summary{Radios: s.Radios()}
	if s.Has(WiFiConcurrent) && s.Has(WiFiAP) {
		sum.TrueRepeater = true
	}
	if s.Has(WiFiAP) || s.Has(AndroidSoftAP) {
		sum.HotspotRouter = true
	}
	if s.Has(UsbUpstream) {
		sum.UsbRouter = true
	}
	if s.Has(EthernetUpstream) {
		sum.EthernetRouter = true
	}
	for _, c := range s.All() {
		if !c.Supported && c.Reason != "" && c.State != "unknown" {
			switch c.ID {
			case WiFiConcurrent, WiFiAP, Iptables, Nftables, Hostapd:
				sum.Reasons = append(sum.Reasons, c.ID+": "+c.Reason)
			}
		}
	}
	return sum
}

// Invalidate forces a re-probe on the next access (after start/stop).
func (s *Set) Invalidate() {
	s.mu.Lock()
	s.probedAt = time.Time{}
	s.mu.Unlock()
}
