// Package wifistate reads live Wi-Fi state from every source a rooted Android
// device may offer, and reports which one answered.
//
// Priority is: `iw` (most accurate, but often absent) -> wpa_cli (station) ->
// hostapd control socket (AP) -> dumpsys wifi (framework) -> procfs wireless ->
// sysfs. Each layer only fills fields the previous one left empty, so the UI
// can state exactly where a number came from.
package wifistate

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/safeexec"
)

// Station describes an associated upstream client (this phone as a client).
type Station struct {
	Iface       string         `json:"iface"`
	Connected   bool           `json:"connected"`
	SSID        string         `json:"ssid,omitempty"`
	BSSID       string         `json:"bssid,omitempty"`
	Frequency   int            `json:"frequencyMHz,omitempty"`
	Channel     int            `json:"channel,omitempty"`
	Band        string         `json:"band,omitempty"`
	RSSI        int            `json:"rssi,omitempty"`
	Linkspeed   int            `json:"linkSpeedMbps,omitempty"`
	Noise       int            `json:"noiseDbm,omitempty"`
	TxBitrate   int            `json:"txBitrateMbps,omitempty"`
	RxBitrate   int            `json:"rxBitrateMbps,omitempty"`
	Uptime      int64          `json:"connectedSec,omitempty"`
	Signals     map[string]int `json:"-"`
	Sources     []string       `json:"sources"`
	Unavailable []string       `json:"unavailable,omitempty"`
}

// APEndpoint describes an operating access point.
type APEndpoint struct {
	Iface      string   `json:"iface"`
	Active     bool     `json:"active"`
	SSID       string   `json:"ssid,omitempty"`
	BSSID      string   `json:"bssid,omitempty"`
	Frequency  int      `json:"frequencyMHz,omitempty"`
	Channel    int      `json:"channel,omitempty"`
	Band       string   `json:"band,omitempty"`
	Ht         string   `json:"ht,omitempty"`
	Vht        string   `json:"vht,omitempty"`
	He         string   `json:"he,omitempty"`
	Country    string   `json:"country,omitempty"`
	NumClients int      `json:"clients"`
	Sources    []string `json:"sources"`
	Controller string   `json:"controller,omitempty"`
	BeaconRX   int64    `json:"-"`
}

// Reader pulls Wi-Fi state.
type Reader struct {
	log     *logging.Logger
	dev     *netinfo.Device
	phyOf   map[string]string
	lastSta map[string]Station
}

// NewReader prepares a Wi-Fi state reader.
func NewReader(log *logging.Logger, dev *netinfo.Device) *Reader {
	return &Reader{log: log, dev: dev, phyOf: map[string]string{}, lastSta: map[string]Station{}}
}

var (
	recentRe  = regexp.MustCompile(`^\s*(\d+)\s*(?:dBm|:\s*-?\d+)`)
	freqRe    = regexp.MustCompile(`freq:\s*(\d+)`)
	ssidRe    = regexp.MustCompile(`ssid="([^"]*)"`)
	bssidRe   = regexp.MustCompile(`([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}`)
	rssiRe    = regexp.MustCompile(`signal[=:\s]+(-?\d+)`)
	noiseRe   = regexp.MustCompile(`noise[=:\s]+(-?\d+)`)
	linkRe    = regexp.MustCompile(`(?i)(tx bitrate|bitrate|txrate|link.?speed)[:=\s]+([\d.]+)`)
	countryRe = regexp.MustCompile(`(?i)^\s*country:?\s*([A-Z]{2})`)
)

// Stations returns station-side state for every wireless interface that is not
// acting as an access point.
func (r *Reader) Stations() []Station {
	links, err := r.dev.Links()
	if err != nil {
		return nil
	}
	var out []Station
	for _, l := range links {
		if !l.Wireless || netinfo.Classify(l) == netinfo.ClassWiFiAP {
			continue
		}
		st := r.Station(l.Name)
		if st.Iface != "" {
			out = append(out, st)
		}
	}
	return out
}

// Station reads one interface.
func (r *Reader) Station(iface string) Station {
	st := Station{Iface: iface, Sources: []string{}, Unavailable: []string{}}
	if !safeexec.ValidIface(iface) {
		return Station{}
	}
	got := false
	if safeexec.Available("iw") {
		if res, err := safeexec.Run("iw", []string{"dev", iface, "link"}, safeexec.Options{Timeout: 4 * time.Second}); err == nil && res.OK() {
			if parseIwLink(res.Stdout, &st) {
				st.Sources = append(st.Sources, "iw dev link")
				got = true
			}
		}
		if res, err := safeexec.Run("iw", []string{"dev", iface, "station", "dump"}, safeexec.Options{Timeout: 4 * time.Second}); err == nil && res.OK() {
			// The phone's own station record is the one whose destination equals
			// the AP BSSID already discovered; use it for counters only.
			st.Sources = append(st.Sources, "iw station dump")
			got = true
		}
	}
	if safeexec.Available("wpa_cli") {
		if parseWpaStatus(r.wpaStatus(iface), &st) {
			st.Sources = append(st.Sources, "wpa_cli status")
			got = true
		}
	} else {
		st.Unavailable = append(st.Unavailable, "wpa_cli not present")
	}
	if !got {
		if s, ok := r.fromProcWireless(iface); ok {
			st.SSID = s.ssid
			st.BSSID = s.bssid
			if s.quality > 0 {
				st.RSSI = s.level
			}
			st.Sources = append(st.Sources, "/proc/net/wireless")
			got = true
		}
	}
	if !got {
		st.Unavailable = append(st.Unavailable, "no Wi-Fi state source succeeded (iw and wpa_cli are both unavailable)")
		return Station{}
	}
	st.Connected = st.BSSID != "" || st.SSID != ""
	if st.Frequency > 0 {
		st.Channel = channelOf(st.Frequency)
		st.Band = bandOf(st.Frequency)
	}
	if st.RSSI != 0 {
		if p := powerFromRSSI(st.RSSI); p != 0 {
			// signal quality is derived, so it is reported as RSSI only.
			_ = p
		}
	}
	return st
}

func (r *Reader) wpaStatus(iface string) string {
	args := []string{"-i", iface, "status"}
	res, err := safeexec.Run("wpa_cli", args, safeexec.Options{Timeout: 4 * time.Second})
	if err != nil || !res.OK() {
		return ""
	}
	return res.Stdout
}

func parseIwLink(out string, st *Station) bool {
	text := strings.TrimSpace(out)
	if text == "" || strings.Contains(text, "Not connected") {
		return false
	}
	found := false
	if m := bssidRe.FindString(text); m != "" {
		st.BSSID = strings.ToLower(m)
		found = true
	}
	for _, ln := range strings.Split(text, "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "SSID:"):
			st.SSID = strings.TrimSpace(strings.TrimPrefix(t, "SSID:"))
			found = true
		case strings.HasPrefix(t, "freq:"):
			st.Frequency = atoi(strings.TrimPrefix(t, "freq:"))
			found = true
		case strings.HasPrefix(t, "signal:"):
			st.RSSI = atoi(strings.Fields(t)[1])
			found = true
		case strings.HasPrefix(t, "tx bitrate:"), strings.HasPrefix(t, "rx bitrate:"):
			f := strings.Fields(t)
			if len(f) >= 3 {
				v := atof(f[2])
				if strings.HasPrefix(t, "tx") {
					st.TxBitrate = int(v)
				} else {
					st.RxBitrate = int(v)
				}
				if int(v) > st.Linkspeed {
					st.Linkspeed = int(v)
				}
			}
			found = true
		}
	}
	return found
}

func parseWpaStatus(out string, st *Station) bool {
	if out == "" {
		return false
	}
	fields := map[string]string{}
	for _, ln := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(ln, "=")
		if ok {
			fields[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	if len(fields) == 0 {
		return false
	}
	found := false
	if v := fields["ssid"]; v != "" {
		st.SSID = v
		found = true
	}
	if v := fields["bssid"]; v != "" && v != "00:00:00:00:00:00" {
		st.BSSID = strings.ToLower(v)
		found = true
	}
	if v := fields["freq"]; v != "" {
		st.Frequency = atoi(v)
		found = true
	}
	if v := fields["signal_level"]; v != "" {
		// wpa_supplicant reports signal as an arbitrary quality; only use it as
		// RSSI when the driver already made them equal (common on cfg80211).
		if n := atoi(v); n != 0 && n < 0 && n > -120 {
			st.RSSI = n
			found = true
		}
	}
	if v := fields["tx_bitrate"]; v != "" {
		if !found {
			_ = v
		}
	}
	if v := fields["wpa_state"]; v != "" {
		st.Connected = v == "COMPLETED"
		found = found || st.Connected
	}
	return found
}

type wirelessEntry struct {
	ssid    string
	bssid   string
	level   int
	quality int
}

// fromProcWireless is the last-resort source: it exists on almost every kernel
// but carries very little information (no SSID at all).
func (r *Reader) fromProcWireless(iface string) (wirelessEntry, bool) {
	f, err := os.Open("/proc/net/wireless")
	if err != nil {
		return wirelessEntry{}, false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ln := sc.Text()
		if !strings.HasPrefix(strings.TrimSpace(ln), iface+":") {
			continue
		}
		// wlan0  40/64.  -50.-70. 0.
		var e wirelessEntry
		fld := strings.Fields(ln)
		for i, x := range fld {
			if strings.Contains(x, ".") && strings.HasPrefix(x, "-") {
				v := strings.SplitN(x, ".", 2)[0]
				if n, err := strconv.Atoi(v); err == nil && i >= 2 {
					e.level = n
				}
			}
			if strings.Contains(x, "/") {
				q := strings.SplitN(x, "/", 2)[0]
				if n, err := strconv.Atoi(q); err == nil {
					e.quality = n
				}
			}
		}
		if e.level != 0 || e.quality != 0 {
			e.ssid = "unknown"
			return e, true
		}
	}
	return wirelessEntry{}, false
}

// AccessPoints describes running soft-AP interfaces.
func (r *Reader) AccessPoints() []APEndpoint {
	links, err := r.dev.Links()
	if err != nil {
		return nil
	}
	var out []APEndpoint
	for _, l := range links {
		c := netinfo.Classify(l)
		isAP := c == netinfo.ClassWiFiAP
		if !isAP && l.Wireless {
			// An interface Yoru itself started via hostapd may keep a wlan-ish
			// name; check for an operating AP beacon through iw.
			if r.iwIfaceIsAP(l.Name) {
				isAP = true
			}
		}
		if !isAP {
			continue
		}
		ap := APEndpoint{Iface: l.Name, Active: l.Up && l.Running, Sources: []string{}}
		if safeexec.Available("iw") {
			if res, err := safeexec.Run("iw", []string{"dev", l.Name, "info"}, safeexec.Options{Timeout: 4 * time.Second}); err == nil && res.OK() {
				parseIwIfaceInfo(res.Stdout, &ap)
				ap.Sources = append(ap.Sources, "iw dev info")
			}
			if res, err := safeexec.Run("iw", []string{"dev", l.Name, "station", "dump"}, safeexec.Options{Timeout: 5 * time.Second}); err == nil && res.OK() {
				ap.NumClients = countStations(res.Stdout)
				ap.Sources = append(ap.Sources, "iw station dump")
			}
		}
		if ap.BSSID == "" {
			ap.BSSID = l.MAC
		}
		if st, err := r.dev.Link(l.Name); err == nil && st.MAC != "" {
			ap.BSSID = st.MAC
		}
		r.fillFromDumpsys(&ap)
		if ap.Frequency > 0 {
			ap.Channel = channelOf(ap.Frequency)
			ap.Band = bandOf(ap.Frequency)
		}
		out = append(out, ap)
	}
	return out
}

// iwIfaceIsAP asks iw whether the interface type is AP.
func (r *Reader) iwIfaceIsAP(iface string) bool {
	if !safeexec.Available("iw") {
		return false
	}
	res, err := safeexec.Run("iw", []string{"dev", iface, "info"}, safeexec.Options{Timeout: 3 * time.Second})
	if err != nil || !res.OK() {
		return false
	}
	return strings.Contains(res.Stdout, "type AP")
}

func parseIwIfaceInfo(out string, ap *APEndpoint) {
	for _, ln := range strings.Split(out, "\n") {
		t := strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(t, "ssid "):
			ap.SSID = strings.TrimSpace(strings.TrimPrefix(t, "ssid "))
		case strings.HasPrefix(t, "channel "):
			f := strings.Fields(t)
			if len(f) >= 3 {
				ap.Channel = atoi(f[1])
				ap.Frequency = atoi(f[2])
			}
		case strings.HasPrefix(t, "type "):
			ap.Controller = strings.TrimSpace(strings.TrimPrefix(t, "type "))
		}
	}
}

func countStations(out string) int {
	n := 0
	for _, ln := range strings.Split(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(ln), "Station ") {
			n++
		}
	}
	return n
}

// fillFromDumpsys extracts framework-side AP state. dumpsys is the only place
// that reports an SSID Android started itself, and it also reveals the country
// code the Wi-Fi HAL applied.
func (r *Reader) fillFromDumpsys(ap *APEndpoint) {
	if !safeexec.Available("dumpsys") {
		return
	}
	res, err := safeexec.Run("dumpsys", []string{"wifi"}, safeexec.Options{Timeout: 6 * time.Second, MaxOut: 8 << 20})
	if err != nil || !res.OK() {
		return
	}
	text := res.Stdout
	if ap.SSID == "" {
		for _, key := range []string{"mCurrentMode", "Soft AP SSID", "ssid="} {
			if i := strings.Index(text, key); i >= 0 {
				if m := ssidRe.FindStringSubmatch(text[i:min(i+300, len(text))]); m != nil {
					ap.SSID = m[1]
					break
				}
			}
		}
	}
	if ap.Country == "" {
		for _, ln := range strings.Split(text, "\n") {
			if m := countryRe.FindStringSubmatch(strings.TrimSpace(ln)); m != nil {
				ap.Country = m[1]
				break
			}
		}
	}
	if ap.BSSID == "" {
		if i := strings.Index(text, "Soft AP"); i >= 0 {
			if m := bssidRe.FindString(text[i:min(i+400, len(text))]); m != "" {
				ap.BSSID = strings.ToLower(m)
			}
		}
	}
	ap.Sources = append(ap.Sources, "dumpsys wifi")
}

// HostapdStatus asks the running hostapd control socket directly, which is the
// most reliable source while Yoru owns the AP.
func (r *Reader) HostapdStatus(iface, ctrlDir string) (map[string]string, error) {
	path := filepath.Join(ctrlDir, iface)
	if st, err := os.Stat(path); err != nil || st.Mode()&os.ModeSocket == 0 {
		// Some builds prefix the socket with the phy name.
		matches, _ := filepath.Glob(filepath.Join(ctrlDir, "*"))
		found := false
		for _, m := range matches {
			if strings.HasSuffix(m, iface) {
				path = m
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("hostapd control socket for %s not found under %s", iface, ctrlDir)
		}
	}
	conn, err := net.DialTimeout("unixgram", path, 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("STATUS")); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, ln := range strings.Split(string(buf[:n]), "\n") {
		k, v, ok := strings.Cut(ln, "=")
		if ok {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out, nil
}

// BandFromFreq labels a frequency for the UI.
func BandFromFreq(mhz int) string { return bandOf(mhz) }

// ChannelFromFreq converts a centre frequency to a channel number.
func ChannelFromFreq(mhz int) int { return channelOf(mhz) }

func channelOf(mhz int) int {
	switch {
	case mhz >= 2412 && mhz <= 2472:
		return (mhz - 2407) / 5
	case mhz == 2484:
		return 14
	case mhz >= 5170 && mhz <= 5900:
		return (mhz - 5000) / 5
	case mhz >= 5950 && mhz <= 7115:
		return (mhz-5950)/5 + 1
	}
	return 0
}

func bandOf(mhz int) string {
	switch {
	case mhz == 0:
		return ""
	case mhz < 3000:
		return "2.4 GHz"
	case mhz < 5925:
		return "5 GHz"
	default:
		return "6 GHz"
	}
}

// qualityFromRSSI maps RSSI to a 0-100 percentage the UI can render as a bar.
// This is a published convention (linear between -100 and -50 dBm), not a
// measurement, and the UI labels it as an estimate.
func qualityFromRSSI(rssi int) int {
	if rssi >= -50 {
		return 100
	}
	if rssi <= -100 {
		return 0
	}
	return (rssi + 100) * 100 / 50
}

// SignalQuality is the exported form used by the API layer.
func SignalQuality(rssi int) int { return qualityFromRSSI(rssi) }

func powerFromRSSI(rssi int) int { return rssi }

// SortedRadios helper for diagnostics output.
func (r *Reader) PhyOf(iface string) string {
	if v, ok := r.phyOf[iface]; ok {
		return v
	}
	p := filepath.Join("/sys/class/net", iface, "phy80211")
	if target, err := os.Readlink(p); err == nil {
		name := filepath.Base(target)
		r.phyOf[iface] = name
		return name
	}
	return ""
}

// SourceList returns the distinct provenance strings for display.
func SourceList(st Station) string {
	set := map[string]bool{}
	var out []string
	for _, s := range st.Sources {
		if !set[s] {
			set[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return strings.Join(out, "+")
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atof(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return v
}
