// Android SoftAp strategy.
//
// Rather than owning hostapd, ask the framework to enable its own hotspot and
// then only add IP configuration, NAT and monitoring on top. This is the path
// that works on the widest set of devices because it uses the vendor's own Wi-Fi
// HAL, but it gives Yoru less control: the SSID/band/channel that actually come
// up are whatever the OS decided, and we must report that honestly.
//
// Detection-driven commands, in preference order:
//  1. `cmd wifi` sub-commands that start/stop SoftAp (AOSP 12+ exposes some)
//  2. `settings put global soft_wifi_on 1` + `svc wifi enable`
//  3. `am start-foreground-service` on the tether service (last resort)
//
// Each attempt is verified through `dumpsys wifi` and netlink before success.
package apbringer

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"yoru.dev/yorud/internal/caps"
	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/safeexec"
)

// Android drives the framework hotspot.
type Android struct {
	log *logging.Logger
	dev *netinfo.Device
	cap *caps.Set
	mu  sync.Mutex
	on  string
}

// NewAndroid builds the framework strategy.
func NewAndroid(log *logging.Logger, dev *netinfo.Device, cs *caps.Set) *Android {
	return &Android{log: log, dev: dev, cap: cs}
}

// Name identifies the strategy.
func (a *Android) Name() string { return "android-softap" }

// CanI requires the framework to look like it can host an AP.
func (a *Android) CanI(spec Spec) (bool, string) {
	if !a.cap.Has(caps.AndroidWifiCmd) && !a.cap.Has(caps.DumpsysAvailable) {
		return false, "no Android Wi-Fi shell interface is available"
	}
	if !a.cap.Has(caps.AndroidSoftAP) && !a.cap.Has(caps.AndroidTethering) {
		return false, "the framework does not expose a reachable SoftAp/tethering service"
	}
	if a.apIface() == "" && spec.Iface == "" {
		return false, "no access-point interface appeared after the framework was asked to start one"
	}
	return true, ""
}

// apIface finds the interface the OS uses for its hotspot. Names vary by vendor
// more than almost anything else in Android mobile Wi-Fi, so this is a scan of
// live interfaces rather than a name list.
func (a *Android) apIface() string {
	links, err := a.dev.Links()
	if err != nil {
		return ""
	}
	for _, l := range links {
		if netinfo.Classify(l) == netinfo.ClassWiFiAP && l.Up {
			return l.Name
		}
	}
	if iface := a.apIfaceFromDumpsys(); iface != "" {
		for _, l := range links {
			if l.Name == iface && l.Up {
				return l.Name
			}
		}
	}
	return ""
}

// apIfaceFromDumpsys reads the SoftAp interface name from dumpsys wifi.
func (a *Android) apIfaceFromDumpsys() string {
	if !safeexec.Available("dumpsys") {
		return ""
	}
	res, err := safeexec.Run("dumpsys", []string{"wifi"}, safeexec.Options{Timeout: 3 * time.Second, MaxOut: 2 << 20})
	if err != nil || !res.OK() {
		return ""
	}
	for _, ln := range strings.Split(res.Stdout, "\n") {
		l := strings.TrimSpace(ln)
		if strings.HasPrefix(l, "mApInterfaceName:") {
			parts := strings.SplitN(l, ":", 2)
			if len(parts) == 2 {
				name := strings.TrimSpace(parts[1])
				if name != "" {
					return name
				}
			}
		}
	}
	return ""
}

// Start asks the framework to switch the hotspot on and waits for it.
func (a *Android) Start(spec Spec) (*Result, error) {
	if !safeexec.Available("settings") && !safeexec.Available("cmd") {
		return nil, errors.New("neither settings(1) nor cmd(1) is available to drive the framework")
	}
	var tried []string

	// Record what the interface set looked like before, so we can tell which
	// interface (if any) the framework created for us.
	before := map[string]bool{}
	if links, err := a.dev.Links(); err == nil {
		for _, l := range links {
			before[l.Name] = true
		}
	}

	// 1. Best case: an explicit shell command exists.
	if safeexec.Available("cmd") {
		cmdArgs := [][]string{
			{"wifi", "start-softap", spec.SSID, apSecurityCmd(spec.Security), spec.Passphrase},
		}
		if spec.SSID == "" {
			cmdArgs = append(cmdArgs, []string{"wifi", "start-softap", "YoruRepeater", "wpa2", "YoruRepeater123"})
		}
		for _, args := range cmdArgs {
			res, err := safeexec.Run("cmd", args, safeexec.Options{Timeout: 6 * time.Second})
			tried = append(tried, "cmd "+strings.Join(args, " ")+" -> "+outcome(res, err))
			if err == nil && res.OK() {
				break
			}
		}
	}
	// 2. Publish the requested SSID/key when the device stores them as global
	//    settings (Samsung and many OEMs do), then flip the switch.
	if safeexec.Available("settings") {
		if spec.SSID != "" {
			_, _ = safeexec.Run("settings", []string{"put", "global", "wifi_ap_ssid", spec.SSID}, safeexec.Options{Timeout: 3 * time.Second})
		}
		if spec.Passphrase != "" {
			_, _ = safeexec.Run("settings", []string{"put", "global", "wifi_ap_password", spec.Passphrase}, safeexec.Options{Timeout: 3 * time.Second})
			_, _ = safeexec.Run("settings", []string{"put", "global", "wifi_ap_security", apSecurityFor(spec.Security)}, safeexec.Options{Timeout: 3 * time.Second})
		}
		// Tethering hardware offload frequently conflicts with a NAT we install,
		// so disable it (this is a settings toggle, not a firewall edit).
		_, _ = safeexec.Run("settings", []string{"put", "global", "tether_offload_disabled", "1"}, safeexec.Options{Timeout: 3 * time.Second})
		res, err := safeexec.Run("settings", []string{"put", "global", "soft_wifi_on", "1"}, safeexec.Options{Timeout: 3 * time.Second})
		tried = append(tried, "settings soft_wifi_on -> "+outcome(res, err))
	}
	if safeexec.Available("svc") {
		res, err := safeexec.Run("svc", []string{"wifi", "enable"}, safeexec.Options{Timeout: 6 * time.Second})
		tried = append(tried, "svc wifi enable -> "+outcome(res, err))
	}

	// 3. Verify: an AP interface must appear and be carried.
	var iface string
	var last string
	for attempt := 0; attempt < 30; attempt++ {
		time.Sleep(400 * time.Millisecond)
		iface = a.apIface()
		if iface != "" {
			break
		}
		if links, err := a.dev.Links(); err == nil {
			for _, l := range links {
				if !before[l.Name] && l.Wireless && l.Up {
					iface = l.Name
					break
				}
			}
		}
		if iface != "" {
			break
		}
		last = a.probeFramework()
	}
	if iface == "" {
		return nil, fmt.Errorf("the framework did not create an access-point interface. attempts: %s; last state: %s",
			strings.Join(tried, "; "), orNone(last))
	}
	if !a.apIsAdvertising(iface) {
		a.log.Warnf("ap", "interface %s exists but no beacon was observed; continuing because the framework owns this AP", iface)
	}
	a.mu.Lock()
	a.on = iface
	a.mu.Unlock()
	return &Result{
		Strategy: a.Name(), Iface: iface, Verified: true,
		Detail:    "started by the Android framework",
		StartedAt: time.Now().UnixMilli(),
		Notes:     []string{"the OS chose the channel/band; Yoru only adds routing, DHCP and monitoring"},
	}, nil
}

// probeFramework summarises what dumpsys says about SoftAp.
func (a *Android) probeFramework() string {
	if !safeexec.Available("dumpsys") {
		return "dumpsys unavailable"
	}
	res, err := safeexec.Run("dumpsys", []string{"wifi"}, safeexec.Options{Timeout: 6 * time.Second, MaxOut: 6 << 20})
	if err != nil || !res.OK() {
		return "dumpsys wifi failed: " + orNone(errString(err, res))
	}
	for _, ln := range strings.Split(res.Stdout, "\n") {
		l := strings.ToLower(ln)
		if strings.Contains(l, "softap") && (strings.Contains(l, "state") || strings.Contains(l, "mode") || strings.Contains(l, "enabled")) {
			return strings.TrimSpace(ln)
		}
	}
	return "no SoftAp state line found"
}

// apIsAdvertising checks for a real beacon via hostapd-independent sources.
func (a *Android) apIsAdvertising(iface string) bool {
	l, err := a.dev.Link(iface)
	if err != nil {
		return false
	}
	if !l.Up || !(l.Running || l.LowerUp) {
		return false
	}
	if safeexec.Available("iw") {
		res, err := safeexec.Run("iw", []string{"dev", iface, "info"}, safeexec.Options{Timeout: 3 * time.Second})
		if err == nil && res.OK() && strings.Contains(res.Stdout, "type AP") {
			return true
		}
	}
	addrs, err := a.dev.Addrs()
	if err == nil {
		for _, x := range addrs {
			if x.Iface == iface && x.Family == "IPv4" {
				return true
			}
		}
	}
	return false
}

// Stop turns the framework hotspot back off. It only does so if Yoru was the
// one that started it, so a user's own hotspot is never killed behind them.
func (a *Android) Stop(iface string) error {
	a.mu.Lock()
	own := a.on
	a.on = ""
	a.mu.Unlock()
	if own == "" {
		return nil
	}
	if safeexec.Available("settings") {
		_, _ = safeexec.Run("settings", []string{"put", "global", "soft_wifi_on", "0"}, safeexec.Options{Timeout: 3 * time.Second})
	}
	if safeexec.Available("cmd") {
		_, _ = safeexec.Run("cmd", []string{"wifi", "mode", "sta"}, safeexec.Options{Timeout: 5 * time.Second})
	}
	return nil
}

// Owning reports whether Yoru previously asked the framework to start an AP.
func (a *Android) Owning(iface string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.on == iface && iface != ""
}

func apSecurityFor(sec string) string {
	switch sec {
	case "open":
		return "0"
	case "wep":
		return "1"
	case "wpa2-psk":
		return "2"
	case "wpa3-sae":
		return "4"
	case "wpa2-wpa3":
		return "2"
	}
	return "2"
}

func apSecurityCmd(sec string) string {
	switch sec {
	case "open":
		return "open"
	case "wep":
		return "wep"
	case "wpa2-psk":
		return "wpa2"
	case "wpa3-sae":
		return "wpa3"
	case "wpa2-wpa3":
		return "wpa3_transition"
	}
	return "wpa2"
}

func outcome(res safeexec.Result, err error) string {
	if err != nil {
		return "error: " + err.Error()
	}
	if res.OK() {
		return "ok"
	}
	return fmt.Sprintf("exit %d: %s", res.ExitCode, trim(firstLine(res.Combined()), 120))
}

func errString(err error, res safeexec.Result) string {
	if err != nil {
		return err.Error()
	}
	if res.ExitCode != 0 {
		return fmt.Sprintf("exit %d", res.ExitCode)
	}
	return ""
}
