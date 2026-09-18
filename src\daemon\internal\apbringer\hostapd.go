// Package apbringer starts and stops a Wi-Fi access point.
//
// This is the part of Yoru that cannot be written generically: whether a phone
// can host an AP at all depends on the driver, the vendor HAL and what already
// owns the interface. The package is therefore built as ordered strategies,
// each of which must pass its own pre-flight check before it is attempted, and
// each of which reports precisely why it failed.
//
// Strategies, in preference order:
//
//	hostapd-direct   Take an idle radio interface and run hostapd against it.
//	                 The only way to get a true, user-configured AP. Needs the
//	                 interface to be free (Android's Wi-Fi must not own it).
//	hostapd-bundled  Same, using a hostapd binary supplied with the module.
//	android-softap   Ask the Android framework to turn its own hotspot on and
//	                 then only add routing/NAT on top. Never touches hostapd.
//	                 This is how the phone already shares its connection.
//
// Nothing here pretends success: after starting a backend the caller must see
// an operational interface with a beacon, verified through hostapd's control
// socket, `iw` or dumpsys, or the attempt is rolled back.
package apbringer

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"yoru.dev/yorud/internal/caps"
	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/safeexec"
	"yoru.dev/yorud/internal/wifistate"
)

// Spec is a validated request to bring up an AP.
type Spec struct {
	Iface       string
	SSID        string
	Passphrase  string
	Security    string
	Band        string
	Channel     int
	Frequency   int
	Hidden      bool
	MaxClients  int
	CountryCode string
	HT40        bool
	VHT         bool
	HE          bool
	ControlDir  string
	Driver      string
	Isolate     bool
}

// Result is what a successful strategy returns.
type Result struct {
	Strategy  string   `json:"strategy"`
	Iface     string   `json:"iface"`
	Verified  bool     `json:"verified"`
	Detail    string   `json:"detail"`
	PID       int      `json:"pid,omitempty"`
	StartedAt int64    `json:"startedAtMs"`
	Notes     []string `json:"notes,omitempty"`
}

// Strategy is one implementation of AP bring-up.
type Strategy interface {
	Name() string
	// CanI says whether this strategy could work here, without changing state.
	CanI(spec Spec) (bool, string)
	Start(spec Spec) (*Result, error)
	Stop(iface string) error
	// Owning returns true if a previous Yoru run left this backend behind.
	Owning(iface string) bool
}

// Controller manages strategy selection and lifecycle.
type Controller struct {
	mu       sync.Mutex
	log      *logging.Logger
	dev      *netinfo.Device
	cap      *caps.Set
	wifi     *wifistate.Reader
	order    []Strategy
	current  *Result
	stateDir string
}

// NewController wires the strategies in preference order.
func NewController(log *logging.Logger, dev *netinfo.Device, cs *caps.Set, wifi *wifistate.Reader, stateDir string) *Controller {
	c := &Controller{log: log, dev: dev, cap: cs, wifi: wifi, stateDir: stateDir}
	c.order = []Strategy{
		NewHostapd(log, dev, cs, stateDir, false),
		NewHostapd(log, dev, cs, stateDir, true),
		NewAndroid(log, dev, cs),
	}
	return c
}

// Strategies reports each strategy's verdict so the UI can explain a failure
// instead of showing a generic error.
func (c *Controller) Strategies(spec Spec) []map[string]any {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []map[string]any
	for _, s := range c.order {
		ok, why := s.CanI(spec)
		out = append(out, map[string]any{"name": s.Name(), "available": ok, "reason": why})
	}
	return out
}

// Start picks the first strategy that both can work and actually works.
func (c *Controller) Start(spec Spec) (*Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current != nil {
		return c.current, nil
	}
	var failures []string
	for _, s := range c.order {
		ok, why := s.CanI(spec)
		if !ok {
			failures = append(failures, fmt.Sprintf("%s: %s", s.Name(), why))
			c.log.Infof("ap", "strategy %s not applicable: %s", s.Name(), why)
			continue
		}
		c.log.Infof("ap", "trying AP strategy %s on %s", s.Name(), spec.Iface)
		res, err := s.Start(spec)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", s.Name(), err))
			c.log.Warnf("ap", "strategy %s failed: %v", s.Name(), err)
			continue
		}
		c.current = res
		c.log.Infof("ap", "access point up via %s on %s (verified=%v)", res.Strategy, res.Iface, res.Verified)
		return res, nil
	}
	return nil, fmt.Errorf("no access-point strategy could bring up %s: %s", spec.Iface, strings.Join(failures, "; "))
}

// Stop terminates the active backend.
func (c *Controller) Stop(iface string) error {
	c.mu.Lock()
	cur := c.current
	c.current = nil
	c.mu.Unlock()
	if cur != nil {
		for _, s := range c.order {
			if s.Name() == cur.Strategy {
				return s.Stop(iface)
			}
		}
	}
	for _, s := range c.order {
		if s.Owning(iface) {
			return s.Stop(iface)
		}
	}
	return nil
}

// Current exposes the active backend for status reporting.
func (c *Controller) Current() *Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.current == nil {
		return nil
	}
	cp := *c.current
	return &cp
}

// ---------------------------------------------------------------------------
// hostapd strategy
// ---------------------------------------------------------------------------

// Hostapd runs a hostapd binary against a free radio interface.
type Hostapd struct {
	log      *logging.Logger
	dev      *netinfo.Device
	cap      *caps.Set
	stateDir string
	bundled  bool
	mu       sync.Mutex
	procs    map[string]*os.Process
	pidFiles map[string]string
}

// NewHostapd builds the strategy. bundled selects the module-provided binary.
func NewHostapd(log *logging.Logger, dev *netinfo.Device, cs *caps.Set, stateDir string, bundled bool) *Hostapd {
	return &Hostapd{
		log: log, dev: dev, cap: cs, stateDir: stateDir, bundled: bundled,
		procs: map[string]*os.Process{}, pidFiles: map[string]string{},
	}
}

// Name identifies the strategy.
func (h *Hostapd) Name() string {
	if h.bundled {
		return "hostapd-bundled"
	}
	return "hostapd-direct"
}

func (h *Hostapd) binary() (string, bool) {
	if h.bundled {
		for _, p := range []string{
			filepath.Join(h.stateDir, "bin", "hostapd"),
			"/data/adb/yoru-repeater/bin/hostapd",
			"/data/adb/modules/yoru-repeater/yoru/bin/hostapd",
		} {
			if st, err := os.Stat(p); err == nil && st.Mode().Perm()&0111 != 0 {
				return p, true
			}
		}
		return "", false
	}
	if p, ok := safeexec.Resolve("hostapd"); ok {
		return p, true
	}
	return "", false
}

// CanI checks binary presence, driver support and interface freedom.
func (h *Hostapd) CanI(spec Spec) (bool, string) {
	bin, ok := h.binary()
	if !ok {
		if h.bundled {
			return false, "no bundled hostapd was installed (optional; add one with build.sh --with-hostapd)"
		}
		return false, "no hostapd binary exists on this device"
	}
	if !h.cap.Has(caps.WiFiAP) {
		return false, "the Wi-Fi driver does not advertise AP mode"
	}
	if spec.Iface == "" {
		return false, "no candidate AP interface was identified"
	}
	if l, err := h.dev.Link(spec.Iface); err == nil && l.Up && l.Running {
		if werr := h.interfaceBusy(spec.Iface); werr != nil {
			return false, werr.Error()
		}
	}
	_ = bin
	return true, ""
}

// interfaceBusy reports whether something else owns the interface.
func (h *Hostapd) interfaceBusy(iface string) error {
	// An interface carrying a non-Yoru IPv4 address is in use by the framework.
	addrs, err := h.dev.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if a.Iface == iface && a.Family == "IPv4" && !a.Deprecated {
			return fmt.Errorf("%s already has address %s assigned by another service", iface, a.CIDR)
		}
	}
	if h.procs[iface] != nil {
		return fmt.Errorf("yoru already runs hostapd on %s", iface)
	}
	return nil
}

// hostapdConfPath is where a generated config is written (0600: it holds the PSK).
func (h *Hostapd) confPath(iface string) string {
	return filepath.Join(h.stateDir, "run", "hostapd-"+iface+".conf")
}

// BuildConfig renders a hostapd configuration. It is exported for the
// diagnostics page, which shows the config with the passphrase masked.
func BuildConfig(spec Spec) (string, error) {
	if !safeexec.ValidIface(spec.Iface) {
		return "", errors.New("invalid interface name")
	}
	var b strings.Builder
	b.WriteString("# Generated by Yoru Repeater. Do not edit: it is rewritten on\n")
	b.WriteString("# every start and contains the network key in cleartext (mode 0600).\n")
	b.WriteString("interface=" + spec.Iface + "\n")
	driver := spec.Driver
	if driver == "" {
		driver = "nl80211"
	}
	b.WriteString("driver=" + driver + "\n")
	b.WriteString("ctrl_interface=" + spec.ControlDir + "\n")
	b.WriteString("ctrl_interface_group=0\n")
	b.WriteString("logger_syslog=-1\nlogger_stdout=-1\nlogger_syslog_level=1\nlogger_stdout_level=1\n")
	b.WriteString("debug=0\n")
	b.WriteString("ieee80211_n_bi_beacons=0\n")
	ssid := spec.SSID
	if ssid == "" {
		ssid = "YoruRepeater"
	}
	b.WriteString("ssid=" + sanitizeSSID(ssid) + "\n")
	if spec.Hidden {
		b.WriteString("ignore_broadcast_ssid=1\n")
	} else {
		b.WriteString("ignore_broadcast_ssid=0\n")
	}
	if spec.CountryCode != "" {
		b.WriteString("country_code=" + spec.CountryCode + "\n")
		b.WriteString("country3=0x20\n")
	}
	// Band / channel
	freq := spec.Frequency
	if freq == 0 && spec.Channel > 0 {
		freq = caps.ChannelFrequency(spec.Channel, spec.Band)
	}
	switch {
	case strings.HasPrefix(bandOf(freq), "2.4"):
		b.WriteString("hw_mode=g\n")
	case strings.HasPrefix(bandOf(freq), "5"):
		b.WriteString("hw_mode=a\n")
	case strings.HasPrefix(bandOf(freq), "6"):
		b.WriteString("hw_mode=a\n")
		b.WriteString("he_oper_chwidth=0\nieee80211ax=1\n")
	default:
		b.WriteString("channel=0\nhw_mode=g\n")
	}
	if spec.Channel > 0 {
		b.WriteString("channel=" + itoa(spec.Channel) + "\n")
	}
	if freq > 0 {
		b.WriteString("frequency_list=" + itoa(freq) + "\n")
	}
	// Security. The mapping follows hostapd's own scheme:
	//   wpa=2 -> WPA, wpa=2|8 (10) -> WPA2, sae alone -> WPA3.
	switch spec.Security {
	case "open":
		b.WriteString("wpa=0\nauth_algs=3\n")
	case "wep":
		b.WriteString("wep_key0=" + spec.Passphrase + "\nwep_default_key=0\nauth_algs=2\nwpa=0\n")
	case "wpa2-psk":
		b.WriteString("wpa=2\nwpa_pairwise=CCMP\nauth_algs=1\nwpa_psk=" + hexPSK(spec) + "\nrsn_pairwise=CCMP\n")
	case "wpa3-sae":
		b.WriteString("wpa=2\nwpa_key_mgmt=SAE\nwpa_pairwise=CCMP\nrsn_pairwise=CCMP\nauth_algs=1\nsae_password=" + quote(spec.Passphrase) + "\nsae_pwe=2\n")
	case "wpa2-wpa3":
		b.WriteString("wpa=2\nwpa_key_mgmt=WPA-PSK SAE\nwpa_pairwise=CCMP\nrsn_pairwise=CCMP\nauth_algs=1\nwpa_psk=" + hexPSK(spec) + "\nsae_password=" + quote(spec.Passphrase) + "\nsae_pwe=2\n")
	default:
		return "", fmt.Errorf("unsupported security mode %q", spec.Security)
	}
	// 802.11n/ac/ax
	if spec.HT40 {
		b.WriteString("ieee80211n=1\n")
		switch {
		case spec.Band == "2g":
			b.WriteString("ht_capab=[HT40+]\n")
		default:
			b.WriteString("ht_capab=[HT40+][SHORT-GI-20][SHORT-GI-40][RX-STBC1]\n")
		}
	} else {
		b.WriteString("ieee80211n=0\n")
	}
	if spec.VHT {
		b.WriteString("ieee80211ac=1\nvht_oper_chwidth=0\nvht_capab=[MAX-MPDU-11454][RXLDPC][SHORT-GI-80]\n")
	}
	if spec.HE {
		b.WriteString("ieee80211ax=1\nhe_oper_chwidth=0\nhe_bss_color=1\nhe_su_beamformer=0\nhe_mu_beamformer=0\n")
	}
	if spec.MaxClients > 0 {
		b.WriteString("max_num_sta=" + itoa(spec.MaxClients) + "\n")
	}
	if spec.Isolate {
		b.WriteString("ap_isolate=1\n")
	}
	b.WriteString("dtim_period=1\n")
	b.WriteString("beacon_int=100\n")
	b.WriteString("rts_threshold=-1\nfragmentation_threshold=-1\n")
	b.WriteString("short_retries=7\nlong_retries=4\n")
	b.WriteString("wmm_enabled=1\n")
	b.WriteString("macaddr_acl=0\n")
	b.WriteString("eapol_version=2\n")
	b.WriteString("pmk=1\n")
	return b.String(), nil
}

// Start writes the config and launches hostapd, then waits for a beacon.
func (h *Hostapd) Start(spec Spec) (*Result, error) {
	bin, ok := h.binary()
	if !ok {
		return nil, errors.New("hostapd binary disappeared between check and start")
	}
	if spec.ControlDir == "" {
		spec.ControlDir = filepath.Join(h.stateDir, "run", "hostapd-ctrl")
	}
	if err := os.MkdirAll(spec.ControlDir, 0700); err != nil {
		return nil, fmt.Errorf("cannot create hostapd control directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(h.confPath(spec.Iface)), 0700); err != nil {
		return nil, err
	}
	conf, err := BuildConfig(spec)
	if err != nil {
		return nil, err
	}
	path := h.confPath(spec.Iface)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot write hostapd config: %w", err)
	}
	if _, err := f.WriteString(conf); err != nil {
		_ = f.Close()
		return nil, err
	}
	_ = f.Close()

	// Validate before launching so a bad config produces a clear message.
	if vres, verr := safeexec.Run("hostapd", []string{"-s", "-i", spec.Iface, path}, safeexec.Options{Timeout: 4 * time.Second}); verr == nil && vres.ExitCode != 0 {
		msg := summariseHostapdOutput(vres.Combined())
		if strings.Contains(strings.ToLower(msg), "unknown") || strings.Contains(strings.ToLower(msg), "invalid") {
			_ = os.Remove(path)
			return nil, fmt.Errorf("hostapd rejected the configuration: %s", msg)
		}
	}

	// The interface must be down before hostapd claims it.
	if err := h.dev.LinkDown(spec.Iface); err != nil {
		h.log.Debugf("ap", "could not bring %s down first: %v", spec.Iface, err)
	}
	args := []string{"-s", "-B", "-P", filepath.Join(h.stateDir, "run", "hostapd-"+spec.Iface+".pid"), path}
	hh, err := h.startDetached(bin, args)
	if err != nil {
		_ = os.Remove(path)
		return nil, fmt.Errorf("hostapd failed to start: %w", err)
	}
	pid := hh.Pid()

	verified := false
	var detail string
	for attempt := 0; attempt < 24; attempt++ {
		time.Sleep(250 * time.Millisecond)
		st, err := h.status(spec.ControlDir, spec.Iface)
		if err == nil {
			if st["state"] == "COMPLETED" || st["state"] == "ENABLED" {
				verified = true
				detail = "hostapd reports state=" + st["state"]
				break
			}
			detail = "hostapd state=" + st["state"]
		}
		if hh.Pid() > 0 && !processAlive(hh.Pid()) {
			detail = "hostapd exited before the AP came up"
			break
		}
	}
	if !verified {
		_ = h.Stop(spec.Iface)
		_ = os.Remove(path)
		return nil, fmt.Errorf("hostapd started but the access point never became ready (%s)", detail)
	}
	res := &Result{
		Strategy: h.Name(), Iface: spec.Iface, Verified: true,
		Detail: detail, StartedAt: time.Now().UnixMilli(), PID: pid,
	}
	if pid > 0 {
		if p, perr := os.FindProcess(pid); perr == nil {
			h.mu.Lock()
			h.procs[spec.Iface] = p
			h.pidFiles[spec.Iface] = filepath.Join(h.stateDir, "run", "hostapd-"+spec.Iface+".pid")
			h.mu.Unlock()
		}
	} else {
		// hostapd wrote a pid file rather than staying our child.
		if fp := h.pidOf(spec.Iface); fp > 0 {
			res.PID = fp
			if p, perr := os.FindProcess(fp); perr == nil {
				h.mu.Lock()
				h.procs[spec.Iface] = p
				h.mu.Unlock()
			}
		}
	}
	return res, nil
}

// startDetached launches hostapd in the foreground form so a crash is
// observable; the returned handle gives the pid for liveness checks.
func (h *Hostapd) startDetached(bin string, args []string) (*hostapdHandle, error) {
	fg := make([]string, 0, len(args))
	for _, a := range args {
		if a != "-B" {
			fg = append(fg, a)
		}
	}
	var cmd *exec.Cmd
	var err error
	if h.bundled {
		// A module-supplied binary is executed by absolute path. It is still
		// argument-validated: the only caller-provided values here are the
		// interface name and the config path Yoru itself generated.
		cmd = exec.Command(bin, fg...)
		cmd.Env = append(os.Environ(), "PATH=/system/bin:/vendor/bin:/sbin:/system/bin/xbin")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		cmd.Stdout, cmd.Stderr = nil, nil
		err = cmd.Start()
	} else {
		cmd, err = safeexec.Start("hostapd", fg)
	}
	if err != nil {
		return nil, err
	}
	return &hostapdHandle{cmd: cmd}, nil
}

type hostapdHandle struct{ cmd *exec.Cmd }

func (hh *hostapdHandle) Pid() int {
	if hh == nil || hh.cmd == nil || hh.cmd.Process == nil {
		return 0
	}
	return hh.cmd.Process.Pid
}

func (h *Hostapd) pidOf(iface string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p, ok := h.procs[iface]; ok && p != nil {
		return p.Pid
	}
	b, err := os.ReadFile(filepath.Join(h.stateDir, "run", "hostapd-"+iface+".pid"))
	if err != nil {
		return 0
	}
	n := 0
	for _, c := range strings.TrimSpace(string(b)) {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// status reads hostapd's control socket. Implemented with a datagram socket so
// hostapd_cli is not required on the device.
func (h *Hostapd) status(ctrlDir, iface string) (map[string]string, error) {
	return wifistate.NewReader(h.log, h.dev).HostapdStatus(iface, ctrlDir)
}

// Stop terminates hostapd for one interface.
func (h *Hostapd) Stop(iface string) error {
	if !safeexec.ValidIface(iface) {
		return errors.New("invalid interface")
	}
	pid := h.pidOf(iface)
	h.mu.Lock()
	delete(h.procs, iface)
	pidFile := h.pidFiles[iface]
	delete(h.pidFiles, iface)
	h.mu.Unlock()
	if pid > 0 {
		proc, err := os.FindProcess(pid)
		if err == nil {
			_ = proc.Signal(os.Interrupt)
			for i := 0; i < 20; i++ {
				if !processAlive(pid) {
					break
				}
				time.Sleep(100 * time.Millisecond)
			}
			if processAlive(pid) {
				_ = proc.Kill()
			}
		}
	}
	// Remove our own socket/config/pid artefacts only.
	for _, p := range []string{h.confPath(iface), filepath.Join(h.stateDir, "run", "hostapd-"+iface+".pid")} {
		_ = os.Remove(p)
	}
	if pidFile != "" && pidFile != filepath.Join(h.stateDir, "run", "hostapd-"+iface+".pid") {
		_ = os.Remove(pidFile)
	}
	ctrlSock := filepath.Join(h.stateDir, "run", "hostapd-ctrl", iface)
	if st, err := os.Stat(ctrlSock); err == nil && st.Mode()&os.ModeSocket != 0 {
		_ = os.Remove(ctrlSock)
	}
	return nil
}

// Owning detects a hostapd left behind by a crashed previous run.
func (h *Hostapd) Owning(iface string) bool { return h.pidOf(iface) > 0 }

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err != nil {
		return false
	}
	return true
}

// summariseHostapdOutput trims the very chatty hostapd stderr down to the lines
// that explain a failure.
func summariseHostapdOutput(s string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	keep := []string{}
	for _, ln := range lines {
		l := strings.ToLower(ln)
		if strings.Contains(l, "error") || strings.Contains(l, "failed") || strings.Contains(l, "unknown") ||
			strings.Contains(l, "invalid") || strings.Contains(l, "denied") || strings.Contains(l, "busy") ||
			strings.Contains(l, "not supported") || strings.Contains(l, "cannot") {
			keep = append(keep, strings.TrimSpace(ln))
		}
	}
	if len(keep) == 0 {
		if len(lines) > 0 {
			return strings.TrimSpace(lines[len(lines)-1])
		}
		return "no output"
	}
	sort.Strings(keep)
	return strings.Join(keep, " | ")
}

func sanitizeSSID(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func quote(s string) string { return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"` }

// hexPSK emits either a 64-hex PSK (pre-derived) or the passphrase. hostapd
// accepts a passphrase only when it is 8..63 printable characters, which the
// configuration validator already enforced.
func hexPSK(spec Spec) string {
	if len(spec.Passphrase) == 64 && isHex(spec.Passphrase) {
		return spec.Passphrase
	}
	return spec.Passphrase
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return len(s) == 64
}

func bandOf(mhz int) string { return wifistate.BandFromFreq(mhz) }

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
