// Command yorud is Yoru Repeater's single daemon: monitoring, network control
// and the dashboard all live in this process.
//
// Lifecycle (see docs/SERVICE.md for the boot-timing rationale):
//
//	yorud supervise      supervisor: re-spawns the child with backoff
//	  -> yorud run         the worker: detection -> API -> optional autostart
//
// Keeping supervision in a separate process means a crash in the worker (a bad
// vendor sysfs read, an unexpected netlink reply) is recoverable without
// involving init, Magisk or a shell loop, and without ever looping fast enough
// to hurt the phone.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"yoru.dev/yorud/internal/api"
	"yoru.dev/yorud/internal/caps"
	"yoru.dev/yorud/internal/clients"
	"yoru.dev/yorud/internal/config"
	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/metrics"
	"yoru.dev/yorud/internal/monitors"
	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/repeater"
	"yoru.dev/yorud/internal/telegram"
	"yoru.dev/yorud/internal/version"
	"yoru.dev/yorud/internal/wifistate"
)

const (
	defaultStateDir = "/data/adb/yoru-repeater"
	defaultModPath  = "/data/adb/modules/yoru-repeater"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "supervise":
			os.Exit(supervise(os.Args[2:]))
		case "status", "start", "stop", "restart", "logs", "config", "diagnose", "probe", "password", "version", "help":
			os.Exit(control(os.Args[1], os.Args[2:]))
		}
	}
	os.Exit(run())
}

// ---------------------------------------------------------------------------
// worker
// ---------------------------------------------------------------------------

func run() int {
	var (
		stateDir   = flag.String("state", envOr("YORU_STATE_DIR", defaultStateDir), "state directory")
		modPath    = flag.String("mod", envOr("YORU_MODPATH", defaultModPath), "module directory")
		webRoot    = flag.String("web", "", "serve the dashboard from this directory instead of the embedded copy (development)")
		foreground = flag.Bool("f", true, "stay in the foreground (default; supervision is external)")
		pidFile    = flag.String("pidfile", "", "write the daemon pid here")
		waitBoot   = flag.Bool("wait-boot", true, "wait for Android to finish booting")
		pflag      = flag.String("port", "", "override the dashboard port")
		noStart    = flag.Bool("no-autostart", false, "never auto-start the repeater")
	)
	flag.Parse()
	_ = foreground
	_ = webRoot

	// Single instance: a second yorud would fight the first over hostapd, DHCP
	// and the netfilter chains, so it must refuse to start.
	lockFile, err := acquireLock(filepath.Join(*stateDir, "yorud.lock"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "yorud: refusing to start: %v\n", err)
		return 1
	}
	defer releaseLock(lockFile)

	if *pidFile != "" {
		_ = os.MkdirAll(filepath.Dir(*pidFile), 0700)
		_ = os.WriteFile(*pidFile, []byte(strconv.Itoa(os.Getpid())+"\n"), 0644)
		defer os.Remove(*pidFile)
	}

	logPath := filepath.Join(*stateDir, "logs", "yoru.log")
	log := logging.New(logging.Options{
		Path: logPath, Level: logging.Info, MaxBytes: 1 << 20, MaxFiles: 3,
		RingSize: 2000, Stderr: os.Getenv("YORU_VERBOSE") != "",
	})
	defer log.Close()

	log.Infof("main", "Yoru Repeater %s (%s) starting, built %s", version.GitTag, version.GitHash, version.BuildDate)
	log.Infof("main", "uid=%d pid=%d state=%s mod=%s", os.Getuid(), os.Getpid(), *stateDir, *modPath)
	if os.Getuid() != 0 {
		log.Warnf("main", "not running as root (%d); monitoring works but every network change will be refused", os.Getuid())
	}
	if err := log.FileErr(); err != nil {
		log.Warnf("main", "log file unavailable (%v); continuing with in-memory log only", err)
	}

	cfgPath := filepath.Join(*stateDir, "config", "config.json")
	store, err := config.Load(cfgPath)
	if err != nil {
		log.Errorf("main", "configuration could not be prepared (%v); continuing with defaults", err)
	}
	store.SetLogger(log)
	for _, w := range store.Warnings() {
		log.Warnf("config", "%s", w)
	}
	cfg := store.Get()
	if cfg.Advanced.Debug {
		log.SetLevel(logging.Debug)
	}
	if *pflag != "" {
		if p, err := strconv.Atoi(*pflag); err == nil && p > 0 && p < 65536 {
			cfg.Web.Port = p
			log.Infof("main", "dashboard port overridden to %d", p)
		} else {
			log.Warnf("main", "invalid -port %q; using the configured value", *pflag)
		}
	}
	// Runtime environment overrides (advanced.env) are applied to our own
	// process only, which is how a user can point Yoru at an unusual tool path
	// without editing the module.
	for k, v := range cfg.Advanced.Env {
		_ = os.Setenv(k, v)
	}

	if *waitBoot && envOr("YORU_NO_BOOT_WAIT", "") == "" {
		waitForBoot(log)
	}

	dev := netinfo.NewDevice()
	cs := caps.NewSet(log, dev, *modPath)
	cs.Probe()
	for _, c := range cs.All() {
		if c.State == "no" && c.Reason != "" {
			log.Infof("caps", "%-22s unavailable: %s", c.ID, c.Reason)
		}
	}
	summary := cs.Summarise()
	log.Infof("main", "mode availability: repeater=%v hotspot=%v usb=%v ethernet=%v",
		summary.TrueRepeater, summary.HotspotRouter, summary.UsbRouter, summary.EthernetRouter)

	hist := metrics.NewStore(cfg.Monitor.HistoryPoints)
	wifi := wifistate.NewReader(log, dev)
	trk := clients.NewTracker(log, dev, filepath.Join(*stateDir, "state", "clients.json"))
	trk.SetMaskMACs(cfg.Monitor.MaskMACs)

	eng := repeater.New(store, log, dev, cs, trk, wifi, repeater.Options{
		StateDir: *stateDir, RunDir: filepath.Join(*stateDir, "run"),
	})
	dmon := monitors.NewDaemon(store, log, dev, cs, eng, hist, trk, wifi, eng.DNS)

	srv := api.NewServer(store, log, dev, cs, eng, dmon, hist, trk, wifi, nil, api.Version{
		Tag: version.GitTag, Hash: version.GitHash, Built: version.BuildDate, Schema: version.SchemaVersion,
	})

	// Start the monitor loops so the cache is populated continuously.
	dmon.Start()

	// Publish realtime frames from the monitors into the SSE stream.
	publisher := newPublisher(srv, dmon, log)
	publisher.start()

	addrs := bindAddresses(cfg, dev, log)
	if len(addrs) == 0 {
		log.Errorf("main", "no dashboard bind address could be determined; the WebUI will not be reachable")
	} else {
		go func() {
			if err := srv.ListenAndServe(addrs); err != nil {
				log.Errorf("main", "dashboard server failed: %v", err)
			}
		}()
	}
	for _, u := range srv.DashboardURLs(cfg.Web.Port) {
		log.Infof("main", "dashboard available at %s", u)
	}

	// Auto-start the repeater if the operator asked for it.
	autostart := cfg.Repeater.AutoStart && !*noStart
	if autostart {
		go func() {
			delays := []time.Duration{3 * time.Second, 10 * time.Second, 20 * time.Second, 30 * time.Second, 60 * time.Second}
			for i, d := range delays {
				time.Sleep(d)
				if err := eng.Start(true); err != nil {
					log.Warnf("main", "auto-start attempt %d/%d failed: %v", i+1, len(delays), err)
					continue
				}
				log.Infof("main", "auto-start succeeded on attempt %d", i+1)
				go sendBootNotification(cfg, srv, log)
				return
			}
			log.Warnf("main", "auto-start gave up after %d attempts", len(delays))
		}()
	}

	// Graceful shutdown.
	sig := make(chan os.Signal, 4)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP, syscall.SIGUSR2)
	restartRequested := false
	select {
	case s := <-sig:
		log.Infof("main", "received %s", s)
		if s == syscall.SIGHUP {
			restartRequested = true
		}
	case <-shutdownSignal():
		restartRequested = true
	}

	log.Infof("main", "shutting down")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
	publisher.stop()
	if err := eng.Stop(); err != nil {
		log.Warnf("main", "repeater stop reported problems: %v", err)
	}
	dmon.Stop()
	if err := store.Save(); err != nil {
		log.Warnf("main", "final configuration save failed: %v", err)
	}
	if restartRequested {
		log.Infof("main", "exiting for restart")
		return exitRestart
	}
	log.Infof("main", "stopped cleanly")
	return 0
}

// exitRestart tells the supervisor to start a fresh worker immediately.
const exitRestart = 75

// sendBootNotification sends a Telegram message with dashboard URLs after
// a successful auto-start on boot.
func sendBootNotification(cfg *config.Config, srv *api.Server, log *logging.Logger) {
	tg := cfg.Telegram
	if !tg.Enabled || tg.BotToken == "" || tg.ChatID == "" {
		log.Infof("main", "boot notification skipped: telegram not configured (enabled=%v)", tg.Enabled)
		return
	}
	time.Sleep(2 * time.Second)
	urls := srv.DashboardURLs(cfg.Web.Port)
	if len(urls) == 0 {
		log.Warnf("main", "boot notification skipped: no dashboard URLs available")
		return
	}
	host, _ := os.Hostname()
	model := readProp("ro.product.model")
	device := host
	if model != "" {
		device = model + " (" + host + ")"
	}
	var sb strings.Builder
	sb.WriteString("🚀 <b>Yoru Repeater</b> is online!\n\n")
	sb.WriteString("📱 Device: ")
	sb.WriteString(device)
	sb.WriteString("\n\n🔗 Dashboard:\n")
	for _, u := range urls {
		sb.WriteString("• <code>")
		sb.WriteString(u)
		sb.WriteString("</code>\n")
	}
	sb.WriteString("\n⏱️ ")
	sb.WriteString(time.Now().Format("2006-01-02 15:04:05"))
	if err := telegram.Send(tg.BotToken, tg.ChatID, sb.String()); err != nil {
		log.Warnf("main", "boot notification send failed: %v", err)
	} else {
		log.Infof("main", "boot notification sent with %d URLs", len(urls))
	}
}

func readProp(key string) string {
	if !syspropAvailable() {
		return ""
	}
	out, err := exec.Command("/system/bin/getprop", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// boot timing
// ---------------------------------------------------------------------------

// waitForBoot blocks until Android reports boot completion, with a hard cap so
// a stuck property can never keep the daemon from running.
func waitForBoot(log *logging.Logger) {
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		if boolProp("sys.boot_completed") || boolProp("dev.bootcomplete") {
			log.Infof("main", "Android boot completed")
			setProp(log, "persist.yoru.boot_seen", "1")
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	log.Warnf("main", "boot-completed property never became true within 180s; continuing anyway")
}

func boolProp(key string) bool {
	if !syspropAvailable() {
		return false
	}
	out, err := exec.Command("/system/bin/getprop", key).Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "1"
}

var syspropOnce = func() func() bool {
	done := false
	val := false
	return func() bool {
		if !done {
			_, err := os.Stat("/system/bin/getprop")
			val = err == nil
			done = true
		}
		return val
	}
}()

func syspropAvailable() bool { return syspropOnce() }

func setProp(log *logging.Logger, key, val string) {
	if !syspropAvailable() {
		return
	}
	if err := exec.Command("/system/bin/setprop", key, val).Run(); err != nil {
		log.Debugf("main", "setprop %s failed: %v", key, err)
	}
}

// ---------------------------------------------------------------------------
// binding
// ---------------------------------------------------------------------------

// bindAddresses decides what the dashboard listens on. The order matters:
// binding the LAN address first is what guarantees clients can reach it, and
// loopback last keeps the phone's own CLI working even with bind=lan.
func bindAddresses(cfg *config.Config, dev *netinfo.Device, log *logging.Logger) []string {
	port := cfg.Web.Port
	var out []string
	switch cfg.Web.Bind {
	case "all":
		out = append(out, fmt.Sprintf("0.0.0.0:%d", port))
	case "loopback":
		out = append(out, fmt.Sprintf("127.0.0.1:%d", port))
	default: // lan
		addrs, err := dev.Addrs()
		if err != nil {
			log.Warnf("main", "cannot enumerate addresses to choose a bind target: %v", err)
		}
		st := cfg.Repeater.LAN.Gateway
		for _, a := range addrs {
			if a.Family != "IPv4" {
				continue
			}
			ip := net.ParseIP(a.IP)
			if ip == nil || ip.IsLoopback() {
				continue
			}
			if st != "" && a.IP == st {
				out = append(out, a.IP+":"+strconv.Itoa(port))
				continue
			}
			l, err := dev.Link(a.Iface)
			if err != nil || !l.Up {
				continue
			}
			class := netinfo.Classify(l)
			if class == netinfo.ClassWiFiAP || class == netinfo.ClassWiFiSTA ||
				class == netinfo.ClassEthernet || class == netinfo.ClassUSB {
				out = append(out, a.IP+":"+strconv.Itoa(port))
			}
		}
	}
	seen := map[string]bool{}
	var uniq []string
	for _, a := range out {
		if !seen[a] {
			seen[a] = true
			uniq = append(uniq, a)
		}
	}
	uniq = append(uniq, fmt.Sprintf("127.0.0.1:%d", port))
	return uniq
}

// ---------------------------------------------------------------------------
// lock file
// ---------------------------------------------------------------------------

func acquireLock(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("cannot create state directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("cannot open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		other := make([]byte, 32)
		n, _ := f.Read(other)
		_ = f.Close()
		return nil, fmt.Errorf("another yorud is already running (pid %s); refusing to start a second instance", strings.TrimSpace(string(other[:n])))
	}
	if err := f.Truncate(0); err == nil {
		_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
	}
	return f, nil
}

func releaseLock(f *os.File) {
	if f == nil {
		return
	}
	_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	_ = f.Close()
}

// ---------------------------------------------------------------------------
// supervisor
// ---------------------------------------------------------------------------

// supervise restarts `yorud run` with exponential backoff, and gives up in a
// controlled way rather than spinning. It is the only thing that may restart a
// worker, which makes the restart budget auditable in one place.
func supervise(args []string) int {
	fs := flag.NewFlagSet("supervise", flag.ContinueOnError)
	stateDir := fs.String("state", envOr("YORU_STATE_DIR", defaultStateDir), "state directory")
	window := fs.Int("window", 300, "restart counting window in seconds")
	max := fs.Int("max", 5, "maximum restarts inside the window")
	step := fs.Int("backoff", 2000, "backoff step in milliseconds")
	quiet := fs.Bool("quiet", false, "less logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	log := logging.New(logging.Options{
		Path: filepath.Join(*stateDir, "logs", "supervisor.log"),
		Level: func() logging.Level {
			if *quiet {
				return logging.Warn
			}
			return logging.Info
		}(),
		MaxBytes: 256 << 10, MaxFiles: 2, RingSize: 200,
		Stderr: !*quiet,
	})
	defer log.Close()

	self, err := os.Executable()
	if err != nil {
		log.Errorf("supervise", "cannot determine my own path: %v", err)
		return 1
	}
	var starts []time.Time
	consecutiveCrash := 0
	for {
		starts = prune(starts, time.Duration(*window)*time.Second)
		if len(starts) >= *max {
			log.Errorf("supervise", "%d restarts inside %ds; refusing to restart again. Investigate %s",
				len(starts), *window, filepath.Join(*stateDir, "logs", "yoru.log"))
			_ = os.WriteFile(filepath.Join(*stateDir, "state", "supervisor-halted"),
				[]byte(time.Now().Format(time.RFC3339)+"\n"), 0600)
			return 3
		}
		starts = append(starts, time.Now())

		cmd := exec.Command(self, append([]string{"run"}, fs.Args()...)...)
		cmd.Env = os.Environ()
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		log.Infof("supervise", "starting worker (attempt %d in window)", len(starts))
		if err := cmd.Start(); err != nil {
			log.Errorf("supervise", "cannot start worker: %v", err)
			time.Sleep(time.Duration(*step) * time.Millisecond)
			continue
		}
		waitCh := make(chan error, 1)
		go func() { waitCh <- cmd.Wait() }()

		// Forward operator signals to the worker; SIGHUP means "restart me".
		sig := make(chan os.Signal, 4)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		var exitCode int
		select {
		case err := <-waitCh:
			exitCode = exitStatus(err)
		case s := <-sig:
			if s == syscall.SIGHUP {
				log.Infof("supervise", "SIGHUP: restarting the worker")
				_ = cmd.Process.Signal(syscall.SIGUSR2)
			} else {
				log.Infof("supervise", "%s: stopping the worker", s)
				_ = cmd.Process.Signal(s)
			}
			exitCode = exitStatus(<-waitCh)
		}
		signal.Stop(sig)

		if exitCode == exitRestart {
			log.Infof("supervise", "worker asked to restart")
			consecutiveCrash = 0
			time.Sleep(200 * time.Millisecond)
			continue
		}
		ran := time.Since(starts[len(starts)-1])
		if exitCode == 0 {
			log.Infof("supervise", "worker exited cleanly (rc=0); supervisor stopping")
			return 0
		}
		if ran > 60*time.Second {
			consecutiveCrash = 0
		} else {
			consecutiveCrash++
		}
		backoff := time.Duration(*step) * time.Millisecond * time.Duration(consecutiveCrash+1)
		if backoff > 30*time.Second {
			backoff = 30 * time.Second
		}
		log.Warnf("supervise", "worker exited rc=%d after %s; restarting in %s",
			exitCode, ran.Round(time.Second), backoff)
		time.Sleep(backoff)
	}
}

func prune(ts []time.Time, d time.Duration) []time.Time {
	cut := time.Now().Add(-d)
	var out []time.Time
	for _, t := range ts {
		if t.After(cut) {
			out = append(out, t)
		}
	}
	return out
}

func exitStatus(err error) int {
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
	}
	if err != nil {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------------------
// realtime publisher
// ---------------------------------------------------------------------------

// publisher batches monitor readings into SSE frames. It samples the cache
// rather than the hardware, so the cost per frame is a map copy.
type publisher struct {
	srv    *api.Server
	mon    monitorSource
	log    *logging.Logger
	stopCh chan struct{}
	done   chan struct{}
	seq    uint64
}

type monitorSource interface {
	CPU() map[string]any
	Memory() map[string]any
	Battery() map[string]any
	Thermal() map[string]any
	Storage() map[string]any
	Traffic() map[string]any
	WiFi() map[string]any
	Network() map[string]any
	System() map[string]any
	Health() map[string]any
	Diagnostics() map[string]any
}

func newPublisher(srv *api.Server, mon monitorSource, log *logging.Logger) *publisher {
	return &publisher{srv: srv, mon: mon, log: log}
}

func (p *publisher) start() {
	p.stopCh = make(chan struct{})
	p.done = make(chan struct{})
	go p.loop()
}

func (p *publisher) loop() {
	defer close(p.done)
	fast := time.NewTicker(1000 * time.Millisecond)
	slow := time.NewTicker(5 * time.Second)
	verySlow := time.NewTicker(15 * time.Second)
	defer fast.Stop()
	defer slow.Stop()
	defer verySlow.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case <-fast.C:
			p.publishFast()
		case <-slow.C:
			p.publishSlow()
		case <-verySlow.C:
			p.publishStatus()
		}
	}
}

func (p *publisher) stop() {
	if p.stopCh != nil {
		close(p.stopCh)
		<-p.done
	}
}

func (p *publisher) publishFast() {
	t := p.mon.Traffic()
	p.srv.Publish("traffic", pick(t, "rates"))
	c := p.mon.CPU()
	p.srv.Publish("cpu", pick(c, "total", "perCore", "load", "frequencies"))
	m := p.mon.Memory()
	p.srv.Publish("memory", pick(m, "mem"))
}

func (p *publisher) publishSlow() {
	p.srv.Publish("battery", p.mon.Battery())
	p.srv.Publish("thermal", pick(p.mon.Thermal(), "grouped", "maxC", "count", "unavailable"))
}

func (p *publisher) publishStatus() {
	p.srv.Publish("status", p.mon.Health())
}

func pick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// shutdownSignal is a hook point for tests to trigger a clean exit.
func shutdownSignal() <-chan struct{} {
	return nil
}

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	return 1
}

var _ = json.Marshal
var _ = http.StatusOK
var _ = exitCodeOf
