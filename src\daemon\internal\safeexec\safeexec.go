// Package safeexec runs host binaries under strict control.
//
// This is the only place in Yoru that spawns processes, and it enforces:
//   - a fixed allowlist of known binaries (never a shell, never interpolation),
//   - per-binary subcommand restrictions,
//   - argument shape/count bounds,
//   - hard timeouts with process-group kill (a hung `iw` must not wedge a tick),
//   - bounded output capture,
//   - a scrubbed environment.
//
// The HTTP API never reaches this package with user-supplied free text: only
// validated interface names, ports and numeric arguments chosen by the engine.
package safeexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"
)

// binaryPaths maps a logical tool name to every place it may live. Android
// moves things between /system, /vendor and APEX containers across releases, so
// each tool is probed rather than assumed.
var binaryPaths = map[string][]string{
	"ip":              {"/system/bin/ip", "/bin/ip", "/sbin/ip"},
	"iw":              {"/system/bin/iw", "/vendor/bin/iw", "/bin/iw", "/sbin/iw", "/usr/sbin/iw"},
	"iwconfig":        {"/system/bin/iwconfig", "/sbin/iwconfig", "/system/xbin/iwconfig"},
	"iptables":        {"/system/bin/iptables", "/sbin/iptables", "/usr/sbin/iptables", "/system/bin/iptables-nft", "/system/bin/iptables-legacy"},
	"iptables-nft":    {"/system/bin/iptables-nft"},
	"iptables-legacy": {"/system/bin/iptables-legacy"},
	"ip6tables":       {"/system/bin/ip6tables", "/sbin/ip6tables", "/system/bin/ip6tables-nft"},
	"nft":             {"/system/bin/nft", "/sbin/nft", "/usr/sbin/nft"},
	"tc":              {"/system/bin/tc", "/sbin/tc", "/usr/sbin/tc"},
	"hostapd":         {"/system/bin/hostapd", "/vendor/bin/hostapd", "/apex/com.android.wifi/bin/hostapd"},
	"hostapd_cli":     {"/system/bin/hostapd_cli", "/vendor/bin/hostapd_cli"},
	"dnsmasq":         {"/system/bin/dnsmasq", "/vendor/bin/dnsmasq"},
	"wpa_cli":         {"/system/bin/wpa_cli", "/vendor/bin/wpa_cli"},
	"wpa_supplicant":  {"/system/bin/wpa_supplicant", "/vendor/bin/wpa_supplicant"},
	"dumpsys":         {"/system/bin/dumpsys"},
	"cmd":             {"/system/bin/cmd"},
	"settings":        {"/system/bin/settings"},
	"getprop":         {"/system/bin/getprop"},
	"setprop":         {"/system/bin/setprop"},
	"svc":             {"/system/bin/svc"},
	"toybox":          {"/system/bin/toybox"},
	"busybox":         {"/system/bin/busybox", "/sbin/busybox", "/debug/busybox"},
	"pidof":           {"/system/bin/pidof", "/bin/pidof"},
	"uptime":          {"/system/bin/uptime", "/bin/uptime"},
	"sleep":           {"/system/bin/sleep", "/bin/sleep"},
	"ping":            {"/system/bin/ping", "/bin/ping"},
	"modprobe":        {"/system/bin/modprobe", "/sbin/modprobe"},
	"ifconfig":        {"/system/bin/ifconfig", "/sbin/ifconfig"},
}

// subcommands restricts the first positional argument of multi-call tools.
var subcommands = map[string][]string{
	"ip":          {"link", "addr", "address", "route", "neigh", "neighbor", "rule", "tuntap"},
	"iw":          {"dev", "phy", "interface", "scan", "wowlan", "debug", "event"},
	"iptables":    {"-t", "-L", "-S", "-n", "-v", "-N", "-X", "-A", "-I", "-D", "-C", "-P", "-Z", "--line-numbers", "--version", "--wait", "--check"},
	"ip6tables":   {"-t", "-L", "-S", "-n", "-v", "-N", "-X", "-A", "-I", "-D", "-C", "-P", "-Z", "--line-numbers", "--version", "--wait"},
	"nft":         {"list", "add", "delete", "create", "flush", "describe", "insert", "replace", "monitor"},
	"dumpsys":     {"wifi", "connectivity", "netd", "network_stack", "tethering", "batteryproperties", "power", "activity", "telephony", "usagestats"},
	"cmd":         {"wifi", "connectivity", "netpolicy", "network_management", "tethering", "svc"},
	"settings":    {"get", "put", "list", "delete"},
	"svc":         {"wifi", "data", "usb", "vpn"},
	"toybox":      {"df", "free", "uptime", "ps", "ifconfig", "netstat", "route", "arp"},
	"busybox":     {"netstat", "ifconfig", "route", "arp", "free", "df", "ps", "sleep", "nslookup"},
	"wpa_cli":     {"status", "scan", "scan_results", "list_networks", "interface", "ifname", "signal_poll", "version", "reassociate", "disconnect"},
	"hostapd_cli": {"status", "interface", "list_stations", "all_sta", "sta", "mib", "version", "ping", "channel", "fcs", "get_config", "config"},
	"tc":          {"qdisc", "class", "filter", "chain", "monitor"},
	"dnsmasq":     {"--test", "--version", "--help", "--no-daemon", "--keep-in-foreground"},
}

// ErrDenied reports a policy rejection.
var ErrDenied = errors.New("command not permitted by Yoru policy")

// ErrNotAvailable reports that a permitted tool simply is not installed.
var ErrNotAvailable = errors.New("tool not available on this device")

var (
	ifaceRe  = regexp.MustCompile(`^[A-Za-z0-9@._+-]{1,15}$`)
	tokenRe  = regexp.MustCompile(`^[A-Za-z0-9:._/+=@%~*()?<>[\]{}!#$^&| -]{0,120}$`)
	strictRe = regexp.MustCompile(`^[A-Za-z0-9:._/+=@,-]{1,96}$`)
)

// ValidIface reports whether s is a plausible interface name.
func ValidIface(s string) bool { return ifaceRe.MatchString(s) && !strings.Contains(s, "..") }

// Available reports whether a permitted binary exists on this device.
func Available(name string) bool { _, ok := Resolve(name); return ok }

// Resolve returns the concrete path of a permitted binary.
func Resolve(name string) (string, bool) {
	cands, ok := binaryPaths[name]
	if !ok {
		return "", false
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() && st.Mode().Perm()&0111 != 0 {
			return c, true
		}
	}
	// KernelSU/Magisk sometimes provide tools through these overlay dirs.
	for _, extra := range []string{"/data/adb", "/sbin/.magisk"} {
		c := filepath.Join(extra, "bin", name)
		if st, err := os.Stat(c); err == nil && st.Mode().Perm()&0111 != 0 {
			return c, true
		}
	}
	return "", false
}

// Options tweaks one invocation.
type Options struct {
	Timeout time.Duration
	MaxOut  int
	Dir     string
	Env     []string
}

// Result is the outcome of one execution.
type Result struct {
	Path     string
	Stdout   string
	Stderr   string
	ExitCode int
	TimedOut bool
}

// OK reports a clean exit.
func (r Result) OK() bool { return r.ExitCode == 0 && !r.TimedOut }

// Combined returns stdout+stderr, already bounded and UTF-8 sanitised.
func (r Result) Combined() string {
	if r.Stderr == "" {
		return r.Stdout
	}
	return r.Stdout + r.Stderr
}

func validateArgs(name string, args []string) error {
	if len(args) > 24 {
		return fmt.Errorf("%w: too many arguments for %s", ErrDenied, name)
	}
	for _, a := range args {
		if !strictRe.MatchString(a) {
			return fmt.Errorf("%w: argument %q rejected for %s", ErrDenied, a, name)
		}
		if strings.Contains(a, "..") {
			return fmt.Errorf("%w: path traversal in argument", ErrDenied)
		}
	}
	allowed, ok := subcommands[name]
	if !ok || len(args) == 0 {
		return nil
	}
	first := args[0]
	if strings.HasPrefix(first, "-") {
		return nil
	}
	for _, a := range allowed {
		if a == first {
			return nil
		}
	}
	return fmt.Errorf("%w: %s %s", ErrDenied, name, first)
}

// Run executes a permitted command with a deadline.
func Run(name string, args []string, opts Options) (Result, error) {
	path, ok := Resolve(name)
	if !ok {
		return Result{}, fmt.Errorf("%w: %s", ErrNotAvailable, name)
	}
	if err := validateArgs(name, args); err != nil {
		return Result{}, err
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 4 * time.Second
	}
	if opts.MaxOut <= 0 {
		opts.MaxOut = 1 << 20
	}
	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Dir = opts.Dir
	cmd.Env = append(baseEnv(), opts.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out, errb bytes.Buffer
	cmd.Stdout = &limitedWriter{buf: &out, left: opts.MaxOut}
	cmd.Stderr = &limitedWriter{buf: &errb, left: opts.MaxOut / 4}

	if err := cmd.Start(); err != nil {
		return Result{}, fmt.Errorf("start %s: %w", path, err)
	}
	waitc := make(chan error, 1)
	go func() { waitc <- cmd.Wait() }()

	res := Result{Path: path}
	select {
	case werr := <-waitc:
		res.ExitCode = exitCode(werr)
	case <-ctx.Done():
		res.TimedOut = true
		res.ExitCode = -1
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		// A child wedged in uninterruptible sleep (seen with iptables on kernels
		// missing netfilter modules) cannot reap even after SIGKILL. Never let a
		// probe block the daemon: wait briefly, then abandon the goroutine.
		select {
		case werr := <-waitc:
			res.ExitCode = exitCode(werr)
		case <-time.After(2 * time.Second):
			slog.Warn("abandoned hung child", "path", path, "pid", cmd.Process.Pid)
		}
	}
	res.Stdout = strings.ToValidUTF8(out.String(), "\ufffd")
	res.Stderr = strings.ToValidUTF8(errb.String(), "\ufffd")
	return res, nil
}

// Out is Run with defaults, returning trimmed stdout and an error on failure.
func Out(name string, args ...string) (string, error) {
	r, err := Run(name, args, Options{})
	if err != nil {
		return "", err
	}
	if !r.OK() {
		msg := strings.TrimSpace(r.Stderr)
		if msg == "" {
			msg = strings.TrimSpace(r.Stdout)
		}
		if msg == "" {
			msg = fmt.Sprintf("exit %d", r.ExitCode)
		}
		return strings.TrimSpace(r.Stdout), fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), msg)
	}
	return strings.TrimSpace(r.Stdout), nil
}

// OutArgs is Out for callers that already hold the arguments as a slice.
func OutArgs(name string, args []string) (string, error) { return Out(name, args...) }

// RunArgs is Run for callers holding a pre-built argument vector.
func RunArgs(name string, args []string, opts Options) (Result, error) { return Run(name, args, opts) }

// Start launches a long-running permitted child in its own session. The caller
// owns the process and must terminate it (see Stop).
func Start(name string, args []string, extraEnv ...string) (*exec.Cmd, error) {
	path, ok := Resolve(name)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrNotAvailable, name)
	}
	if err := validateArgs(name, args); err != nil {
		return nil, err
	}
	cmd := exec.Command(path, args...)
	cmd.Env = append(baseEnv(), extraEnv...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	var out, errb bytes.Buffer
	cmd.Stdout = &limitedWriter{buf: &out, left: 1 << 16}
	cmd.Stderr = &limitedWriter{buf: &errb, left: 1 << 16}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// Stop terminates a started child, escalating to SIGKILL.
func Stop(cmd *exec.Cmd, grace time.Duration) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	deadline := time.Now().Add(grace)
	for time.Now().Before(deadline) {
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func baseEnv() []string {
	return []string{
		"PATH=/system/bin:/system/xbin:/vendor/bin:/sbin",
		"ANDROID_ROOT=/system",
		"ANDROID_DATA=/data",
		"HOME=/data/local/tmp",
		"TMPDIR=/data/local/tmp",
		"LANG=C",
		"LC_ALL=C",
	}
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok {
			if ws.Signaled() {
				return 128 + int(ws.Signal())
			}
			return ws.ExitStatus()
		}
		return ee.ExitCode()
	}
	return -1
}

type limitedWriter struct {
	buf  *bytes.Buffer
	left int
}

func (w *limitedWriter) Write(p []byte) (int, error) {
	if w.left <= 0 {
		return len(p), nil
	}
	if len(p) > w.left {
		p = p[:w.left]
	}
	w.left -= len(p)
	return w.buf.Write(p)
}

// Tools lists every known tool with its resolved path, for diagnostics.
func Tools() map[string]string {
	out := map[string]string{}
	for name := range binaryPaths {
		if p, ok := Resolve(name); ok {
			out[name] = p
		} else {
			out[name] = ""
		}
	}
	return out
}
