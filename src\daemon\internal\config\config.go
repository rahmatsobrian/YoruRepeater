// Package config owns Yoru's on-disk configuration: defaults, validation,
// schema migration and atomic, permission-safe persistence.
//
// Rules enforced here (and relied upon by the API layer):
//   - every value is validated before use; a malformed file never panics the
//     daemon, it is reported and the daemon continues on safe defaults,
//   - the file is 0600/root-owned because it can contain a Wi-Fi passphrase,
//   - secrets are replaced by a sentinel before anything reaches the WebUI.
package config

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SchemaVersion is the schema this build reads and writes.
const SchemaVersion = 2

// SecretSentinel replaces the passphrase in every API response.
const SecretSentinel = "__YORU_SECRET_SET__"

// Paths.
const (
	DefaultStateDir = "/data/adb/yoru-repeater"
)

// Config is the complete daemon configuration.
type Config struct {
	Schema   int            `json:"schemaVersion"`
	Repeater RepeaterConfig `json:"repeater"`
	Web      WebConfig      `json:"web"`
	Monitor  MonitorConfig  `json:"monitor"`
	Advanced AdvancedConfig `json:"advanced"`
	Telegram TelegramConfig `json:"telegram"`
	Meta     MetaConfig     `json:"meta"`
}

// RepeaterConfig controls the network engine.
type RepeaterConfig struct {
	Enabled    bool        `json:"enabled"`
	AutoStart  bool        `json:"autoStart"`
	Mode       string      `json:"mode"`
	Upstream   string      `json:"upstream"`
	Downstream string      `json:"downstream"`
	AP         APConfig    `json:"ap"`
	LAN        LANConfig   `json:"lan"`
	Routing    RoutingConf `json:"routing"`
}

// APConfig is the access point wish-list; the engine verifies each item
// against hardware capability and reports what it could not honour.
type APConfig struct {
	SSID        string `json:"ssid"`
	Passphrase  string `json:"passphrase"`
	Security    string `json:"security"`
	Band        string `json:"band"`
	Channel     int    `json:"channel"`
	Hidden      bool   `json:"hidden"`
	MaxClients  int    `json:"maxClients"`
	CountryCode string `json:"countryCode"`
	HT40        bool   `json:"ht40"`
	VHT         bool   `json:"vht"`
	HE          bool   `json:"he"`
	Strategy    string `json:"strategy"`
}

// LANConfig is the downstream addressing/DHCP/DNS wish-list.
type LANConfig struct {
	Gateway   string `json:"gateway"`
	Prefix    int    `json:"prefix"`
	DHCPStart string `json:"dhcpStart"`
	DHCPEnd   string `json:"dhcpEnd"`
	LeaseMin  int    `json:"leaseMinutes"`
	DNS1      string `json:"dns1"`
	DNS2      string `json:"dns2"`
	DHCPMode  string `json:"dhcpMode"`
	DNSMode   string `json:"dnsMode"`
	IPv6Mode  string `json:"ipv6"`
	Domain    string `json:"domain"`
}

// RoutingConf controls forwarding/NAT behaviour.
type RoutingConf struct {
	NAT             bool   `json:"nat"`
	IPForward       bool   `json:"ipForward"`
	IPv6Forward     bool   `json:"ipv6Forward"`
	IsolateClients  bool   `json:"isolateClients"`
	FirewallBackend string `json:"firewallBackend"`
}

// WebConfig configures the dashboard server.
type WebConfig struct {
	Port            int        `json:"port"`
	Bind            string     `json:"bind"`
	Auth            AuthConfig `json:"auth"`
	Readonly        bool       `json:"readonlyEnabled"`
	SessionHours    int        `json:"sessionHours"`
	RateLimitPerMin int        `json:"rateLimitPerMin"`
	MaxHistory      int        `json:"maxHistory"`
}

// AuthConfig stores PBKDF2-verified credentials (never the plaintext).
type AuthConfig struct {
	Enabled    bool   `json:"enabled"`
	Algorithm  string `json:"algorithm"`
	Iterations int    `json:"iterations"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	UpdatedAt  int64  `json:"updatedAt"`
}

// MonitorConfig sets per-subsystem polling intervals.
type MonitorConfig struct {
	CPUIntervalMs     int   `json:"cpuIntervalMs"`
	MemIntervalMs     int   `json:"memIntervalMs"`
	BatteryIntervalMs int   `json:"batteryIntervalMs"`
	ThermalIntervalMs int   `json:"thermalIntervalMs"`
	TrafficIntervalMs int   `json:"trafficIntervalMs"`
	ClientsIntervalMs int   `json:"clientsIntervalMs"`
	HistoryPoints     int   `json:"historyPoints"`
	LogMaxBytes       int64 `json:"logMaxBytes"`
	LogMaxFiles       int   `json:"logMaxFiles"`
	MaskMACs          bool  `json:"maskMacs"`
}

// AdvancedConfig holds escape hatches for power users plus health bookkeeping.
type AdvancedConfig struct {
	Debug          bool              `json:"debug"`
	ForceInterface bool              `json:"forceInterface"`
	UpstreamCmd    string            `json:"upstreamHint"`
	Env            map[string]string `json:"env"`
	DisabledCaps   []string          `json:"disabledCapabilities"`
	Watchdog       WatchdogConfig    `json:"watchdog"`
}

// WatchdogConfig bounds crash-recovery restarts.
type WatchdogConfig struct {
	Enabled       bool `json:"enabled"`
	MaxRestarts   int  `json:"maxRestarts"`
	WindowSec     int  `json:"windowSec"`
	BackoffStepMs int  `json:"backoffStepMs"`
}

// TelegramConfig holds Telegram notification settings.
type TelegramConfig struct {
	Enabled        bool   `json:"enabled"`
	BotToken       string `json:"botToken"`
	ChatID         string `json:"chatId"`
	NotifyLowBat   bool   `json:"notifyLowBat"`
	LowBatPercent  int    `json:"lowBatPercent"`
	NotifyCharge   bool   `json:"notifyCharge"`
	Charge80       bool   `json:"charge80"`
	Charge90       bool   `json:"charge90"`
	Charge100      bool   `json:"charge100"`
}

// MetaConfig is machine-managed bookkeeping, not user intent.
type MetaConfig struct {
	FirstRun      int64  `json:"firstRun"`
	LastMigration string `json:"lastMigration"`
	MigratedFrom  int    `json:"migratedFrom"`
	InstallID     string `json:"installId"`
}

// Default returns a fully populated, valid configuration.
func Default() *Config {
	now := time.Now().Unix()
	return &Config{
		Schema: SchemaVersion,
		Repeater: RepeaterConfig{
			Mode:       "auto",
			Upstream:   "auto",
			Downstream: "auto",
			AP: APConfig{
				SSID:       "YoruRepeater",
				Security:   "wpa2-psk",
				Band:       "auto",
				Channel:    0,
				MaxClients: 10,
				HT40:       true,
				VHT:        true,
				HE:         true,
				Strategy:   "auto",
			},
			LAN: LANConfig{
				Gateway:   "192.168.50.1",
				Prefix:    24,
				DHCPStart: "192.168.50.10",
				DHCPEnd:   "192.168.50.200",
				LeaseMin:  120,
				DHCPMode:  "auto",
				DNSMode:   "auto",
				IPv6Mode:  "auto",
				Domain:    "yoru",
			},
			Routing: RoutingConf{
				NAT: true, IPForward: true, IPv6Forward: true, FirewallBackend: "auto",
			},
		},
		Web: WebConfig{
			Port: 8080, Bind: "lan", Readonly: true, SessionHours: 12,
			RateLimitPerMin: 600, MaxHistory: 900,
			Auth: AuthConfig{Enabled: true, Algorithm: "pbkdf2-sha256", Iterations: 150000},
		},
		Monitor: MonitorConfig{
			CPUIntervalMs: 1000, MemIntervalMs: 1000, BatteryIntervalMs: 5000,
			ThermalIntervalMs: 2000, TrafficIntervalMs: 1000, ClientsIntervalMs: 2000,
			HistoryPoints: 300, LogMaxBytes: 1048576, LogMaxFiles: 3,
		},
		Advanced: AdvancedConfig{
			Env: map[string]string{},
			Watchdog: WatchdogConfig{
				Enabled: true, MaxRestarts: 5, WindowSec: 300, BackoffStepMs: 1500,
			},
		},
		Meta: MetaConfig{FirstRun: now, InstallID: newInstallID()},
	}
}

func newInstallID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unknown"
	}
	return hex.EncodeToString(b[:])
}

// Store loads, validates and atomically persists configuration.
type Store struct {
	mu       sync.RWMutex
	path     string
	cfg      *Config
	warnings []string
	logger   ConfigLogger
}

// ConfigLogger is the narrow logging surface config needs; keeping it an
// interface avoids a circular dependency on the logging package.
type ConfigLogger interface {
	Warnf(src, format string, args ...any)
}

// Load reads path, migrating and validating as required. A missing file yields
// defaults (written out so the first boot leaves a readable config). An
// unparseable file is backed up and defaults are used - the daemon must never
// fail to start because of a bad config.
func Load(path string) (*Store, error) {
	s := &Store{path: path, cfg: Default()}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			s.warnings = append(s.warnings, "config not found; created defaults")
			s.cfg.Meta.FirstRun = time.Now().Unix()
			if err := s.save(); err != nil {
				return s, err
			}
			return s, nil
		}
		s.warnings = append(s.warnings, "config unreadable: "+err.Error())
		return s, nil
	}
	raw, err := migrate(data)
	if err != nil {
		s.backup(path, data)
		s.warnings = append(s.warnings, "config parse failed ("+err.Error()+"); defaults in use, original saved as "+filepath.Base(path)+".bad")
		return s, nil
	}
	merged := Default()
	if err := json.Unmarshal(raw, merged); err != nil {
		s.backup(path, data)
		s.warnings = append(s.warnings, "config type error ("+err.Error()+"); defaults in use")
		return s, nil
	}
	merged.Meta.FirstRun = s.cfg.Meta.FirstRun
	if merged.Meta.InstallID == "" {
		merged.Meta.InstallID = s.cfg.Meta.InstallID
	}
	s.cfg = merged
	if msgs := Validate(merged); len(msgs) > 0 {
		s.warnings = append(s.warnings, msgs...)
	}
	if merged.Schema != SchemaVersion {
		merged.Schema = SchemaVersion
	}
	return s, nil
}

// migrate upgrades any known historical schema to the current one.
func migrate(data []byte) ([]byte, error) {
	var probe struct {
		Schema int `json:"schemaVersion"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	switch probe.Schema {
	case 0, 1:
		// Schema 0/1 (pre-release layout): monitor used a single global
		// refreshInterval and web.auth lived at web.password. Promote them to
		// the independent per-subsystem intervals and the PBKDF2 auth block.
		var legacy struct {
			Monitor struct {
				RefreshInterval *int `json:"refreshInterval"`
			} `json:"monitor"`
			Web struct {
				PasswordHash   string `json:"passwordHash"`
				PasswordSalt   string `json:"passwordSalt"`
				AuthIterations int    `json:"authIterations"`
			} `json:"web"`
		}
		_ = json.Unmarshal(data, &legacy)
		var generic map[string]any
		if err := json.Unmarshal(data, &generic); err != nil {
			return nil, err
		}
		if legacy.Monitor.RefreshInterval != nil {
			v := *legacy.Monitor.RefreshInterval
			if v < 200 {
				v = 200
			}
			setNested(generic, []string{"monitor", "cpuIntervalMs"}, v)
			setNested(generic, []string{"monitor", "memIntervalMs"}, v)
			setNested(generic, []string{"monitor", "trafficIntervalMs"}, v)
			setNested(generic, []string{"monitor", "clientsIntervalMs"}, v*2)
			setNested(generic, []string{"monitor", "thermalIntervalMs"}, v*2)
			setNested(generic, []string{"monitor", "batteryIntervalMs"}, v*5)
		}
		if legacy.Web.PasswordHash != "" {
			auth := map[string]any{
				"enabled": true, "algorithm": "pbkdf2-sha256",
				"hash": legacy.Web.PasswordHash, "salt": legacy.Web.PasswordSalt,
				"iterations": orInt(legacy.Web.AuthIterations, 100000),
			}
			setNested(generic, []string{"web", "auth"}, auth)
		}
		dropNested(generic, []string{"monitor", "refreshInterval"})
		dropNested(generic, []string{"web", "passwordHash"})
		dropNested(generic, []string{"web", "passwordSalt"})
		setNested(generic, []string{"schemaVersion"}, SchemaVersion)
		if meta, ok := generic["meta"].(map[string]any); ok {
			meta["migratedFrom"] = probe.Schema
			meta["lastMigration"] = fmt.Sprintf("%d->%d", probe.Schema, SchemaVersion)
		} else {
			generic["meta"] = map[string]any{"migratedFrom": probe.Schema, "lastMigration": fmt.Sprintf("%d->%d", probe.Schema, SchemaVersion)}
		}
		out, err := json.Marshal(generic)
		if err != nil {
			return nil, err
		}
		return out, nil
	case SchemaVersion:
		return data, nil
	default:
		return nil, fmt.Errorf("config schema %d is newer than this build supports (%d)", probe.Schema, SchemaVersion)
	}
}

func orInt(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func setNested(m map[string]any, keys []string, value any) {
	for i, k := range keys {
		if i == len(keys)-1 {
			m[k] = value
			return
		}
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}
		m = next
	}
}

func dropNested(m map[string]any, keys []string) {
	for i, k := range keys {
		if i == len(keys)-1 {
			delete(m, k)
			return
		}
		next, ok := m[k].(map[string]any)
		if !ok {
			return
		}
		m = next
	}
}

func (s *Store) backup(path string, data []byte) {
	_ = os.WriteFile(path+".bad", data, 0600)
}

// Validate normalises and checks every field, returning human-readable notes.
// Invalid values are corrected in place so the daemon always has a usable
// configuration; the notes tell the user exactly what was fixed.
func Validate(c *Config) []string {
	var w []string
	note := func(f string, args ...any) { w = append(w, " "+fmt.Sprintf(f, args...)) }

	switch c.Repeater.Mode {
	case "auto", "repeater", "hotspot", "usb", "ethernet", "disabled":
	default:
		note("repeater.mode %q unknown, using \"auto\"", c.Repeater.Mode)
		c.Repeater.Mode = "auto"
	}
	if ip := net.ParseIP(c.Repeater.Upstream); ip != nil {
		note("repeater.upstream is an address, not an interface; using \"auto\"")
		c.Repeater.Upstream = "auto"
	}
	c.Repeater.Upstream = cleanIfName(c.Repeater.Upstream)
	c.Repeater.Downstream = cleanIfName(c.Repeater.Downstream)

	// --- AP ---
	ap := &c.Repeater.AP
	ap.SSID = strings.TrimSpace(ap.SSID)
	if ap.SSID == "" {
		ap.SSID = "YoruRepeater"
		note("AP SSID was empty, using %q", ap.SSID)
	}
	if len(ap.SSID) > 32 {
		ap.SSID = ap.SSID[:32]
		note("AP SSID truncated to 32 bytes (802.11 limit)")
	}
	if strings.ContainsAny(ap.SSID, "\x00\r\n") {
		ap.SSID = strings.Map(func(r rune) rune {
			if r < 0x20 {
				return -1
			}
			return r
		}, ap.SSID)
		note("AP SSID contained control characters; stripped")
	}
	switch ap.Security {
	case "open", "wpa2-psk", "wpa3-sae", "wpa2-wpa3", "wep":
	default:
		note("AP security %q unsupported, using wpa2-psk", ap.Security)
		ap.Security = "wpa2-psk"
	}
	if pw := ap.Passphrase; pw != "" && ap.Security != "open" {
		if len(pw) < 8 || len(pw) > 63 {
			note("AP passphrase must be 8-63 bytes for %s (current %d); AP start will be refused until fixed", ap.Security, len(pw))
		}
		if strings.ContainsAny(pw, "\x00\r\n\"\\") {
			note("AP passphrase contains characters hostapd cannot quote safely; AP start will be refused until fixed")
		}
	}
	switch ap.Band {
	case "auto", "2g", "5g", "6g":
	default:
		note("AP band %q unsupported, using auto", ap.Band)
		ap.Band = "auto"
	}
	if ap.Channel < 0 || ap.Channel > 233 {
		note("AP channel %d out of range; using auto (0)", ap.Channel)
		ap.Channel = 0
	}
	if ap.MaxClients < 1 || ap.MaxClients > 255 {
		note("AP maxClients %d clamped to 1-255", ap.MaxClients)
		ap.MaxClients = minmax(ap.MaxClients, 1, 255)
	}
	ap.CountryCode = strings.ToUpper(strings.TrimSpace(ap.CountryCode))
	if len(ap.CountryCode) > 2 {
		note("AP countryCode %q must be a 2-letter ISO code; ignored", ap.CountryCode)
		ap.CountryCode = ""
	}
	switch ap.Strategy {
	case "auto", "hostapd", "android":
	default:
		note("AP strategy %q unknown, using auto", ap.Strategy)
		ap.Strategy = "auto"
	}

	// --- LAN ---
	lan := &c.Repeater.LAN
	gw := net.ParseIP(lan.Gateway)
	if gw == nil || gw.To4() == nil {
		note("LAN gateway %q is not an IPv4 address; using 192.168.50.1", lan.Gateway)
		lan.Gateway = "192.168.50.1"
		gw = net.ParseIP(lan.Gateway)
	}
	if lan.Prefix < 16 || lan.Prefix > 30 {
		note("LAN prefix %d clamped to 16-30", lan.Prefix)
		lan.Prefix = minmax(lan.Prefix, 16, 30)
	}
	_, network, err := net.ParseCIDR(fmt.Sprintf("%s/%d", lan.Gateway, lan.Prefix))
	if err != nil {
		note("LAN gateway/prefix combination invalid (%v); using /24", err)
		lan.Prefix = 24
		_, network, _ = net.ParseCIDR(lan.Gateway + "/24")
	}
	start := net.ParseIP(lan.DHCPStart)
	end := net.ParseIP(lan.DHCPEnd)
	if start == nil || end == nil || !network.Contains(start) || !network.Contains(end) {
		note("DHCP range %s-%s is outside %s; regenerated from gateway", lan.DHCPStart, lan.DHCPEnd, network.String())
		lan.DHCPStart = nthIP(network, 10)
		lan.DHCPEnd = nthIP(network, 200)
		if end = net.ParseIP(lan.DHCPEnd); start == nil {
			start = net.ParseIP(lan.DHCPStart)
		}
	}
	if ipv4ToU32(start) > ipv4ToU32(end) {
		note("DHCP start was above end; swapped")
		lan.DHCPStart, lan.DHCPEnd = lan.DHCPEnd, lan.DHCPStart
	}
	if lan.Gateway == network.IP.String() || lan.Gateway == broadcastOf(network).String() {
		note("LAN gateway may not be the network or broadcast address; using .1")
		lan.Gateway = nthIP(network, 1)
	}
	for _, d := range []*string{&lan.DNS1, &lan.DNS2} {
		*d = strings.TrimSpace(*d)
		if *d != "" && net.ParseIP(*d) == nil {
			note("DNS server %q is not an IP literal; cleared", *d)
			*d = ""
		}
	}
	if lan.LeaseMin < 1 || lan.LeaseMin > 10080 {
		note("DHCP lease %d minutes clamped to 1-10080", lan.LeaseMin)
		lan.LeaseMin = minmax(lan.LeaseMin, 1, 10080)
	}
	switch lan.DHCPMode {
	case "auto", "dnsmasq", "builtin", "off":
	default:
		note("dhcpMode %q unknown, using auto", lan.DHCPMode)
		lan.DHCPMode = "auto"
	}
	switch lan.DNSMode {
	case "auto", "dnsmasq", "builtin", "off":
	default:
		note("dnsMode %q unknown, using auto", lan.DNSMode)
		lan.DNSMode = "auto"
	}
	switch lan.IPv6Mode {
	case "auto", "off", "forward", "ula":
	default:
		note("ipv6 mode %q unknown, using auto", lan.IPv6Mode)
		lan.IPv6Mode = "auto"
	}
	if !validDomain(lan.Domain) {
		note("LAN domain %q invalid; using \"yoru\"", lan.Domain)
		lan.Domain = "yoru"
	}

	// --- Web ---
	if c.Web.Port < 1 || c.Web.Port > 65535 {
		note("web.port %d invalid; using 8080", c.Web.Port)
		c.Web.Port = 8080
	}
	switch c.Web.Bind {
	case "lan", "all", "loopback":
	default:
		note("web.bind %q unknown, using lan", c.Web.Bind)
		c.Web.Bind = "lan"
	}
	if c.Web.SessionHours < 1 || c.Web.SessionHours > 720 {
		note("web.sessionHours %d clamped to 1-720", c.Web.SessionHours)
		c.Web.SessionHours = minmax(c.Web.SessionHours, 1, 720)
	}
	if c.Web.RateLimitPerMin < 10 || c.Web.RateLimitPerMin > 100000 {
		note("web.rateLimitPerMin %d clamped to 10-100000", c.Web.RateLimitPerMin)
		c.Web.RateLimitPerMin = minmax(c.Web.RateLimitPerMin, 10, 100000)
	}
	if c.Web.Auth.Enabled && c.Web.Auth.Hash == "" {
		note("web.auth.enabled but no password is set; dashboard is reachable until you set one")
	}
	switch c.Web.Auth.Algorithm {
	case "pbkdf2-sha256", "":
		c.Web.Auth.Algorithm = "pbkdf2-sha256"
	default:
		note("auth algorithm %q unsupported; using pbkdf2-sha256", c.Web.Auth.Algorithm)
		c.Web.Auth.Algorithm = "pbkdf2-sha256"
	}
	if c.Web.Auth.Iterations < 1000 || c.Web.Auth.Iterations > 2000000 {
		note("auth iterations %d clamped to 1000-2000000", c.Web.Auth.Iterations)
		c.Web.Auth.Iterations = minmax(c.Web.Auth.Iterations, 1000, 2000000)
	}
	if c.Web.MaxHistory < 60 || c.Web.MaxHistory > 7200 {
		c.Web.MaxHistory = minmax(c.Web.MaxHistory, 60, 7200)
	}

	// --- Monitor ---
	m := &c.Monitor
	m.CPUIntervalMs = clampInterval(m.CPUIntervalMs, 250, 60000, 1000, "cpuIntervalMs", note)
	m.MemIntervalMs = clampInterval(m.MemIntervalMs, 500, 60000, 1000, "memIntervalMs", note)
	m.BatteryIntervalMs = clampInterval(m.BatteryIntervalMs, 1000, 600000, 5000, "batteryIntervalMs", note)
	m.ThermalIntervalMs = clampInterval(m.ThermalIntervalMs, 500, 600000, 2000, "thermalIntervalMs", note)
	m.TrafficIntervalMs = clampInterval(m.TrafficIntervalMs, 250, 60000, 1000, "trafficIntervalMs", note)
	m.ClientsIntervalMs = clampInterval(m.ClientsIntervalMs, 500, 600000, 2000, "clientsIntervalMs", note)
	if m.HistoryPoints < 30 || m.HistoryPoints > 7200 {
		note("monitor.historyPoints %d clamped to 30-7200", m.HistoryPoints)
		m.HistoryPoints = minmax(m.HistoryPoints, 30, 7200)
	}
	if m.LogMaxBytes < 65536 || m.LogMaxBytes > 64<<20 {
		note("monitor.logMaxBytes %d clamped to 64KiB-64MiB", m.LogMaxBytes)
		m.LogMaxBytes = int64(minmax64(m.LogMaxBytes, 65536, 64<<20))
	}
	if m.LogMaxFiles < 1 || m.LogMaxFiles > 20 {
		note("monitor.logMaxFiles %d clamped to 1-20", m.LogMaxFiles)
		m.LogMaxFiles = minmax(m.LogMaxFiles, 1, 20)
	}

	// --- Advanced ---
	if c.Advanced.Watchdog.MaxRestarts < 1 || c.Advanced.Watchdog.MaxRestarts > 100 {
		note("watchdog.maxRestarts %d clamped to 1-100", c.Advanced.Watchdog.MaxRestarts)
		c.Advanced.Watchdog.MaxRestarts = minmax(c.Advanced.Watchdog.MaxRestarts, 1, 100)
	}
	if c.Advanced.Watchdog.WindowSec < 30 || c.Advanced.Watchdog.WindowSec > 86400 {
		c.Advanced.Watchdog.WindowSec = minmax(c.Advanced.Watchdog.WindowSec, 30, 86400)
	}
	if c.Advanced.Watchdog.BackoffStepMs < 100 || c.Advanced.Watchdog.BackoffStepMs > 60000 {
		c.Advanced.Watchdog.BackoffStepMs = minmax(c.Advanced.Watchdog.BackoffStepMs, 100, 60000)
	}
	seen := map[string]bool{}
	var caps []string
	for _, cp := range c.Advanced.DisabledCaps {
		cp = strings.ToUpper(strings.TrimSpace(cp))
		if cp != "" && !seen[cp] {
			seen[cp] = true
			caps = append(caps, cp)
		}
	}
	c.Advanced.DisabledCaps = caps
	if c.Advanced.Env == nil {
		c.Advanced.Env = map[string]string{}
	}
	for k := range c.Advanced.Env {
		if !envKeyRe.MatchString(k) {
			note("advanced.env key %q invalid; dropped", k)
			delete(c.Advanced.Env, k)
		}
	}
	return w
}

var envKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)

type noteFn func(string, ...any)

func clampInterval(v, lo, hi, def int, name string, note noteFn) int {
	switch {
	case v == 0:
		return def
	case v < lo || v > hi:
		note("monitor.%s %d clamped to %d-%d ms", name, v, lo, hi)
		return minmax(v, lo, hi)
	}
	return v
}

func cleanIfName(s string) string {
	s = strings.TrimSpace(s)
	if s == "auto" || s == "" {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s) && i < 15; i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '@' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func validDomain(d string) bool {
	if d == "" {
		return true
	}
	if len(d) > 63 {
		return false
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' {
			continue
		}
		return false
	}
	return true
}

func ipv4ToU32(ip net.IP) uint32 {
	v := ip.To4()
	if v == nil {
		return 0
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

func u32ToIPv4(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u))
}

func nthIP(network *net.IPNet, n int) string {
	base := ipv4ToU32(network.IP)
	return u32ToIPv4(base + uint32(n)).String()
}

func broadcastOf(network *net.IPNet) net.IP {
	return u32ToIPv4(ipv4ToU32(network.IP) | ^maskToU32(network.Mask))
}

// maskToU32 converts an IPv4 netmask to its 32-bit form.
func maskToU32(m net.IPMask) uint32 {
	v := net.IP(m).To4()
	if v == nil {
		return 0
	}
	return uint32(v[0])<<24 | uint32(v[1])<<16 | uint32(v[2])<<8 | uint32(v[3])
}

// Network returns the downstream subnet as a *net.IPNet.
func (c *Config) Network() (*net.IPNet, error) {
	_, n, err := net.ParseCIDR(c.Repeater.LAN.Gateway + "/" + strconv.Itoa(c.Repeater.LAN.Prefix))
	return n, err
}

// DHCPBounds returns the inclusive numeric DHCP pool.
func (c *Config) DHCPBounds() (uint32, uint32) {
	return ipv4ToU32(net.ParseIP(c.Repeater.LAN.DHCPStart)), ipv4ToU32(net.ParseIP(c.Repeater.LAN.DHCPEnd))
}

// ConflictsWith reports whether the downstream subnet overlaps an upstream CIDR
// such as a cellular rmnet route or an existing Wi-Fi /24.
func (c *Config) ConflictsWith(other *net.IPNet) bool {
	n, err := c.Network()
	if err != nil || other == nil {
		return false
	}
	return n.Contains(other.IP) || other.Contains(n.IP)
}

// Get returns a copy of the current configuration.
func (s *Store) Get() *Config {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cloneLocked()
}

func (s *Store) cloneLocked() *Config {
	b, err := json.Marshal(s.cfg)
	if err != nil {
		return Default()
	}
	cp := &Config{}
	if err := json.Unmarshal(b, cp); err != nil {
		return Default()
	}
	return cp
}

// Warnings returns validation notes from the last load/apply.
func (s *Store) Warnings() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.warnings...)
}

// Apply validates and persists a full replacement configuration.
func (s *Store) Apply(next *Config) ([]string, error) {
	if next == nil {
		return nil, errors.New("nil configuration")
	}
	if s.cfg != nil && next.Meta.InstallID == "" {
		next.Meta.InstallID = s.cfg.Meta.InstallID
	}
	next.Schema = SchemaVersion
	w := Validate(next)
	s.mu.Lock()
	prev := s.cfg
	s.cfg = next
	s.warnings = w
	s.mu.Unlock()
	if err := s.save(); err != nil {
		s.mu.Lock()
		s.cfg = prev
		s.mu.Unlock()
		return w, err
	}
	return w, nil
}

// MergePatch applies a partial JSON document (Settings page sends only what
// changed) and returns the resulting warnings.
func (s *Store) MergePatch(patch []byte) ([]string, error) {
	s.mu.RLock()
	base := *s.cfg
	s.mu.RUnlock()
	raw, err := json.Marshal(&base)
	if err != nil {
		return nil, err
	}
	var merged map[string]any
	if err := json.Unmarshal(raw, &merged); err != nil {
		return nil, err
	}
	var pm map[string]any
	if err := json.Unmarshal(patch, &pm); err != nil {
		return nil, fmt.Errorf("request body is not a JSON object: %w", err)
	}
	if err := checkPatchAllowed(pm, ""); err != nil {
		return nil, err
	}
	deepMerge(merged, pm)
	out, err := json.Marshal(merged)
	if err != nil {
		return nil, err
	}
	next := Default()
	if err := json.Unmarshal(out, next); err != nil {
		return nil, fmt.Errorf("resulting config invalid: %w", err)
	}
	return s.Apply(next)
}

// writableKeys restricts which paths the HTTP API may change. Anything else is
// refused, which keeps a compromised dashboard from rewriting daemon internals.
var writableKeys = map[string]bool{
	"repeater": true, "web": true, "monitor": true, "advanced": true, "telegram": true, "schemaVersion": true,
}

var writableNested = map[string]map[string]bool{
	"repeater": {"enabled": true, "autoStart": true, "mode": true, "upstream": true, "downstream": true, "ap": true, "lan": true, "routing": true},
	"web":      {"port": true, "bind": true, "auth": true, "readonlyEnabled": true, "sessionHours": true, "rateLimitPerMin": true, "maxHistory": true},
	"monitor":  {"cpuIntervalMs": true, "memIntervalMs": true, "batteryIntervalMs": true, "thermalIntervalMs": true, "trafficIntervalMs": true, "clientsIntervalMs": true, "historyPoints": true, "logMaxBytes": true, "logMaxFiles": true, "maskMacs": true},
	"advanced": {"debug": true, "forceInterface": true, "upstreamHint": true, "disabledCapabilities": true, "watchdog": true},
	"telegram": {"enabled": true, "botToken": true, "chatId": true, "notifyLowBat": true, "lowBatPercent": true, "notifyCharge": true, "charge80": true, "charge90": true, "charge100": true},
	"web.auth": {"enabled": true, "password": true},
}

func checkPatchAllowed(m map[string]any, prefix string) error {
	for k, v := range m {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}
		allowed := writableKeys[k]
		if prefix != "" {
			allowed = writableNested[prefix][k]
		}
		if !allowed {
			return fmt.Errorf("configuration key %q cannot be changed through the API", path)
		}
		if sub, ok := v.(map[string]any); ok {
			if err := checkPatchAllowed(sub, path); err != nil {
				return err
			}
			continue
		}
		if isSensitiveKey(k) {
			return fmt.Errorf("configuration key %q must be changed with POST /api/v1/password", path)
		}
	}
	return nil
}

func isSensitiveKey(k string) bool {
	switch strings.ToLower(k) {
	case "hash", "salt", "iterations", "algorithm", "passphrase", "passwordhash":
		return true
	}
	return false
}

// HasPassphrase reports whether a Wi-Fi key is configured (for UI masking).
func (c *Config) HasPassphrase() bool { return c.Repeater.AP.Passphrase != "" }

// Public returns a deep copy safe to send to the browser: the passphrase is
// replaced by a sentinel and the auth hash/salt are removed.
func (c *Config) Public() map[string]any {
	b, _ := json.Marshal(c)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if rep, ok := m["repeater"].(map[string]any); ok {
		if ap, ok := rep["ap"].(map[string]any); ok {
			if s, _ := ap["passphrase"].(string); s != "" {
				ap["passphrase"] = SecretSentinel
			} else {
				ap["passphrase"] = ""
			}
			ap["hasPassphrase"] = c.HasPassphrase()
		}
	}
	if wb, ok := m["web"].(map[string]any); ok {
		if a, ok := wb["auth"].(map[string]any); ok {
			delete(a, "hash")
			delete(a, "salt")
			a["passwordSet"] = c.Web.Auth.Hash != ""
		}
	}
	return m
}

func deepMerge(dst, src map[string]any) {
	for k, v := range src {
		if sub, ok := v.(map[string]any); ok {
			if dm, ok := dst[k].(map[string]any); ok {
				deepMerge(dm, sub)
				continue
			}
		}
		dst[k] = v
	}
}

// SetPassphrase stores a new Wi-Fi key (empty clears it).
func (s *Store) SetPassphrase(pw string) error {
	s.mu.Lock()
	s.cfg.Repeater.AP.Passphrase = pw
	s.mu.Unlock()
	return s.save()
}

// PasswordHash derives a PBKDF2 verifier for the dashboard password.
func PasswordHash(password string, iterations int) (saltHex, hashHex string, err error) {
	if len(password) < 8 {
		return "", "", errors.New("password must be at least 8 characters")
	}
	if len(password) > 256 {
		return "", "", errors.New("password too long")
	}
	if iterations <= 0 {
		iterations = 150000
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", "", err
	}
	dk := pbkdf2SHA256([]byte(password), salt, iterations, 32)
	return hex.EncodeToString(salt), hex.EncodeToString(dk), nil
}

// pbkdf2SHA256 is a local PBKDF2 implementation (RFC 8018) so the daemon has
// zero third-party dependencies. 32-byte key, SHA-256 PRF.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	var dk []byte
	for block := 1; len(dk) < keyLen; block++ {
		u := hmacSHA256(password, append(append([]byte{}, salt...), byte(block>>24), byte(block>>16), byte(block>>8), byte(block)))
		t := append([]byte{}, u...)
		for i := 1; i < iter; i++ {
			u = hmacSHA256(password, u)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// VerifyPassword constant-time checks the submitted dashboard password.
func (c *Config) VerifyPassword(password string) bool {
	if !c.Web.Auth.Enabled || c.Web.Auth.Hash == "" || c.Web.Auth.Salt == "" {
		return false
	}
	salt, err := hex.DecodeString(c.Web.Auth.Salt)
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(c.Web.Auth.Hash)
	if err != nil {
		return false
	}
	got := pbkdf2SHA256([]byte(password), salt, c.Web.Auth.Iterations, len(want))
	return subtleEqual(want, got)
}

func subtleEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := range a {
		v |= a[i] ^ b[i]
	}
	return v == 0
}

// SetPassword installs a fresh dashboard credential.
func (s *Store) SetPassword(password string) error {
	salt, hash, err := PasswordHash(password, s.Get().Web.Auth.Iterations)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cfg.Web.Auth.Salt = salt
	s.cfg.Web.Auth.Hash = hash
	s.cfg.Web.Auth.Enabled = true
	s.cfg.Web.Auth.UpdatedAt = time.Now().Unix()
	s.mu.Unlock()
	return s.save()
}

// DisablePassword removes the dashboard credential.
func (s *Store) DisablePassword() error {
	s.mu.Lock()
	s.cfg.Web.Auth.Enabled = false
	s.cfg.Web.Auth.Hash = ""
	s.cfg.Web.Auth.Salt = ""
	s.mu.Unlock()
	return s.save()
}

// Save persists the current configuration atomically.
func (s *Store) Save() error { return s.save() }

func (s *Store) save() error {
	s.mu.RLock()
	cfg := s.cfg
	path := s.path
	s.mu.RUnlock()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".tmp")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	// fsync the directory so the rename survives a hard reset.
	if d, derr := os.Open(dir); derr == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// MergePatchSet mutates the live configuration through fn, validates and
// persists it. It is the internal counterpart of MergePatch, used by the engine
// to record state (e.g. "the operator started the repeater, so auto-start next
// boot should match") without round-tripping JSON.
func (s *Store) MergePatchSet(fn func(*Config)) error {
	s.mu.RLock()
	backup, err := json.Marshal(s.cfg)
	s.mu.RUnlock()
	if err != nil {
		return err
	}
	next := Default()
	if err := json.Unmarshal(backup, next); err != nil {
		return err
	}
	fn(next)
	if msgs := Validate(next); len(msgs) > 0 && s.logger != nil {
		s.logger.Warnf("config", "configuration normalised: %s", strings.Join(msgs, " "))
	}
	_, err = s.Apply(next)
	return err
}

// SetLogger attaches the daemon logger for configuration diagnostics.
func (s *Store) SetLogger(l ConfigLogger) {
	s.mu.Lock()
	s.logger = l
	s.mu.Unlock()
}

// Path returns the backing file path.
func (s *Store) Path() string { return s.path }

// StatePath joins the state directory with sub paths.
func StatePath(dir string, parts ...string) string {
	all := append([]string{dir}, parts...)
	return filepath.Join(all...)
}

// SortedKeys aids deterministic diagnostics output.
func SortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
