// Package api exposes Yoru's HTTP surface.
//
// This is the only network-facing component, so it is written defensively:
//   - every response is JSON with an explicit schema; there is no "raw command"
//     endpoint of any kind,
//   - request bodies are size-bounded and strictly parsed (no unknown fields
//     are honoured),
//   - configuration writes go through a key allowlist in the config package,
//   - authentication uses PBKDF2 + constant-time compare + random session
//     tokens with expiry, delivered only in a HttpOnly cookie or a bearer
//     header, never in a URL,
//   - per-client token buckets rate-limit reads and, more tightly, privileged
//     writes; login attempts are throttled and locked out,
//   - static asset serving is confined to the embedded file set: paths are
//     resolved against an index, so there is no filesystem access at all,
//   - responses carry CSP/no-sniffing/no-referrer headers, and the log/API
//     output is redacted before serialisation.
//
// Realtime updates use Server-Sent Events over plain HTTP: it is universally
// supported by browsers, needs no extra framing code, and works fine through
// the phone's own stack.
package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"yoru.dev/yorud/internal/caps"
	"yoru.dev/yorud/internal/clients"
	"yoru.dev/yorud/internal/config"
	"yoru.dev/yorud/internal/firewall"
	"yoru.dev/yorud/internal/logging"
	"yoru.dev/yorud/internal/metrics"
	"yoru.dev/yorud/internal/netinfo"
	"yoru.dev/yorud/internal/repeater"
	"yoru.dev/yorud/internal/sysinfo"
	"yoru.dev/yorud/internal/telegram"
	"yoru.dev/yorud/internal/version"
	"yoru.dev/yorud/internal/wifistate"
)

// Server is the HTTP front end.
type Server struct {
	Cfg     *config.Store
	Log     *logging.Logger
	Dev     *netinfo.Device
	Cap     *caps.Set
	Eng     *repeater.Engine
	Mon     Monitor
	Metrics *metrics.Store
	Clients *clients.Tracker
	WiFi    *wifistate.Reader
	Fire    *firewall.Manager
	Version Version

	http      *http.Server
	tokens    map[string]*session
	mu        sync.RWMutex
	buckets   map[string]*bucket
	bmu       sync.Mutex
	logins    map[string]*attempt
	lmu       sync.Mutex
	broad     *broadcaster
	srvMu     sync.Mutex
	bindAddrs []string
	started   time.Time
}

// Version identity for /api/v1/status.
type Version struct {
	Tag    string
	Hash   string
	Built  string
	Schema int
}

// Monitor supplies live readings; the daemon implements it. Keeping it an
// interface lets tests drive the API without any hardware at all.
type Monitor interface {
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

// session is an authenticated browser session.
type session struct {
	token    string
	created  time.Time
	expires  time.Time
	remote   string
	readonly bool
}

// NewServer wires routes.
func NewServer(cfg *config.Store, log *logging.Logger, dev *netinfo.Device, cs *caps.Set,
	eng *repeater.Engine, mon Monitor, hist *metrics.Store, trk *clients.Tracker,
	wifi *wifistate.Reader, fw *firewall.Manager, v Version) *Server {
	s := &Server{
		Cfg: cfg, Log: log, Dev: dev, Cap: cs, Eng: eng, Mon: mon, Metrics: hist,
		Clients: trk, WiFi: wifi, Fire: fw, Version: v,
		tokens: map[string]*session{}, buckets: map[string]*bucket{},
		logins: map[string]*attempt{}, broad: newBroadcaster(),
		started: time.Now(),
	}
	mux := http.NewServeMux()
	s.routes(mux)
	s.http = &http.Server{
		Handler:        s.middleware(mux),
		ReadTimeout:    15 * time.Second,
		WriteTimeout:   0, // SSE streams stay open; per-handler deadlines are used
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 16 << 10,
	}
	return s
}

// routes registers every endpoint explicitly.
func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/status", s.hStatus)
	mux.HandleFunc("GET /api/v1/health", s.hHealth)
	mux.HandleFunc("GET /api/v1/system", s.hSystem)
	mux.HandleFunc("GET /api/v1/cpu", s.hCPU)
	mux.HandleFunc("GET /api/v1/memory", s.hMemory)
	mux.HandleFunc("GET /api/v1/battery", s.hBattery)
	mux.HandleFunc("GET /api/v1/temperature", s.hThermal)
	mux.HandleFunc("GET /api/v1/storage", s.hStorage)
	mux.HandleFunc("GET /api/v1/wifi", s.hWiFi)
	mux.HandleFunc("GET /api/v1/network", s.hNetwork)
	mux.HandleFunc("GET /api/v1/clients", s.hClients)
	mux.HandleFunc("GET /api/v1/traffic", s.hTraffic)
	mux.HandleFunc("GET /api/v1/streams", s.hStreams)
	mux.HandleFunc("GET /api/v1/history", s.hHistory)
	mux.HandleFunc("GET /api/v1/logs", s.hLogs)
	mux.HandleFunc("GET /api/v1/config", s.hGetConfig)
	mux.HandleFunc("GET /api/v1/capabilities", s.hCapabilities)
	mux.HandleFunc("GET /api/v1/diagnostics", s.hDiagnostics)
	mux.HandleFunc("GET /api/v1/info", s.hInfo)

	mux.HandleFunc("POST /api/v1/login", s.hLogin)
	mux.HandleFunc("POST /api/v1/logout", s.hLogout)
	mux.HandleFunc("POST /api/v1/password", s.hPassword)
	mux.HandleFunc("POST /api/v1/repeater/start", s.hStart)
	mux.HandleFunc("POST /api/v1/repeater/stop", s.hStop)
	mux.HandleFunc("POST /api/v1/repeater/restart", s.hRestart)
	mux.HandleFunc("POST /api/v1/config", s.hPatchConfig)
	mux.HandleFunc("POST /api/v1/clients/clear", s.hClearClients)
	mux.HandleFunc("POST /api/v1/telegram/test", s.hTelegramTest)

	mux.HandleFunc("GET /api/v1/stream", s.hStream)
	mux.HandleFunc("GET /", s.hStatic)
}

// ListenAndServe binds the dashboard.
func (s *Server) ListenAndServe(addrs []string) error {
	if len(addrs) == 0 {
		return errors.New("no bind address available for the dashboard")
	}
	s.mu.Lock()
	s.bindAddrs = addrs
	s.mu.Unlock()
	var last error
	for _, a := range addrs {
		ln, err := net.Listen("tcp", a)
		if err != nil {
			last = fmt.Errorf("%s: %w", a, err)
			s.Log.Warnf("api", "cannot bind %s: %v", a, err)
			continue
		}
		s.Log.Infof("api", "dashboard listening on http://%s", a)
		if err := s.http.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
	return fmt.Errorf("dashboard could not bind any address (%s): %w", strings.Join(addrs, ", "), last)
}

// Shutdown stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

// BindAddrs returns what the server is currently listening on.
func (s *Server) BindAddrs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]string(nil), s.bindAddrs...)
}

// ---------------------------------------------------------------------------
// middleware
// ---------------------------------------------------------------------------

const maxBody = 64 << 10 // 64 KiB is far more than any config patch needs

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusWriter{ResponseWriter: w, code: 200}

		// Bounded body first, before any parsing can happen.
		if r.Body != nil {
			r.Body = http.MaxBytesReader(ww, r.Body, maxBody)
		}
		s.securityHeaders(ww, r)

		if !s.allow(r) {
			s.writeErr(ww, r, http.StatusTooManyRequests, "rate_limited",
				"Too many requests from this client. The dashboard polls slower than that; if you are scripting against the API, raise web.rateLimitPerMin.")
			s.access(r, ww, start)
			return
		}
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/") {
			if !s.authorised(ww, r) {
				s.access(r, ww, start)
				return
			}
		}
		next.ServeHTTP(ww, r)
		s.access(r, ww, start)
	})
}

func (s *Server) securityHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	h.Set("Permissions-Policy", "geolocation=(), camera=(), microphone=(), payment=()")
	// The dashboard is entirely same-origin with no inline script exceptions
	// other than a small style allowance, so CSP can stay tight.
	h.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'self'",
		"script-src 'self'",
		// Data URIs are used for the embedded logo/favicon so the module has no
		// external asset dependency at all.
		"img-src 'self' data:",
		"style-src 'self' 'unsafe-inline'",
		"font-src 'self'",
		"connect-src 'self'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
		"form-action 'self'",
	}, "; "))
	if s.Cfg.Get().Web.Auth.Enabled {
		h.Set("Vary", "Cookie")
	}
}

// access logs one request without ever recording query strings that could hold
// a token (our auth never uses queries, but defence in depth is cheap).
func (s *Server) access(r *http.Request, w *statusWriter, start time.Time) {
	d := time.Since(start)
	lvl := "debug"
	switch {
	case w.code >= 500:
		lvl = "error"
	case w.code >= 400:
		lvl = "warn"
	}
	msg := fmt.Sprintf("%s %s -> %d in %dms (%d bytes) ua=%q", r.Method, r.URL.Path, w.code, d.Milliseconds(), w.bytes, userAgent(r))
	switch lvl {
	case "error":
		s.Log.Errorf("http", "%s", msg)
	case "warn":
		s.Log.Warnf("http", "%s", msg)
	default:
		s.Log.Debugf("http", "%s", msg)
	}
}

func userAgent(r *http.Request) string {
	ua := r.UserAgent()
	if len(ua) > 80 {
		ua = ua[:80]
	}
	return logging.Redact(ua)
}

type statusWriter struct {
	http.ResponseWriter
	code  int
	bytes int
}

func (w *statusWriter) WriteHeader(c int) {
	w.code = c
	w.ResponseWriter.WriteHeader(c)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ---------------------------------------------------------------------------
// rate limiting + auth
// ---------------------------------------------------------------------------

type bucket struct {
	tokens float64
	last   time.Time
}

// allow implements a per-client token bucket. Reads and writes share the
// bucket; privileged writes additionally consume extra.
func (s *Server) allow(r *http.Request) bool {
	cfg := s.Cfg.Get()
	key := clientKey(r)
	cost := 1.0
	if privilegedPath(r.URL.Path) {
		cost = 8
	}
	s.bmu.Lock()
	defer s.bmu.Unlock()
	b, ok := s.buckets[key]
	if !ok {
		if len(s.buckets) > 4096 {
			s.pruneBucketsLocked()
		}
		b = &bucket{tokens: float64(cfg.Web.RateLimitPerMin), last: time.Now()}
		s.buckets[key] = b
	}
	rate := float64(cfg.Web.RateLimitPerMin) / 60.0
	b.tokens += time.Since(b.last).Seconds() * rate
	if b.tokens > float64(cfg.Web.RateLimitPerMin) {
		b.tokens = float64(cfg.Web.RateLimitPerMin)
	}
	b.last = time.Now()
	if b.tokens < cost {
		return false
	}
	b.tokens -= cost
	return true
}

func (s *Server) pruneBucketsLocked() {
	for k, b := range s.buckets {
		if time.Since(b.last) > 10*time.Minute {
			delete(s.buckets, k)
		}
	}
}

func privilegedPath(p string) bool {
	return strings.HasPrefix(p, "/api/v1/repeater/") ||
		p == "/api/v1/config" || p == "/api/v1/password" ||
		p == "/api/v1/clients/clear"
}

// clientKey identifies a caller for rate limiting: IP only (a LAN client behind
// NAT shares a key, which is acceptable and intentional on a private network).
func clientKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return host
}

// authorised checks the session cookie / bearer token.
//
// Policy:
//   - auth disabled                    -> everything allowed
//   - valid session                    -> everything allowed
//   - GET of monitoring endpoints, and
//     readonlyEnabled + LAN-bound      -> allowed without a session
//   - anything else                    -> 401
func (s *Server) authorised(w http.ResponseWriter, r *http.Request) bool {
	cfg := s.Cfg.Get()
	if !cfg.Web.Auth.Enabled || cfg.Web.Auth.Hash == "" {
		return true
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/login" {
		return true
	}
	// Liveness endpoint: watchdogs (and the dashboard's own "is the daemon
	// alive" probe) must reach it without a session. It exposes engine state
	// only - never configuration, secrets, logs or client detail.
	if r.Method == http.MethodGet && r.URL.Path == "/api/v1/health" {
		return true
	}
	tok := s.tokenFrom(r)
	if tok != "" {
		if sess := s.lookup(tok); sess != nil {
			if !sess.readonly || !privilegedPath(r.URL.Path) {
				return true
			}
			s.writeErr(w, r, http.StatusForbidden, "read_only_session",
				"This session is read-only. Sign in again without the read-only option to change repeater settings.")
			return false
		}
	}
	if r.Method == http.MethodGet && cfg.Web.Readonly && readOnlyPath(r.URL.Path) {
		// Unauthenticated reads are only permitted for the monitoring subset,
		// and only when the request really came from the local segment.
		if s.fromLAN(r) {
			return true
		}
		s.writeErr(w, r, http.StatusForbidden, "not_local",
			"Anonymous monitoring is restricted to the repeater's own network. Open the dashboard through the address shown on your phone.")
		return false
	}
	s.writeErr(w, r, http.StatusUnauthorized, "unauthenticated",
		"Sign in with the dashboard password to read this data.")
	return false
}

// readOnlyPath is the subset that may be exposed without credentials.
func readOnlyPath(p string) bool {
	switch p {
	case "/api/v1/status", "/api/v1/health", "/api/v1/cpu", "/api/v1/memory",
		"/api/v1/battery", "/api/v1/temperature", "/api/v1/storage",
		"/api/v1/traffic", "/api/v1/wifi", "/api/v1/network",
		"/api/v1/clients", "/api/v1/system", "/api/v1/capabilities", "/api/v1/info":
		return true
	}
	return false
}

func (s *Server) tokenFrom(r *http.Request) string {
	if c, err := r.Cookie(sessionCookie); err == nil && c.Value != "" {
		return c.Value
	}
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	return ""
}

const (
	sessionCookie = "yorusid"
	sessionHeader = "X-Yoru-Token"
)

func (s *Server) newSession(readonly bool, remote string) *session {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return nil
	}
	tok := base64.RawURLEncoding.EncodeToString(buf)
	cfg := s.Cfg.Get()
	now := time.Now()
	sess := &session{
		token: tok, created: now,
		expires: now.Add(time.Duration(cfg.Web.SessionHours) * time.Hour),
		remote:  remote, readonly: readonly,
	}
	s.mu.Lock()
	s.gcSessionsLocked()
	s.tokens[tok] = sess
	s.mu.Unlock()
	return sess
}

func (s *Server) lookup(tok string) *session {
	s.mu.RLock()
	sess, ok := s.tokens[tok]
	s.mu.RUnlock()
	if !ok {
		return nil
	}
	if time.Now().After(sess.expires) {
		s.drop(tok)
		return nil
	}
	return sess
}

func (s *Server) drop(tok string) {
	s.mu.Lock()
	delete(s.tokens, tok)
	s.mu.Unlock()
}

func (s *Server) gcSessionsLocked() {
	now := time.Now()
	for t, sess := range s.tokens {
		if now.After(sess.expires) {
			delete(s.tokens, t)
		}
	}
}

// fromLAN verifies the peer is on a network Yoru knows about (a downstream LAN
// or loopback). This is what makes "allow LAN access" a real boundary.
func (s *Server) fromLAN(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	cfg := s.Cfg.Get()
	if n, err := cfg.Network(); err == nil && n.Contains(ip) {
		return true
	}
	addrs, _ := s.Dev.Addrs()
	for _, a := range addrs {
		if a.Family != "IPv4" {
			continue
		}
		if _, n, err := net.ParseCIDR(a.CIDR); err == nil && n.Contains(ip) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// response helpers
// ---------------------------------------------------------------------------

type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
	Path    string `json:"path,omitempty"`
}

type apiResp struct {
	OK    bool      `json:"ok"`
	Data  any       `json:"data,omitempty"`
	Error *apiError `json:"error,omitempty"`
	Meta  metaBlock `json:"meta"`
}

type metaBlock struct {
	API     string `json:"api"`
	Version string `json:"version"`
	Time    int64  `json:"timeMs"`
	Schema  int    `json:"schema"`
}

func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, code int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	resp := apiResp{OK: code < 400, Data: data, Meta: s.meta()}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(resp); err != nil {
		s.Log.Warnf("api", "encode failed: %v", err)
	}
}

func (s *Server) writeErr(w http.ResponseWriter, r *http.Request, code int, ec, msg string) {
	s.writeErrHint(w, r, code, ec, msg, "")
}

func (s *Server) writeErrHint(w http.ResponseWriter, r *http.Request, code int, ec, msg, hint string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if code == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Yoru realm="Yoru Repeater dashboard"`)
	}
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(apiResp{
		OK:    false,
		Error: &apiError{Code: ec, Message: logging.Redact(msg), Hint: hint, Path: r.URL.Path},
		Meta:  s.meta(),
	})
}

func (s *Server) meta() metaBlock {
	return metaBlock{API: version.APIVersion, Version: s.Version.Tag, Time: time.Now().UnixMilli(), Schema: s.Version.Schema}
}

// decode reads a bounded JSON body into v, rejecting unknown fields so a typo
// cannot silently do nothing.
func (s *Server) decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if r.Body == nil {
		s.writeErr(w, r, http.StatusBadRequest, "empty_body", "A JSON request body is required.")
		return false
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			s.writeErr(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "Request body exceeds 64 KiB.")
			return false
		}
		s.writeErr(w, r, http.StatusBadRequest, "malformed_json", "The request body is not valid JSON: "+err.Error())
		return false
	}
	// Reject trailing content after the object.
	if dec.More() {
		s.writeErr(w, r, http.StatusBadRequest, "trailing_data", "Only one JSON object may be sent per request.")
		return false
	}
	return true
}

var identRe = regexp.MustCompile(`^[A-Za-z0-9._:\-]{1,64}$`)

// ---------------------------------------------------------------------------
// read handlers
// ---------------------------------------------------------------------------

func (s *Server) hInfo(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Get()
	kernel := sysinfo.KernelInfo()
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"product": "Yoru Repeater",
		"version": s.Version.Tag,
		"hash":    s.Version.Hash,
		"built":   s.Version.Built,
		"api":     version.APIVersion,
		"schema":  s.Version.Schema,
		"android": map[string]any{
			"release":       sysinfo.Getprop("ro.build.version.release"),
			"sdk":           atoi(sysinfo.Getprop("ro.build.version.sdk")),
			"securityPatch": sysinfo.Getprop("ro.build.version.security_patch"),
			"incremental":   sysinfo.Getprop("ro.build.version.incremental"),
			"board":         sysinfo.Getprop("ro.product.board"),
			"hardware":      sysinfo.Getprop("ro.hardware"),
			"soc":           sysinfo.Getprop("ro.soc.model"),
			"device":        sysinfo.Getprop("ro.product.device"),
			"manufacturer":  sysinfo.Getprop("ro.product.manufacturer"),
			"model":         sysinfo.Getprop("ro.product.model"),
			"fingerprint":   sysinfo.Getprop("ro.build.fingerprint"),
		},
		"kernel":    kernel,
		"arch":      sysinfo.Getprop("ro.product.cpu.abi"),
		"bootId":    sysinfo.BootId(),
		"uptimeSec": sysinfo.ReadUptime(),
		"root":      rootInfo(),
		"selinux":   selinuxInfo(),
		"web": map[string]any{
			"port": cfg.Web.Port, "auth": cfg.Web.Auth.Enabled,
			"readonly": cfg.Web.Readonly, "bind": cfg.Web.Bind,
		},
		"endpoints": s.endpoints(),
	})
}

func (s *Server) endpoints() []string {
	return []string{
		"GET /api/v1/status", "GET /api/v1/health", "GET /api/v1/system",
		"GET /api/v1/cpu", "GET /api/v1/memory", "GET /api/v1/battery",
		"GET /api/v1/temperature", "GET /api/v1/storage", "GET /api/v1/wifi",
		"GET /api/v1/network", "GET /api/v1/clients", "GET /api/v1/traffic",
		"GET /api/v1/history", "GET /api/v1/logs", "GET /api/v1/config",
		"GET /api/v1/capabilities", "GET /api/v1/diagnostics", "GET /api/v1/info",
		"GET /api/v1/stream", "POST /api/v1/login", "POST /api/v1/logout",
		"POST /api/v1/password", "POST /api/v1/repeater/start",
		"POST /api/v1/repeater/stop", "POST /api/v1/repeater/restart",
		"POST /api/v1/config", "POST /api/v1/clients/clear",
	}
}

func (s *Server) hStatus(w http.ResponseWriter, r *http.Request) {
	st := s.Eng.Status()
	cfg := s.Cfg.Get()
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"repeater":      st,
		"internet":      st.Internet,
		"clientsOnline": s.Clients.Stats().Online,
		"clientsTotal":  s.Clients.Stats().Total,
		"auth": map[string]any{
			"required":      cfg.Web.Auth.Enabled && cfg.Web.Auth.Hash != "",
			"authenticated": s.hasSession(r),
			"readonly":      cfg.Web.Readonly,
		},
		"mode": st.Mode, "modeLabel": st.ModeLabel,
		"uptimeSec":     int64(time.Since(s.started).Seconds()),
		"dashboardUrls": s.DashboardURLs(cfg.Web.Port),
	})
}

func (s *Server) hasSession(r *http.Request) bool {
	tok := s.tokenFrom(r)
	return tok != "" && s.lookup(tok) != nil
}

// DashboardURLs computes the addresses a client can actually use, which is the
// single most useful thing to show in the UI.
func (s *Server) DashboardURLs(port int) []string {
	var out []string
	addrs, err := s.Dev.Addrs()
	if err != nil {
		return out
	}
	seen := map[string]bool{}
	for _, a := range addrs {
		if a.Family != "IPv4" || a.IP == "" {
			continue
		}
		ip := net.ParseIP(a.IP)
		if ip == nil || ip.IsLoopback() {
			continue
		}
		l, err := s.Dev.Link(a.Iface)
		if err != nil || !l.Up {
			continue
		}
		class := netinfo.Classify(l)
		if class == netinfo.ClassWiFiAP || class == netinfo.ClassWiFiSTA ||
			class == netinfo.ClassEthernet || class == netinfo.ClassUSB || class == netinfo.ClassCellular {
			u := fmt.Sprintf("http://%s:%d", ip, port)
			if !seen[u] {
				seen[u] = true
				out = append(out, u)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (s *Server) hHealth(w http.ResponseWriter, r *http.Request) {
	h := s.Mon.Health()
	code := http.StatusOK
	if st, ok := h["state"].(string); ok && (st == "failed" || st == "cooldown") {
		code = http.StatusServiceUnavailable
	}
	s.writeJSON(w, r, code, h)
}

func (s *Server) hSystem(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.System())
}
func (s *Server) hCPU(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.CPU())
}
func (s *Server) hMemory(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.Memory())
}
func (s *Server) hBattery(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.Battery())
}
func (s *Server) hThermal(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.Thermal())
}
func (s *Server) hStorage(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.Storage())
}
func (s *Server) hWiFi(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.WiFi())
}
func (s *Server) hNetwork(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.Network())
}
func (s *Server) hTraffic(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.Traffic())
}
func (s *Server) hCapabilities(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"capabilities": s.Cap.All(),
		"summary":      s.Cap.Summarise(),
		"strategies":   s.Eng.Strategies(),
	})
}

func (s *Server) hDiagnostics(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, s.Mon.Diagnostics())
}

func (s *Server) hClients(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// Every lease source the device actually has, in trust order. Missing
	// sources are simply absent - never faked.
	readers := []clients.LeaseReader{
		clients.DHCPLeases{Path: s.Eng.LeaseFile()},
		clients.DnsmasqLeases{Paths: dnsmasqLeasePaths()},
		clients.ARPFileLeases{},
	}
	list := s.Clients.Scan(readers...)
	filtered := applyClientFilters(list, q.Get("q"), q.Get("state"))
	sortClients(filtered, q.Get("sort"))
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"clients": filtered, "stats": s.Clients.Stats(),
		"mask":         s.Cfg.Get().Monitor.MaskMACs,
		"leaseSources": sourcesOf(readers),
	})
}

// dnsmasqLeasePaths lists where a dnsmasq lease file may live on Android.
func dnsmasqLeasePaths() []string {
	return []string{
		"/data/misc/dhcp/dnsmasq.leases",
		"/data/misc/apexdata/com.android.tethering/misc/dhcp/dnsmasq.leases",
		"/data/misc/dnsmasq.leases",
		"/mnt/vendor/persist/dnsmasq.leases",
		"/tmp/dnsmasq.leases",
	}
}

func sourcesOf(rs []clients.LeaseReader) []string {
	var out []string
	for _, r := range rs {
		out = append(out, r.SourceName())
	}
	return out
}

func applyClientFilters(list []clients.Client, q, state string) []clients.Client {
	q = strings.ToLower(strings.TrimSpace(q))
	var out []clients.Client
	for _, c := range list {
		if state == "online" && !c.Online {
			continue
		}
		if state == "offline" && c.Online {
			continue
		}
		if q != "" {
			hay := strings.ToLower(c.Hostname + " " + c.IPv4 + " " + strings.Join(c.IPv6, " ") + " " + c.MACDisplay + " " + c.DeviceGuess)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, c)
	}
	return out
}

func sortClients(list []clients.Client, key string) {
	switch key {
	case "name":
		sort.Slice(list, func(i, j int) bool {
			a, b := list[i].Hostname, list[j].Hostname
			if a == "" {
				a = list[i].IPv4
			}
			if b == "" {
				b = list[j].IPv4
			}
			return a < b
		})
	case "traffic":
		sort.Slice(list, func(i, j int) bool {
			return list[i].RxBytes+list[i].TxBytes > list[j].RxBytes+list[j].TxBytes
		})
	case "rx":
		sort.Slice(list, func(i, j int) bool { return list[i].RxBytes > list[j].RxBytes })
	case "tx":
		sort.Slice(list, func(i, j int) bool { return list[i].TxBytes > list[j].TxBytes })
	case "newest":
		sort.Slice(list, func(i, j int) bool { return list[i].FirstSeen > list[j].FirstSeen })
	default: // online first, then oldest connection
		sort.SliceStable(list, func(i, j int) bool {
			if list[i].Online != list[j].Online {
				return list[i].Online
			}
			return list[i].FirstSeen < list[j].FirstSeen
		})
	}
}

func (s *Server) hHistory(w http.ResponseWriter, r *http.Request) {
	n := atoiDefault(r.URL.Query().Get("points"), 120)
	if n > 1200 {
		n = 1200
	}
	series := r.URL.Query().Get("series")
	all := s.Metrics.Range(n)
	if series != "" && series != "all" {
		if v, ok := all[series]; ok {
			all = map[string][]metrics.Sample{series: v}
		} else {
			var names []string
			for _, k := range seriesNames(s.Metrics) {
				names = append(names, k)
			}
			s.writeErr(w, r, http.StatusBadRequest, "unknown_series",
				fmt.Sprintf("No history series named %q. Available: %s", series, strings.Join(names, ", ")))
			return
		}
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"points": n, "series": all})
}

func (s *Server) hStreams(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for k, v := range s.Metrics.All() {
		out[k] = v.Summary()
	}
	s.writeJSON(w, r, http.StatusOK, out)
}

func (s *Server) hLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	n := atoiDefault(q.Get("limit"), 200)
	if n > 5000 {
		n = 5000
	}
	level := logging.ParseLevel(q.Get("level"))
	entries := s.Log.Tail(n*3, level, q.Get("q"))
	if len(entries) > n {
		entries = entries[len(entries)-n:]
	}
	resp := map[string]any{
		"entries": entries, "count": len(entries),
		"level": level.String(), "logger": s.Log.Stats(),
	}
	if q.Get("download") == "text" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="yoru-logs.txt"`)
		w.WriteHeader(http.StatusOK)
		for _, e := range entries {
			fmt.Fprintf(w, "%s [%s] %s: %s\n", time.UnixMilli(e.Time).Format("2006-01-02 15:04:05"), e.Level, e.Src, e.Msg)
		}
		return
	}
	s.writeJSON(w, r, http.StatusOK, resp)
}

func (s *Server) hGetConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Get()
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"config":   cfg.Public(),
		"warnings": s.Cfg.Warnings(),
		"available": map[string]any{
			"bands":      availableBands(s.Cap),
			"channels":   availableChannels(s.Cap),
			"securities": availableSecurities(s.Cap),
			"interfaces": interfaceNames(s.Dev),
			"dhcpModes":  []string{"auto", "builtin", "off"},
			"dnsModes":   []string{"auto", "builtin", "off"},
		},
		"password": map[string]any{"required": cfg.Web.Auth.Enabled && cfg.Web.Auth.Hash == ""},
	})
}

// availableBands only offers what the radios can actually do.
func availableBands(c *caps.Set) []string {
	out := []string{}
	for _, r := range c.Radios() {
		if len(r.Channels2G) > 0 && !contains(out, "2g") {
			out = append(out, "2g")
		}
		if len(r.Channels5G) > 0 && !contains(out, "5g") {
			out = append(out, "5g")
		}
		if len(r.Channels6G) > 0 && !contains(out, "6g") {
			out = append(out, "6g")
		}
	}
	if len(out) == 0 {
		out = []string{"2g"}
	}
	return out
}

func availableChannels(c *caps.Set) map[string][]int {
	out := map[string][]int{}
	for _, r := range c.Radios() {
		if len(r.Channels2G) > 0 {
			out["2g"] = append(out["2g"], r.Channels2G...)
		}
		if len(r.Channels5G) > 0 {
			out["5g"] = append(out["5g"], r.Channels5G...)
		}
		if len(r.Channels6G) > 0 {
			out["6g"] = append(out["6g"], r.Channels6G...)
		}
	}
	for k := range out {
		sortInts(out[k])
		out[k] = uniqInts(out[k])
	}
	if _, ok := out["2g"]; !ok {
		out["2g"] = []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}
	}
	return out
}

// availableSecurities downgrades WPA3 if the driver cannot do it.
func availableSecurities(c *caps.Set) []string {
	out := []string{"open", "wpa2-psk", "wpa2-wpa3"}
	for _, r := range c.Radios() {
		if r.He || r.Vht {
			out = append(out, "wpa3-sae")
			break
		}
	}
	if !c.Has(caps.Hostapd) && !c.Has(caps.HostapdBundled) {
		// With the framework hotspot the OS chooses security.
		return []string{"wpa2-psk"}
	}
	return out
}

func interfaceNames(dev *netinfo.Device) []string {
	links, err := dev.Links()
	if err != nil {
		return nil
	}
	var out []string
	for _, l := range links {
		if l.Loopback {
			continue
		}
		out = append(out, l.Name)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// write handlers
// ---------------------------------------------------------------------------

func (s *Server) hLogin(w http.ResponseWriter, r *http.Request) {
	cfg := s.Cfg.Get()
	if !cfg.Web.Auth.Enabled {
		s.writeErr(w, r, http.StatusBadRequest, "auth_disabled", "Authentication is disabled, so there is nothing to sign in to.")
		return
	}
	if cfg.Web.Auth.Hash == "" {
		s.writeErrHint(w, r, http.StatusPreconditionFailed, "no_password",
			"No dashboard password has been set yet.",
			"Set one from a root shell: yoructl password <new-password>")
		return
	}
	var body struct {
		Password string `json:"password"`
		Readonly bool   `json:"readonly"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	key := clientKey(r)
	if retryAfter, locked := s.locked(key); locked {
		wd := retryAfter.Round(time.Second)
		w.Header().Set("Retry-After", fmt.Sprint(int(wd.Seconds())))
		s.writeErr(w, r, http.StatusTooManyRequests, "login_throttled",
			fmt.Sprintf("Too many failed sign-in attempts. Try again in %s.", wd))
		return
	}
	if !cfg.VerifyPassword(body.Password) {
		s.recordFail(key)
		s.Log.Warnf("auth", "failed sign-in from %s", key)
		s.writeErr(w, r, http.StatusUnauthorized, "bad_credentials", "That password is not correct.")
		return
	}
	s.recordOK(key)
	sess := s.newSession(body.Readonly, key)
	if sess == nil {
		s.writeErr(w, r, http.StatusInternalServerError, "session_error", "Could not create a session.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: sess.token, Path: "/",
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		Secure:  false, // the dashboard is served over plain HTTP on a LAN
		Expires: sess.expires, MaxAge: int(time.Until(sess.expires).Seconds()),
	})
	s.Log.Infof("auth", "signed in from %s (read-only=%v)", key, body.Readonly)
	s.writeJSON(w, r, http.StatusOK, map[string]any{
		"expiresMs": sess.expires.UnixMilli(), "readonly": body.Readonly,
		"token": sess.token, "hint": "Use the Authorization: Bearer <token> header for scripting.",
	})
}

type attempt struct {
	fails     int
	firstFail time.Time
	nextTry   time.Time
}

// recordFail implements escalating lockout: 5 failures -> 30s, 10 -> 5m, more
// -> 30m. This stops a LAN client from brute-forcing the dashboard while keeping
// a legitimate fat-fingered user unblocked quickly.
func (s *Server) recordFail(key string) {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	a := s.logins[key]
	if a == nil {
		a = &attempt{firstFail: time.Now()}
		s.logins[key] = a
	}
	a.fails++
	switch {
	case a.fails >= 20:
		a.nextTry = time.Now().Add(30 * time.Minute)
	case a.fails >= 10:
		a.nextTry = time.Now().Add(5 * time.Minute)
	case a.fails >= 5:
		a.nextTry = time.Now().Add(30 * time.Second)
	}
}

func (s *Server) recordOK(key string) {
	s.lmu.Lock()
	delete(s.logins, key)
	s.lmu.Unlock()
}

func (s *Server) locked(key string) (time.Duration, bool) {
	s.lmu.Lock()
	defer s.lmu.Unlock()
	a := s.logins[key]
	if a == nil {
		return 0, false
	}
	if time.Now().After(a.nextTry) {
		if time.Since(a.firstFail) > time.Hour {
			delete(s.logins, key)
		}
		return 0, false
	}
	return time.Until(a.nextTry), true
}

func (s *Server) hLogout(w http.ResponseWriter, r *http.Request) {
	if tok := s.tokenFrom(r); tok != "" {
		s.drop(tok)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Expires: time.Unix(0, 0)})
	s.writeJSON(w, r, http.StatusOK, map[string]any{"signedOut": true})
}

func (s *Server) hPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Current  string `json:"current"`
		Disable  bool   `json:"disable"`
	}
	if !s.decode(w, r, &body) {
		return
	}
	cfg := s.Cfg.Get()
	if cfg.Web.Auth.Hash != "" {
		if body.Current == "" {
			s.writeErrHint(w, r, http.StatusBadRequest, "current_required",
				"Changing the dashboard password requires the current one.",
				"Sign out and back in if you have forgotten it, or reset it from a root shell with yoructl password.")
			return
		}
		if !cfg.VerifyPassword(body.Current) {
			s.writeErr(w, r, http.StatusUnauthorized, "bad_credentials", "The current password is not correct.")
			return
		}
	}
	if body.Disable {
		if err := s.Cfg.DisablePassword(); err != nil {
			s.writeErr(w, r, http.StatusInternalServerError, "write_failed", "Could not save: "+err.Error())
			return
		}
		s.mu.Lock()
		s.tokens = map[string]*session{}
		s.mu.Unlock()
		s.Log.Warnf("auth", "dashboard authentication disabled through the API")
		s.writeJSON(w, r, http.StatusOK, map[string]any{"authEnabled": false})
		return
	}
	if err := s.Cfg.SetPassword(body.Password); err != nil {
		s.writeErrHint(w, r, http.StatusBadRequest, "weak_password", err.Error(),
			"Use at least 8 characters. Avoid putting the Wi-Fi key here.")
		return
	}
	s.mu.Lock()
	s.tokens = map[string]*session{}
	s.mu.Unlock()
	s.Log.Infof("auth", "dashboard password changed through the API")
	s.writeJSON(w, r, http.StatusOK, map[string]any{"authEnabled": true, "sessionsRevoked": true})
}

// hPatchConfig applies a partial config change. Repeater changes are staged:
// validate -> apply -> if the engine rejects it, restore and report.
func (s *Server) hPatchConfig(w http.ResponseWriter, r *http.Request) {
	var patch map[string]any
	if !s.decode(w, r, &patch) {
		return
	}
	if len(patch) == 0 {
		s.writeErr(w, r, http.StatusBadRequest, "empty_patch", "Send at least one configuration key to change.")
		return
	}
	before := s.Cfg.Get()
	body, err := json.Marshal(patch)
	if err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "encode_failed", err.Error())
		return
	}
	warnings, err := s.Cfg.MergePatch(body)
	if err != nil {
		s.writeErrHint(w, r, http.StatusUnprocessableEntity, "invalid_config", err.Error(),
			"Nothing was changed. Fix the value and send the request again.")
		return
	}
	after := s.Cfg.Get()
	resp := map[string]any{"warnings": warnings, "config": after.Public()}

	// Decide what must happen to the running engine.
	needRestart := repeaterTouched(before, after)
	needApply := monitorTouched(before, after)
	if needApply {
		s.applyRuntime(after)
	}
	if needRestart {
		switch s.Eng.State() {
		case repeater.Running, repeater.Degraded:
			if err := s.Eng.Restart(); err != nil {
				// Roll the configuration back so the persistent state matches
				// reality rather than promising something that is not running.
				if _, rbErr := s.Cfg.Apply(before); rbErr != nil {
					s.Log.Errorf("api", "config rollback FAILED (%v) - manual review needed", rbErr)
					resp["rollbackFailed"] = rbErr.Error()
				} else {
					resp["rolledBack"] = true
					s.applyRuntime(before)
				}
				s.writeErrHint(w, r, http.StatusConflict, "apply_failed",
					"The new settings were rejected and reverted: "+err.Error(),
					"Open Diagnostics for the full step-by-step failure report.")
				return
			}
			resp["restarted"] = true
		case repeater.Stopped:
			resp["saved"] = true
			resp["note"] = "Settings saved. The repeater is stopped, so they will apply the next time it starts."
		default:
			resp["saved"] = true
			resp["note"] = "Settings saved but the repeater is " + string(s.Eng.State()) + "; restart it to apply."
		}
	}
	_ = after
	s.Log.Infof("api", "configuration updated (restart=%v keys=%s)", needRestart, strings.Join(keysOf(patch), ","))
	s.writeJSON(w, r, http.StatusOK, resp)
}

// applyRuntime pushes configuration that needs no restart into live objects.
func (s *Server) applyRuntime(cfg *config.Config) {
	if cfg.Monitor.MaskMACs {
		s.Clients.SetMaskMACs(true)
	} else {
		s.Clients.SetMaskMACs(false)
	}
	s.Log.SetLevel(levelFor(cfg))
	s.Metrics.Resize(cfg.Monitor.HistoryPoints)
}

func levelFor(cfg *config.Config) logging.Level {
	if cfg.Advanced.Debug {
		return logging.Debug
	}
	return logging.Info
}

func repeaterTouched(a, b *config.Config) bool {
	sa, sb := fmt.Sprintf("%#v", a.Repeater), fmt.Sprintf("%#v", b.Repeater)
	return sa != sb
}

func monitorTouched(a, b *config.Config) bool {
	return fmt.Sprintf("%#v", a.Monitor) != fmt.Sprintf("%#v", b.Monitor) || a.Advanced.Debug != b.Advanced.Debug
}

func (s *Server) hStart(w http.ResponseWriter, r *http.Request)   { s.control(w, r, "start") }
func (s *Server) hStop(w http.ResponseWriter, r *http.Request)    { s.control(w, r, "stop") }
func (s *Server) hRestart(w http.ResponseWriter, r *http.Request) { s.control(w, r, "restart") }

func (s *Server) control(w http.ResponseWriter, r *http.Request, action string) {
	cfg := s.Cfg.Get()
	// Enforce a password before any network change if auth is on.
	if cfg.Web.Auth.Enabled && cfg.Web.Auth.Hash != "" && !s.hasSession(r) {
		s.writeErr(w, r, http.StatusUnauthorized, "unauthenticated", "Sign in before changing the repeater.")
		return
	}
	var err error
	switch action {
	case "start":
		err = s.Eng.Start(false)
	case "stop":
		err = s.Eng.Stop()
	case "restart":
		err = s.Eng.Restart()
	}
	if err != nil {
		s.writeErrHint(w, r, http.StatusConflict, action+"_failed", err.Error(),
			"The repeater page lists which capability blocked it, and Diagnostics has the raw probe results.")
		return
	}
	if action == "start" {
		if err := s.Cfg.MergePatchSet(func(c *config.Config) { c.Repeater.Enabled = true }); err != nil {
			s.Log.Debugf("api", "could not persist enabled=true: %v", err)
		}
	} else {
		if err := s.Cfg.MergePatchSet(func(c *config.Config) { c.Repeater.Enabled = false }); err != nil {
			s.Log.Debugf("api", "could not persist enabled=false: %v", err)
		}
	}
	s.Cap.Invalidate()
	s.writeJSON(w, r, http.StatusOK, map[string]any{"action": action, "status": s.Eng.Status()})
}

func (s *Server) hClearClients(w http.ResponseWriter, r *http.Request) {
	if err := s.Clients.Clear(); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "clear_failed", err.Error())
		return
	}
	s.Log.Infof("api", "device history cleared")
	s.writeJSON(w, r, http.StatusOK, map[string]any{"cleared": true})
}

func (s *Server) hTelegramTest(w http.ResponseWriter, r *http.Request) {
	tg := s.Cfg.Get().Telegram
	var body struct {
		BotToken string `json:"botToken"`
		ChatID   string `json:"chatId"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 1024)).Decode(&body)
	if body.BotToken != "" {
		tg.BotToken = body.BotToken
	}
	if body.ChatID != "" {
		tg.ChatID = body.ChatID
	}
	if tg.BotToken == "" || tg.ChatID == "" {
		s.writeErr(w, r, http.StatusBadRequest, "missing_config", "Bot token and Chat ID are required")
		return
	}
	msg := "🔔 <b>Yoru Repeater</b>\nTest notification from " + s.Version.Tag + "\nDevice: " + hostname()
	if err := telegram.Send(tg.BotToken, tg.ChatID, msg); err != nil {
		s.writeErr(w, r, http.StatusInternalServerError, "send_failed", err.Error())
		return
	}
	s.writeJSON(w, r, http.StatusOK, map[string]any{"sent": true})
}

func hostname() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "yoru-device"
	}
	return h
}

// ---------------------------------------------------------------------------
// SSE
// ---------------------------------------------------------------------------

func (s *Server) hStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		s.writeErr(w, r, http.StatusInternalServerError, "streaming_unsupported", "This server cannot stream.")
		return
	}
	// Streaming endpoints are cheap to hold open but expensive to ignore, so
	// bind them to the same session policy as reads.
	if !s.authorised(w, r) {
		return
	}
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	sub := s.broad.subscribe()
	defer s.broad.unsubscribe(sub)

	_, _ = io.WriteString(w, "retry: 3000\n\n")
	_, _ = io.WriteString(w, "event: hello\ndata: "+`{"version":"`+s.Version.Tag+`","ts":`+fmt.Sprint(time.Now().UnixMilli())+"}\n\n")
	flusher.Flush()

	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	beat := time.NewTicker(20 * time.Second)
	defer beat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case evt, ok := <-sub:
			if !ok {
				return
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", evt.Name, evt.Data); err != nil {
				return
			}
			flusher.Flush()
		case <-beat.C:
			if _, err := io.WriteString(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-ticker.C:
			// Idle: nothing to send; the ticker exists so the select stays cheap.
		}
	}
}

// Publish sends one realtime frame to every open stream.
func (s *Server) Publish(name string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		s.Log.Warnf("api", "cannot encode %s event: %v", name, err)
		return
	}
	s.broad.publish(event{Name: name, Data: string(b)})
}

type event struct {
	Name string
	Data string
}

type broadcaster struct {
	mu      sync.Mutex
	subs    map[chan event]bool
	dropped uint64
}

func newBroadcaster() *broadcaster {
	return &broadcaster{subs: map[chan event]bool{}}
}

func (b *broadcaster) subscribe() chan event {
	ch := make(chan event, 12)
	b.mu.Lock()
	b.subs[ch] = true
	b.mu.Unlock()
	return ch
}

func (b *broadcaster) unsubscribe(ch chan event) {
	b.mu.Lock()
	delete(b.subs, ch)
	b.mu.Unlock()
	close(ch)
}

// publish never blocks: a slow or dead client is dropped rather than stalling
// the monitoring loop that produced the frame.
func (b *broadcaster) publish(e event) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs {
		select {
		case ch <- e:
		default:
			b.dropped++
		}
	}
}

func (b *broadcaster) clients() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.subs)
}

// ---------------------------------------------------------------------------
// static assets
// ---------------------------------------------------------------------------

func (s *Server) hStatic(w http.ResponseWriter, r *http.Request) {
	p := path.Clean(r.URL.Path)
	if strings.Contains(p, "..") {
		s.writeErr(w, r, http.StatusBadRequest, "bad_path", "Invalid path.")
		return
	}
	name := strings.TrimPrefix(p, "/")
	if name == "" || name == "." {
		name = "index.html"
	}
	data, ctype, ok := s.asset(name)
	if !ok {
		// Unknown non-API paths fall back to the SPA shell only for GET of a
		// path with no extension; otherwise 404 so mistakes are visible.
		if !strings.Contains(path.Base(name), ".") && r.Method == http.MethodGet {
			data, ctype, ok = s.asset("index.html")
		}
		if !ok {
			s.writeErr(w, r, http.StatusNotFound, "not_found", "No such file: "+name)
			return
		}
	}
	// Auth gate for the dashboard itself: unauthenticated callers get the
	// sign-in page (which is part of the bundle), never the data.
	cfg := s.Cfg.Get()
	if cfg.Web.Auth.Enabled && cfg.Web.Auth.Hash != "" && !s.hasSession(r) && name == "index.html" {
		w.Header().Set("Cache-Control", "no-store")
	}
	w.Header().Set("Content-Type", ctype)
	if name == "index.html" || strings.HasSuffix(name, ".css") || strings.HasSuffix(name, ".js") {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	} else {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeContent(w, r, name, s.started, bytesReaderAt(data))
}

func (s *Server) asset(name string) ([]byte, string, bool) {
	// Only a fixed set of extensions may be served, which removes any chance of
	// the embed index being tricked into exposing something odd.
	ext := strings.ToLower(path.Ext(name))
	valid := map[string]bool{
		".html": true, ".css": true, ".js": true, ".json": true, ".svg": true,
		".png": true, ".woff2": true, ".ico": true, ".webmanifest": true, ".txt": true,
	}
	if !valid[ext] {
		return nil, "", false
	}
	if !embedded(name) {
		return nil, "", false
	}
	b, err := distFS.ReadFile("dist/" + name)
	if err != nil {
		return nil, "", false
	}
	return b, ctypeFor(ext), true
}

var typeMap = map[string]string{
	".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
	".js": "text/javascript; charset=utf-8", ".json": "application/json",
	".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
	".woff2": "font/woff2", ".webmanifest": "application/manifest+json",
	".txt": "text/plain; charset=utf-8",
}

func ctypeFor(ext string) string {
	if t, ok := typeMap[ext]; ok {
		return t
	}
	return "application/octet-stream"
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

func atoi(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return n
		}
		n = n*10 + int(s[i]-'0')
	}
	return n
}

func atoiDefault(s string, def int) int {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	n := 0
	for i := 0; i < len(s) && i < 7; i++ {
		if s[i] < '0' || s[i] > '9' {
			return def
		}
		n = n*10 + int(s[i]-'0')
	}
	if neg {
		return -n
	}
	return n
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// seriesNames lists available chart series for error messages.
func seriesNames(m *metrics.Store) []string {
	out := make([]string, 0, len(m.All()))
	for k := range m.All() {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func sortInts(l []int) {
	sort.Slice(l, func(i, j int) bool { return l[i] < l[j] })
}

func uniqInts(in []int) []int {
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

func rootInfo() map[string]any {
	out := map[string]any{}
	if v := os.Getenv("KSU"); v != "" {
		out["implementation"] = "KernelSU"
		out["version"] = v
	} else if v := os.Getenv("APATCH"); v != "" {
		out["implementation"] = "APatch"
		out["version"] = v
	} else if v := sysinfo.Getprop("ro.magisk.version"); v != "" {
		out["implementation"] = "Magisk"
		out["version"] = v
	}
	if _, err := os.Stat("/data/adb/magisk"); err == nil {
		out["magiskDir"] = true
	}
	if _, err := os.Stat("/data/adb/ksu"); err == nil {
		out["kernelsuDir"] = true
	}
	out["uid"] = os.Getuid()
	out["pid"] = os.Getpid()
	return out
}

func selinuxInfo() map[string]any {
	mode, policy := sysinfo.SELinuxStatus()
	out := map[string]any{"mode": mode}
	if mode == "" {
		out["state"] = "not readable"
	} else {
		out["state"] = mode
	}
	if policy != "" {
		out["policy"] = policy
	}
	return out
}
