// CLI control commands: `yorud start|stop|restart|status|config|logs|diagnose|password`.
//
// The CLI talks to the running daemon over loopback HTTP using a token that only
// root can read, so there is exactly one implementation of every privileged
// action and no second, unauthenticated root path into the network stack.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"yoru.dev/yorud/internal/config"
	"yoru.dev/yorud/internal/version"
)

// control implements the sub-commands. Exit codes:
//
//	0 ok | 1 generic error | 2 usage | 3 not running | 4 refused by policy
func control(cmd string, args []string) int {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	stateDir := fs.String("state", envOr("YORU_STATE_DIR", defaultStateDir), "state directory")
	port := fs.Int("port", 0, "dashboard port (0 = read from the configuration)")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	timeout := fs.Duration("timeout", 10*time.Second, "how long to wait")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cfg, cfgPath := loadConfigForCLI(*stateDir)
	p := *port
	if p == 0 {
		p = cfg.Web.Port
	}
	base := fmt.Sprintf("http://127.0.0.1:%d", p)

	switch cmd {
	case "version":
		fmt.Printf("Yoru Repeater %s (%s) schema=%d api=%s\n", version.GitTag, version.GitHash, version.SchemaVersion, version.APIVersion)
		return 0

	case "help":
		usage()
		return 0

	case "status":
		body, code, err := apiGet(base, "/api/v1/status", cfg, *timeout)
		if err != nil {
			return reportDown(err, *jsonOut)
		}
		if code == http.StatusUnauthorized {
			fmt.Fprintln(os.Stderr, "the dashboard requires authentication; pass --json to read the raw response")
		}
		return emit(body, *jsonOut, renderStatus)

	case "start":
		return action(base, cfg, "/api/v1/repeater/start", *timeout, *jsonOut)
	case "stop":
		return action(base, cfg, "/api/v1/repeater/stop", *timeout, *jsonOut)
	case "restart":
		return action(base, cfg, "/api/v1/repeater/restart", *timeout, *jsonOut)

	case "logs":
		lfs := flag.NewFlagSet("logs", flag.ContinueOnError)
		n := lfs.Int("n", 60, "lines")
		level := lfs.String("level", "debug", "minimum level")
		q := lfs.String("grep", "", "filter")
		_ = lfs.Parse(args)
		u := fmt.Sprintf("/api/v1/logs?limit=%d&level=%s&q=%s", *n, *level, *q)
		body, _, err := apiGet(base, u, cfg, *timeout)
		if err != nil {
			return reportDown(err, *jsonOut)
		}
		if *jsonOut {
			os.Stdout.Write(body)
			return 0
		}
		var resp struct {
			Data struct {
				Entries []struct {
					T     int64  `json:"t"`
					Level string `json:"level"`
					Src   string `json:"src"`
					Msg   string `json:"msg"`
				} `json:"entries"`
			} `json:"data"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return 1
		}
		for _, e := range resp.Data.Entries {
			fmt.Printf("%s [%-5s] %-8s %s\n", time.UnixMilli(e.T).Format("15:04:05"), e.Level, e.Src, e.Msg)
		}
		return 0

	case "diagnose":
		body, _, err := apiGet(base, "/api/v1/diagnostics", cfg, 30*time.Second)
		if err != nil {
			fmt.Fprintln(os.Stderr, "the daemon is not reachable; reporting on-disk diagnostics instead")
			return offlineDiagnose(cfgPath, cfg, *jsonOut)
		}
		if *jsonOut {
			os.Stdout.Write(body)
			return 0
		}
		return renderDiag(body)

	case "probe":
		// Offline capability probe: never needs a running daemon, which is what
		// makes it useful while debugging a module that will not start.
		return offlineProbe()

	case "config":
		if fs.NArg() == 0 {
			body, _, err := apiGet(base, "/api/v1/config", cfg, *timeout)
			if err != nil {
				return reportDown(err, *jsonOut)
			}
			os.Stdout.Write(body)
			return 0
		}
		// `yorud config set a.b=value`
		pairs := fs.Args()
		patch := map[string]any{}
		for _, p := range pairs {
			if p == "set" {
				continue
			}
			k, v, ok := strings.Cut(p, "=")
			if !ok {
				fmt.Fprintf(os.Stderr, "expected key=value, got %q\n", p)
				return 2
			}
			setDeep(patch, strings.Split(k, "."), coerce(v))
		}
		if *jsonOut {
			b, _ := json.Marshal(patch)
			fmt.Println(string(b))
			return 0
		}
		return apiPost(base, "/api/v1/config", patch, cfg, *timeout, *jsonOut)

	case "password":
		// Direct credential change: the documented recovery path when the
		// dashboard is unreachable, so a lost password never means reflashing.
		newPw := fs.Arg(0)
		if newPw == "" {
			if st, err := os.Stdin.Stat(); err == nil && (st.Mode()&os.ModeCharDevice) == 0 {
				b, _ := io.ReadAll(io.LimitReader(os.Stdin, 512))
				newPw = strings.TrimSpace(string(b))
			}
		}
		if newPw == "" {
			fmt.Fprintln(os.Stderr, "usage: yorud password <new-password>   (or pipe it on stdin)")
			return 2
		}
		if len(newPw) < 8 {
			fmt.Fprintln(os.Stderr, "password must be at least 8 characters")
			return 4
		}
		store, err := config.Load(cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "config:", err)
			return 1
		}
		if err := store.SetPassword(newPw); err != nil {
			fmt.Fprintln(os.Stderr, "cannot set password:", err)
			return 1
		}
		if err := store.Save(); err != nil {
			fmt.Fprintln(os.Stderr, "cannot save config:", err)
			return 1
		}
		fmt.Println("dashboard password updated; existing sessions were invalidated")
		return 0

	default:
		usage()
		return 2
	}
}

func action(base string, cfg *config.Config, path string, timeout time.Duration, asJSON bool) int {
	return apiPost(base, path, map[string]any{}, cfg, timeout, asJSON)
}

func usage() {
	fmt.Print(`Yoru Repeater control

Usage: yorud [global-flags] <command>

  status              repeater + system summary
  start | stop | restart
                      control the repeater
  config [set k=v..]  show or change configuration
  logs [-n N] [-grep S]  recent daemon log lines
  diagnose            full capability + network report
  probe               offline capability probe (no daemon needed)
  password <pw>       set the dashboard password (recovery path)
  version             print version

Global flags:
  --state DIR         state directory (default ` + defaultStateDir + `)
  --port N            dashboard port override
  --json              machine-readable output
  --timeout D         request timeout (default 10s)
`)
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

func apiGet(base, path string, cfg *config.Config, timeout time.Duration) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodGet, base+path, nil)
	if err != nil {
		return nil, 0, err
	}
	if tok := readToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return do(req, timeout)
}

func apiPost(base, path string, body any, cfg *config.Config, timeout time.Duration, asJSON bool) int {
	b, err := json.Marshal(body)
	if err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		return 1
	}
	req, err := http.NewRequest(http.MethodPost, base+path, bytes.NewReader(b))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := readToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	out, code, err := do(req, timeout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 3
	}
	if asJSON {
		os.Stdout.Write(out)
		return exitForCode(code)
	}
	var resp struct {
		OK    bool `json:"ok"`
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
			Hint    string `json:"hint"`
		} `json:"error"`
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(out, &resp); err != nil {
		os.Stdout.Write(out)
		return 1
	}
	if resp.Error != nil {
		fmt.Fprintf(os.Stderr, "%s: %s\n", resp.Error.Code, resp.Error.Message)
		if resp.Error.Hint != "" {
			fmt.Fprintf(os.Stderr, "  hint: %s\n", resp.Error.Hint)
		}
		return 1
	}
	var pretty json.RawMessage = resp.Data
	var buf bytes.Buffer
	if err := json.Indent(&buf, pretty, "", "  "); err == nil {
		fmt.Println(buf.String())
	} else {
		fmt.Println(string(pretty))
	}
	return 0
}

func do(req *http.Request, timeout time.Duration) ([]byte, int, error) {
	client := &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext:       (&net.Dialer{Timeout: 3 * time.Second}).DialContext,
		MaxIdleConns:      4,
		DisableKeepAlives: false,
	}}
	res, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 8<<20))
	if err != nil {
		return nil, res.StatusCode, err
	}
	return body, res.StatusCode, nil
}

func exitForCode(code int) int {
	switch {
	case code < 400:
		return 0
	case code == http.StatusUnauthorized:
		return 4
	case code == http.StatusServiceUnavailable:
		return 3
	default:
		return 1
	}
}

// readToken returns the CLI bearer token from the root-only token file. The
// daemon writes it at startup; if it is missing the CLI still works against an
// unauthenticated dashboard.
func readToken() string {
	for _, p := range []string{
		filepath.Join(envOr("YORU_STATE_DIR", defaultStateDir), "state", "cli.token"),
		"/data/adb/yoru-repeater/state/cli.token",
	} {
		b, err := os.ReadFile(p)
		if err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

func emit(body []byte, asJSON bool, fn func(map[string]any)) int {
	if asJSON {
		os.Stdout.Write(body)
		return 0
	}
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil || resp.Data == nil {
		os.Stdout.Write(body)
		return 1
	}
	fn(resp.Data)
	return 0
}

func renderStatus(d map[string]any) {
	r, _ := d["repeater"].(map[string]any)
	fmt.Printf("Yoru Repeater %s\n", version.GitTag)
	if r == nil {
		fmt.Println("  status: no repeater data")
		return
	}
	fmt.Printf("  state:    %v\n", str(r["state"]))
	fmt.Printf("  mode:     %v\n", str(r["modeLabel"]))
	up, _ := r["upstream"].(map[string]any)
	dn, _ := r["downstream"].(map[string]any)
	fmt.Printf("  upstream: %v (%v)\n", str(up["name"]), str(up["kind"]))
	fmt.Printf("  downstream: %v (%v) ap=%v\n", str(dn["name"]), str(dn["kind"]), str(r["apStrategy"]))
	fmt.Printf("  gateway:  %v  dhcp=%v dns=%v firewall=%v\n", str(r["gateway"]), str(r["dhcpRunning"]), str(r["dnsRunning"]), str(r["firewall"]))
	if in, ok := r["internet"].(map[string]any); ok {
		verdict := "offline"
		if b, _ := in["reachable"].(bool); b {
			verdict = "online"
		}
		fmt.Printf("  internet: %s (%v)\n", verdict, str(in["detail"]))
	}
	if le, _ := r["lastError"].(string); le != "" {
		fmt.Printf("  lastError: %s\n", le)
	}
	for _, u := range stringsList(d["dashboardUrls"]) {
		fmt.Printf("  dashboard: %s\n", u)
	}
	fmt.Printf("  clients:   %v online / %v known\n", str(d["clientsOnline"]), str(d["clientsTotal"]))
}

func stringsList(v any) []string {
	arr, _ := v.([]any)
	var out []string
	for _, x := range arr {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func str(v any) string {
	if v == nil {
		return "-"
	}
	if b, ok := v.(bool); ok {
		if b {
			return "yes"
		}
		return "no"
	}
	return fmt.Sprint(v)
}

func renderDiag(body []byte) int {
	var resp struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		os.Stdout.Write(body)
		return 1
	}
	d := resp.Data
	if a, ok := d["android"].(map[string]any); ok {
		fmt.Printf("Android %s (SDK %s, %s)\n", str(a["release"]), str(a["sdk"]), str(a["apiLevelName"]))
		fmt.Printf("Model %s %s / board %s / hardware %s\n", str(a["manufacturer"]), str(a["model"]), str(a["board"]), str(a["hardware"]))
	}
	if k, ok := d["kernel"].(map[string]any); ok {
		fmt.Printf("Kernel %s (%s) page=%s bytes\n", str(k["release"]), str(k["machine"]), str(k["pageSize"]))
	}
	if s, ok := d["selinux"].(map[string]any); ok {
		fmt.Printf("SELinux %s\n", str(s["state"]))
	}
	if r, ok := d["root"].(map[string]any); ok {
		fmt.Printf("Root %s uid=%s\n", str(r["implementation"]), str(r["uid"]))
	}
	if sum, ok := d["summary"].(map[string]any); ok {
		fmt.Printf("Modes: repeater=%s hotspot=%s usb=%s ethernet=%s\n",
			str(sum["trueRepeater"]), str(sum["hotspotRouter"]), str(sum["usbRouter"]), str(sum["ethernetRouter"]))
	}
	fmt.Println("\nCapabilities:")
	capsList, _ := d["capabilities"].([]any)
	sort.Slice(capsList, func(i, j int) bool {
		a, _ := capsList[i].(map[string]any)
		b, _ := capsList[j].(map[string]any)
		return str(a["id"]) < str(b["id"])
	})
	for _, c := range capsList {
		m, _ := c.(map[string]any)
		fmt.Printf("  %-22s %-9s %s\n", str(m["id"]), str(m["state"]), truncate(str(m["reason"])+str(m["detail"]), 70))
	}
	if st, ok := d["strategies"].([]any); ok && len(st) > 0 {
		fmt.Println("\nAP strategies:")
		for _, x := range st {
			m, _ := x.(map[string]any)
			avail := "no "
			if b, _ := m["available"].(bool); b {
				avail = "yes"
			}
			fmt.Printf("  %-16s %s %s\n", str(m["name"]), avail, truncate(str(m["reason"]), 60))
		}
	}
	if e, ok := d["engine"].(map[string]any); ok {
		fmt.Printf("\nEngine: %s / %s\n", str(e["state"]), str(e["modeLabel"]))
		if steps, ok := e["steps"].([]any); ok {
			for _, x := range steps {
				m, _ := x.(map[string]any)
				status := "ok"
				if b, _ := m["ok"].(bool); !b {
					status = "FAIL"
				}
				fmt.Printf("  [%-4s] %-14s %s\n", status, str(m["step"]), truncate(str(m["detail"]), 60))
			}
		}
	}
	return 0
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ---------------------------------------------------------------------------
// offline paths
// ---------------------------------------------------------------------------

// offlineProbe runs the capability engine directly, which is how an operator
// diagnoses a module that cannot start at all.
func offlineProbe() int {
	log := newQuietLogger()
	dev := newDevice()
	cs := newCapSet(log, dev)
	cs.Probe()
	fmt.Println("Yoru Repeater offline capability probe")
	fmt.Println(strings.Repeat("-", 60))
	for _, c := range cs.All() {
		fmt.Printf("%-24s %-9s %s\n", c.ID, c.State, truncate(c.Reason+c.Detail, 60))
	}
	s := cs.Summarise()
	fmt.Printf("\ntrue repeater: %v\nhotspot router: %v\nusb router: %v\nethernet router: %v\n",
		s.TrueRepeater, s.HotspotRouter, s.UsbRouter, s.EthernetRouter)
	for _, r := range s.Reasons {
		fmt.Println("  -", r)
	}
	return 0
}

// offlineDiagnose prints what can be learned without a daemon.
func offlineDiagnose(cfgPath string, cfg *config.Config, asJSON bool) int {
	out := map[string]any{
		"daemon":    "not reachable",
		"config":    cfgPath,
		"configOk":  fileExists(cfgPath),
		"port":      cfg.Web.Port,
		"auth":      cfg.Web.Auth.Enabled && cfg.Web.Auth.Hash != "",
		"autoStart": cfg.Repeater.AutoStart,
	}
	if asJSON {
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 3
	}
	fmt.Printf("daemon: not reachable on the configured port (%d)\n", cfg.Web.Port)
	fmt.Printf("config: %s (present=%v)\n", cfgPath, out["configOk"])
	fmt.Println("hint: start it with 'yorud supervise &' or check the log at")
	fmt.Println("      /data/adb/yoru-repeater/logs/yoru.log")
	return 3
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// reportDown explains that the daemon is unreachable, and offers the offline
// alternative, instead of printing a bare connection error.
func reportDown(err error, asJSON bool) int {
	if asJSON {
		b, _ := json.Marshal(map[string]any{
			"ok": false,
			"error": map[string]string{
				"code":    "daemon_unreachable",
				"message": err.Error(),
				"hint":    "Start it with 'yorud supervise &' or run 'yorud probe' to check the device offline.",
			},
		})
		fmt.Println(string(b))
		return 3
	}
	fmt.Fprintln(os.Stderr, "cannot reach the Yoru daemon:", err)
	fmt.Fprintln(os.Stderr, "  - is it running?   yorud status reports this too")
	fmt.Fprintln(os.Stderr, "  - start it:        yorud supervise &")
	fmt.Fprintln(os.Stderr, "  - diagnose offline: yorud probe")
	fmt.Fprintln(os.Stderr, "  - read the log:    cat /data/adb/yoru-repeater/logs/yoru.log")
	return 3
}

func loadConfigForCLI(stateDir string) (*config.Config, string) {
	path := filepath.Join(stateDir, "config", "config.json")
	cfg := config.Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return cfg, path
	}
	_ = json.Unmarshal(b, cfg)
	config.Validate(cfg)
	return cfg, path
}

func coerce(v string) any {
	switch strings.ToLower(v) {
	case "true", "yes":
		return true
	case "false", "no":
		return false
	case "null":
		return nil
	}
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	if strings.HasPrefix(v, "[") {
		var arr []any
		if json.Unmarshal([]byte(v), &arr) == nil {
			return arr
		}
	}
	return v
}

func setDeep(m map[string]any, keys []string, value any) {
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

var errNoDaemon = errors.New("yorud is not running")
