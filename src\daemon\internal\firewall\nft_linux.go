//go:build linux

package firewall

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"yoru.dev/yorud/internal/clients"
	"yoru.dev/yorud/internal/safeexec"
)

// nftScript is the complete, self-contained ruleset Yoru installs when the
// device speaks nftables natively. It uses a dedicated table so Yoru's objects
// can never collide with Android's own `tethering`, `bandwidth` or `nat` tables,
// and `delete table` is the only teardown primitive.
const nftScriptHead = "table ip %s {\n"

func nftChainDecls(ap, up string, isolate, account bool) string {
	s := ""
	s += fmt.Sprintf("  chain %s {\n    type filter hook forward priority filter + 10; policy accept;\n", NftChainFwd)
	s += fmt.Sprintf("    iifname \"%s\" oifname \"%s\" accept comment \"%s\"\n", ap, up, CommentMarker)
	s += fmt.Sprintf("    oifname \"%s\" iifname \"%s\" ct state established,related accept comment \"%s\"\n", ap, up, CommentMarker)
	s += fmt.Sprintf("    iifname \"%s\" oifname \"%s\" udp dport { 53, 67, 68 } accept comment \"%s\"\n", ap, ap, CommentMarker)
	s += fmt.Sprintf("    iifname \"%s\" oifname \"%s\" tcp dport { 53 } accept comment \"%s\"\n", ap, ap, CommentMarker)
	if isolate {
		s += fmt.Sprintf("    jump %s\n", NftChainIsol)
		s += fmt.Sprintf("  }\n  chain %s {\n    iifname \"%s\" oifname \"%s\" ip protocol != udp drop comment \"%s\"\n",
			NftChainIsol, ap, ap, CommentMarker)
		s += fmt.Sprintf("    iifname \"%s\" oifname \"%s\" udp dport { 53, 67, 68 } accept comment \"%s\"\n",
			ap, ap, CommentMarker)
	}
	s += "  }\n"
	s += fmt.Sprintf("  chain %s {\n    type nat hook postrouting priority srcval - 10; policy accept;\n", NftChainNat)
	s += fmt.Sprintf("    oifname \"%s\" masquerade comment \"%s\"\n", up, CommentMarker)
	s += "  }\n"
	if account {
		s += fmt.Sprintf("  chain %s {\n    type filter hook forward priority filter + 20; policy accept;\n  }\n", NftChainAcc)
	}
	s += "}\n"
	return s
}

// applyNft installs (or replaces) Yoru's own nftables table. Because the table
// is exclusively ours, `delete table` on teardown is both complete and safe.
func (m *Manager) applyNft(p Plan) error {
	script := strings.ReplaceAll(fmt.Sprintf(nftScriptHead, NftTable), "\n", "\n")
	script += nftChainDecls(p.AP, p.Upstream, p.Isolate, p.Account)
	path, err := writeTemp("yoru-nft-", script)
	if err != nil {
		return err
	}
	defer removeFile(path)
	res, err := safeexec.Run("nft", []string{"-f", path}, safeexec.Options{Timeout: 6 * time.Second})
	if err != nil {
		return err
	}
	if !res.OK() {
		return fmt.Errorf("nft rejected the Yoru ruleset: %s", strings.TrimSpace(res.Combined()))
	}
	m.nftHasAcc = p.Account
	m.enabled = true
	m.log.Infof("firewall", "nftables table %s installed (accounting=%v isolate=%v)", NftTable, p.Account, p.Isolate)
	return nil
}

func (m *Manager) nftAccReady() bool { return m.nftHasAcc }

func (m *Manager) nftRemoveHandle(ip string) error {
	if !validIPv4(ip) {
		return errors.New("invalid address")
	}
	res, err := safeexec.Run("nft", []string{"-a", "list", "chain", "ip", NftTable, NftChainAcc}, safeexec.Options{Timeout: 4 * time.Second})
	if err != nil || !res.OK() {
		return nil
	}
	for _, ln := range strings.Split(res.Stdout, "\n") {
		if ipInLine(ln) != ip {
			continue
		}
		h := handleRe.FindStringSubmatch(ln)
		if h == nil {
			continue
		}
		_, _ = safeexec.Out("nft", "delete", "rule", "ip", NftTable, NftChainAcc, h[1])
	}
	return nil
}

// nftTrack adds a counter rule for one client address if not already present.
func (m *Manager) nftTrack(ip string) error {
	if !validIPv4(ip) {
		return errors.New("invalid address")
	}
	out, err := safeexec.Out("nft", "-a", "list", "chain", "ip", NftTable, NftChainAcc)
	if err != nil {
		return err
	}
	for _, ln := range strings.Split(out, "\n") {
		if ipInLine(ln) == ip {
			return nil
		}
	}
	_, err = safeexec.Out("nft", "add", "rule", "ip", NftTable, NftChainAcc,
		"ip", "saddr", ip, "counter", "comment", `"`+CommentMarker+`-acc-"`)
	return err
}

// observeNft reads per-client counters out of the acc chain.
func (m *Manager) observeNft() (map[string]clients.Counters, bool, error) {
	out := map[string]clients.Counters{}
	res, err := safeexec.Run("nft", []string{"-a", "list", "chain", "ip", NftTable, NftChainAcc}, safeexec.Options{Timeout: 4 * time.Second})
	if err != nil {
		return out, false, err
	}
	if !res.OK() {
		return out, false, errors.New(strings.TrimSpace(res.Combined()))
	}
	for _, ln := range strings.Split(res.Stdout, "\n") {
		ip := ipInLine(ln)
		if ip == "" {
			continue
		}
		c := parseNftCounters(ln)
		v := out[ip]
		v.TxBytes += c.bytes
		v.TxPackets += c.packets
		out[ip] = v
	}
	return out, true, nil
}

// file helpers --------------------------------------------------------------

func writeTemp(prefix, content string) (string, error) {
	for _, dir := range []string{"/data/local/tmp", "/data/adb/yoru-repeater/tmp", "/tmp"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			continue
		}
		f, err := os.CreateTemp(dir, prefix+"*.nft")
		if err != nil {
			continue
		}
		if _, err := f.WriteString(content); err != nil {
			_ = f.Close()
			_ = os.Remove(f.Name())
			return "", err
		}
		if err := f.Close(); err != nil {
			return "", err
		}
		_ = os.Chmod(f.Name(), 0600)
		return f.Name(), nil
	}
	return "", errors.New("no writable temporary directory (/data/local/tmp, /tmp)")
}

func writeFile(path, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content), 0600)
}

func removeFile(path string) { _ = os.Remove(path) }

func readFileSafe(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

// nftTableExists verifies the kernel actually created our probe table. Reading
// /proc/net/netfilter/nf_tables is not portable across kernels, so the check is
// advisory: when the proc file is absent we fall back to `nft list tables`.
func nftTableExists() bool {
	res, err := safeexec.Run("nft", []string{"list", "tables"}, safeexec.Options{Timeout: 3 * time.Second})
	if err != nil {
		return false
	}
	return strings.Contains(res.Stdout, "yoru_probe") || strings.Contains(res.Stdout, NftTable)
}

var _ = strconv.Itoa
