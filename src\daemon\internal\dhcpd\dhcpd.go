// Package dhcpd is Yoru's built-in DHCP server.
//
// Why this exists: Android images vary wildly - some ship dnsmasq, some ship a
// tethering helper that cannot be reconfigured, and some ship nothing usable at
// all. Bundling a large binary is undesirable on a 2 GB-RAM device, so Yoru
// speaks DHCP itself. The implementation is deliberately minimal but complete
// for a tethering LAN: DISCOVER/OFFER, REQUEST/ACK, RENEW, DECLINE, INFORM,
// reserved addresses, expiry, and a lease file another component can read.
//
// Constraints: it only serves the single downstream interface it is bound to
// (SO_BINDTODEVICE), never relays, and refuses to start if its pool overlaps an
// existing route - a hard requirement to avoid blackholing the upstream network.
package dhcpd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"yoru.dev/yorud/internal/clients"
	"yoru.dev/yorud/internal/logging"
)

// DHCP message types (RFC 2131).
const (
	discover = 1
	offer    = 2
	request  = 3
	decline  = 4
	ack      = 5
	nak      = 6
	release  = 7
	inform   = 8
)

// DHCP option codes used here.
const (
	optPad        = 0
	optSubnet     = 1
	optRouter     = 3
	optDNS        = 6
	optHostname   = 12
	optDomain     = 15
	optReqList    = 55
	optIPAddr     = 50
	optLeaseTime  = 51
	optOverload   = 52
	optServerID   = 54
	optMessage    = 53
	optMaxMsgSize = 57
	optRenewal    = 58
	optRebind     = 59
	optEnd        = 255
	magicCookie   = 0x63825363
)

// Lease is one binding.
type Lease struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Expiry   int64  `json:"expiryMs"`
	Assigned int64  `json:"assignedMs"`
}

// Config is the server's operating parameters.
type Config struct {
	Iface        string
	ServerID     net.IP
	Router       net.IP
	Subnet       *net.IPNet
	PoolStart    net.IP
	PoolEnd      net.IP
	DNS          []net.IP
	Lease        time.Duration
	Domain       string
	LeaseFile    string
	MaxClients   int
	Reservations map[string]net.IP
}

// Validate rejects unsafe pool definitions before the server binds.
func (c *Config) Validate() error {
	if c.Iface == "" || c.Subnet == nil || c.ServerID == nil {
		return errors.New("dhcp: interface, subnet and server id are required")
	}
	if c.PoolStart == nil || c.PoolEnd == nil {
		return errors.New("dhcp: pool bounds are required")
	}
	if !c.Subnet.Contains(c.ServerID) {
		return fmt.Errorf("dhcp: server address %s is outside the subnet %s", c.ServerID, c.Subnet)
	}
	if !c.Subnet.Contains(c.PoolStart) || !c.Subnet.Contains(c.PoolEnd) {
		return errors.New("dhcp: pool is outside the subnet")
	}
	if binary.BigEndian.Uint32(c.PoolStart.To4()) > binary.BigEndian.Uint32(c.PoolEnd.To4()) {
		return errors.New("dhcp: pool start is above pool end")
	}
	if c.Lease < time.Minute {
		c.Lease = 120 * time.Minute
	}
	if c.MaxClients <= 0 {
		c.MaxClients = 254
	}
	return nil
}

// PoolSize returns the number of assignable addresses.
func (c *Config) PoolSize() int {
	a := binary.BigEndian.Uint32(c.PoolStart.To4())
	b := binary.BigEndian.Uint32(c.PoolEnd.To4())
	return int(b-a) + 1
}

// Server is the DHCP daemon.
type Server struct {
	cfg Config
	log *logging.Logger

	mu      sync.Mutex
	leases  map[string]*Lease
	byIP    map[string]string
	pending map[string]net.IP // offered, not yet requested
	socket  *net.UDPConn
	stop    chan struct{}
	running bool
	count   uint64
	packets map[string]uint64
	err     error
}

// New creates a server. Nothing is bound until Start.
func New(cfg Config, log *logging.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Server{
		cfg: cfg, log: log,
		leases: map[string]*Lease{}, byIP: map[string]string{}, pending: map[string]net.IP{},
		stop: make(chan struct{}), packets: map[string]uint64{},
	}, nil
}

// Start binds UDP/67 to the downstream interface and serves in the background.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("dhcp: already running")
	}
	s.mu.Unlock()

	s.loadLeases()

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				// Serving only the AP interface prevents Yoru's DHCP from ever
				// answering on the phone's upstream link.
				if err := syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, s.cfg.Iface); err != nil {
					serr = fmt.Errorf("SO_BINDTODEVICE %s: %w (the kernel or SELinux refused interface binding)", s.cfg.Iface, err)
					return
				}
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_BROADCAST, 1)
				_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			}); err != nil {
				return err
			}
			return serr
		},
	}
	ctx, cancel := timeoutContext(3 * time.Second)
	defer cancel()
	conn, err := lc.ListenPacket(ctx, "udp", "0.0.0.0:67")
	if err != nil {
		s.mu.Lock()
		s.err = err
		s.mu.Unlock()
		return fmt.Errorf("dhcp: cannot bind UDP/67 on %s: %w", s.cfg.Iface, err)
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		_ = conn.Close()
		return errors.New("dhcp: unexpected packet connection type")
	}
	s.mu.Lock()
	s.socket = uc
	s.running = true
	s.err = nil
	s.stop = make(chan struct{})
	s.mu.Unlock()

	_ = uc.SetReadBuffer(1 << 16)
	_ = uc.SetWriteBuffer(1 << 16)
	go s.serve(uc)
	s.log.Infof("dhcp", "server up on %s pool=%s-%s lease=%s (%d addresses)",
		s.cfg.Iface, s.cfg.PoolStart, s.cfg.PoolEnd, s.cfg.Lease, s.cfg.PoolSize())
	return nil
}

// Stop shuts the server down and persists leases.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	close(s.stop)
	sock := s.socket
	s.socket = nil
	s.mu.Unlock()
	if sock != nil {
		_ = sock.Close()
	}
	s.saveLeases()
	s.log.Infof("dhcp", "server stopped")
	return nil
}

// Running reports server state.
func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Status is the dashboard view.
func (s *Server) Status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{
		"running": s.running, "iface": s.cfg.Iface,
		"pool":         fmt.Sprintf("%s-%s", s.cfg.PoolStart, s.cfg.PoolEnd),
		"poolSize":     s.cfg.PoolSize(),
		"leaseSeconds": int(s.cfg.Lease / time.Second),
		"active":       len(s.leases),
		"packets":      s.count,
	}
	if s.err != nil {
		out["error"] = s.err.Error()
	}
	return out
}

// Leases returns the current bindings, sorted by address.
func (s *Server) Leases() []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Lease
	for _, l := range s.leases {
		if time.Now().UnixMilli() > l.Expiry {
			continue
		}
		cp := *l
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out
}

// ReadLeaseFiles satisfies the clients package's lease reader.
func (s *Server) ReadLeaseFiles() []clients.Lease {
	ls := s.Leases()
	out := make([]clients.Lease, 0, len(ls))
	for _, l := range ls {
		out = append(out, clients.Lease{
			MAC: l.MAC, IP: l.IP, Hostname: l.Hostname,
			Expiry: time.UnixMilli(l.Expiry), Source: "yoru-dhcp",
		})
	}
	return out
}

// SourceName identifies this lease source in the UI.
func (s *Server) SourceName() string { return "yoru-dhcp" }

// Assign reserves an address for a MAC (used when the user pins a device).
func (s *Server) Assign(mac string, ip string) error {
	mac = strings.ToLower(mac)
	parsed := net.ParseIP(ip)
	if parsed == nil || !s.cfg.Subnet.Contains(parsed) {
		return errors.New("address is outside the Yoru subnet")
	}
	s.mu.Lock()
	s.cfg.Reservations[mac] = parsed
	s.mu.Unlock()
	return nil
}

// serve is the packet loop.
func (s *Server) serve(conn *net.UDPConn) {
	buf := make([]byte, 1500)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.log.Warnf("dhcp", "read error: %v", err)
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		go s.handle(conn, addr, pkt)
	}
}

func (s *Server) handle(conn *net.UDPConn, from *net.UDPAddr, pkt []byte) {
	msg, err := parse(pkt)
	if err != nil {
		s.log.Debugf("dhcp", "ignoring malformed packet from %s: %v", from, err)
		return
	}
	if msg.op != 1 || msg.xid == 0 && msg.htype != 1 {
		return
	}
	mac := hwAddr(msg.chaddr, msg.hlen)
	if mac == "" {
		return
	}
	s.mu.Lock()
	s.count++
	s.mu.Unlock()

	reqIP := msg.opts[optIPAddr]
	// giaddr is intentionally unused: Yoru never relays, and a packet that
	// arrives with a relay address is dropped below.
	if msg.giaddr != 0 {
		s.log.Debugf("dhcp", "ignoring relayed packet (giaddr set)")
		return
	}

	switch msg.msgType() {
	case discover:
		ip, ok := s.pick(mac, reqIP)
		if !ok {
			s.log.Warnf("dhcp", "pool exhausted, no address for %s", logging.MaskMAC(mac))
			return
		}
		s.mu.Lock()
		s.pending[mac] = ip
		s.mu.Unlock()
		s.send(conn, from, msg, offer, ip, nil)
	case request:
		ip, ok := s.pick(mac, reqIP)
		if !ok {
			s.send(conn, from, msg, nak, nil, []byte("pool exhausted"))
			return
		}
		// A REQUEST naming an address the client got from someone else must be
		// NAKed so it re-DISCOVERs instead of squatting on a foreign IP.
		if len(reqIP) == 4 && s.belongsToOtherClient(reqIP, mac) {
			s.send(conn, from, msg, nak, nil, []byte("address in use"))
			return
		}
		hostname := string(msg.opts[optHostname])
		if err := s.commit(mac, ip, hostname); err != nil {
			s.send(conn, from, msg, nak, nil, []byte(err.Error()))
			return
		}
		s.send(conn, from, msg, ack, ip, nil)
	case inform:
		// INFORM asks for configuration only; reply with the client's own
		// address as yiaddr and never touch the pool.
		if msg.ciaddr == 0 {
			return
		}
		s.send(conn, from, msg, ack, u32ToIP(msg.ciaddr), nil)
	case decline:
		if len(reqIP) == 4 {
			s.log.Warnf("dhcp", "client declined %s; excluding it for the rest of the lease", reqIP)
			s.decline(reqIP)
		}
	case release:
		s.release(mac)
	default:
		s.log.Debugf("dhcp", "unhandled message type from %s", logging.MaskMAC(mac))
	}
}

// pick chooses an address: reservation, existing lease, requested, or free.
func (s *Server) pick(mac string, requested []byte) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.cfg.Reservations[mac]; ok {
		return r, true
	}
	if l, ok := s.leases[mac]; ok && s.cfg.Subnet.Contains(net.ParseIP(l.IP)) {
		return net.ParseIP(l.IP), true
	}
	if len(requested) == 4 {
		ip := net.IP(requested)
		if s.cfg.Subnet.Contains(ip) && !s.inUse(ip, mac) {
			return ip, true
		}
	}
	if ip := s.freeLocked(); ip != nil {
		return ip, true
	}
	// Last resort: reclaim the oldest expired lease.
	return s.reclaimLocked()
}

func (s *Server) freeLocked() net.IP {
	start := binary.BigEndian.Uint32(s.cfg.PoolStart.To4())
	end := binary.BigEndian.Uint32(s.cfg.PoolEnd.To4())
	used := map[string]bool{}
	for _, l := range s.leases {
		used[l.IP] = true
	}
	for _, ip := range s.byIP {
		used[ip] = true
	}
	// Rotate from a random-ish offset so a rebooted pool does not always hand
	// out the same first address (which confuses clients with stale ARP).
	off := int(time.Now().Unix()) % int(end-start+1)
	for i := 0; i <= int(end-start); i++ {
		u := start + uint32((off+i)%int(end-start+1))
		ip := u32ToIP(u)
		if ip.Equal(s.cfg.ServerID) || ip.Equal(s.cfg.Router) {
			continue
		}
		if !used[ip.String()] {
			return ip
		}
	}
	return nil
}

func (s *Server) reclaimLocked() (net.IP, bool) {
	var oldest *Lease
	for _, l := range s.leases {
		if oldest == nil || l.Expiry < oldest.Expiry {
			oldest = l
		}
	}
	if oldest == nil {
		return nil, false
	}
	ip := net.ParseIP(oldest.IP)
	delete(s.leases, oldest.MAC)
	delete(s.byIP, oldest.IP)
	return ip, ip != nil
}

func (s *Server) inUse(ip net.IP, exceptMac string) bool {
	if ip.Equal(s.cfg.ServerID) || ip.Equal(s.cfg.Router) {
		return true
	}
	if mac, ok := s.byIP[ip.String()]; ok && mac != exceptMac {
		return true
	}
	if l, ok := s.leases[exceptMac]; ok && l.IP == ip.String() {
		return true
	}
	return false
}

func (s *Server) belongsToOtherClient(ip net.IP, mac string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if owner, ok := s.byIP[ip.String()]; ok && owner != mac {
		if l, exists := s.leases[owner]; exists && time.Now().UnixMilli() < l.Expiry {
			return true
		}
	}
	return false
}

func (s *Server) commit(mac string, ip net.IP, hostname string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.leases) >= s.cfg.MaxClients {
		if _, ok := s.leases[mac]; !ok {
			return fmt.Errorf("client limit (%d) reached", s.cfg.MaxClients)
		}
	}
	now := time.Now()
	lease := &Lease{
		MAC: mac, IP: ip.String(), Hostname: sanitiseHost(hostname),
		Expiry: now.Add(s.cfg.Lease).UnixMilli(), Assigned: now.UnixMilli(),
	}
	if old, ok := s.leases[mac]; ok && old.IP == ip.String() && old.Hostname != "" {
		lease.Hostname = old.Hostname
		if hostname != "" {
			lease.Hostname = sanitiseHost(hostname)
		}
	}
	if owner, ok := s.byIP[ip.String()]; ok && owner != mac {
		delete(s.leases, owner)
	}
	s.leases[mac] = lease
	s.byIP[ip.String()] = mac
	delete(s.pending, mac)
	s.saveLeasesLocked()
	return nil
}

func (s *Server) lookup(mac string) (net.IP, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if l, ok := s.leases[mac]; ok {
		return net.ParseIP(l.IP), true
	}
	return nil, false
}

func (s *Server) release(mac string) {
	s.mu.Lock()
	if l, ok := s.leases[mac]; ok {
		delete(s.byIP, l.IP)
		delete(s.leases, mac)
		s.saveLeasesLocked()
	}
	s.mu.Unlock()
}

func (s *Server) decline(ip net.IP) {
	s.mu.Lock()
	if mac, ok := s.byIP[ip.String()]; ok {
		if l, exists := s.leases[mac]; exists && time.Now().UnixMilli() < l.Expiry {
			l.Expiry = time.Now().Add(60 * time.Second).UnixMilli()
		}
	}
	s.saveLeasesLocked()
	s.mu.Unlock()
}

// send builds and transmits a reply.
func (s *Server) send(conn *net.UDPConn, from *net.UDPAddr, req *dhcpMsg, msgType byte, ip net.IP, message []byte) {
	rep := buildReply(req, msgType, ip, s.cfg, message)
	dgram := rep.Encode()
	var dst *net.UDPAddr
	switch {
	case req.flags&0x8000 != 0:
		// Client asked for broadcast (it has no address yet).
		dst = &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	case req.ciaddr != 0:
		dst = &net.UDPAddr{IP: u32ToIP(req.ciaddr), Port: 68}
	default:
		dst = &net.UDPAddr{IP: net.IPv4bcast, Port: 68}
	}
	if _, err := conn.WriteToUDP(dgram, dst); err != nil {
		s.log.Warnf("dhcp", "reply to %s failed: %v", logging.MaskMAC(hwAddr(req.chaddr, req.hlen)), err)
		return
	}
	name := ""
	if l := s.leasesFor(hwAddr(req.chaddr, req.hlen)); l != nil {
		name = l.Hostname
	}
	s.log.Infof("dhcp", "%s %s -> %s (%s)", typeName(msgType), ip, logging.MaskMAC(hwAddr(req.chaddr, req.hlen)), orDefault(name, "-"))
}

func (s *Server) leasesFor(mac string) *Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.leases[mac]
}

func typeName(t byte) string {
	switch t {
	case offer:
		return "OFFER"
	case ack:
		return "ACK"
	case nak:
		return "NAK"
	}
	return fmt.Sprintf("TYPE%d", t)
}

// lease persistence ---------------------------------------------------------

func (s *Server) saveLeases() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveLeasesLocked()
}

func (s *Server) saveLeasesLocked() {
	if s.cfg.LeaseFile == "" {
		return
	}
	list := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		list = append(list, *l)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].IP < list[j].IP })
	var b strings.Builder
	b.WriteString("# Yoru Repeater DHCP leases - do not edit while the daemon is running\n")
	for _, l := range list {
		b.WriteString(fmt.Sprintf("%s %s %s %d\n", l.IP, l.MAC, orDefault(l.Hostname, "*"), l.Expiry))
	}
	dir := filepath.Dir(s.cfg.LeaseFile)
	if err := os.MkdirAll(dir, 0700); err != nil {
		s.log.Warnf("dhcp", "cannot create lease dir: %v", err)
		return
	}
	tmp := s.cfg.LeaseFile + ".tmp"
	if err := os.WriteFile(tmp, []byte(b.String()), 0600); err != nil {
		s.log.Warnf("dhcp", "cannot write lease file: %v", err)
		return
	}
	if err := os.Rename(tmp, s.cfg.LeaseFile); err != nil {
		_ = os.Remove(tmp)
		s.log.Warnf("dhcp", "cannot publish lease file: %v", err)
	}
}

func (s *Server) loadLeases() {
	if s.cfg.LeaseFile == "" {
		return
	}
	b, err := os.ReadFile(s.cfg.LeaseFile)
	if err != nil {
		return
	}
	now := time.Now()
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		f := strings.Fields(ln)
		if len(f) < 3 {
			continue
		}
		ip := net.ParseIP(f[0])
		mac := strings.ToLower(f[1])
		if ip == nil || !s.cfg.Subnet.Contains(ip) || !validMAC(mac) {
			continue
		}
		var exp int64
		if len(f) >= 4 {
			exp, _ = strconv.ParseInt(f[3], 10, 64)
		}
		if exp == 0 {
			exp = now.Add(s.cfg.Lease).UnixMilli()
		}
		host := f[2]
		if host == "*" {
			host = ""
		}
		l := &Lease{MAC: mac, IP: ip.String(), Hostname: host, Expiry: exp}
		s.leases[mac] = l
		s.byIP[ip.String()] = mac
	}
	if len(s.leases) > 0 {
		s.log.Infof("dhcp", "restored %d leases", len(s.leases))
	}
}

func validMAC(s string) bool {
	s = strings.ReplaceAll(s, ":", "")
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func sanitiseHost(h string) string {
	h = strings.TrimSpace(h)
	if len(h) > 63 {
		h = h[:63]
	}
	var b strings.Builder
	for i := 0; i < len(h); i++ {
		c := h[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func ipLess(a, b string) bool {
	ai, bi := net.ParseIP(a).To4(), net.ParseIP(b).To4()
	if ai == nil || bi == nil {
		return a < b
	}
	for i := range ai {
		if ai[i] != bi[i] {
			return ai[i] < bi[i]
		}
	}
	return false
}

func u32ToIP(u uint32) net.IP {
	return net.IPv4(byte(u>>24), byte(u>>16), byte(u>>8), byte(u)).To4()
}

func ipToU32(ip net.IP) uint32 {
	v := ip.To4()
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint32(v)
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}
