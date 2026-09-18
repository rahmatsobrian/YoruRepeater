// Package dnsd is a small, safe DNS forwarder for the repeater LAN.
//
// It exists because a tethered client must be able to resolve names while the
// phone's own resolver is bound to loopback. Responsibilities are narrow:
//   - answer A/AAAA queries by forwarding upstream over UDP (TCP fallback when
//     the reply is truncated),
//   - answer PTR requests for leased clients so LAN names work offline,
//   - refuse everything else (recursion for other zones is never offered),
//   - cap concurrency, cache size and response size so a phone with 2 GB RAM
//     cannot be pushed over its limits by one noisy client.
//
// The server binds only the LAN address it is given, so it can never become an
// open resolver on the upstream network.
package dnsd

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"yoru.dev/yorud/internal/logging"
)

// rrTypes we understand.
const (
	typeA        = 1
	typeNS       = 2
	typePTR      = 12
	typeMX       = 15
	typeTXT      = 16
	typeAAAA     = 28
	classIN      = 1
	rflagRA      = 1 << 7
	rflagRD      = 1 << 0
	rcodeOK      = 0
	rcodeRefused = 5
)

// Config configures the forwarder.
type Config struct {
	Bind      net.IP
	Port      int
	Upstream  []net.IP
	TTL       uint32
	MaxCache  int
	LocalName map[string]net.IP // hostname -> LAN address (PTR + A)
	LocalZone string            // e.g. "yoru"
}

// Server forwards DNS on one LAN address.
type Server struct {
	cfg Config
	log *logging.Logger

	mu       sync.Mutex
	conn     *net.UDPConn
	running  bool
	queries  uint64
	cache    map[string]*cacheEntry
	order    []string
	stop     chan struct{}
	upstream []net.IP
}

type cacheEntry struct {
	bytes  []byte
	expiry time.Time
	qname  string
}

// New validates configuration and returns an unstarted server.
func New(cfg Config, log *logging.Logger) (*Server, error) {
	if cfg.Bind == nil {
		return nil, errors.New("dns: a bind address is required (refusing to listen on all interfaces)")
	}
	if cfg.Port == 0 {
		cfg.Port = 53
	}
	if cfg.TTL == 0 {
		cfg.TTL = 120
	}
	if cfg.MaxCache <= 0 {
		cfg.MaxCache = 256
	}
	if len(cfg.Upstream) == 0 {
		return nil, errors.New("dns: no upstream resolver configured")
	}
	return &Server{
		cfg: cfg, log: log,
		cache: map[string]*cacheEntry{}, upstream: cfg.Upstream, stop: make(chan struct{}),
	}, nil
}

// Start binds the socket and begins serving.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return errors.New("dns: already running")
	}
	s.mu.Unlock()
	addr := &net.UDPAddr{IP: s.cfg.Bind, Port: s.cfg.Port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("dns: cannot bind %s: %w (another resolver may already own port 53 on this address)", addr, err)
	}
	_ = conn.SetReadBuffer(1 << 17)
	_ = conn.SetWriteBuffer(1 << 17)
	s.mu.Lock()
	s.conn = conn
	s.running = true
	s.stop = make(chan struct{})
	s.mu.Unlock()
	go s.serve(conn)
	s.log.Infof("dns", "forwarder listening on %s, upstreams %s", addr, joinIPs(s.upstream))
	return nil
}

// Stop releases the socket.
func (s *Server) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = false
	c := s.conn
	s.conn = nil
	close(s.stop)
	s.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	s.log.Infof("dns", "forwarder stopped")
	return nil
}

// Running reports state.
func (s *Server) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.running
}

// Status is the dashboard view.
func (s *Server) Status() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return map[string]any{
		"running": s.running, "bind": s.cfg.Bind.String(), "port": s.cfg.Port,
		"upstream": joinIPs(s.upstream), "queries": s.queries, "cached": len(s.cache),
	}
}

// SetUpstream changes the forward targets at runtime (used when the WAN flips).
func (s *Server) SetUpstream(ips []net.IP) {
	s.mu.Lock()
	if len(ips) > 0 {
		s.upstream = ips
		s.cache = map[string]*cacheEntry{}
		s.order = nil
	}
	s.mu.Unlock()
}

// SetLocalRecords replaces the in-LAN name map used for offline resolution.
func (s *Server) SetLocalRecords(m map[string]net.IP) {
	s.mu.Lock()
	s.cfg.LocalName = m
	s.mu.Unlock()
}

func (s *Server) serve(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.stop:
				return
			default:
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			s.log.Warnf("dns", "read error: %v", err)
			return
		}
		q := append([]byte(nil), buf[:n]...)
		go s.handle(conn, from, q)
	}
}

// handle processes one query. Work is bounded by the UDP read loop itself; a
// forwarder that spawns a goroutine per packet is fine here because each one
// does at most two short upstream round trips.
func (s *Server) handle(conn *net.UDPConn, from *net.UDPAddr, q []byte) {
	name, qtype, qclass, ok := parseQuery(q)
	if !ok {
		return
	}
	s.mu.Lock()
	s.queries++
	s.mu.Unlock()

	key := strings.ToLower(name) + "|" + fmt.Sprint(qtype)

	// LAN-local answers first: they must work with no upstream at all.
	if ans := s.localAnswer(name, qtype); ans != nil {
		ans.ID = idOf(q)
		if err := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); err == nil {
			_, _ = conn.WriteToUDP(ans.Bytes(), from)
		}
		return
	}

	s.mu.Lock()
	ce := s.cache[key]
	s.mu.Unlock()
	if ce != nil && time.Now().Before(ce.expiry) {
		out := make([]byte, len(ce.bytes))
		copy(out, ce.bytes)
		binary.BigEndian.PutUint16(out[0:2], idOf(q))
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.WriteToUDP(out, from)
		return
	}

	resp, err := s.forward(q)
	if err != nil {
		s.log.Debugf("dns", "forward %s failed: %v", name, err)
		refused := buildServfail(q)
		_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
		_, _ = conn.WriteToUDP(refused, from)
		return
	}
	s.store(key, resp)
	_ = conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.WriteToUDP(resp, from); err != nil {
		s.log.Debugf("dns", "reply to %s failed: %v", from, err)
	}
	_ = qclass
}

func (s *Server) localAnswer(name string, qtype uint16) *Message {
	lower := strings.TrimSuffix(strings.ToLower(name), ".")
	s.mu.Lock()
	zone := s.cfg.LocalZone
	local := map[string]net.IP{}
	for k, v := range s.cfg.LocalName {
		local[strings.ToLower(k)] = v
	}
	s.mu.Unlock()

	if qtype == typePTR && strings.HasSuffix(lower, ".in-addr.arpa") {
		ip := reverseFromArpa(lower)
		if ip == nil {
			return nil
		}
		s.mu.Lock()
		host := ""
		for k, v := range s.cfg.LocalName {
			if v.Equal(ip) {
				host = k
				break
			}
		}
		s.mu.Unlock()
		if host == "" {
			return nil
		}
		m := NewMessage(0, true)
		m.Questions = []Question{{Name: name, Type: qtype, Class: classIN}}
		m.Answers = []RR{{Name: name, Type: typePTR, Class: classIN, TTL: s.cfg.TTL, Data: host + "." + zone}}
		return m
	}
	if qtype != typeA && qtype != typeAAAA {
		return nil
	}
	candidates := []string{lower}
	if zone != "" {
		candidates = append(candidates, strings.TrimSuffix(lower, "."+zone))
	}
	for _, c := range candidates {
		if ip, ok := local[c]; ok && ip != nil {
			m := NewMessage(0, true)
			m.Questions = []Question{{Name: name, Type: qtype, Class: classIN}}
			if qtype == typeA {
				if v4 := ip.To4(); v4 != nil {
					m.Answers = []RR{{Name: name, Type: typeA, Class: classIN, TTL: s.cfg.TTL, Data: v4.String()}}
				}
			} else if ip.To4() == nil {
				m.Answers = []RR{{Name: name, Type: typeAAAA, Class: classIN, TTL: s.cfg.TTL, Data: ip.String()}}
			}
			if len(m.Answers) == 0 {
				continue
			}

			return m
		}
	}
	return nil
}

func reverseFromArpa(name string) net.IP {
	f := strings.Split(name, ".")
	if len(f) < 5 {
		return nil
	}
	var b [4]byte
	for i := 0; i < 4; i++ {
		v, err := atoi(f[3-i])
		if err != nil || v > 255 {
			return nil
		}
		b[i] = byte(v)
	}
	return net.IP(b[:])
}

// forward sends the query upstream, retrying each server once.
func (s *Server) forward(q []byte) ([]byte, error) {
	s.mu.Lock()
	ups := append([]net.IP(nil), s.upstream...)
	s.mu.Unlock()
	if len(ups) == 0 {
		return nil, errors.New("no upstream resolver")
	}
	var lastErr error
	for _, u := range ups {
		resp, err := exchangeUDP(u, q, 2500*time.Millisecond)
		if err != nil {
			lastErr = err
			continue
		}
		if truncated(resp) {
			tcpResp, terr := exchangeTCP(u, q, 4*time.Second)
			if terr == nil && len(tcpResp) > 0 {
				return tcpResp, nil
			}
			lastErr = terr
		}
		return resp, nil
	}
	return nil, fmt.Errorf("all upstream resolvers failed (last: %v)", lastErr)
}

func exchangeUDP(server net.IP, q []byte, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout("udp", net.JoinHostPort(server.String(), "53"), timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	if _, err := c.Write(q); err != nil {
		return nil, err
	}
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	if err != nil {
		return nil, err
	}
	if n < 12 {
		return nil, errors.New("short DNS reply")
	}
	return append([]byte(nil), buf[:n]...), nil
}

func exchangeTCP(server net.IP, q []byte, timeout time.Duration) ([]byte, error) {
	c, err := net.DialTimeout("tcp", net.JoinHostPort(server.String(), "53"), timeout)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))
	hdr := []byte{byte(len(q) >> 8), byte(len(q))}
	if _, err := c.Write(append(hdr, q...)); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n <= 0 || n > 4096 {
		return nil, fmt.Errorf("invalid TCP DNS length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func truncated(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	return b[2]&0x02 != 0
}

func (s *Server) store(key string, resp []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ttl := s.cfg.TTL
	if t, ok := minTTL(resp); ok && t > 0 {
		ttl = t
	}
	if len(s.cache) >= s.cfg.MaxCache {
		// Evict oldest first: append order tracks insertion.
		if len(s.order) > 0 {
			victim := s.order[0]
			s.order = s.order[1:]
			delete(s.cache, victim)
		}
	}
	s.cache[key] = &cacheEntry{bytes: resp, expiry: time.Now().Add(time.Duration(ttl) * time.Second), qname: key}
	s.order = append(s.order, key)
}

func minTTL(b []byte) (uint32, bool) {
	if len(b) < 12 {
		return 0, false
	}
	ans := int(binary.BigEndian.Uint16(b[6:8]))
	if ans == 0 {
		return 0, false
	}
	min := uint32(0xffffffff)
	// Skip the question section, then read each answer's TTL.
	i := 12
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	for q := 0; q < qd && i < len(b); q++ {
		for i < len(b) {
			l := int(b[i])
			if l == 0 {
				i++
				break
			}
			if l >= 0xc0 {
				i += 2
				break
			}
			i += 1 + l
		}
		i += 4
	}
	for a := 0; a < ans; a++ {
		if i+10 > len(b) {
			break
		}
		for i < len(b) {
			l := int(b[i])
			if l == 0 {
				i++
				break
			}
			if l >= 0xc0 {
				i += 2
				break
			}
			i += 1 + l
		}
		if i+6 > len(b) {
			break
		}
		t := binary.BigEndian.Uint32(b[i : i+4])
		if t < min {
			min = t
		}
		rdlen := int(binary.BigEndian.Uint16(b[i+8 : i+10]))
		i += 10 + rdlen
	}
	if min == 0xffffffff {
		return 0, false
	}
	return min, true
}

func idOf(q []byte) uint16 {
	if len(q) < 2 {
		return 0
	}
	return binary.BigEndian.Uint16(q[:2])
}

// buildServfail answers with SERVFAIL so clients retry another resolver rather
// than treating the answer as authoritative.
func buildServfail(q []byte) []byte {
	if len(q) < 12 {
		return nil
	}
	out := make([]byte, len(q))
	copy(out, q)
	out[2] |= rflagRA
	out[3] |= rcodeRefused
	binary.BigEndian.PutUint16(out[6:8], 0)
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	return out
}

func joinIPs(ips []net.IP) string {
	var s []string
	for _, i := range ips {
		s = append(s, i.String())
	}
	return strings.Join(s, ",")
}

func atoi(s string) (int, error) {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("not a number")
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, nil
}

// CacheEntries lists cache keys for the diagnostics page.
func (s *Server) CacheEntries() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.cache))
	for k := range s.cache {
		out = append(out, k)
	}
	sort.Strings(out)
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}
