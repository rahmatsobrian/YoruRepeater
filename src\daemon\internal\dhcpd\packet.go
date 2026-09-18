package dhcpd

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// dhcpMsg is the fixed BOOTP header (RFC 951/1542) plus parsed options.
type dhcpMsg struct {
	op      byte
	htype   byte
	hlen    byte
	hops    byte
	xid     uint32
	secs    uint16
	flags   uint16
	ciaddr  uint32
	yiaddr  uint32
	siaddr  uint32
	giaddr  uint32
	chaddr  [16]byte
	sname   [64]byte
	file    [128]byte
	opts    map[int][]byte
	rawOpts []byte
}

// msgType returns option 53, defaulting to DISCOVER for old clients that omit
// it (a REQUEST naming a server id is an INIT-REBOOT selection).
func (m *dhcpMsg) msgType() byte {
	if v, ok := m.opts[optMessage]; ok && len(v) > 0 {
		return v[0]
	}
	if v, ok := m.opts[optServerID]; ok && len(v) > 0 {
		return request
	}
	return discover
}

// encodeOpt packs an option list.
type optList struct{ buf []byte }

func (o *optList) byte(code int, v byte) *optList {
	o.buf = append(o.buf, byte(code), 1, v)
	return o
}

func (o *optList) ip(code int, v net.IP) *optList {
	if v == nil {
		return o
	}
	b := v.To4()
	if b == nil {
		return o
	}
	o.buf = append(o.buf, byte(code), byte(len(b)))
	o.buf = append(o.buf, b...)
	return o
}

func (o *optList) ips(code int, v []net.IP) *optList {
	if len(v) == 0 {
		return o
	}
	var body []byte
	for _, ip := range v {
		b := ip.To4()
		if b == nil {
			continue
		}
		body = append(body, b...)
	}
	if body == nil {
		return o
	}
	o.buf = append(o.buf, byte(code), byte(len(body)))
	o.buf = append(o.buf, body...)
	return o
}

func (o *optList) u32(code int, v uint32) *optList {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	o.buf = append(o.buf, byte(code), 4)
	o.buf = append(o.buf, b[:]...)
	return o
}

func (o *optList) str(code int, v string) *optList {
	if v == "" {
		return o
	}
	if len(v) > 255 {
		v = v[:255]
	}
	o.buf = append(o.buf, byte(code), byte(len(v)))
	o.buf = append(o.buf, v...)
	return o
}

// parse decodes a DHCP request.
func parse(b []byte) (*dhcpMsg, error) {
	if len(b) < 240 {
		return nil, fmt.Errorf("short packet (%d bytes)", len(b))
	}
	m := &dhcpMsg{}
	m.op = b[0]
	m.htype = b[1]
	m.hlen = b[2]
	m.hops = b[3]
	m.xid = binary.BigEndian.Uint32(b[4:8])
	m.secs = binary.BigEndian.Uint16(b[8:10])
	m.flags = binary.BigEndian.Uint16(b[10:12])
	m.ciaddr = binary.BigEndian.Uint32(b[12:16])
	m.yiaddr = binary.BigEndian.Uint32(b[16:20])
	m.siaddr = binary.BigEndian.Uint32(b[20:24])
	m.giaddr = binary.BigEndian.Uint32(b[24:28])
	copy(m.chaddr[:], b[28:44])
	copy(m.sname[:], b[44:108])
	copy(m.file[:], b[108:236])
	if binary.BigEndian.Uint32(b[236:240]) != magicCookie {
		return nil, errors.New("missing DHCP magic cookie (not a DHCP packet)")
	}
	if m.hlen == 0 || m.hlen > 16 {
		return nil, fmt.Errorf("invalid hardware address length %d", m.hlen)
	}
	m.opts = map[int][]byte{}
	i := 240
	for i < len(b) {
		code := b[i]
		if code == optPad {
			i++
			continue
		}
		if code == optEnd {
			break
		}
		if i+1 >= len(b) {
			return nil, errors.New("truncated option")
		}
		l := int(b[i+1])
		if l == 0 || i+2+l > len(b) {
			break
		}
		m.opts[int(code)] = append([]byte(nil), b[i+2:i+2+l]...)
		i += 2 + l
	}
	return m, nil
}

func hwAddr(a [16]byte, hlen byte) string {
	if hlen == 0 || int(hlen) > len(a) {
		return ""
	}
	var parts []string
	for i := 0; i < int(hlen); i++ {
		parts = append(parts, fmt.Sprintf("%02x", a[i]))
	}
	return net.HardwareAddr(partsToBytes(parts)).String()
}

func partsToBytes(parts []string) []byte {
	out := make([]byte, 0, len(parts))
	for _, p := range parts {
		var v byte
		for _, c := range p {
			switch {
			case c >= '0' && c <= '9':
				v = v*16 + byte(c-'0')
			case c >= 'a' && c <= 'f':
				v = v*16 + byte(c-'a'+10)
			case c >= 'A' && c <= 'F':
				v = v*16 + byte(c-'A'+10)
			}
		}
		out = append(out, v)
	}
	return out
}

// buildReply composes a DHCP reply for the given message type.
func buildReply(req *dhcpMsg, msgType byte, yiaddr net.IP, cfg Config, message []byte) *dhcpMsg {
	rep := &dhcpMsg{
		op:    2, // BOOTREPLY
		htype: 1, hlen: 6,
		xid:    req.xid,
		flags:  req.flags,
		giaddr: req.giaddr,
	}
	copy(rep.chaddr[:], req.chaddr[:])
	rep.yiaddr = ipToU32(yiaddr)
	rep.siaddr = ipToU32(cfg.ServerID)

	opts := &optList{}
	opts.byte(optMessage, msgType)
	opts.ip(optServerID, cfg.ServerID)
	opts.u32(optLeaseTime, uint32(cfg.Lease/time.Second))
	opts.ip(optSubnet, net.IP(cfg.Subnet.Mask))
	if cfg.Router != nil {
		opts.ips(optRouter, []net.IP{cfg.Router})
	}
	if len(cfg.DNS) > 0 {
		opts.ips(optDNS, cfg.DNS)
	}
	if cfg.Domain != "" {
		opts.str(optDomain, cfg.Domain)
	}
	if msgType == ack && yiaddr != nil {
		opts.u32(optRenewal, uint32(cfg.Lease/time.Second)/2)
		opts.u32(optRebind, uint32(cfg.Lease/time.Second)*7/8)
	}
	if len(message) > 0 {
		opts.str(56, string(message))
	}
	rep.rawOpts = opts.buf
	return rep
}

// Encode serialises a reply into an Ethernet-level-free UDP payload.
func (m *dhcpMsg) Encode() []byte {
	b := make([]byte, 240)
	b[0] = m.op
	b[1] = m.htype
	b[2] = m.hlen
	b[3] = m.hops
	binary.BigEndian.PutUint32(b[4:8], m.xid)
	binary.BigEndian.PutUint16(b[8:10], m.secs)
	binary.BigEndian.PutUint16(b[10:12], m.flags)
	binary.BigEndian.PutUint32(b[12:16], m.ciaddr)
	binary.BigEndian.PutUint32(b[16:20], m.yiaddr)
	binary.BigEndian.PutUint32(b[20:24], m.siaddr)
	binary.BigEndian.PutUint32(b[24:28], m.giaddr)
	copy(b[28:44], m.chaddr[:])
	copy(b[44:108], m.sname[:])
	copy(b[108:236], m.file[:])
	binary.BigEndian.PutUint32(b[236:240], magicCookie)
	b = append(b, m.rawOpts...)
	b = append(b, optEnd)
	return b
}

// timeoutContext is a tiny helper so the caller does not have to import context
// at every call site.
func timeoutContext(d time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), d)
}
