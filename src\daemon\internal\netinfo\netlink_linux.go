//go:build linux

package netinfo

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

// Netlink / rtnetlink constants that Go's syscall package does not export.
const (
	syscallRTMGetlink  = 16 // RTM_GETLINK
	syscallRTMGetaddr  = 22 // RTM_GETADDR
	syscallRTMGetroute = 26 // RTM_GETROUTE
	syscallRTMGetneigh = 30 // RTM_GETNEIGH

	iflaUnspec    = 0
	iflaAddress   = 1
	iflaBroadcast = 2
	iflaIfname    = 3
	iflaMtu       = 4
	iflaLink      = 5
	iflaQdisc     = 6
	iflaStats     = 7
	iflaMaster    = 10
	iflaTxqlen    = 13
	iflaOperstate = 16
	iflaLinkinfo  = 21
	iflaStats64   = 23
	iflaInfoKind  = 1

	ifaAddress   = 1
	ifaLocal     = 2
	ifaLabel     = 3
	ifaCacheinfo = 4
	ifaFlags     = 8

	rtaDst      = 1
	rtaSrc      = 2
	rtaIif      = 3
	rtaOif      = 4
	rtaGateway  = 5
	rtaPriority = 6
	rtaPrefsrc  = 8
	rtaTable    = 15
	rtaVia      = 16

	ndaDst       = 1
	ndaLLaddr    = 2
	ndaCacheinfo = 3

	rtTableMain  = 252
	rtTableLocal = 255

	rtNUnicast = 1
	rtNLocal   = 3

	rtScopeUniverse = 0
	rtScopeSite     = 200
	rtScopeLink     = 253
	rtScopeHost     = 254

	rtProtKernel   = 0
	rtProtBoot     = 2
	rtProtStatic   = 4
	rtProtRA       = 9
	rtProtDHCP     = 16
	rtProtRedirect = 6
	rtProtNDRA     = 5

	nudIncomplete = 0x01
	nudReachable  = 0x02
	nudStale      = 0x04
	nudDelay      = 0x08
	nudProbe      = 0x10
	nudFailed     = 0x20
	nudNoARP      = 0x80
	nudPermanent  = 0x80
)

func netlinkDump(proto int) ([]syscall.NetlinkMessage, error) {
	b, err := syscall.NetlinkRIB(proto, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(b)
	if err != nil {
		return nil, err
	}
	// Drop error acks (NLMSG_ERROR with code 0 ends a dump).
	out := msgs[:0]
	for _, m := range msgs {
		if m.Header.Type == syscall.NLMSG_DONE {
			continue
		}
		if m.Header.Type == syscall.NLMSG_ERROR {
			continue
		}
		out = append(out, m)
	}
	return out, nil
}

func attrs(m *syscall.NetlinkMessage) map[uint16][]byte {
	res := map[uint16][]byte{}
	list, err := syscall.ParseNetlinkRouteAttr(m)
	if err != nil {
		return res
	}
	for _, a := range list {
		res[a.Attr.Type] = a.Value
	}
	return res
}

// ifinfomsg: family(1) pad(1) type(2) index(4) flags(4) change(4) = 16 bytes
func parseIfInfo(m syscall.NetlinkMessage) (Link, bool) {
	if len(m.Data) < 16 {
		return Link{}, false
	}
	var raw [16]byte
	copy(raw[:], m.Data[:16])
	l := Link{}
	l.KernelType = binary.LittleEndian.Uint16(raw[2:4])
	l.Index = int(*(*int32)(unsafe.Pointer(&raw[4])))
	flags := binary.LittleEndian.Uint32(raw[8:12])
	l.Up = flags&ifFlagUp != 0
	l.Running = flags&ifFlagRunning != 0
	l.Loopback = flags&ifFlagLoopback != 0
	l.LowerUp = flags&ifFlagLowerUp != 0
	l.Type = typeName(l.KernelType)
	a := attrs(&m)
	if v, ok := a[iflaIfname]; ok {
		l.Name = cstr(v)
	}
	if v, ok := a[iflaAddress]; ok && len(v) == 6 {
		l.MAC = macString(v)
	}
	if v, ok := a[iflaAddress]; ok && len(v) == 20 { // IPoIB etc
		l.MAC = macString(v[:6])
	}
	if v, ok := a[iflaMtu]; ok && len(v) >= 4 {
		l.MTU = int(binary.LittleEndian.Uint32(v))
	}
	if v, ok := a[iflaMaster]; ok && len(v) >= 4 {
		l.Master = linkNameByIndex(int(binary.LittleEndian.Uint32(v)))
	}
	if v, ok := a[iflaTxqlen]; ok && len(v) >= 4 {
		l.TxQLen = int(binary.LittleEndian.Uint32(v))
	}
	if v, ok := a[iflaOperstate]; ok && len(v) >= 1 {
		l.OperState = operStateName(v[0])
	}
	// IFLA_LINKINFO is nested; extract IFLA_INFO_KIND to spot virtual devices.
	if v, ok := a[iflaLinkinfo]; ok {
		if kind := nestedKind(v); kind != "" {
			l.Kind = kind
			switch kind {
			case "veth", "bridge", "dummy", "ifb", "macvlan", "macvtap", "ipip", "sit", "gre", "gretap", "wg", "tun", "tap", "vxlan", "bond", "xtun", "erspan":
				l.IsVirtual = true
			}
			if kind == "bridge" {
				l.Type = "bridge"
			}
		}
	}
	if l.Name == "" {
		return Link{}, false
	}
	l.State = deriveState(l)
	return l, true
}

func nestedKind(b []byte) string {
	for len(b) >= 4 {
		l := int(binary.LittleEndian.Uint16(b[0:2]))
		t := binary.LittleEndian.Uint16(b[2:4])
		if l < 4 || l > len(b) {
			break
		}
		if t == iflaInfoKind {
			return cstr(b[4:l])
		}
		pad := (l + 3) & ^3
		if pad > len(b) {
			break
		}
		b = b[pad:]
	}
	return ""
}

func operStateName(v byte) string {
	states := []string{"unknown", "notpresent", "down", "lowerlayerdown", "testing", "dormant", "up"}
	if int(v) < len(states) {
		return states[v]
	}
	return "unknown"
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func macString(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return net.HardwareAddr(b[:6]).String()
}

// ifaddrmsg: family(1) prefixlen(1) flags(1) scope(1) index(4) = 8 bytes
func parseIfAddr(m syscall.NetlinkMessage) (Addr, bool) {
	if len(m.Data) < 8 {
		return Addr{}, false
	}
	var raw [8]byte
	copy(raw[:], m.Data[:8])
	fam := raw[0]
	a := Addr{}
	a.PrefixLen = int(raw[1])
	a.Scope = scopeName(raw[3], fam)
	idx := int(binary.LittleEndian.Uint32(raw[4:8]))
	switch fam {
	case syscall.AF_INET:
		a.Family = "IPv4"
	case syscall.AF_INET6:
		a.Family = "IPv6"
	default:
		return Addr{}, false
	}
	at := attrs(&m)
	ipb := at[ifaLocal]
	if len(ipb) == 0 {
		ipb = at[ifaAddress]
	}
	if len(ipb) == 0 {
		return Addr{}, false
	}
	ip := net.IP(ipb)
	a.IP = ip.String()
	a.CIDR = ip.String() + "/" + itoa(a.PrefixLen)
	if v, ok := at[ifaLabel]; ok {
		a.Label = cstr(v)
		if a.Label != "" && a.Iface == "" {
			a.Iface = a.Label
		}
	}
	if v, ok := at[ifaFlags]; ok && len(v) >= 4 {
		f := binary.LittleEndian.Uint32(v)
		const ifaFDeprecated = 0x100
		const ifaFTentative = 0x200
		a.Deprecated = f&ifaFDeprecated != 0
		a.Tentative = f&ifaFTentative != 0
	}
	if v, ok := at[ifaCacheinfo]; ok && len(v) >= 16 {
		a.Preferred = int(binary.LittleEndian.Uint32(v[4:8]))
		a.Valid = int(binary.LittleEndian.Uint32(v[8:12]))
	}
	if name := linkNameByIndex(idx); name != "" {
		a.Iface = name
	}
	return a, true
}

func scopeName(v byte, fam byte) string {
	if fam == syscall.AF_INET {
		switch v {
		case rtScopeUniverse:
			return "global"
		case rtScopeSite:
			return "site"
		case rtScopeLink:
			return "link"
		case rtScopeHost:
			return "host"
		}
	}
	switch v {
	case rtScopeUniverse:
		return "global"
	case rtScopeLink:
		return "link"
	case rtScopeHost:
		return "host"
	case rtScopeSite:
		return "site"
	}
	return "unknown"
}

// rtmsg: family(1) dst_len(1) src_len(1) tos(1) table(1) protocol(1) scope(1)
// type(1) flags(4) = 12 bytes
func parseRoute(m syscall.NetlinkMessage) (Route, bool) {
	if len(m.Data) < 12 {
		return Route{}, false
	}
	var raw [12]byte
	copy(raw[:], m.Data[:12])
	r := Route{}
	switch raw[0] {
	case syscall.AF_INET:
		r.Family = "IPv4"
	case syscall.AF_INET6:
		r.Family = "IPv6"
	default:
		return Route{}, false
	}
	dstLen := int(raw[1])
	r.Table = tableName(raw[4])
	r.Protocol = protoName(raw[5])
	r.Scope = scopeName(raw[6], raw[0])
	r.Type = rtnName(raw[7])
	at := attrs(&m)
	if v, ok := at[rtaDst]; ok {
		ip := net.IP(v)
		r.Dst = ip.String() + "/" + itoa(dstLen)
	} else {
		if r.Family == "IPv4" {
			r.Dst = "0.0.0.0/" + itoa(dstLen)
		} else {
			r.Dst = "::/" + itoa(dstLen)
		}
	}
	if v, ok := at[rtaGateway]; ok && len(v) > 0 {
		r.Gateway = net.IP(v).String()
	}
	if v, ok := at[rtaPrefsrc]; ok && len(v) > 0 {
		r.Prefsrc = net.IP(v).String()
	}
	if v, ok := at[rtaPriority]; ok && len(v) >= 4 {
		r.Metric = int(binary.LittleEndian.Uint32(v))
	}
	if v, ok := at[rtaOif]; ok && len(v) >= 4 {
		idx := int(binary.LittleEndian.Uint32(v))
		r.Dev = linkNameByIndex(idx)
	}
	if dstLen == 0 {
		r.IsDefault = true
	}
	return r, true
}

func tableName(v byte) string {
	switch v {
	case 0:
		return "unspec"
	case 252:
		return "main"
	case 253:
		return "default"
	case 254:
		return "local"
	case 255:
		return "main"
	}
	return "table-" + itoa(int(v))
}

func protoName(v byte) string {
	switch v {
	case rtProtKernel:
		return "kernel"
	case rtProtBoot:
		return "boot"
	case rtProtStatic:
		return "static"
	case rtProtRA, rtProtNDRA:
		return "ra"
	case rtProtRedirect:
		return "redirect"
	case rtProtDHCP:
		return "dhcp"
	}
	return "proto-" + itoa(int(v))
}

func rtnName(v byte) string {
	names := map[byte]string{1: "unicast", 2: "local", 3: "broadcast", 5: "anycast", 6: "multicast", 7: "blackhole", 8: "unreachable", 9: "prohibit"}
	if s, ok := names[v]; ok {
		return s
	}
	return "type-" + itoa(int(v))
}

// ndmsg: family(1) pad(3) state(2) flags(2) = 8 bytes
func parseNeigh(m syscall.NetlinkMessage, names map[int]string) (Neigh, bool) {
	if len(m.Data) < 8 {
		return Neigh{}, false
	}
	var raw [8]byte
	copy(raw[:], m.Data[:8])
	switch raw[0] {
	case syscall.AF_INET, syscall.AF_INET6:
	default:
		return Neigh{}, false
	}
	state := binary.LittleEndian.Uint16(raw[4:6])
	n := Neigh{State: nudName(state)}
	at := attrs(&m)
	if v, ok := at[ndaDst]; ok && len(v) > 0 {
		n.IP = net.IP(v).String()
	}
	if v, ok := at[ndaLLaddr]; ok && len(v) >= 6 {
		n.MAC = macString(v)
	}
	if n.IP == "" {
		return Neigh{}, false
	}
	// The interface index for a neighbour lives in ndmsg.ifindex, which is the
	// 4 bytes following family/pad/state/flags on modern kernels.
	if len(m.Data) >= 12 {
		idx := int(binary.LittleEndian.Uint32(m.Data[8:12]))
		if name, ok := names[idx]; ok {
			n.Iface = name
		}
	}
	return n, true
}

func nudName(v uint16) string {
	switch {
	case v&nudPermanent != 0:
		return "permanent"
	case v&nudNoARP != 0:
		return "noarp"
	case v&nudReachable != 0:
		return "reachable"
	case v&nudStale != 0:
		return "stale"
	case v&nudDelay != 0:
		return "delay"
	case v&nudProbe != 0:
		return "probe"
	case v&nudFailed != 0:
		return "failed"
	case v&nudIncomplete != 0:
		return "incomplete"
	}
	return "unknown"
}

// linkNameByIndex resolves an ifindex to a name through sysfs, which avoids
// recursing into Links() (which itself uses this).
func linkNameByIndex(idx int) string {
	if idx <= 0 {
		return ""
	}
	matches, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range matches {
		if i.Index == idx {
			return i.Name
		}
	}
	return ""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
