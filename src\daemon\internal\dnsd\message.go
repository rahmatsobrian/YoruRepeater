package dnsd

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

// Question is a DNS question record.
type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

// RR is a resource record with the subset of types Yoru needs.
type RR struct {
	Name  string
	Type  uint16
	Class uint16
	TTL   uint32
	Data  string
}

// Message is a minimal DNS message. Only the fields the forwarder touches are
// modelled; unknown sections are dropped, which is correct behaviour for a
// stub forwarder that answers locally.
type Message struct {
	ID        uint16
	Response  bool
	RA        bool
	RD        bool
	Code      byte
	Questions []Question
	Answers   []RR
}

// NewMessage builds a header.
func NewMessage(id uint16, response bool) *Message {
	m := &Message{ID: id, Response: response, RA: response, Code: rcodeOK}
	return m
}

// Bytes serialises the message.
func (m *Message) Bytes() []byte {
	var flags uint16
	if m.Response {
		flags |= 0x8000
	}
	if m.RA {
		flags |= uint16(rflagRA)
	}
	if m.RD {
		flags |= uint16(rflagRD)
	}
	flags |= uint16(m.Code & 0x0f)
	out := make([]byte, 12)
	binary.BigEndian.PutUint16(out[0:2], m.ID)
	binary.BigEndian.PutUint16(out[2:4], flags)
	binary.BigEndian.PutUint16(out[4:6], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(out[6:8], uint16(len(m.Answers)))
	for _, q := range m.Questions {
		out = appendName(out, q.Name)
		var tail [4]byte
		binary.BigEndian.PutUint16(tail[0:2], q.Type)
		binary.BigEndian.PutUint16(tail[2:4], q.Class)
		out = append(out, tail[:]...)
	}
	for _, r := range m.Answers {
		out = appendName(out, r.Name)
		var head [10]byte
		binary.BigEndian.PutUint16(head[0:2], r.Type)
		binary.BigEndian.PutUint16(head[2:4], r.Class)
		binary.BigEndian.PutUint32(head[4:8], r.TTL)
		rd := rdata(r)
		binary.BigEndian.PutUint16(head[8:10], uint16(len(rd)))
		out = append(out, head[:]...)
		out = append(out, rd...)
	}
	return out
}

func rdata(r RR) []byte {
	switch r.Type {
	case typeA:
		if ip := net.ParseIP(r.Data); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				return v4
			}
		}
		return []byte{0, 0, 0, 0}
	case typeAAAA:
		ip := net.ParseIP(r.Data)
		if ip == nil {
			return make([]byte, 16)
		}
		v6 := ip.To16()
		if v6 == nil {
			return make([]byte, 16)
		}
		return v6
	case typePTR, typeNS, typeMX, typeTXT:
		if r.Type == typeTXT {
			s := r.Data
			if len(s) > 255 {
				s = s[:255]
			}
			return append([]byte{byte(len(s))}, s...)
		}
		return appendName(nil, strings.TrimSuffix(r.Data, ".")+".")
	}
	return []byte(r.Data)
}

// appendName writes an uncompressed domain name.
func appendName(b []byte, name string) []byte {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return append(b, 0)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			label = label[:63]
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	return append(b, 0)
}

// parseQuery extracts the first question from a DNS request.
func parseQuery(b []byte) (name string, qtype, qclass uint16, ok bool) {
	if len(b) < 12 {
		return "", 0, 0, false
	}
	qd := int(binary.BigEndian.Uint16(b[4:6]))
	if qd == 0 {
		return "", 0, 0, false
	}
	i := 12
	var labels []string
	for i < len(b) {
		l := int(b[i])
		if l == 0 {
			i++
			break
		}
		if l >= 0xc0 {
			// Compression is not expected in a query; treat the rest as the name.
			i += 2
			break
		}
		if i+1+l > len(b) {
			return "", 0, 0, false
		}
		labels = append(labels, string(b[i+1:i+1+l]))
		i += 1 + l
	}
	if i+4 > len(b) {
		return "", 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(b[i : i+2])
	qclass = binary.BigEndian.Uint16(b[i+2 : i+4])
	name = strings.Join(labels, ".") + "."
	if len(labels) == 0 {
		name = "."
	}
	return name, qtype, qclass, true
}

// String renders the message for logs.
func (m *Message) String() string {
	if len(m.Questions) == 0 {
		return fmt.Sprintf("dns id=%d answers=%d", m.ID, len(m.Answers))
	}
	return fmt.Sprintf("dns id=%d q=%s/%d answers=%d", m.ID, m.Questions[0].Name, m.Questions[0].Type, len(m.Answers))
}
