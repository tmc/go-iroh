//go:build !js

package mdns

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/tmc/go-iroh/dns"
)

const (
	dnsTypeA    uint16 = 1
	dnsTypePTR  uint16 = 12
	dnsTypeTXT  uint16 = 16
	dnsTypeAAAA uint16 = 28
	dnsTypeSRV  uint16 = 33
	dnsTypeANY  uint16 = 255
	dnsClassIN  uint16 = 1
)

type dnsBuilder struct {
	buf []byte
}

func buildQuery(names ...string) ([]byte, error) {
	b := dnsBuilder{buf: make([]byte, 12)}
	binary.BigEndian.PutUint16(b.buf[4:6], uint16(len(names)))
	for _, name := range names {
		if err := b.name(name); err != nil {
			return nil, err
		}
		b.u16(dnsTypePTR)
		b.u16(dnsClassIN)
	}
	return b.buf, nil
}

func buildAnnouncement(service string, data announcementData) ([]byte, error) {
	inst := instanceName(service, data.id)
	host := hostName(data.id)
	txt := []string{}
	if data.relay != "" {
		txt = append(txt, "relay="+data.relay)
	}
	if data.userData != "" {
		txt = append(txt, "user-data="+data.userData)
	}

	answers := 3
	for _, ap := range data.ips {
		ip := ap.Addr()
		if ip.Is4() || ip.Is4In6() {
			answers++
		} else if ip.Is6() {
			answers++
		}
	}

	b := dnsBuilder{buf: make([]byte, 12)}
	binary.BigEndian.PutUint16(b.buf[2:4], 0x8400)
	binary.BigEndian.PutUint16(b.buf[6:8], uint16(answers))
	if err := b.ptr(serviceName(service), inst); err != nil {
		return nil, err
	}
	if err := b.srv(inst, data.port, host); err != nil {
		return nil, err
	}
	if err := b.txt(inst, txt); err != nil {
		return nil, err
	}
	for _, ap := range data.ips {
		ip := ap.Addr()
		if ip.Is4() || ip.Is4In6() {
			if err := b.a(host, ip); err != nil {
				return nil, err
			}
		} else if ip.Is6() {
			if err := b.aaaa(host, ip); err != nil {
				return nil, err
			}
		}
	}
	return b.buf, nil
}

func (b *dnsBuilder) ptr(name, ptr string) error {
	if err := b.rrHeader(name, dnsTypePTR, 120); err != nil {
		return err
	}
	start := len(b.buf)
	b.u16(0)
	if err := b.name(ptr); err != nil {
		return err
	}
	b.setLen(start)
	return nil
}

func (b *dnsBuilder) srv(name string, port uint16, target string) error {
	if err := b.rrHeader(name, dnsTypeSRV, 120); err != nil {
		return err
	}
	start := len(b.buf)
	b.u16(0)
	b.u16(0)
	b.u16(0)
	b.u16(port)
	if err := b.name(target); err != nil {
		return err
	}
	b.setLen(start)
	return nil
}

func (b *dnsBuilder) txt(name string, values []string) error {
	if err := b.rrHeader(name, dnsTypeTXT, 120); err != nil {
		return err
	}
	start := len(b.buf)
	b.u16(0)
	for _, value := range values {
		if len(value) > 255 {
			continue
		}
		b.buf = append(b.buf, byte(len(value)))
		b.buf = append(b.buf, value...)
	}
	b.setLen(start)
	return nil
}

func (b *dnsBuilder) a(name string, ip netip.Addr) error {
	if err := b.rrHeader(name, dnsTypeA, 120); err != nil {
		return err
	}
	a := ip.As4()
	b.u16(4)
	b.buf = append(b.buf, a[:]...)
	return nil
}

func (b *dnsBuilder) aaaa(name string, ip netip.Addr) error {
	if err := b.rrHeader(name, dnsTypeAAAA, 120); err != nil {
		return err
	}
	a := ip.As16()
	b.u16(16)
	b.buf = append(b.buf, a[:]...)
	return nil
}

func (b *dnsBuilder) rrHeader(name string, typ uint16, ttl uint32) error {
	if err := b.name(name); err != nil {
		return err
	}
	b.u16(typ)
	b.u16(dnsClassIN)
	b.u32(ttl)
	return nil
}

func (b *dnsBuilder) name(name string) error {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		b.buf = append(b.buf, 0)
		return nil
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("mdns: invalid dns label %q", label)
		}
		b.buf = append(b.buf, byte(len(label)))
		b.buf = append(b.buf, label...)
	}
	b.buf = append(b.buf, 0)
	return nil
}

func (b *dnsBuilder) u16(v uint16) { b.buf = binary.BigEndian.AppendUint16(b.buf, v) }
func (b *dnsBuilder) u32(v uint32) { b.buf = binary.BigEndian.AppendUint32(b.buf, v) }

func (b *dnsBuilder) setLen(start int) {
	binary.BigEndian.PutUint16(b.buf[start:start+2], uint16(len(b.buf)-start-2))
}

func parseAnnouncement(packet []byte, service string) (dns.EndpointInfo, bool) {
	msg, err := parseDNS(packet)
	if err != nil {
		return dns.EndpointInfo{}, false
	}
	instService := "." + serviceName(service)
	hosts := make(map[string][]netip.Addr)
	txt := make(map[string]map[string]string)
	srv := make(map[string]struct {
		port uint16
		host string
	})
	instances := make(map[string]struct{})
	for _, rr := range msg.answers {
		switch rr.typ {
		case dnsTypePTR:
			if strings.EqualFold(rr.name, serviceName(service)) {
				instances[rr.ptr] = struct{}{}
			}
		case dnsTypeSRV:
			srv[rr.name] = struct {
				port uint16
				host string
			}{port: rr.port, host: rr.target}
			instances[rr.name] = struct{}{}
		case dnsTypeTXT:
			txt[rr.name] = rr.txt
			instances[rr.name] = struct{}{}
		case dnsTypeA, dnsTypeAAAA:
			hosts[rr.name] = append(hosts[rr.name], rr.ip)
		}
	}
	for inst := range instances {
		if !strings.HasSuffix(strings.ToLower(inst), strings.ToLower(instService)) {
			continue
		}
		label := strings.TrimSuffix(inst, instService)
		id, err := parseEndpointLabel(label)
		if err != nil {
			continue
		}
		s, ok := srv[inst]
		if !ok || s.port == 0 {
			continue
		}
		var data announcementData
		data.id = id
		data.port = s.port
		for _, ip := range hosts[s.host] {
			data.ips = append(data.ips, netip.AddrPortFrom(ip, s.port))
		}
		if len(data.ips) == 0 {
			continue
		}
		if attrs := txt[inst]; attrs != nil {
			data.relay = attrs["relay"]
			data.userData = attrs["user-data"]
		}
		return infoFromAnnouncement(data), true
	}
	return dns.EndpointInfo{}, false
}

// dnsQuestion is one question from a multicast query.
type dnsQuestion struct {
	name string
	typ  uint16
}

// parseQuestions returns the questions in packet. It reports false for a
// response, a packet with no questions, and a malformed one: only a query is
// worth answering.
func parseQuestions(packet []byte) ([]dnsQuestion, bool) {
	if len(packet) < 12 {
		return nil, false
	}
	if binary.BigEndian.Uint16(packet[2:4])&0x8000 != 0 {
		return nil, false // a response
	}
	qd := int(binary.BigEndian.Uint16(packet[4:6]))
	if qd == 0 {
		return nil, false
	}
	off := 12
	questions := make([]dnsQuestion, 0, qd)
	for i := 0; i < qd; i++ {
		name, next, err := readName(packet, off)
		if err != nil {
			return nil, false
		}
		off = next
		if off+4 > len(packet) {
			return nil, false
		}
		questions = append(questions, dnsQuestion{name: name, typ: binary.BigEndian.Uint16(packet[off : off+2])})
		off += 4
	}
	return questions, true
}

type dnsMessage struct {
	answers []resourceRecord
}

type resourceRecord struct {
	name   string
	typ    uint16
	ptr    string
	port   uint16
	target string
	txt    map[string]string
	ip     netip.Addr
}

func parseDNS(packet []byte) (dnsMessage, error) {
	if len(packet) < 12 {
		return dnsMessage{}, errors.New("mdns: short packet")
	}
	qd := int(binary.BigEndian.Uint16(packet[4:6]))
	an := int(binary.BigEndian.Uint16(packet[6:8]))
	ns := int(binary.BigEndian.Uint16(packet[8:10]))
	ar := int(binary.BigEndian.Uint16(packet[10:12]))
	off := 12
	for i := 0; i < qd; i++ {
		var err error
		_, off, err = readName(packet, off)
		if err != nil {
			return dnsMessage{}, err
		}
		if off+4 > len(packet) {
			return dnsMessage{}, errors.New("mdns: short question")
		}
		off += 4
	}
	var msg dnsMessage
	for i := 0; i < an+ns+ar; i++ {
		rr, next, err := readRR(packet, off)
		if err != nil {
			return dnsMessage{}, err
		}
		off = next
		msg.answers = append(msg.answers, rr)
	}
	return msg, nil
}

func readRR(packet []byte, off int) (resourceRecord, int, error) {
	name, off, err := readName(packet, off)
	if err != nil {
		return resourceRecord{}, 0, err
	}
	if off+10 > len(packet) {
		return resourceRecord{}, 0, errors.New("mdns: short resource record")
	}
	typ := binary.BigEndian.Uint16(packet[off : off+2])
	off += 2
	off += 2 // class
	off += 4 // ttl
	n := int(binary.BigEndian.Uint16(packet[off : off+2]))
	off += 2
	if off+n > len(packet) {
		return resourceRecord{}, 0, errors.New("mdns: short rdata")
	}
	data := packet[off : off+n]
	next := off + n
	rr := resourceRecord{name: name, typ: typ}
	switch typ {
	case dnsTypePTR:
		rr.ptr, _, err = readName(packet, off)
	case dnsTypeSRV:
		if len(data) < 6 {
			return resourceRecord{}, 0, errors.New("mdns: short srv")
		}
		rr.port = binary.BigEndian.Uint16(data[4:6])
		rr.target, _, err = readName(packet, off+6)
	case dnsTypeTXT:
		rr.txt = parseTXT(data)
	case dnsTypeA:
		if len(data) == 4 {
			rr.ip = netip.AddrFrom4([4]byte(data))
		}
	case dnsTypeAAAA:
		if len(data) == 16 {
			rr.ip = netip.AddrFrom16([16]byte(data))
		}
	}
	if err != nil {
		return resourceRecord{}, 0, err
	}
	return rr, next, nil
}

func readName(packet []byte, off int) (string, int, error) {
	var labels []string
	next := off
	jumped := false
	for depth := 0; depth < 32; depth++ {
		if off >= len(packet) {
			return "", 0, errors.New("mdns: short name")
		}
		l := packet[off]
		if l&0xc0 == 0xc0 {
			if off+1 >= len(packet) {
				return "", 0, errors.New("mdns: short compression pointer")
			}
			ptr := int(l&0x3f)<<8 | int(packet[off+1])
			if !jumped {
				next = off + 2
				jumped = true
			}
			off = ptr
			continue
		}
		if l&0xc0 != 0 {
			return "", 0, errors.New("mdns: unsupported name label")
		}
		off++
		if l == 0 {
			if !jumped {
				next = off
			}
			return strings.Join(labels, "."), next, nil
		}
		if off+int(l) > len(packet) {
			return "", 0, errors.New("mdns: short label")
		}
		labels = append(labels, string(packet[off:off+int(l)]))
		off += int(l)
	}
	return "", 0, errors.New("mdns: compression loop")
}

func parseTXT(data []byte) map[string]string {
	out := make(map[string]string)
	for len(data) > 0 {
		n := int(data[0])
		data = data[1:]
		if n > len(data) {
			break
		}
		s := string(data[:n])
		data = data[n:]
		k, v, ok := strings.Cut(s, "=")
		if ok {
			out[k] = v
		}
	}
	return out
}
