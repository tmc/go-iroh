//go:build !js

package mdns

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"slices"
	"testing"

	"github.com/tmc/go-iroh/key"
)

// goV023Announcement is what go-iroh v0.2.3's buildAnnouncement wrote for
// rustEndpointID with the addresses 192.0.2.1:7777 and [2001:db8::1]:7777 and
// no relay or user data: PTR, SRV, an empty TXT and the address records, all
// counted as answers.
const goV023Announcement = "000084000000000500000000075f69726f687631045f756470056c6f63616c00000c000100000078004934677972756c70766a3573686d6835697379656d636f6a71347469366173696c7776766a32736679766a647777347a747571617361075f69726f687631045f756470056c6f63616c0034677972756c70766a3573686d6835697379656d636f6a71347469366173696c7776766a32736679766a647777347a747571617361075f69726f687631045f756470056c6f63616c0000210001000000780042000000001e6134677972756c70766a3573686d6835697379656d636f6a71347469366173696c7776766a32736679766a647777347a747571617361056c6f63616c0034677972756c70766a3573686d6835697379656d636f6a71347469366173696c7776766a32736679766a647777347a747571617361075f69726f687631045f756470056c6f63616c000010000100000078000034677972756c70766a3573686d6835697379656d636f6a71347469366173696c7776766a32736679766a647777347a747571617361056c6f63616c0000010001000000780004c000020134677972756c70766a3573686d6835697379656d636f6a71347469366173696c7776766a32736679766a647777347a747571617361056c6f63616c00001c000100000078001020010db8000000000000000000000001"

const rustEndpointID = "362345bea9ec8ec3f512c11827261c9a3c092176ad53a9171548ed6e66748024"

// section records where a resource record sits in a DNS message.
type section int

const (
	answer section = iota
	authority
	additional
)

type rrLayout struct {
	section section
	typ     uint16
	rdlen   int
}

// layout returns the section, type and RDATA length of each resource record
// in packet.
func layout(t *testing.T, packet []byte) []rrLayout {
	t.Helper()
	if len(packet) < 12 {
		t.Fatalf("short packet: %d bytes", len(packet))
	}
	qd := int(binary.BigEndian.Uint16(packet[4:6]))
	counts := [3]int{
		int(binary.BigEndian.Uint16(packet[6:8])),
		int(binary.BigEndian.Uint16(packet[8:10])),
		int(binary.BigEndian.Uint16(packet[10:12])),
	}
	off := 12
	for range qd {
		_, next, err := readName(packet, off)
		if err != nil {
			t.Fatal(err)
		}
		if next+4 > len(packet) {
			t.Fatal("short question")
		}
		off = next + 4
	}
	var out []rrLayout
	for sec, n := range counts {
		for range n {
			_, next, err := readName(packet, off)
			if err != nil {
				t.Fatal(err)
			}
			if next+10 > len(packet) {
				t.Fatal("short resource record")
			}
			rdlen := int(binary.BigEndian.Uint16(packet[next+8 : next+10]))
			out = append(out, rrLayout{section(sec), binary.BigEndian.Uint16(packet[next : next+2]), rdlen})
			off = next + 10 + rdlen
		}
	}
	if off != len(packet) {
		t.Fatalf("%d trailing bytes", len(packet)-off)
	}
	return out
}

func testEndpointID(t *testing.T) key.EndpointID {
	t.Helper()
	b, err := hex.DecodeString(rustEndpointID)
	if err != nil {
		t.Fatal(err)
	}
	id, err := key.EndpointIDFromSlice(b)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAnnouncementLayout(t *testing.T) {
	id := testEndpointID(t)
	v4 := netip.MustParseAddrPort("192.0.2.1:7777")
	v6 := netip.MustParseAddrPort("[2001:db8::1]:7777")
	tests := []struct {
		name string
		data announcementData
		want []rrLayout
	}{
		{
			name: "relay and two addresses",
			data: announcementData{id: id, port: 7777, ips: []netip.AddrPort{v4, v6}, relay: "https://relay.example/"},
			want: []rrLayout{
				{answer, dnsTypePTR, 0},
				{answer, dnsTypeSRV, 0},
				{answer, dnsTypeTXT, 0},
				{additional, dnsTypeA, 4},
				{additional, dnsTypeAAAA, 16},
			},
		},
		{
			name: "no TXT without relay or user data",
			data: announcementData{id: id, port: 7777, ips: []netip.AddrPort{v4}},
			want: []rrLayout{
				{answer, dnsTypePTR, 0},
				{answer, dnsTypeSRV, 0},
				{additional, dnsTypeA, 4},
			},
		},
		{
			name: "user data only",
			data: announcementData{id: id, port: 7777, ips: []netip.AddrPort{v6}, userData: "lan"},
			want: []rrLayout{
				{answer, dnsTypePTR, 0},
				{answer, dnsTypeSRV, 0},
				{answer, dnsTypeTXT, 0},
				{additional, dnsTypeAAAA, 16},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet, err := buildAnnouncement(DefaultServiceName, tt.data)
			if err != nil {
				t.Fatal(err)
			}
			got := layout(t, packet)
			// Only the address record lengths are fixed; the rest need
			// only be nonzero, since hickory-proto 0.26 rejects a
			// packet with an empty record (op/message.rs:431-435).
			for i := range got {
				if got[i].rdlen == 0 {
					t.Errorf("record %d (type %d) has RDLENGTH 0", i, got[i].typ)
				}
				if got[i].typ != dnsTypeA && got[i].typ != dnsTypeAAAA {
					got[i].rdlen = 0
				}
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("layout = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestParseGoV023Announcement checks that an announcement from a Go endpoint
// that predates the move of address records to the additional section still
// resolves.
func TestParseGoV023Announcement(t *testing.T) {
	packet, err := hex.DecodeString(goV023Announcement)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := parseAnnouncement(packet, DefaultServiceName)
	if !ok {
		t.Fatal("parseAnnouncement failed")
	}
	if got.ID != testEndpointID(t) {
		t.Errorf("ID = %v, want %v", got.ID, testEndpointID(t))
	}
	want := []netip.AddrPort{
		netip.MustParseAddrPort("192.0.2.1:7777"),
		netip.MustParseAddrPort("[2001:db8::1]:7777"),
	}
	if !sameAddrPorts(got.Data.IPAddrs(), want) {
		t.Errorf("IPAddrs = %v, want %v", got.Data.IPAddrs(), want)
	}
}
