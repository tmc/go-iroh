package runner

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/netaddr"
)

func TestCompareQADReportShape(t *testing.T) {
	rust := `NetReport {
udp_v4: true,
udp_v6: false,
mapping_varies_by_dest_ipv4: Some(false),
mapping_varies_by_dest_ipv6: None,
preferred_relay: Some("https://relay.example/"),
relay_latency: RelayLatencies {},
global_v4: Some(192.0.2.1:1234),
global_v6: None,
captive_portal: Some(false),
}`
	url, err := netaddr.ParseRelayURL("https://relay.example/")
	if err != nil {
		t.Fatal(err)
	}
	report := iroh.NetReport{
		UDPv4:          true,
		GlobalV4:       netip.MustParseAddrPort("192.0.2.1:1234"),
		RelayLatencies: map[netaddr.RelayURL]time.Duration{url: time.Millisecond},
	}
	if err := compareQADReportShape(rust, report); err != nil {
		t.Fatal(err)
	}
}

func TestQADReportLive(t *testing.T) {
	bin := os.Getenv("RUST_DOCTOR_BIN")
	if bin == "" {
		t.Skip("RUST_DOCTOR_BIN is not set")
	}
	digest, err := FileDigest(bin)
	if err != nil {
		t.Fatal(err)
	}
	cell := RunQADReport(bin, "1.0.3", digest)
	if cell.Result != Pass {
		t.Fatalf("qad-report = %s: %s", cell.Result, cell.Detail)
	}
}
