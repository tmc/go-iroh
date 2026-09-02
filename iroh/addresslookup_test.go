package iroh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
)

type testLookupResult struct {
	item Item
	err  error
}

// drain collects every item/error pair from seq until it is exhausted.
func drain(seq iter.Seq2[Item, error]) []testLookupResult {
	var out []testLookupResult
	if seq == nil {
		return out
	}
	for item, err := range seq {
		out = append(out, testLookupResult{item: item, err: err})
	}
	return out
}

func relayURL(t *testing.T, s string) netaddr.RelayURL {
	t.Helper()
	u, err := netaddr.ParseRelayURL(s)
	if err != nil {
		t.Fatalf("ParseRelayURL(%q): %v", s, err)
	}
	return u
}

func endpointInfoWithIP(id key.EndpointID, ip netip.AddrPort) dns.EndpointInfo {
	return dns.EndpointInfo{
		ID:   id,
		Data: dns.NewEndpointData(netaddr.IPAddr{Addr: ip}),
	}
}

func TestMemoryLookup(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	m := NewMemoryLookup()

	if _, ok := m.GetEndpointInfo(id); ok {
		t.Fatal("empty lookup returned an entry")
	}
	seq := m.Resolve(context.Background(), id)
	if seq == nil {
		t.Fatal("Resolve of unknown id returned a nil sequence")
	}
	if got := drain(seq); len(got) != 0 {
		t.Fatalf("Resolve of unknown id = %+v, want no results", got)
	}

	addr := netaddr.NewEndpointAddr(id).WithRelayURL(relayURL(t, "https://relay.example/"))
	m.AddEndpointAddr(addr)

	got, ok := m.GetEndpointInfo(id)
	if !ok {
		t.Fatal("expected stored info")
	}
	if len(got.Data.RelayURLs()) != 1 {
		t.Fatalf("RelayURLs = %v, want one", got.Data.RelayURLs())
	}

	results := drain(m.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].err != nil {
		t.Fatalf("Resolve = %+v, want one success", results)
	}
	if got := results[0].item.Provenance(); got != MemoryProvenance {
		t.Errorf("provenance = %q, want %q", got, MemoryProvenance)
	}
	if _, ok := results[0].item.LastUpdated(); !ok {
		t.Error("memory item should report last-updated")
	}

	removed, ok := m.RemoveEndpointInfo(id)
	if !ok || removed.ID != id {
		t.Fatalf("RemoveEndpointInfo = %v, %v", removed, ok)
	}
	if _, ok := m.GetEndpointInfo(id); ok {
		t.Fatal("entry should be gone after removal")
	}
}

func TestStaticLookup(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	relay := relayURL(t, "https://relay.example/")
	userData, err := dns.NewUserData("room=7")
	if err != nil {
		t.Fatal(err)
	}
	info := dns.EndpointInfo{
		ID:   id,
		Data: dns.NewEndpointData(netaddr.RelayAddr{URL: relay}).WithUserData(&userData),
	}
	lookup := NewStaticLookup(info)

	results := drain(lookup.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].err != nil {
		t.Fatalf("Resolve = %+v, want one success", results)
	}
	if got := results[0].item.Provenance(); got != StaticProvenance {
		t.Errorf("provenance = %q, want %q", got, StaticProvenance)
	}
	if _, ok := results[0].item.LastUpdated(); !ok {
		t.Fatal("static item should report last-updated")
	}
	if got, ok := results[0].item.UserData(); !ok || got.String() != "room=7" {
		t.Fatalf("UserData = %v, %v, want room=7, true", got, ok)
	}

	// Mutating the source data after construction must not affect the lookup.
	info.Data.ClearRelayURLs()
	results = drain(lookup.Resolve(context.Background(), id))
	if len(results[0].item.Addr().RelayURLs()) != 1 {
		t.Fatalf("StaticLookup changed after source mutation: %v", results[0].item.Addr().RelayURLs())
	}
}

func TestStaticLookupFromAddrs(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	addr := netaddr.NewEndpointAddr(id).WithIP(netip.MustParseAddrPort("127.0.0.1:1"))
	lookup := StaticLookupFromAddrs(addr)

	results := drain(lookup.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].err != nil {
		t.Fatalf("Resolve = %+v, want one success", results)
	}
	if got := results[0].item.Addr().IPAddrs(); len(got) != 1 || got[0] != netip.MustParseAddrPort("127.0.0.1:1") {
		t.Fatalf("IPAddrs = %v, want [127.0.0.1:1]", got)
	}
}

func TestStaticLookupUnknownAndNil(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	lookup := NewStaticLookup()
	if got := lookup.Resolve(context.Background(), id); got != nil {
		t.Fatal("Resolve unknown returned non-nil sequence")
	}
	var nilLookup *StaticLookup
	if got := nilLookup.Resolve(context.Background(), id); got != nil {
		t.Fatal("nil StaticLookup Resolve returned non-nil sequence")
	}
}

func TestItemLastUpdatedTime(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	info := endpointInfoWithIP(sk.Public().EndpointID(), netip.MustParseAddrPort("127.0.0.1:1"))
	micros := uint64(1_700_000_000_123_456)
	item := NewItem(info, "test", &micros)

	gotRaw, ok := item.LastUpdated()
	if !ok || gotRaw != micros {
		t.Fatalf("LastUpdated = %d, %v; want %d, true", gotRaw, ok, micros)
	}
	gotTime, ok := item.LastUpdatedTime()
	if !ok {
		t.Fatal("LastUpdatedTime ok = false, want true")
	}
	if want := time.UnixMicro(int64(micros)); !gotTime.Equal(want) {
		t.Fatalf("LastUpdatedTime = %v, want %v", gotTime, want)
	}

	unknown := NewItem(info, "test", nil)
	if got, ok := unknown.LastUpdatedTime(); ok || !got.IsZero() {
		t.Fatalf("unknown LastUpdatedTime = %v, %v; want zero, false", got, ok)
	}
}

func TestItemUserData(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	info := endpointInfoWithIP(sk.Public().EndpointID(), netip.MustParseAddrPort("127.0.0.1:1"))
	ud, err := dns.NewUserData("hello")
	if err != nil {
		t.Fatal(err)
	}
	info.Data.SetUserData(&ud)

	tests := []struct {
		name string
		item Item
		want string
		ok   bool
	}{
		{"set", NewItem(info, "test", nil), "hello", true},
		{"unset", NewItem(endpointInfoWithIP(sk.Public().EndpointID(), netip.MustParseAddrPort("127.0.0.1:2")), "test", nil), "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := tt.item.UserData()
			if ok != tt.ok {
				t.Fatalf("UserData ok = %v, want %v", ok, tt.ok)
			}
			if got.String() != tt.want {
				t.Fatalf("UserData = %q, want %q", got.String(), tt.want)
			}
		})
	}
}

func ExampleItem_UserData() {
	sk, _ := key.GenerateSecretKey()
	info := endpointInfoWithIP(sk.Public().EndpointID(), netip.MustParseAddrPort("127.0.0.1:1"))
	ud, _ := dns.NewUserData("room=alpha")
	info.Data.SetUserData(&ud)

	item := NewItem(info, "memory", nil)
	got, ok := item.UserData()
	fmt.Println(ok, got.String())
	// Output:
	// true room=alpha
}

func TestMemoryLookupAddMerges(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	m := NewMemoryLookupWithProvenance("custom")

	m.AddEndpointAddr(netaddr.NewEndpointAddr(id).WithIP(netip.MustParseAddrPort("1.2.3.4:1")))
	m.AddEndpointAddr(netaddr.NewEndpointAddr(id).WithIP(netip.MustParseAddrPort("5.6.7.8:2")))

	got, _ := m.GetEndpointInfo(id)
	if len(got.Data.IPAddrs()) != 2 {
		t.Fatalf("IPAddrs = %v, want two after merge", got.Data.IPAddrs())
	}
	results := drain(m.Resolve(context.Background(), id))
	if results[0].item.Provenance() != "custom" {
		t.Errorf("provenance = %q", results[0].item.Provenance())
	}
}

func TestDNSTxtRoundTrip(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	relay := relayURL(t, "https://relay.example/")

	info := dns.EndpointInfo{ID: id, Data: dns.NewEndpointData(
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("9.9.9.9:1234")},
	)}
	values := info.ToTXTStrings()

	name := dns.IrohTXTName + "." + id.Z32() + "." + dns.N0DNSEndpointOriginProd
	back, err := dns.EndpointInfoFromTXTLookup(name, values)
	if err != nil {
		t.Fatalf("EndpointInfoFromTXTLookup: %v", err)
	}
	if !back.ID.Equal(id) {
		t.Errorf("id = %s, want %s", back.ID, id)
	}
	if len(back.Data.RelayURLs()) != 1 || !back.Data.RelayURLs()[0].Equal(relay) {
		t.Errorf("RelayURLs = %v", back.Data.RelayURLs())
	}
	if len(back.Data.IPAddrs()) != 1 {
		t.Errorf("IPAddrs = %v", back.Data.IPAddrs())
	}
}

// fakeTXTLookuper serves canned TXT values for any name, recording the queried
// name.
type fakeTXTLookuper struct {
	values []string
}

func (f *fakeTXTLookuper) LookupTXT(_ context.Context, _ string) ([]string, error) {
	return f.values, nil
}

func TestDNSAddressLookupResolve(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	info := dns.EndpointInfo{ID: id, Data: dns.NewEndpointData(
		netaddr.RelayAddr{URL: relayURL(t, "https://relay.example/")},
	)}

	resolver := &dns.Resolver{Lookuper: &fakeTXTLookuper{values: info.ToTXTStrings()}}
	lookup := NewDNSAddressLookup(dns.N0DNSEndpointOriginProd, resolver)

	results := drain(lookup.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].err != nil {
		t.Fatalf("Resolve = %+v, want one success", results)
	}
	if got := results[0].item.Provenance(); got != DNSProvenance {
		t.Errorf("provenance = %q, want %q", got, DNSProvenance)
	}
	if !results[0].item.EndpointID().Equal(id) {
		t.Errorf("id = %s, want %s", results[0].item.EndpointID(), id)
	}
}

// pkarrTestRelay is an in-memory pkarr relay: PUT /<z32> stores the relay
// payload, GET /<z32> returns it. It matches iroh-dns-server/src/http/pkarr.rs.
func pkarrTestRelay(t *testing.T) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	store := map[string][]byte{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		switch r.Method {
		case http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			store[key] = body
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		case http.MethodGet:
			mu.Lock()
			body, ok := store[key]
			mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/x-pkarr-signed-packet")
			w.Write(body)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
	return httptest.NewServer(mux)
}

func TestPkarrPublishResolveRoundTrip(t *testing.T) {
	srv := pkarrTestRelay(t)
	defer srv.Close()

	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	relay := relayURL(t, "https://relay.example/")

	pub, err := NewPkarrPublisher(sk, srv.URL, &PkarrPublisherConfig{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("NewPkarrPublisher: %v", err)
	}
	defer pub.Close()

	data := dns.NewEndpointData(netaddr.RelayAddr{URL: relay})
	pub.Publish(data)

	res, err := NewPkarrResolver(srv.URL, &PkarrResolverConfig{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("NewPkarrResolver: %v", err)
	}

	// The publish runs in the background; poll until the relay has the packet.
	var item Item
	deadline := time.Now().Add(5 * time.Second)
	for {
		results := drain(res.Resolve(context.Background(), id))
		if len(results) == 1 && results[0].err == nil {
			item = results[0].item
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Resolve never succeeded: %+v", results)
		}
		time.Sleep(20 * time.Millisecond)
	}

	if !item.EndpointID().Equal(id) {
		t.Errorf("id = %s, want %s", item.EndpointID(), id)
	}
	if got := item.Provenance(); got != PkarrProvenance {
		t.Errorf("provenance = %q, want %q", got, PkarrProvenance)
	}
	urls := item.Addr().RelayURLs()
	if len(urls) != 1 || !urls[0].Equal(relay) {
		t.Errorf("RelayURLs = %v, want [%s]", urls, relay)
	}
}

func TestPkarrPublisherRelayOnlyFilter(t *testing.T) {
	srv := pkarrTestRelay(t)
	defer srv.Close()

	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	relay := relayURL(t, "https://relay.example/")

	pub, err := NewPkarrPublisher(sk, srv.URL, &PkarrPublisherConfig{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatalf("NewPkarrPublisher: %v", err)
	}
	defer pub.Close()

	// Publish both a relay and an IP address; default filter keeps relay only.
	data := dns.NewEndpointData(
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:9999")},
	)
	pub.Publish(data)

	res, _ := NewPkarrResolver(srv.URL, &PkarrResolverConfig{HTTPClient: srv.Client()})
	deadline := time.Now().Add(5 * time.Second)
	for {
		results := drain(res.Resolve(context.Background(), id))
		if len(results) == 1 && results[0].err == nil {
			addr := results[0].item.Addr()
			if len(addr.IPAddrs()) != 0 {
				t.Fatalf("IP address leaked past relay-only filter: %v", addr.IPAddrs())
			}
			if len(addr.RelayURLs()) != 1 {
				t.Fatalf("relay address missing: %v", addr.RelayURLs())
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Resolve never succeeded: %+v", results)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// staticLookup is a test [AddressResolver] that resolves to a fixed info after a
// delay, or yields a fixed error.
type staticLookup struct {
	provenance string
	info       *dns.EndpointInfo
	err        error
	delay      time.Duration
}

func (s staticLookup) Resolve(ctx context.Context, _ key.EndpointID) iter.Seq2[Item, error] {
	return func(yield func(Item, error) bool) {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return
		}
		if s.err != nil {
			yield(Item{}, lookupErr(s.provenance, s.err))
			return
		}
		yield(NewItem(*s.info, s.provenance, nil), nil)
	}
}

func TestServicesNoServiceConfigured(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	var svcs AddressLookupServices
	results := drain(svcs.Resolve(context.Background(), sk.Public().EndpointID()))
	if len(results) != 1 || !errors.Is(results[0].err, ErrNoServiceConfigured) {
		t.Fatalf("Resolve = %+v, want ErrNoServiceConfigured", results)
	}
}

func TestServicesSucceedsAfterOtherErrors(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	info := dns.EndpointInfo{ID: id, Data: dns.NewEndpointData(
		netaddr.RelayAddr{URL: relayURL(t, "https://relay.example/")},
	)}

	var svcs AddressLookupServices
	svcs.AddResolver(staticLookup{provenance: "fail", err: errors.New("boom"), delay: 10 * time.Millisecond})
	svcs.AddResolver(staticLookup{provenance: "ok", info: &info, delay: 80 * time.Millisecond})

	results := drain(svcs.Resolve(context.Background(), id))
	var sawErr, sawOK bool
	for _, r := range results {
		if r.err != nil {
			sawErr = true
		} else if r.item.EndpointID().Equal(id) {
			sawOK = true
		}
	}
	if !sawErr {
		t.Error("expected the failing service's error to be delivered inline")
	}
	if !sawOK {
		t.Error("expected the slow successful service's item to be delivered")
	}
}

func TestServicesNoResults(t *testing.T) {
	sk, _ := key.GenerateSecretKey()
	var svcs AddressLookupServices
	svcs.AddResolver(staticLookup{provenance: "fail", err: errors.New("boom"), delay: time.Millisecond})

	results := drain(svcs.Resolve(context.Background(), sk.Public().EndpointID()))
	last := results[len(results)-1]
	if !errors.Is(last.err, ErrNoResults) {
		t.Fatalf("final result = %+v, want ErrNoResults", last)
	}
}

func TestServicesPublishAppliesFilter(t *testing.T) {
	rec := &recordingLookup{}

	var svcs AddressLookupServices
	svcs.SetAddrFilter(RelayOnlyFilter)
	svcs.AddPublisher(rec)

	relay := relayURL(t, "https://relay.example/")
	data := dns.NewEndpointData(
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1")},
	)
	svcs.Publish(data)

	if len(rec.published) != 1 {
		t.Fatalf("published %d times, want 1", len(rec.published))
	}
	got := rec.published[0]
	if len(got.IPAddrs()) != 0 {
		t.Errorf("IP address should be filtered out, got %v", got.IPAddrs())
	}
	if len(got.RelayURLs()) != 1 {
		t.Errorf("relay address should be kept, got %v", got.RelayURLs())
	}
}

func TestAddressLookupFunctionAdapters(t *testing.T) {
	var published []dns.EndpointData
	pub := AddressPublisherFunc(func(data dns.EndpointData) {
		published = append(published, data)
	})
	relay := relayURL(t, "https://relay.example/")
	data := dns.NewEndpointData(netaddr.RelayAddr{URL: relay})
	pub.Publish(data)
	if len(published) != 1 {
		t.Fatalf("published %d times, want 1", len(published))
	}

	sk, _ := key.GenerateSecretKey()
	id := sk.Public().EndpointID()
	resolver := AddressResolverFunc(func(ctx context.Context, got key.EndpointID) iter.Seq2[Item, error] {
		return func(yield func(Item, error) bool) {
			if !got.Equal(id) {
				t.Errorf("Resolve id = %s, want %s", got, id)
			}
			yield(NewItem(dns.EndpointInfo{ID: id, Data: data}, "func", nil), nil)
		}
	})
	results := drain(resolver.Resolve(context.Background(), id))
	if len(results) != 1 || results[0].err != nil || results[0].item.Provenance() != "func" {
		t.Fatalf("results = %+v", results)
	}
}

// recordingLookup records published data.
type recordingLookup struct {
	mu        sync.Mutex
	published []dns.EndpointData
}

func (r *recordingLookup) Publish(data dns.EndpointData) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.published = append(r.published, data)
}

func TestServicesAddPublishesHistorical(t *testing.T) {
	relay := relayURL(t, "https://relay.example/")
	data := dns.NewEndpointData(netaddr.RelayAddr{URL: relay})

	var svcs AddressLookupServices
	svcs.Publish(data)

	rec := &recordingLookup{}
	svcs.AddPublisher(rec) // added after publish; should receive the historical data
	if len(rec.published) != 1 {
		t.Fatalf("late-added service got %d publishes, want 1", len(rec.published))
	}
}

// TestAddrFilterComplement pins IPOnlyFilter as the exact complement of
// RelayOnlyFilter: it keeps custom transport addresses, which its name does not
// suggest, and together the two partition the address set.
func TestAddrFilterComplement(t *testing.T) {
	addrs := []netaddr.TransportAddr{
		netaddr.RelayAddr{URL: relayURL(t, "https://relay.example/")},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1")},
		netaddr.NewCustomAddr(7, []byte{0xde, 0xad}),
	}
	relays := RelayOnlyFilter(addrs)
	rest := IPOnlyFilter(addrs)
	if len(relays) != 1 || len(rest) != 2 {
		t.Fatalf("RelayOnlyFilter kept %d, IPOnlyFilter kept %d; want 1 and 2", len(relays), len(rest))
	}
	if _, ok := rest[1].(netaddr.CustomAddr); !ok {
		t.Errorf("IPOnlyFilter dropped the custom address: %v", rest)
	}
	if got, want := len(relays)+len(rest), len(addrs); got != want {
		t.Errorf("filters kept %d addresses in total, want %d", got, want)
	}
}

func TestFilteredAddressPublisher(t *testing.T) {
	rec := &recordingLookup{}
	f := NewFilteredAddressPublisher(rec, IPOnlyFilter)

	relay := relayURL(t, "https://relay.example/")
	data := dns.NewEndpointData(
		netaddr.RelayAddr{URL: relay},
		netaddr.IPAddr{Addr: netip.MustParseAddrPort("1.2.3.4:1")},
	)
	f.Publish(data)

	if len(rec.published) != 1 {
		t.Fatalf("published %d times, want 1", len(rec.published))
	}
	if len(rec.published[0].RelayURLs()) != 0 {
		t.Errorf("relay should be filtered out by IPOnlyFilter")
	}
	if len(rec.published[0].IPAddrs()) != 1 {
		t.Errorf("IP address should be kept, got %v", rec.published[0].IPAddrs())
	}
}

// nilLookup is an AddressResolver that reports nothing by returning a nil
// sequence, the shape [MemoryLookup] used before it returned an empty one.
type nilLookup struct{}

func (nilLookup) Resolve(context.Context, key.EndpointID) iter.Seq2[Item, error] { return nil }

// TestServicesResolveNilSequence checks that a resolver returning a nil
// sequence is skipped rather than ranged over, which panicked.
func TestServicesResolveNilSequence(t *testing.T) {
	sk, err := key.GenerateSecretKey()
	if err != nil {
		t.Fatal(err)
	}
	id := sk.Public().EndpointID()
	info := endpointInfoWithIP(id, netip.MustParseAddrPort("192.0.2.1:1234"))

	var svcs AddressLookupServices
	svcs.AddResolver(nilLookup{})
	svcs.AddResolver(staticLookup{provenance: "ok", info: &info})

	var got bool
	for item, err := range svcs.Resolve(context.Background(), id) {
		if err == nil && item.EndpointID().Equal(id) {
			got = true
		}
	}
	if !got {
		t.Error("expected the second resolver's item, got none")
	}

	// A nil-only set of resolvers must report ErrNoResults, not hang or panic.
	var only AddressLookupServices
	only.AddResolver(nilLookup{})
	results := drain(only.Resolve(context.Background(), id))
	if len(results) == 0 {
		t.Fatal("nil-only resolve produced no results, want ErrNoResults")
	}
	if last := results[len(results)-1]; !errors.Is(last.err, ErrNoResults) {
		t.Fatalf("final result = %+v, want ErrNoResults", last)
	}
}
