// Package dnsserver implements an embeddable iroh DNS and pkarr relay server.
//
// The Go API is not stable before v1 and may change in any v0 release.
package dnsserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/metrics"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	maxPacketSize    = 64 * 1024
	maxPUTSize       = dns.MaxSignedPacketSize - key.PublicKeySize
	maxStoredPackets = 10_000
	packetRetention  = 7 * 24 * time.Hour
)

type storedPacket struct {
	keyLabel string
	payload  []byte
	packet   *dns.SignedPacket
	storedAt time.Time

	// prev and next link the packet into Server.order.
	prev, next *storedPacket
}

// Server stores pkarr relay payloads in memory and serves them over HTTP and
// DNS. It is safe for concurrent use.
//
// The store holds at most 10,000 records and drops a record 7 days after it
// was last stored. Storing a record first drops expired records and then, if
// the store is full, the record stored least recently; storing a newer packet
// for a key replaces the old one and counts as storing it again.
// The cap is global, not per publisher: anyone who can PUT 10,000 fresh keys
// within the retention window displaces every other record, and those records
// stay gone until their owners publish again. Deployments facing untrusted
// publishers should rate limit PUTs in front of the server.
type Server struct {
	mu         sync.Mutex
	store      map[string]*storedPacket
	order      storedPacket // sentinel; order.next is the least recently stored
	maxPackets int
	retention  time.Duration
	now        func() time.Time
	metrics    dnsMetrics
}

type dnsMetrics struct {
	httpPuts   atomic.Uint64
	httpGets   atomic.Uint64
	dnsQueries atomic.Uint64
}

// New returns an empty DNS server.
func New() *Server {
	s := &Server{
		store:      make(map[string]*storedPacket),
		maxPackets: maxStoredPackets,
		retention:  packetRetention,
		now:        time.Now,
	}
	s.order.prev = &s.order
	s.order.next = &s.order
	return s
}

// Snapshot returns the server's counter snapshot for [metrics.Registry].
func (s *Server) Snapshot() metrics.Snapshot {
	return metrics.Snapshot{
		"http_puts":   s.metrics.httpPuts.Load(),
		"http_gets":   s.metrics.httpGets.Load(),
		"dns_queries": s.metrics.dnsQueries.Load(),
	}
}

// ServeHTTP handles PUT and GET of pkarr relay payloads at /pkarr/<key> or
// /<key>.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	keyLabel := strings.TrimPrefix(r.URL.Path, "/")
	keyLabel = strings.TrimPrefix(keyLabel, "pkarr/")
	if keyLabel == "" || strings.Contains(keyLabel, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		s.metrics.httpPuts.Add(1)
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPUTSize))
		if err != nil {
			http.Error(w, "packet too large", http.StatusRequestEntityTooLarge)
			return
		}
		packet, err := packetFromRelayPayload(keyLabel, body)
		if err != nil {
			http.Error(w, "bad signed packet", http.StatusBadRequest)
			return
		}
		if !s.put(keyLabel, body, packet) {
			http.Error(w, "stale signed packet", http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet:
		s.metrics.httpGets.Add(1)
		body, ok := s.get(keyLabel)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/x-pkarr-signed-packet")
		w.Write(body)
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ServePacketConn serves DNS messages on pc until ctx is canceled or pc returns
// a non-close read error.
func (s *Server) ServePacketConn(ctx context.Context, pc net.PacketConn) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			pc.Close()
		case <-done:
		}
	}()
	defer close(done)

	buf := make([]byte, maxPacketSize)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			return err
		}
		req := bytes.Clone(buf[:n])
		go func() {
			resp, err := s.ServeDNSPacket(req)
			if err != nil {
				return
			}
			_, _ = pc.WriteTo(resp, addr)
		}()
	}
}

// ServeDNSPacket handles one DNS wire-format message and returns a DNS
// wire-format response.
func (s *Server) ServeDNSPacket(msg []byte) ([]byte, error) {
	s.metrics.dnsQueries.Add(1)
	var p dnsmessage.Parser
	header, err := p.Start(msg)
	if err != nil {
		return nil, fmt.Errorf("dnsserver: parse header: %w", err)
	}
	q, err := p.Question()
	if err != nil {
		return nil, fmt.Errorf("dnsserver: parse question: %w", err)
	}
	txt, ok := s.lookupTXT(q)
	responseHeader := dnsmessage.Header{
		ID:                 header.ID,
		Response:           true,
		Authoritative:      true,
		RecursionAvailable: false,
		RCode:              dnsmessage.RCodeSuccess,
	}
	if !ok && q.Type == dnsmessage.TypeTXT {
		responseHeader.RCode = dnsmessage.RCodeNameError
	}
	b := dnsmessage.NewBuilder(nil, responseHeader)
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(q); err != nil {
		return nil, err
	}
	if err := b.StartAnswers(); err != nil {
		return nil, err
	}
	if ok {
		if err := b.TXTResource(dnsmessage.ResourceHeader{
			Name:  q.Name,
			Type:  dnsmessage.TypeTXT,
			Class: dnsmessage.ClassINET,
			TTL:   30,
		}, dnsmessage.TXTResource{TXT: txt}); err != nil {
			return nil, err
		}
	}
	resp, err := b.Finish()
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (s *Server) lookupTXT(q dnsmessage.Question) ([]string, bool) {
	if q.Type != dnsmessage.TypeTXT || q.Class != dnsmessage.ClassINET {
		return nil, false
	}
	keyLabel, ok := keyLabelFromQuery(q.Name.String())
	if !ok {
		return nil, false
	}
	payload, ok := s.get(keyLabel)
	if !ok {
		return nil, false
	}
	packet, err := packetFromRelayPayload(keyLabel, payload)
	if err != nil {
		return nil, false
	}
	txt := packet.TXTRecords(dns.IrohTXTName)
	return txt, len(txt) > 0
}

func (s *Server) get(keyLabel string) ([]byte, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.store[keyLabel]
	if !ok {
		return nil, false
	}
	if s.expired(stored, s.now()) {
		s.remove(stored)
		return nil, false
	}
	return bytes.Clone(stored.payload), true
}

func (s *Server) put(keyLabel string, payload []byte, packet *dns.SignedPacket) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	cutoff := now.Add(-s.retention).UnixMicro()
	if cutoff > 0 && packet.TimestampMicros() < uint64(cutoff) {
		return false
	}
	if old, ok := s.store[keyLabel]; ok {
		if old.packet.MoreRecentThan(packet) {
			return false
		}
		s.remove(old)
	}

	// Records are ordered by storedAt, so the expired ones are at the front.
	for oldest := s.order.next; oldest != &s.order && s.expired(oldest, now); oldest = s.order.next {
		s.remove(oldest)
	}
	if len(s.store) >= s.maxPackets {
		s.remove(s.order.next)
	}
	stored := &storedPacket{
		keyLabel: keyLabel,
		payload:  bytes.Clone(payload),
		packet:   packet,
		storedAt: now,
		prev:     s.order.prev,
		next:     &s.order,
	}
	stored.prev.next = stored
	s.order.prev = stored
	s.store[keyLabel] = stored
	return true
}

func (s *Server) expired(stored *storedPacket, now time.Time) bool {
	return now.Sub(stored.storedAt) >= s.retention
}

// remove deletes stored from the store and from s.order.
func (s *Server) remove(stored *storedPacket) {
	stored.prev.next = stored.next
	stored.next.prev = stored.prev
	stored.prev, stored.next = nil, nil
	delete(s.store, stored.keyLabel)
}

func packetFromRelayPayload(keyLabel string, payload []byte) (*dns.SignedPacket, error) {
	id, err := key.ParseEndpointIDZ32(keyLabel)
	if err != nil {
		return nil, err
	}
	pubBytes := id.PublicKey().Bytes()
	wire := make([]byte, 0, len(pubBytes)+len(payload))
	wire = append(wire, pubBytes[:]...)
	wire = append(wire, payload...)
	return dns.SignedPacketFromBytes(wire)
}

func keyLabelFromQuery(name string) (string, bool) {
	labels := strings.Split(strings.TrimSuffix(name, "."), ".")
	if len(labels) < 2 || labels[0] != dns.IrohTXTName {
		return "", false
	}
	return labels[1], true
}
