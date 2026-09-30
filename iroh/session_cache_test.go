package iroh

import (
	"fmt"
	"testing"

	tls "github.com/tmc/go-iroh/internal/itls/tls"
)

func TestSessionCacheBounded(t *testing.T) {
	c := NewSessionCache()
	for i := range 4 * maxTLSTickets {
		c.Put(fmt.Sprint(i), &tls.ClientSessionState{})
	}
	if n := c.Len(); n != maxTLSTickets {
		t.Fatalf("Len = %d, want %d", n, maxTLSTickets)
	}
	if _, ok := c.Get("0"); ok {
		t.Fatalf("Get(oldest) found an evicted ticket")
	}
	last := fmt.Sprint(4*maxTLSTickets - 1)
	if _, ok := c.Get(last); !ok {
		t.Fatalf("Get(newest) found no ticket")
	}
	c.Put(last, nil)
	if n := c.Len(); n != maxTLSTickets-1 {
		t.Fatalf("Len after removal = %d, want %d", n, maxTLSTickets-1)
	}
}
