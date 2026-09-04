package iroh

import (
	"testing"

	"github.com/tmc/go-iroh/relay"
)

// TestNetReportDefault checks which option combinations start net_report.
// Without it the home relay stays the bootstrap pick from the relay map's
// order rather than the nearest relay, so the default matters.
func TestNetReportDefault(t *testing.T) {
	tests := []struct {
		name  string
		opts  []Option
		relay bool
		want  bool
	}{
		{"default with relays", nil, true, true},
		{"default without relays", nil, false, false},
		{"WithoutNetReport", []Option{WithoutNetReport()}, true, false},
		{"WithNetReport", []Option{WithNetReport()}, true, true},
		{"WithoutNetReport then WithNetReport", []Option{WithoutNetReport(), WithNetReport()}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c config
			for _, opt := range tt.opts {
				if err := opt(&c); err != nil {
					t.Fatal(err)
				}
			}
			m := relay.NewMap()
			if tt.relay {
				m = relay.DefaultMap()
			}
			if got := endpointNetReportRunner(c, m, nil) != nil; got != tt.want {
				t.Errorf("net_report enabled = %v, want %v", got, tt.want)
			}
		})
	}
}
