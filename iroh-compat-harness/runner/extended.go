package runner

type unsupportedScenario struct {
	name   string
	detail string
}

func ExtendedCells(version string) []Cell {
	scenarios := []unsupportedScenario{
		{"handshake/datagrams", "the pinned upstream datagram example is not yet adapted to the driver ABI"},
		{"handshake/zero-rtt", "the pinned upstream 0-RTT example is not yet adapted to the driver ABI"},
		{"handshake/close-semantics", "cross-implementation close codes are not yet recorded by the drivers"},
		{"handshake/pq-only", "the pinned upstream pq-only example is not yet adapted to the driver ABI"},
		{"handshake/prefer-pq", "the pinned upstream prefer-pq example is not yet adapted to the driver ABI"},
		{"handshake/remote-info", "cross-implementation remote-info and connection-type agreement is not yet recorded"},
		{"relay/go-client-go-relay", "a Go-only quadrant cannot satisfy the real-Rust-peer pass invariant"},
		{"discovery/qad-report", "go-iroh does not expose the upstream report schema needed for a field-by-field QAD assertion"},
	}
	cells := make([]Cell, len(scenarios))
	for i, s := range scenarios {
		cells[i] = Cell{
			Scenario: s.name,
			Iroh:     version,
			Tier:     "A",
			Result:   Unsupported,
			Expected: Unsupported,
			Detail:   s.detail,
		}
	}
	return cells
}
