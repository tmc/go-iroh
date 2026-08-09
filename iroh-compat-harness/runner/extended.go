package runner

type unsupportedScenario struct {
	name   string
	detail string
}

func ExtendedCells(version string) []Cell {
	scenarios := []unsupportedScenario{
		{"handshake/pq-only", "go-iroh does not expose a pq-only TLS key-exchange policy"},
		{"handshake/prefer-pq", "go-iroh does not expose a prefer-pq TLS key-exchange policy"},
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
