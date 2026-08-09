// Command go-driver exposes the native side of the parity driver ABI.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

const (
	exitUnsupported = 64
	exitSetupError  = 65
)

type result struct {
	Role     string `json:"role"`
	Scenario string `json:"scenario"`
	Result   string `json:"result"`
	Detail   string `json:"detail,omitempty"`
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: go-driver <role> <scenario>")
		os.Exit(exitSetupError)
	}
	path := os.Getenv("PARITY_RESULT")
	if path == "" {
		fmt.Fprintln(os.Stderr, "go-driver: PARITY_RESULT is not set")
		os.Exit(exitSetupError)
	}
	r := result{Role: os.Args[1], Scenario: os.Args[2], Result: "unsupported", Detail: "scenario is orchestrated by the stage-1 native runner"}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, "go-driver:", err)
		os.Exit(exitSetupError)
	}
	b = append(b, '\n')
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "go-driver:", err)
		os.Exit(exitSetupError)
	}
	os.Exit(exitUnsupported)
}
