package runner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"

	"github.com/tmc/go-iroh/postcard"
)

// A varint is canonical when its final byte is non-zero, or when it is the
// single byte 0x00. Go and Rust must agree on which byte strings meet that
// rule: a decoder that accepts a padded encoding and one that rejects a valid
// one are both wire incompatibilities, so this scenario compares observed
// verdicts rather than asserting that either side rejects.
type canonicalCase struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Hex  string `json:"hex"`
}

type canonicalResult struct {
	Name     string  `json:"name"`
	Accepted bool    `json:"accepted"`
	Value    *string `json:"value"`
}

type canonicalCorpus struct {
	PostcardUint []struct {
		Value    uint64 `json:"value"`
		Postcard string `json:"postcard"`
	} `json:"postcard_uint"`
	NonCanonical []struct {
		Name         string `json:"name"`
		Type         string `json:"type"`
		Hex          string `json:"hex"`
		CanonicalHex string `json:"canonical_hex"`
	} `json:"postcard_non_canonical"`
}

// canonicalCases pairs the non-canonical corpus entries with canonical
// controls taken from the Rust-generated uint vectors. Without the controls a
// decoder that refused every input would agree with Rust on every case.
func canonicalCases(corpus []byte) ([]canonicalCase, error) {
	var c canonicalCorpus
	if err := json.Unmarshal(corpus, &c); err != nil {
		return nil, fmt.Errorf("decode corpus: %w", err)
	}
	if len(c.NonCanonical) == 0 {
		return nil, fmt.Errorf("corpus has no postcard_non_canonical vectors")
	}
	var cases []canonicalCase
	for _, v := range c.PostcardUint {
		switch v.Value {
		case 0, 127, 128:
			cases = append(cases, canonicalCase{Name: fmt.Sprintf("canonical-%d", v.Value), Type: "u64", Hex: v.Postcard})
		}
	}
	if len(cases) != 3 {
		return nil, fmt.Errorf("corpus has %d canonical controls, want 3", len(cases))
	}
	for _, v := range c.NonCanonical {
		cases = append(cases, canonicalCase{Name: v.Name, Type: v.Type, Hex: v.Hex})
	}
	return cases, nil
}

// goDecodeCase reports what Go makes of one case: the decoded value in the
// same textual form the Rust driver reports, or the error it refused with.
func goDecodeCase(c canonicalCase) (value string, err error) {
	raw, err := hex.DecodeString(c.Hex)
	if err != nil {
		return "", fmt.Errorf("decode hex: %w", err)
	}
	switch c.Type {
	case "u64":
		var v uint64
		if err := postcard.Unmarshal(raw, &v); err != nil {
			return "", err
		}
		return fmt.Sprintf("%d", v), nil
	case "bytes":
		var v []byte
		if err := postcard.Unmarshal(raw, &v); err != nil {
			return "", err
		}
		return hex.EncodeToString(v), nil
	default:
		return "", fmt.Errorf("unknown case type %q", c.Type)
	}
}

func canonicalVarintCell(bin string, corpus []byte, version, digest, peer string) Cell {
	cell := Cell{Scenario: canonicalScenario, Iroh: version, Peer: peer, PeerDigest: digest}
	cases, err := canonicalCases(corpus)
	if err != nil {
		cell.Result, cell.Detail = SetupError, err.Error()
		return cell
	}
	input, err := json.Marshal(cases)
	if err != nil {
		cell.Result, cell.Detail = SetupError, fmt.Sprintf("encode postcard cases: %v", err)
		return cell
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, "postcard-decode")
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	start := time.Now()
	if err := cmd.Start(); err != nil {
		cell.Result, cell.Detail = SetupError, fmt.Sprintf("start Rust postcard decoder: %v", err)
		return cell
	}
	cell.PeerPID = cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		cell.Result = SetupError
		cell.Detail = fmt.Sprintf("Rust postcard decoder: %v: %s", err, stderr.String())
		return cell
	}
	cell.DurationMS = time.Since(start).Milliseconds()

	var rust []canonicalResult
	if err := json.Unmarshal(stdout.Bytes(), &rust); err != nil || len(rust) != len(cases) {
		cell.Result, cell.Detail = SetupError, "decode Rust postcard results"
		return cell
	}

	observations := make([]map[string]any, len(cases))
	agreed := 0
	var disagreements []string
	for i, c := range cases {
		got, goErr := goDecodeCase(c)
		observation := map[string]any{
			"case": c.Name, "hex": c.Hex,
			"go_accepted": goErr == nil, "rust_accepted": rust[i].Accepted,
		}
		if goErr != nil {
			observation["go_error"] = goErr.Error()
		} else {
			observation["go_value"] = got
		}
		if rust[i].Value != nil {
			observation["rust_value"] = *rust[i].Value
		}
		observations[i] = observation

		switch {
		case rust[i].Name != c.Name:
			disagreements = append(disagreements, fmt.Sprintf("%s: Rust reported case %q", c.Name, rust[i].Name))
		case (goErr == nil) != rust[i].Accepted:
			disagreements = append(disagreements, fmt.Sprintf("%s: Go accepted=%t, Rust accepted=%t", c.Name, goErr == nil, rust[i].Accepted))
		case goErr == nil && rust[i].Value != nil && got != *rust[i].Value:
			disagreements = append(disagreements, fmt.Sprintf("%s: Go decoded %s, Rust decoded %s", c.Name, got, *rust[i].Value))
		default:
			agreed++
		}
	}

	cell.Result = Fail
	if agreed == len(cases) {
		cell.Result = Pass
	}
	cell.Detail = fmt.Sprintf("Go and Rust agreed on %d/%d canonical-varint cases", agreed, len(cases))
	if len(disagreements) > 0 {
		cell.Detail += ": " + disagreements[0]
	}
	cell.Evidence = map[string]any{"cases": observations, "agreed": agreed}
	return cell
}
