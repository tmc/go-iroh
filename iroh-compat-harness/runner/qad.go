package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/relay"
)

func RunQADReport(bin, version, digest string) (cell Cell) {
	cell = Cell{Scenario: "discovery/qad-report", Iroh: version, Tier: "A", Expected: Pass, Peer: "iroh-doctor@" + digest, PeerDigest: digest}
	start := time.Now()
	defer func() { cell.DurationMS = time.Since(start).Milliseconds() }()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, "report")
	var rust lockedBuffer
	cmd.Stdout, cmd.Stderr = &rust, &rust
	if err := cmd.Start(); err != nil {
		return finishCell(cell, SetupError, fmt.Sprintf("start upstream report: %v", err))
	}
	cell.PeerPID = cmd.Process.Pid
	rustReady := make(chan error, 1)
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				rustReady <- ctx.Err()
				return
			case <-ticker.C:
				text := rust.String()
				if strings.Contains(text, "udp_v4:") && strings.Contains(text, "captive_portal:") {
					rustReady <- nil
					return
				}
			}
		}
	}()

	ep, err := iroh.Bind(ctx, iroh.WithRelayMode(relay.ModeDefault()), iroh.WithNetReport())
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return finishCell(cell, SetupError, fmt.Sprintf("bind Go report endpoint: %v", err))
	}
	defer ep.Shutdown(context.Background())
	var goReport iroh.NetReport
	for {
		report, ok := ep.NetReport()
		if ok {
			goReport = report
			break
		}
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return finishCell(cell, Fail, "Go report: "+ctx.Err().Error())
		case <-time.After(100 * time.Millisecond):
		}
	}
	if err := <-rustReady; err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return finishCell(cell, Fail, fmt.Sprintf("Rust report: %v: %s", err, rust.String()))
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()

	if err := compareQADReportShape(rust.String(), goReport); err != nil {
		return finishCell(cell, Fail, err.Error())
	}
	evidence := fmt.Sprintf("upstream iroh-doctor report:\n%s\nGo report:\n%+v\n", rust.String(), goReport)
	artifact, err := writeQADArtifact(version, evidence)
	if err != nil {
		return finishCell(cell, SetupError, err.Error())
	}
	cell.Artifacts = []string{artifact}
	return finishCell(cell, Pass, "upstream and Go reports expose the same fields; optional values and latencies satisfy honest-subset invariants")
}

func compareQADReportShape(rust string, report iroh.NetReport) error {
	fields := []string{
		"udp_v4:", "udp_v6:",
		"mapping_varies_by_dest_ipv4:", "mapping_varies_by_dest_ipv6:",
		"preferred_relay:", "relay_latency:",
		"global_v4:", "global_v6:", "captive_portal:",
	}
	for _, field := range fields {
		if !strings.Contains(rust, field) {
			return fmt.Errorf("upstream report lacks field %s", strings.TrimSuffix(field, ":"))
		}
	}
	for _, field := range []struct {
		name string
		goV  bool
	}{
		{name: "udp_v4", goV: report.UDPv4},
		{name: "udp_v6", goV: report.UDPv6},
	} {
		rustV, ok := rustBoolField(rust, field.name)
		if !ok {
			return fmt.Errorf("cannot parse upstream %s", field.name)
		}
		if rustV != field.goV {
			return fmt.Errorf("%s differs: Rust=%t Go=%t", field.name, rustV, field.goV)
		}
	}
	if report.UDPv4 != report.GlobalV4.IsValid() {
		return fmt.Errorf("Go udp_v4=%t global_v4=%v", report.UDPv4, report.GlobalV4)
	}
	if report.UDPv6 != report.GlobalV6.IsValid() {
		return fmt.Errorf("Go udp_v6=%t global_v6=%v", report.UDPv6, report.GlobalV6)
	}
	if report.GlobalV4.IsValid() {
		match := regexp.MustCompile(`global_v4:\s*Some\(\s*([0-9.]+):`).FindStringSubmatch(rust)
		if len(match) != 2 || match[1] != report.GlobalV4.Addr().String() {
			return fmt.Errorf("global_v4 address differs: Rust=%q Go=%s", match, report.GlobalV4.Addr())
		}
	}
	if report.GlobalV6.IsValid() {
		match := regexp.MustCompile(`global_v6:\s*Some\(\s*\[([^]]+)\]:`).FindStringSubmatch(rust)
		if len(match) != 2 || match[1] != report.GlobalV6.Addr().String() {
			return fmt.Errorf("global_v6 address differs: Rust=%q Go=%s", match, report.GlobalV6.Addr())
		}
	}
	for relayURL, latency := range report.RelayLatencies {
		if relayURL.IsZero() || latency <= 0 {
			return fmt.Errorf("Go relay latency %v=%v is not plausible", relayURL, latency)
		}
	}
	return nil
}

func rustBoolField(report, field string) (bool, bool) {
	match := regexp.MustCompile(regexp.QuoteMeta(field) + `:\s*(true|false)`).FindStringSubmatch(report)
	if len(match) != 2 {
		return false, false
	}
	return match[1] == "true", true
}

func writeQADArtifact(version, evidence string) (string, error) {
	root, err := harnessRoot()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(root, "results", "artifacts")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("create QAD artifact directory: %w", err)
	}
	path := filepath.Join(dir, "discovery-qad-report-"+version+".log")
	if err := os.WriteFile(path, []byte(strings.TrimSpace(evidence)+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write QAD artifact: %w", err)
	}
	return filepath.ToSlash(filepath.Join("results", "artifacts", filepath.Base(path))), nil
}
