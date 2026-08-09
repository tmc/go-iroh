.PHONY: parity test

IROH_VERSION ?= 1.0.3
RUST_DOCTOR_BIN ?=

parity:
	go run ./cmd/parity -iroh-version $(IROH_VERSION) -rust-doctor "$(RUST_DOCTOR_BIN)"

test:
	go test ./...
