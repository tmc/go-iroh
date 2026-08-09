.PHONY: parity test regen-vectors vectors

IROH_VERSION ?= 1.0.3
RUST_DOCTOR_BIN ?=

parity:
	go run ./cmd/parity -iroh-version $(IROH_VERSION) -rust-doctor "$(RUST_DOCTOR_BIN)"

test:
	go test ./...

regen-vectors:
	cargo run --quiet --release --locked --manifest-path drivers/rust-driver/Cargo.toml > vectors/corpus.json

vectors:
	@work=$$(mktemp -d "$$HOME/tmp/go-iroh-vectors.XXXXXX"); \
	trap 'rm -rf "$$work"' EXIT; \
	cargo run --quiet --release --locked --manifest-path drivers/rust-driver/Cargo.toml > "$$work/corpus.json"; \
	cmp vectors/corpus.json "$$work/corpus.json"
