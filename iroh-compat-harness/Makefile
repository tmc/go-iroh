.PHONY: parity test regen-vectors vectors canaries

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

canaries:
	@set -eu; \
	for pair in \
		'postcard-varint TestPostcardUintVectors' \
		'ticket-prefix TestEndpointTicketVector' \
		'pkarr-signer TestPkarrVector'; do \
		set -- $$pair; \
		if PARITY_MUTATION=$$1 go test -count=1 -tags=mutcanary -run "^$$2$$" ./vectors >/dev/null 2>&1; then \
			echo "mutation $$1 did not make $$2 fail" >&2; \
			exit 1; \
		fi; \
		echo "mutation $$1: failed as expected"; \
	done
