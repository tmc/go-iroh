.PHONY: parity parity-native test regen-vectors vectors canaries doctor-image doctor-image-build release-check

IROH_VERSION ?= 1.0.3
RUST_DOCTOR_BIN ?=
RUST_RELAY_BIN ?=
RUST_VECTOR_BIN ?=
DOCTOR_OUTPUT ?= $(HOME)/tmp/go-iroh-compat/iroh-doctor-$(IROH_VERSION)

parity: doctor-image-build
	IROH_VERSION=$(IROH_VERSION) docker compose run --build --rm parity

parity-native:
	go test ./vectors
	@work=$$(mktemp -d "$$HOME/tmp/go-iroh-parity.XXXXXX"); \
	trap 'rm -rf "$$work"' EXIT; \
	go build -o "$$work/iroh-relay" ../cmd/iroh-relay; \
	go run ./cmd/parity -iroh-version $(IROH_VERSION) -go-relay "$$work/iroh-relay" -rust-doctor "$(RUST_DOCTOR_BIN)" -rust-relay "$(RUST_RELAY_BIN)" -rust-vector "$(RUST_VECTOR_BIN)"

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

doctor-image-build:
	docker build -f images/iroh-$(IROH_VERSION)/Dockerfile -t go-iroh-compat:iroh-$(IROH_VERSION) .

doctor-image: doctor-image-build
	@mkdir -p "$(dir $(DOCTOR_OUTPUT))"; \
	cid=$$(docker create go-iroh-compat:iroh-$(IROH_VERSION)); \
	trap 'docker rm -f "$$cid" >/dev/null 2>&1 || true' EXIT; \
	docker cp "$$cid:/usr/local/bin/iroh-doctor" "$(DOCTOR_OUTPUT)"; \
	chmod +x "$(DOCTOR_OUTPUT)"

release-check:
	$(MAKE) parity IROH_VERSION=1.0.0
	$(MAKE) parity IROH_VERSION=1.0.3
