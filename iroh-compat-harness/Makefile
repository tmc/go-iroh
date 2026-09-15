.PHONY: parity parity-native test regen-vectors vectors canaries doctor-image doctor-image-build release-check

include pins.env

IROH_VERSION ?= $(IROH_RELEASE_VERSION)
RUST_DOCTOR_BIN ?=
RUST_RELAY_BIN ?=
RUST_DNS_BIN ?=
RUST_VECTOR_BIN ?=
RUST_CUSTOM_VECTOR_BIN ?=
DOCTOR_OUTPUT ?= $(HOME)/tmp/go-iroh-compat/iroh-doctor-$(IROH_VERSION)

# The image builds reuse cargo and Go caches. Set PARITY_NO_CACHE=1 to rebuild
# every layer from scratch when an evidence run must not inherit any of it.
NO_CACHE := $(if $(PARITY_NO_CACHE),--no-cache,)

parity: doctor-image-build
	@test -z "$$(git -C .. status --porcelain)" || { echo "go-iroh working tree is dirty" >&2; exit 1; }
	set -eu; \
		export GO_IROH_GIT_COMMON_DIR=$$(git -C .. rev-parse --path-format=absolute --git-common-dir); \
		export IROH_VERSION=$(IROH_VERSION) IROH_CUSTOM_COMMIT=$(IROH_CUSTOM_COMMIT); \
		docker compose build $(NO_CACHE) parity; \
		docker compose run --rm parity

parity-native:
	go test ./vectors
	@set -eu; mkdir -p "$$HOME/tmp"; work=$$(mktemp -d "$$HOME/tmp/go-iroh-parity.XXXXXX"); \
	trap 'rm -rf "$$work"' EXIT; \
	go build -o "$$work/iroh-relay" ../cmd/iroh-relay; \
	go build -o "$$work/iroh-dns-server" ../cmd/iroh-dns-server; \
	go run ./cmd/iroh-compat -release-train $(IROH_RELEASE_TRAIN) -release-version $(IROH_RELEASE_VERSION) -custom-train $(IROH_CUSTOM_TRAIN) -custom-version $(IROH_CUSTOM_VERSION) -custom-commit $(IROH_CUSTOM_COMMIT) -go-relay "$$work/iroh-relay" -go-dns "$$work/iroh-dns-server" -rust-doctor "$(RUST_DOCTOR_BIN)" -rust-relay "$(RUST_RELAY_BIN)" -rust-dns "$(RUST_DNS_BIN)" -rust-vector "$(RUST_VECTOR_BIN)" -rust-custom-vector "$(RUST_CUSTOM_VECTOR_BIN)" -rust-pq "$(RUST_VECTOR_BIN)"

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
		'postcard-8bit TestPostcard8BitVectors' \
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
	docker build $(NO_CACHE) -f images/iroh-$(IROH_VERSION)/Dockerfile \
		--build-arg IROH_VERSION=$(IROH_VERSION) \
		-t go-iroh-compat:iroh-$(IROH_VERSION) .

doctor-image: doctor-image-build
	@mkdir -p "$(dir $(DOCTOR_OUTPUT))"; \
	cid=$$(docker create go-iroh-compat:iroh-$(IROH_VERSION)); \
	trap 'docker rm -f "$$cid" >/dev/null 2>&1 || true' EXIT; \
	docker cp "$$cid:/usr/local/bin/iroh-doctor" "$(DOCTOR_OUTPUT)"; \
	chmod +x "$(DOCTOR_OUTPUT)"

release-check:
	$(MAKE) parity
