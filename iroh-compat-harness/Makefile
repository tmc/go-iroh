.PHONY: parity parity-release parity-report test regen-vectors vectors canaries doctor-image release-check

include pins.mk

# A parity run covers the newest PARITY_RELEASES pinned releases, one column
# each. IROH_VERSION selects the release for parity-release and doctor-image.
PARITY_RELEASES ?= 2
RELEASES := $(wordlist $(shell n=$$(( $(words $(IROH_RELEASES)) - $(PARITY_RELEASES) + 1 )); [ $$n -ge 1 ] || n=1; echo $$n),$(words $(IROH_RELEASES)),$(IROH_RELEASES))
IROH_VERSION ?= $(lastword $(IROH_RELEASES))
IROH_COMMIT = $(IROH_COMMIT_$(IROH_VERSION))

RUST_DOCTOR_BIN ?=
RUST_RELAY_BIN ?=
RUST_DNS_BIN ?=
RUST_VECTOR_BIN ?=
DOCTOR_OUTPUT ?= $(HOME)/tmp/go-iroh-compat/iroh-doctor-$(IROH_VERSION)

# The image builds reuse cargo and Go caches. Set PARITY_NO_CACHE=1 to rebuild
# every layer from scratch when an evidence run must not inherit any of it.
NO_CACHE := $(if $(PARITY_NO_CACHE),--no-cache,)

# parity builds a parity image per release, runs the releases in concurrent
# containers, and merges their run files into the report. A failed release run
# prints its log and fails the target without writing the report.
parity: $(RELEASES:%=peer-image-%)
	@test -z "$$(git -C .. status --porcelain)" || { echo "go-iroh working tree is dirty" >&2; exit 1; }
	@set -eu; \
		export GO_IROH_GIT_COMMON_DIR=$$(git -C .. rev-parse --path-format=absolute --git-common-dir); \
		rm -rf results/runs; mkdir -p results/runs; \
		for v in $(RELEASES); do IROH_VERSION=$$v docker compose build $(NO_CACHE) parity; done; \
		pids=; \
		for v in $(RELEASES); do \
			echo "parity: running iroh $$v"; \
			IROH_VERSION=$$v docker compose run --rm -T parity >results/runs/iroh-$$v.log 2>&1 & pids="$$pids $$!:$$v"; \
		done; \
		failed=; \
		for p in $$pids; do wait $${p%%:*} || failed="$$failed $${p#*:}"; done; \
		for v in $$failed; do echo "parity: iroh $$v run failed:" >&2; cat results/runs/iroh-$$v.log >&2; done; \
		test -z "$$failed"; \
		IROH_VERSION=$(lastword $(RELEASES)) docker compose run --rm parity make parity-report RELEASES="$(RELEASES)"

peer-image-%:
	docker build $(NO_CACHE) -f images/iroh-$*/Dockerfile \
		--build-arg IROH_VERSION=$* \
		-t go-iroh-compat:iroh-$* .

# parity-release measures one release, IROH_VERSION, with the Rust peers named
# by the RUST_*_BIN variables, and writes results/runs/iroh-$(IROH_VERSION).json.
parity-release:
	@test -n "$(IROH_COMMIT)" || { echo "iroh $(IROH_VERSION) is not pinned in pins.mk" >&2; exit 1; }
	@set -eu; mkdir -p "$$HOME/tmp"; work=$$(mktemp -d "$$HOME/tmp/go-iroh-parity.XXXXXX"); \
	trap 'rm -rf "$$work"' EXIT; \
	go build -o "$$work/iroh-relay" ../cmd/iroh-relay; \
	go build -o "$$work/iroh-dns-server" ../cmd/iroh-dns-server; \
	go run ./cmd/iroh-compat -release-version $(IROH_VERSION) -release-commit $(IROH_COMMIT) -go-relay "$$work/iroh-relay" -go-dns "$$work/iroh-dns-server" -rust-doctor "$(RUST_DOCTOR_BIN)" -rust-relay "$(RUST_RELAY_BIN)" -rust-dns "$(RUST_DNS_BIN)" -rust-vector "$(RUST_VECTOR_BIN)" -rust-pq "$(RUST_VECTOR_BIN)"

# parity-report verifies every release's vector corpus with Go and merges the
# run files of RELEASES into results.json, badge.json, and COMPATIBILITY.md.
parity-report:
	go test ./vectors
	go run ./cmd/iroh-compat -merge $(RELEASES:%=results/runs/iroh-%.json)

test:
	go test ./...

regen-vectors:
	@set -eu; for v in $(IROH_RELEASES); do \
		cargo run --quiet --release --locked --manifest-path drivers/rust-driver/iroh-$$v/Cargo.toml > vectors/corpus/$$v.json; \
	done

vectors:
	@set -eu; work=$$(mktemp -d "$$HOME/tmp/go-iroh-vectors.XXXXXX"); \
	trap 'rm -rf "$$work"' EXIT; \
	for v in $(IROH_RELEASES); do \
		cargo run --quiet --release --locked --manifest-path drivers/rust-driver/iroh-$$v/Cargo.toml > "$$work/$$v.json"; \
		cmp vectors/corpus/$$v.json "$$work/$$v.json"; \
	done

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

doctor-image: peer-image-$(IROH_VERSION)
	@mkdir -p "$(dir $(DOCTOR_OUTPUT))"; \
	cid=$$(docker create go-iroh-compat:iroh-$(IROH_VERSION)); \
	trap 'docker rm -f "$$cid" >/dev/null 2>&1 || true' EXIT; \
	docker cp "$$cid:/usr/local/bin/iroh-doctor" "$(DOCTOR_OUTPUT)"; \
	chmod +x "$(DOCTOR_OUTPUT)"

release-check:
	$(MAKE) parity
