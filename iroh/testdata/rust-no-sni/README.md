This client uses released iroh 1.2.0's default TLS configuration and disables
relays. It connects to the Go test server over loopback and verifies an echo.
The Go test also requires the accepted TLS connection's server name to be empty.

From the repository root:

```sh
cargo build --locked --manifest-path iroh/testdata/rust-no-sni/Cargo.toml \
  --target-dir "$HOME/tmp/codex-compat-repin/sni-target" \
  --config "patch.crates-io.iroh.path='$IROH_RUST_REPO/iroh'"
GO_IROH_RUST_NO_SNI_BIN="$HOME/tmp/codex-compat-repin/sni-target/debug/go-iroh-no-sni-client" \
  go test -count=1 -v ./iroh -run '^TestLiveRustClientNoSNI$'
```

Use a clean upstream checkout at v1.2.0 (17c0612f80f78f5288e97b818b1360ae6ea0a51a).
For a negative control, build a scratch copy with `crypto.enable_sni = true`
in `iroh/src/tls.rs`; the same Go test must fail on the nonempty server name.
These native results are diagnostic evidence, not generated compatibility cells.
