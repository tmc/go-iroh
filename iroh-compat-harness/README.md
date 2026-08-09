# iroh compatibility harness

This nested module runs wire-compatibility scenarios between go-iroh and pinned Rust iroh releases. A passing cell requires a real Rust process and records its PID and binary SHA-256.

Run the stage-1 loopback matrix with an unmodified `iroh-doctor` 0.101.0 binary built against iroh 1.0.3:

```sh
make parity IROH_VERSION=1.0.3 RUST_DOCTOR_BIN=/path/to/iroh-doctor
```

The command writes `results/results.json`, `results/badge.json`, and the repository-root `COMPATIBILITY.md`.
