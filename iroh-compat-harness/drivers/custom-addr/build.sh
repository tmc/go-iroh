#!/bin/sh
# Build against the named checkout and reject an unused path patch.
set -eu
repo=$1
target=$2
manifest=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/Cargo.toml
mkdir -p "$target"
if cargo build --release --manifest-path "$manifest" --target-dir "$target" \
    --config "patch.crates-io.iroh-base.path='$repo/iroh-base'" >"$target/build.log" 2>&1; then
    cat "$target/build.log"
else
    cat "$target/build.log" >&2
    exit 1
fi
if grep -E 'patch .*not used|patch .*was not used' "$target/build.log"; then
    exit 1
fi
awk '
/^\[\[/ { base = 0 }
/^name = "iroh-base"$/ { base = 1; found++ }
base && /^source = / { bad = 1 }
base && /^version = / && $0 != "version = \"1.2.0\"" { bad = 1 }
/^\[\[patch.unused\]\]/ { bad = 1 }
END { exit (found != 1 || bad) }
' "$(dirname "$manifest")/Cargo.lock"
