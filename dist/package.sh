#!/usr/bin/env bash
#
# package.sh: build the static musl binary and bundle it with the default config, rules,
# skills and systemd units:  target/bundle/logscan-<version>-x86_64-linux.tar.gz
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cargo test --quiet
cargo build --release --target x86_64-unknown-linux-musl
BIN=target/x86_64-unknown-linux-musl/release/logscan
VERSION="$("$BIN" --version | cut -d' ' -f2)"
NAME="logscan-$VERSION-x86_64-linux"
OUT="target/bundle/$NAME"

# The shipped rules must pass their own inline tests.
"$BIN" --config defaults/config.toml rules check >/dev/null
"$BIN" --config defaults/config.toml skills check >/dev/null

rm -rf "$OUT"
mkdir -p "$OUT"
cp "$BIN" README.md "$OUT/"
cp -r defaults dist/systemd "$OUT/"
tar -C target/bundle -czf "target/bundle/$NAME.tar.gz" "$NAME"
sha256sum "target/bundle/$NAME.tar.gz"
