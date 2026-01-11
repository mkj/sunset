#!/bin/bash

set -v
set -e

export CARGO_TARGET_DIR=target/ci

# Set OFFLINE=1 to avoid rustup. cargo might still run offline.

if ! grep -sq '^name = "sunset"' Cargo.toml; then
    echo "Run ci.sh from the toplevel sunset directory"
    exit 2
fi

mkdir -p ci_out
OUT="$(realpath ci_out)"

export RUSTDOCFLAGS='-D warnings'
export RUSTFLAGS='-D warnings'

# dependencies
which cargo-bloat > /dev/null || cargo install cargo-bloat
if [ -z "$OFFLINE" ]; then
    (
    cd demo/picow
    rustup target add thumbv6m-none-eabi
    )
    rustup component add rustfmt
fi

cargo fmt --check

# stable
# only test lib since some examples are broken
cargo test --lib
# build non-testing, will be no_std
cargo build
cargo doc
cargo test --doc

(
cd stdasync
# only test lib since some examples are broken
cargo test --lib
# test backtrace feature too
cargo build --example sunsetc --features sunset/backtrace
# with/without release to test debug_assertions
cargo build --release --example sunsetc
)

(
cd async
cargo test
cargo test --doc
cargo doc
)

(
cd demo/std
cargo build
)

(
cd demo/common
cargo test
)

(
cd demo/picow
cargo build --release
cargo bloat --release -n 100 | tee "$OUT/picow-bloat.txt"
cargo bloat --release --crates | tee "$OUT/picow-bloat-crates.txt"
cargo build --release --no-default-features --features w5500,romfw
)
size target/thumbv6m-none-eabi/release/sunset-demo-picow | tee "$OUT/picow-size.txt"

(
cd fuzz
cargo check --features nofuzz --profile fuzz
)

# other checks

if [ $(find async -name rust-toolchain.toml -print0 | xargs -0 grep -h ^channel | uniq | wc -l) -ne 1 ]; then
    echo "rust-toolchain.toml has varying toolchains"
    find async -name rust-toolchain.toml -print0 | xargs -0 grep .
    exit 1
fi

echo success
