#!/bin/bash

set -v
set -e

export CARGO_TARGET_DIR=testing/target

# Set OFFLINE=1 to avoid rustup. cargo might still run offline.

if ! grep -sq '^name = "sunset"' Cargo.toml; then
    echo "Run ci.sh from the toplevel sunset directory"
    exit 2
fi

mkdir -p ci_out
OUT="$(realpath ci_out)"

export RUSTDOCFLAGS='-D warnings'

# dependencies
which cargo-bloat > /dev/null || cargo install cargo-bloat
if [ -z "$OFFLINE" ]; then
    (
    cd embassy/demos/picow
    rustup target add thumbv6m-none-eabi
    )
fi

# stable
cargo test
# build non-testing, will be no_std
cargo build
cargo doc
cargo test --doc

(
cd async
# only test lib since some examples are broken
cargo test --lib
cargo test --lib
cargo build --example sunsetc
# with/without release to test debug_assertions
cargo build --release --example sunsetc
)

(
cd embassy
cargo test
cargo test --doc
cargo doc
)

(
cd embassy/demos/std
cargo build
)

(
cd embassy/demos/common
cargo test
)

(
cd embassy/demos/picow
cargo build --release
cargo bloat --release -n 100 | tee "$OUT/picow-bloat.txt"
cargo bloat --release --crates | tee "$OUT/picow-bloat-crates.txt"
cargo build --release --no-default-features --features w5500,romfw
)
size target/thumbv6m-none-eabi/release/sunset-demo-embassy-picow | tee "$OUT/picow-size.txt"


# other checks

if [ $(find embassy -name rust-toolchain.toml -print0 | xargs -0 grep -h ^channel | uniq | wc -l) -ne 1 ]; then
    echo "rust-toolchain.toml has varying toolchains"
    find embassy -name rust-toolchain.toml -print0 | xargs -0 grep .
    exit 1
fi

echo success
