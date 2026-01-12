# `fuzz-server` target

This uses fuzz input as the entire SSH input network stream.

The fuzz target runs a simple server with scattered `debug_assert` to
test expected behaviour. The Sunset crate contains various
`debug_assert` statements, and `Error::Bug` also panics when
debug assertions are enabled.

Decryption and signature verification is disabled.

## Input

The input is treated as
```
data length (u32 be)
data bytes
control length (u32 be)
control bytes
```

`data` is the network input. `control` is used to randomise the server
actions, such as amount of data to read, which channel to read/write/close/accept,
whether to accept a password, etc.

`data` and `control` lengths must be at least 2044 bytes, so that some blank padding
is left to make mutations more reusable.

`reformat-server.py` will convert an existing raw SSH network dump into the expected input
format.

# `fuzz-arb-server` target

`fuzz-arb-server` is similar to `fuzz-server`, but a stream of
valid SSH protocol packets is crafted as the `data` input part.
That implements [`Arbitrary`](https://docs.rs/arbitrary) on Sunset's `Packet` data structure,
then uses the `sshwire` encoding mechanism. That is fed into the fuzz target as normal.

This is quite efficient at finding new paths, since it only feeds real packets.
It is not as comprehensive as fuzzing with pure random input, since it's
constrained to normal SSH protocol.

`fuzz-arb-server --fuzzin destdir/` (built with `--feature nofuzz`) will write out 
a corpus suitable for `fuzz-server`target.

# Fuzz engines

Targets work with afl-fuzz or honggfuzz. libfuzzer would be easy to add.

AFL++ seemed to give better results, but honggfuzz is simpler to run
with lots of threads. Interleaving runs of both seems to work well.

### afl-fuzz

Install [`afl.rs`](https://github.com/rust-fuzz/afl.rs).

```
RUSTFLAGS="-C target-cpu=native" cargo afl build --features afl --profile fuzz --bins
```

You can use `cargo afl run`, but multiple threads are easier with
[aflr](https://github.com/0xricksanchez/afl_runner). Note you'll need a
similar version afl++ binary to `afl.rs`, perhaps build from source.

```
aflr run -x server.dict -t ../target/fuzz/fuzz-server -n 23 -i ~/tmp/inputcorpus -o ~/tmp/rundir

# when done:
aflr kill fuzz-server
```

Minimise a corpus

```
# afl-cmin runs other programs in the aflpp installation, so make sure PATH is good.
(PATH=$HOME/inst/aflpp/bin:$PATH ; afl-cmin -i ~/tmp/fuzzsunset/afl51/m_fuzz-server/queue -o ~/tmp/fuzzsunset/min51  -T all  -- ../target/fuzz/fuzz-server)
```

### Honggfuzz

Install [`honggfuzz-rs`](https://github.com/rust-fuzz/honggfuzz-rs)

```
HFUZZ_INPUT=$HOME/tmp/fuzzsunset/afl61/m_fuzz-server/queue HFUZZ_BUILD_ARGS="--profile=fuzz --features honggfuzz" RUSTFLAGS='-C target-cpu=native'  HFUZZ_RUN_ARGS='-n24  --dict server.dict ' nice cargo hfuzz run fuzz-server
```

Add `-M` to the `HFUZZ_RUN_ARGS` to minimise a corpus in-place.

### Running without fuzzing

Build with `--nofuzz` for a binary that takes input files or directories as 
arguments and runs them all.
It's useful for debugging crashes or getting coverage.

```
cargo build --features nofuzz

RUST_LOG=trace ../target/debug/fuzz-server ~/tmp/crashes
```

### Coverage

`cargo install cargo-llvm-cov`

```
cargo llvm-cov run --features nofuzz --html --open --bin fuzz-server ~/tmp/fuzzsunset/afl53/m_fuzz-server/queue
```
