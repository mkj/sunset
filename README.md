# Sunset SSH

A SSH client and server implementation. It is intended to be very flexible to
embed pretty much anywhere, I'm collecting possible use cases in
[discussions](https://github.com/mkj/sunset/discussions/1). Don't hesitate to
suggest something!

** This software is incomplete but nearly ready to be used **

- `sunset` (this toplevel) is the core SSH implementation. It provides a
  non-async API, runs with `no_std` and no alloc.

- [`sunset-embassy`](embassy) - async SSH client and server library, also
  `no_std`. This uses [Embassy](https://embassy.dev/) crate but is async
  executor agnostic.

- [`embassy/demos`](embassy/demos) has demos with Embassy executor for wifi on a Raspberry Pi
  [Pico W](embassy/demos/picow) or a
  [Linux tap device on `std`](embassy/demos/std) running locally.

  At present the Pico W build is around 150kB binary size
  (plus ~200KB [cyw43](https://github.com/embassy-rs/cyw43/) wifi firmware),
  using about 15kB RAM per concurrent SSH session (max stack size not confirmed).

- [`sunset-async`](async/) adds functionality to use Sunset as a normal SSH client or
  server async library in normal Rust (not `no_std`). The
  [examples](async/examples) include a Linux commandline SSH client.
  This uses Tokio or async-std.

## SSH Features

Working:

- Shell or command connection
- Password and public key authentication
- ed25519 signatures
- curve25519 key exchange
- chacha20-poly1305, aes256-ctr ciphers
- hmac-sha256 integrity
- rsa (will be `std`-only unless someone writes a `no_std` crate)
- `~.` client escape sequences

Desirable:

- TCP forwarding
- dh-group14 (probably `std`-only, need to investigate crates)
- Perhaps aes256-gcm
- Perhaps ECDSA, hardware often supports it ahead of ed25519
- SFTP

## License

Currently MPL2, though may possibly move to MIT-style in future (I'm undecided)

## Rust versions

At present `sunset` requires nightly Rust, in order to use async functions in
the `Behaviour` traits. It is intended to switch to stable Rust once that
feature stabilises.

`sunset-embassy` requires a nightly Rust version, as required by Embassy. See the
[embassy/rust-toolchain.toml](rust-toolchain.toml) for a known-good version.
Once [async functions in traits](https://github.com/rust-lang/rust/issues/91611)
becomes stable, Embassy should support stable Rust too.

## Safety

Sunset uses `forbid(unsafe)`, apart from `sunset-async` which requires `unsafe`
for Unix interactions.

Release builds should not panic, instead returning `Error::bug()`.
`debug_assert!` is used in some places for invariants during testing or
fuzzing.

Some attempts are made to clear sensitive memory after use, but stack copies
will not be cleared.

## Author

Matt Johnston <matt@ucc.asn.au>

It's built on top of lots of other work, particularly Embassy, the rust-crypto crates,
Virtue, and Salty.
