# Sunset SSH

A SSH client and server implementation. It is intended to be very flexible to
embed pretty much anywhere, I'm collecting possible use cases in
[discussions](https://github.com/mkj/sunset/discussions/1). Don't hesitate to
suggest something!

- `sunset` (this toplevel) is the core SSH implementation. It provides a
  non-async API, runs with `no_std` and no alloc.

- [`sunset-async`](async) - async SSH client and server library, also
  `no_std` no-alloc. This is async-executor agnostic (using Embassy for mutexes, but works on std too).

- [`demos`](demos) has demos with Embassy executor for wifi on a Raspberry Pi
  [Pico W](demos/picow) or a
  [Linux tap device on `std`](demos/std) running locally.

  At present the Pico W build is around 150kB binary size
  (plus ~200KB [cyw43](https://github.com/embassy-rs/embassy/tree/main/cyw43) wifi firmware),
  using about 13kB RAM per concurrent SSH session.

- [`sunset-stdasync`](stdasync/) adds functionality to use Sunset as a normal SSH client or
  server async library in normal Rust (not `no_std`). This uses Tokio or async-std.

  The [examples](stdasync/examples) include a Linux commandline SSH client `sunsetc`. It works as a day-to-day SSH client.

## SSH Features

Working:

- Client and server
- Shell or command connection
- Password and public key authentication
- ed25519 signatures
- curve25519 key exchange
- chacha20-poly1305, aes256-ctr ciphers
- hmac-sha256 integrity
- rsa (`std`-only unless someone writes a `no_std` crate)
- `~.` client escape sequences
- Post quantum hybrid key exchange (mlkem)

Desirable:

- SFTP
- sntrup761
- TCP forwarding
- A std server example
- Perhaps aes256-gcm
- Perhaps ECDSA, hardware often supports it ahead of ed25519

## Rust versions

At the time of writing Sunset will build with Rust 1.87.
The requirement may increase whenever useful, targetting stable.

## Checks

Sunset uses `forbid(unsafe)`, apart from `sunset-async` which 
requires `unsafe` for Unix interactions.

Release builds should not panic, instead returning `Error::bug()`.
`debug_assert!` is used in some places for invariants during testing or
fuzzing.

Some attempts are made to clear sensitive memory after use, but compiler-generated copies
will not be cleared.

## Author

Matt Johnston <matt@ucc.asn.au>

It's built on top of lots of other work, particularly Embassy, the rust-crypto crates,
Virtue, smoltcp, and Salty.
