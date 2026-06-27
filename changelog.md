# Sunset Changelog

## 0.5.0 - 2026-06-23

### Changed

- Emit `ServAuth::Authenticated` when authentication succeeds.
  This is common to all auth types. ServPubkeyAuth::real() is
  removed.

- Reduce memory required by mlkem, thanks to Marko Malenic
  @mmalenic with SSH Stamp

- Improve handling of a full send window. Channel window
  adjustments won't return `Error::NoRoom` when reading
  from a channel. A new error `Error::BusySend` is added
  for the remaining cases where a packet cannot be sent
  because of insufficient space, such as trying to open
  a channel while rekeying is in progress.

- Fix bug in waking channels, this could cause connections
  to stall in `sunset-async`.

- `TextString` methods renamed to `to_ascii()` and `to_str()`

- Update various dependencies.

- Minimum Rust version is 1.95

- Improvements to packet handling during rekeying.

- zeroize is enabled for more signkey types to clear
  sensitive memory.

### Added

- Add ecdsa256 key support. Enabled by default on std, or with
  `ecdsa256` feature. This currently depends on some "rc"
  versions of RustCrypto crates, so will lead to some
  size duplication.

- `Runner::new_client_owned()` and `new_server_owned()`
  allocate a fixed buffer, giving instances with a static
  lifetime. Requires `std` or `alloc` feature.

- Fixed missing export of `CliSessionOpener` which
  was undocumented.

- Initiate rekeying when every ~30GB of data has been transferred.

- SSH software version identification now uses the crate version number.
  In the unlikely chance Sunset has protocol bugs this can be used by other
  implementations for workarounds.

### Removed

- Remove `sunset::random` export. `getrandom` crate can be used
  directly instead.

## 0.4.0 - 2026-01-11

### Added

- Add server authentication helpers `matches_username()`,
  `matches_password()` for constant time comparison.

- Add environment session variable support

- Add mlkem768x25519 hybrid post-quantum key exchange
  Enabled by `mlkem` feature, will soon be default.

### Fixed

- Fix public key authentication for the server, previously signatures
  would not validate. Github #30

- Don't fail in some circumstances during key exchange when
  packets are received in particular order. Github #25, Github #27

- Fix a hang where channels wouldn't get woken for more output
  after the SSH stream was written out. Github #25

- Fix using sshwire-derive outside of sunset

### Changed

- Server auth events such as `ServFirstAuth` can enable or disable
  password or public key auth for subsequent attempts. Now no authentication methods are enabled by default, they must be explicitly enabled with eg `enable_password_auth()`, `enable_pubkey_auth()`.

- Minimum Rust version is 1.87

- `Channels::by_handle_mut()` renamed from `from_handle_mut()` to be
  more idiomatic.

- Log a better warning when host key signatures fail

- Code size improvements.

- Fail with `PacketWrong` when calling an event method, rather
  than on a subsequent `progress()` call.

- CI scripts now build in `target/ci` rather than `testing/target`

## 0.3.0 - 2025-06-16

### Changed

- New `Event` API to customise program behaviour, replacing
  previous `Behaviour` trait.

- Reduced code size, client or server code is not included where not used
  (implemented with `CliServ` generic parameter).

- Various fixes and API improvements. Edge conditions caught
  by fuzzing are now handled properly.

- picow and Embassy std demos are moved to a separate top level demos/
  directory.

- Demos config username changed from "admin" to "config".

- `sunset-async` is now the common async crate, for both no_std and
  std (previously named `sunset-embassy`).
- `sunset-stdasync` crate has std-specific features and the `sunsetc`
  commandline client example (previously named `sunset-async`).

### Added

- Added an initial server fuzzing target.

- Improved some API documentation.

### Removed

- Removed `defmt`, now only have `log`.
  `defmt` could be re-added if there is a use, but at present
  it's simpler to keep one format syntax.


## 0.2.0 - 2024-03-03

- First working release

## Start

April 2022


