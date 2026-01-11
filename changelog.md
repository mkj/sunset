# Sunset Changelog

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


