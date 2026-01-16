# Sunset Changelog

# unreleased

### Added

- Add server authentication helpers `matches_username()`,
  `matches_password()`.

- Add environment session variable support

- Add mlkem768x25519 hybrid post-quantum key exchange
  Enabled by `mlkem` feature, will soon be default.

### Fixed

- Fix public key authentication. Github #30

- Don't fail in some circumstances during key exchange when
  packets are received in particular order. Github #25, Github #27

- Fix a hang where channels wouldn't get woken for more output
  after the SSH stream was written out. Github #25

- Fix using sshwire-derive outside of sunset

- Fix winch signal for sunsetc (regression in 0.3.0)

### Changed

- Log a better warning when host key signatures fail

- Improve exit code handling in sunsetc

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


