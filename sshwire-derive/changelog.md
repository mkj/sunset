# `sunset-sshwire-derive` Changelog

## 0.3.0 - 2026-08-02

### Added

- Allow enum struct and tuple variants.

- Allow `#[sshwire(unknown)]` on unit variants, discarding the name.

- Add `#[sshwire(decode_unknown_fail)]` to return an error instead
  of storing unknown variants.

### Changed

- Encoding an enum returns `WireError::EncodeUnknown`

### Fixed

- Don't warn about `.finish()` when derive fails.

## 0.2.2 - 2026-06-23

- Disallow `derive(SSHEncode)` for enums with values. They could
  be implemented in future, but make it obvious that they won't work now.

- Update to edition 2024

## 0.2.1 - 2026-01-11

### Fixed

- Allow external use without needing `use sunset::sshwire`.

### Changed

- Disallow enum values which would be ignored.

## 0.2.0 - 2024-03-03

- First working release
