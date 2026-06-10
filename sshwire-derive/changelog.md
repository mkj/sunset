# `sunset-sshwire-derive` Changelog

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
