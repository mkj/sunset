# `sunset-stdasync` Changelog

## 0.3.0 - 2025-06-16

### Changed

- Application customisation is now controlled by responding to `ServEvent`
  or `CliEvent` from `progress()`, replacing the previous `Behaviour` trait.

- Improvements from updated `sunset` core crate.

- Reduced RAM and memory copying.

- `sunset-async` is now the common async crate, for both no_std and std.
  (Previously named `sunset-embassy`).
- `sunset-stdasync` crate has std-specific features and the `sunsetc`
  commandline client example.
  (Previously named `sunset-async`).

## 0.2.0 - 2024-03-03

- First working release
 
