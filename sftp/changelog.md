# `sunset-sftp` Changelog

## 0.2.0 - 2026-08-02

### Changed

- `SftpHandler` now takes `REQ_BUF` and `RESP_BUF` size parameters
  and allocates the buffer internally. Constructors are `const` to allow
  static allocations.

- `SftpHandler::process_loop` has been renamed to `SftpHandler::run`.
  That now takes a `SftpServer` argument.

- Changed `SftpServer` trait, replaced `OpaqueFileHandle` parameter.
  Now `FileHandle` or `DirHandle` types are used as handles by
  the application, wrapping a `u32`.

- Generic parameters on `SftpServer` trait methods have changed.

- `SftpError` variants have changed.

### Fixed

- Packet decoding is better at handling unknown packet types. Previously
  the stream could get into an unrecoverable state if unknown packets
  were received across buffer boundaries.

## 0.1.3 - 2026-06-23

- First release. Implemented by Julio Beltran Ortega
  @jubeormk1 with SSH Stamp
