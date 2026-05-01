# sunset-demo-sftp-std

`demo/sftp/std` contains a host-side (`std`) demo that runs an SSH server with SFTP support using the `sunset` and `sunset-sftp` crates. It runs on linux distributions.

It is intended as a **reference implementation** for building your own SFTP server with `sunset-sftp`. It is not a complete implementation and you should make your own choices for your sftp server.

In particular, this demo shows how to:

- implement an `SftpServer` for request handling
- add a `FileHandleManager` to track/open/close active handles
- define an `OpaqueFileHandle` format to safely encode/decode handle IDs across requests

Use `src/demosftpserver.rs`, `src/demofilehandlemanager.rs`, and `src/demoopaquefilehandle.rs` together with `main.rs` and common demo files as a reference for custom server development.

## What this folder contains

- `src/main.rs`  
    Demo entry point. Sets up logging, runtime/executor, network stack, and starts the SSH/SFTP demo server.
- `src/demosftpserver.rs`  
    Demo SFTP server wiring and request handling glue.
- `src/demofilehandlemanager.rs`  
    Tracks and manages open file handles used by the SFTP session.
- `src/demoopaquefilehandle.rs`  
    Defines/encodes opaque file handle values used by the demo protocol layer.
- `tap.sh`  
    Helper script to create/configure a TAP interface for local testing.
- `debug_sftp_client.sh`  
    Convenience script for running an SFTP client in a debug-friendly way.
- `testing/`  
    Test and log scripts (read/write/stat/readdir scenarios, log helpers, and parsing utilities).

## Setup

This demo uses a tap interface to run the server and accept connections. The tap.sh sets this up in a linux environment. I have not find a way to run this on MacOS. On windows I recommend using WSL2.

Run:

```bash
sudo ./tap.sh
```

## Build / run

From base project folder `sunset`:

```bash
cargo run -p sunset-demo-sftp-std
```

Then connect with an SFTP client using the configured demo host/user settings. The first info log will display the server ipv4 address.

## Testing

`testing/` contains runnable scripts and utilities to validate SFTP behavior end-to-end. It includes scenarios for:

- file reads/writes
- `stat`/metadata checks
- directory listing (`readdir`)
- log capture and parsing helpers (Requires a tshark installation with the current user in wireshark group)

These scripts are useful both for regression checks and as examples of expected server behavior during development.

these scripts have been used through the development of `sunset-sftp` and might not respond to a general use but some particular troubleshooting. I hope that they are useful as a reference for you exploration.

