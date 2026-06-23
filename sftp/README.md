# SFTP

A SFTP implementation for use with Sunset SSH.

This is a work in progress, basic server functionality works.

Applications implement `SftpHandler` trait to define the filesystem.
See `demo/sftp/std` for an example server.

This crate should also be usable separately from Sunset with
async `Read`/`Write` implementations.

### Credits

This was implemenented by Julio Beltran Ortega (@jubeormk1) as part of
[SSH Stamp](https://github.com/brainstorm/ssh-stamp)
