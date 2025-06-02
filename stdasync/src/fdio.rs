//! Helpers for async file descriptor IO
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};

use std::fs::File;
use std::io::Error as IoError;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};

use core::pin::Pin;
use core::task::{Context, Poll};

use nix::fcntl::{fcntl, FcntlArg, OFlag};

// Returns Ok(None) if the FD isn't suitable for async
fn dup_async(
    f: &impl AsRawFd,
    interest: Interest,
) -> Result<Option<AsyncFd<File>>, IoError> {
    // Duplicate the fd so we can set non-blocking without interfering
    // with other users (including println!() etc)
    let fd = nix::unistd::dup(f.as_raw_fd())?;
    // Wrap in a File, will ensure the FD closes on drop
    // OK unsafe - was freshly dup()ed
    debug!("dup fd {} -> {}", f.as_raw_fd(), fd);
    let fa = unsafe { File::from_raw_fd(fd) };

    match AsyncFd::with_interest(fa, interest) {
        Ok(a) => {
            // Set async FD non-blocking
            fcntl(fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
            Ok(Some(a))
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            // epoll_ctl() disallowed this FD. fallback to non-async, this kind
            // of FD should complete operations "immediately"
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

pub enum InFd<F> {
    Sync(F),
    Async(AsyncFd<File>),
}

pub enum OutFd<F> {
    Sync(F),
    Async(AsyncFd<File>),
}

pub fn stdin() -> Result<InFd<std::io::Stdin>, IoError> {
    let f = std::io::stdin();
    Ok(match dup_async(&f, Interest::READABLE)? {
        Some(a) => InFd::Async(a),
        None => InFd::Sync(f),
    })
}

pub fn stdout() -> Result<OutFd<std::io::Stdout>, IoError> {
    let f = std::io::stdout();
    Ok(match dup_async(&f, Interest::WRITABLE)? {
        Some(a) => OutFd::Async(a),
        None => OutFd::Sync(f),
    })
}

pub fn stderr_out() -> Result<OutFd<std::io::Stderr>, IoError> {
    let f = std::io::stderr();
    Ok(match dup_async(&f, Interest::WRITABLE)? {
        Some(a) => OutFd::Async(a),
        None => OutFd::Sync(f),
    })
}

impl<F: Read + Unpin> AsyncRead for InFd<F> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        match self.get_mut() {
            Self::Sync(f) => {
                let b = buf.initialize_unfilled();
                let l = f.read(b)?;
                buf.advance(l);
                Poll::Ready(Ok(()))
            }
            Self::Async(a) => {
                // XXX loop was copy pasted from AsyncFd docs, perhaps it could be simpler
                loop {
                    let mut guard = match a.poll_read_ready(cx)? {
                        Poll::Ready(r) => r,
                        Poll::Pending => return Poll::Pending,
                    };

                    match guard.try_io(|inner| {
                        let mut fd = inner.get_ref();

                        let b = buf.initialize_unfilled();
                        let r = fd.read(b);
                        match r {
                            Ok(s) => {
                                buf.advance(s);
                                Ok(())
                            }
                            Err(_) => Err(std::io::Error::last_os_error()),
                        }
                    }) {
                        Ok(result) => return Poll::Ready(result),
                        Err(_would_block) => continue,
                    }
                }
            }
        }
    }
}

impl<F: Write + Unpin> AsyncWrite for OutFd<F> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Sync(f) => Poll::Ready(f.write(buf)),
            Self::Async(a) => loop {
                let mut guard = match a.poll_write_ready(cx)? {
                    Poll::Ready(r) => r,
                    Poll::Pending => return Poll::Pending,
                };

                match guard.try_io(|inner| {
                    let mut fd = inner.get_ref();
                    fd.write(buf).map_err(|_| std::io::Error::last_os_error())
                }) {
                    Ok(result) => return Poll::Ready(result),
                    Err(_would_block) => continue,
                }
            },
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        warn!("shutdown on fd not implemented");
        Poll::Ready(Ok(()))
        // nix::sys::socket::shutdown(*self.f.get_ref(), nix::sys::socket::Shutdown::Write)?;
        // Poll::Ready(Ok(()))
    }
}
