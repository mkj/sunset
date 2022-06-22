#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use snafu::{prelude::*, Whatever};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::io::unix::AsyncFd;
use std::os::unix::io::RawFd;

use std::io::Error as IoError;

use core::pin::Pin;
use core::task::{Context, Poll};

use nix::fcntl::{fcntl, FcntlArg, OFlag};

fn dup_async(orig_fd: libc::c_int) -> Result<AsyncFd<RawFd>, IoError> {
    let fd = nix::unistd::dup(orig_fd)?;
    fcntl(fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    AsyncFd::new(fd)
}

pub struct Stdin {
    f: AsyncFd<RawFd>,
}
pub struct Stdout {
    f: AsyncFd<RawFd>,
}
pub struct Stderr {
    f: AsyncFd<RawFd>,
}

pub fn stdin() -> Result<Stdin, IoError> {
    Ok(Stdin {
        f: dup_async(libc::STDIN_FILENO)?,
    })
}
pub fn stdout() -> Result<Stdout, IoError> {
    Ok(Stdout {
        f: dup_async(libc::STDOUT_FILENO)?,
    })
}
pub fn stderr() -> Result<Stderr, IoError> {
    Ok(Stderr {
        f: dup_async(libc::STDERR_FILENO)?,
    })
}

impl AsRef<AsyncFd<RawFd>> for Stdin {
    fn as_ref(&self) -> &AsyncFd<RawFd> {
        &self.f
    }
}

impl AsRef<AsyncFd<RawFd>> for Stdout {
    fn as_ref(&self) -> &AsyncFd<RawFd> {
        &self.f
    }
}

impl AsRef<AsyncFd<RawFd>> for Stderr {
    fn as_ref(&self) -> &AsyncFd<RawFd> {
        &self.f
    }
}

impl AsyncRead for Stdin {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        // XXX loop was copy pasted from docs, perhaps it could be simpler
        loop {
            let mut guard = match self.f.poll_read_ready(cx)? {
                Poll::Ready(r) => r,
                Poll::Pending => return Poll::Pending,
            };

            match guard.try_io(|inner| {
                let fd = *inner.get_ref();
                let b = buf.initialize_unfilled();

                let r = nix::unistd::read(fd, b);
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

impl AsyncWrite for Stdout {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<std::io::Result<usize>> {
        loop {
            let mut guard = match self.f.poll_write_ready(cx)? {
                Poll::Ready(r) => r,
                Poll::Pending => return Poll::Pending,
            };

            match guard.try_io(|inner| {
                let fd = *inner.get_ref();
                nix::unistd::write(fd, buf)
                    .map_err(|_| std::io::Error::last_os_error())
            }) {
                Ok(result) => return Poll::Ready(result),
                Err(_would_block) => continue,
            }
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
        nix::sys::socket::shutdown(*self.f.get_ref(), nix::sys::socket::Shutdown::Write)?;
        Poll::Ready(Ok(()))
    }
}
