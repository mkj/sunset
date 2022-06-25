#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use snafu::{prelude::*, Whatever};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, Interest};
use tokio::io::unix::AsyncFd;
use std::os::unix::io::RawFd;

use std::io::Error as IoError;

use core::pin::Pin;
use core::task::{Context, Poll};

use nix::fcntl::{fcntl, FcntlArg, OFlag};

fn dup_async(orig_fd: libc::c_int, interest: Interest) -> Result<AsyncFd<RawFd>, IoError> {
    let fd = nix::unistd::dup(orig_fd)?;
    fcntl(fd, FcntlArg::F_SETFL(OFlag::O_NONBLOCK))?;
    // TODO: is with_interest necessary?
    AsyncFd::with_interest(fd, interest)
}

pub struct InFd {
    f: AsyncFd<RawFd>,
}
pub struct OutFd {
    f: AsyncFd<RawFd>,
}
pub fn stdin() -> Result<InFd, IoError> {
    Ok(InFd {
        f: dup_async(libc::STDIN_FILENO, Interest::READABLE)?,
    })
}
pub fn stdout() -> Result<OutFd, IoError> {
    Ok(OutFd {
        f: dup_async(libc::STDOUT_FILENO, Interest::WRITABLE)?,
    })
}
pub fn stderr() -> Result<OutFd, IoError> {
    Ok(OutFd {
        f: dup_async(libc::STDERR_FILENO, Interest::WRITABLE)?,
    })
}

impl AsyncRead for InFd {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf,
    ) -> Poll<Result<(), IoError>> {
        trace!("infd rd {:?}", self.f);
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

impl AsyncWrite for OutFd {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8]
    ) -> Poll<std::io::Result<usize>> {
        trace!("outfd wr {:?}", self.f);
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
