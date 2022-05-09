use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use core::pin::Pin;
use core::task::{Context,Poll};

// TODO
// use anyhow::{Context as _, Result, Error};

pub struct AsyncDoor<'a> {
    pub runner: door_sshproto::Runner<'a>,
}

impl<'a> AsyncRead for AsyncDoor<'a> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>,
        buf: &mut ReadBuf) -> Poll<Result<(), std::io::Error>>
    {
        if self.runner.output_pending() {
            let r = self.runner.output(buf.initialize_unfilled())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
            if let Ok(l) = r {
                buf.advance(l)
            }
            Poll::Ready(r.map(|_| ()))
        } else {
            self.runner.set_output_waker(cx.waker().clone());
            Poll::Pending
        }
    }
}

impl<'a> AsyncWrite for AsyncDoor<'a> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>,
        buf: &[u8]) -> Poll<Result<usize, std::io::Error>>
    {
        if self.runner.ready_input() {
            let r = self.runner.input(buf)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e));
            Poll::Ready(r)
        } else {
            self.runner.set_input_waker(cx.waker().clone());
            Poll::Pending
        }

    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>)
    -> Poll<Result<(), std::io::Error>>
    {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>)
    -> Poll<Result<(), std::io::Error>>
    {
        todo!("poll_close")
    }

}



#[cfg(test)]
mod tests {
}
