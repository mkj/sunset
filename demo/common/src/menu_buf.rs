#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

/// A wrapper writing `Menu` output into a buffer that can be later written
/// asynchronously to a channel.
#[derive(Default)]
pub struct AsyncMenuBuf {
    /// Sufficient to hold output produced from a single keystroke input. Further output will be discarded
    // pub s: String<300>,
    // todo size
    pub s: heapless::String<500>,
}

impl AsyncMenuBuf {
    pub async fn flush<W>(&mut self, w: &mut W) -> sunset::Result<()>
    where
        W: embedded_io_async::Write<Error = sunset::Error>,
    {
        let mut b = self.s.as_str().as_bytes();
        while !b.is_empty() {
            let l = w.write(b).await?;
            b = &b[l..];
        }
        self.s.clear();
        Ok(())
    }
}

impl core::fmt::Write for AsyncMenuBuf {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        let mut inner = || {
            for c in s.chars() {
                if c == '\n' {
                    self.s.push('\r').map_err(|_| core::fmt::Error)?;
                }
                self.s.push(c).map_err(|_| core::fmt::Error)?;
            }
            Ok::<_, core::fmt::Error>(())
        };

        if inner().is_err() {
            trace!("Buffer full in AsyncMenuBuf");
        }

        Ok(())
    }
}
