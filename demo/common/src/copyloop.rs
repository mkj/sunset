//! Helpers for copying

#[allow(unused_imports)]
pub use log::{debug, error, info, log, trace, warn};

use embedded_io_async::{BufRead, Read, Write};

use sunset::{Error, Result};

pub async fn io_copy<const B: usize, R, W>(r: &mut R, w: &mut W) -> Result<()>
where
    R: Read<Error = sunset::Error>,
    W: Write<Error = sunset::Error>,
{
    let mut b = [0u8; B];
    loop {
        let n = r.read(&mut b).await?;
        if n == 0 {
            return sunset::error::ChannelEOF.fail();
        }
        let b = &b[..n];
        w.write_all(b).await?
    }
    #[allow(unreachable_code)]
    Ok::<_, Error>(())
}

pub async fn io_copy_nowriteerror<const B: usize, R, W>(
    r: &mut R,
    w: &mut W,
) -> Result<()>
where
    R: Read<Error = sunset::Error>,
    W: Write,
{
    let mut b = [0u8; B];
    loop {
        let n = r.read(&mut b).await?;
        if n == 0 {
            return sunset::error::ChannelEOF.fail();
        }
        let b = &b[..n];
        if let Err(e) = w.write_all(b).await {
            info!("write error {e:?}");
        }
    }
    #[allow(unreachable_code)]
    Ok::<_, Error>(())
}

pub async fn io_buf_copy<R, W>(r: &mut R, w: &mut W) -> Result<()>
where
    R: BufRead<Error = sunset::Error>,
    W: Write<Error = sunset::Error>,
{
    loop {
        let b = r.fill_buf().await?;
        if b.is_empty() {
            return sunset::error::ChannelEOF.fail();
        }
        let n = b.len();
        w.write_all(b).await?;
        r.consume(n)
    }
    #[allow(unreachable_code)]
    Ok::<_, Error>(())
}

pub async fn io_buf_copy_noreaderror<R, W>(r: &mut R, w: &mut W) -> Result<()>
where
    R: BufRead,
    W: Write<Error = sunset::Error>,
{
    loop {
        let b = match r.fill_buf().await {
            Ok(b) => b,
            Err(_) => {
                info!("read error");
                embassy_futures::yield_now().await;
                continue;
            }
        };
        if b.is_empty() {
            return sunset::error::ChannelEOF.fail();
        }
        let n = b.len();
        w.write_all(b).await?;
        r.consume(n)
    }
    #[allow(unreachable_code)]
    Ok::<_, Error>(())
}
