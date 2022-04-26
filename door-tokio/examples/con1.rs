#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::Context;
use std::error::Error;
use pretty_hex::PrettyHex;
use tokio::{io::AsyncWriteExt,io};
use tokio::net::TcpStream;

use door_sshproto::*;

use simplelog::*;

#[tokio::main]
async fn main() {

    let r = run().await;
    if let Err(e) = r {
        error!("Finished with error: {:?}", e);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {

    CombinedLogger::init(
    vec![
        TermLogger::new(LevelFilter::Trace, Config::default(), TerminalMode::Mixed, ColorChoice::Auto),
    ]
    ).unwrap();

    info!("running main");
    trace!("tracing main");

    // Connect to a peer
    let mut stream = TcpStream::connect("dropbear.nl:22").await?;

    let mut work = vec![0; 1000];
    let c = conn::Conn::new()?;
    let mut r = conn::Runner::new(c, work.as_mut_slice())?;

    let mut inbuf = vec![0; 1000];
    let mut inpos = 0;
    let mut inlen = 0;
    let mut outbuf = vec![0; 1000];

    loop {
        while r.output_pending() {
            let b = outbuf.as_mut_slice();
            let l = r.output(b)?;
            let b = &b[..l];
            stream.write_all(b).await.context("write_all")?;
        }

        if r.ready_input() {
            trace!("ready in");
            stream.readable().await.context("readable")?;
            if inlen == inpos {
                inlen = match stream.try_read(&mut inbuf) {
                    Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                        trace!("wouldblock");
                        Ok(0)
                    },
                    Ok(n) => {
                        if n == 0 {
                            Err(io::Error::from(io::ErrorKind::UnexpectedEof))
                        } else {
                            Ok(n)
                        }
                    }

                    other_error => other_error,
                }.context("read")?;
                trace!("read new {inlen}");
                inpos = 0;
            }

            trace!("nputting {inlen}..{inpos}");
            let l = r.input(&inbuf[inpos..inlen])?;
            inpos += l;
        }
    }


    // let mut d = ident::RemoteVersion::new();
    // let (taken, done) = d.consume(&buf)?;
    // println!("taken {taken} done {done}");
    // let v = d.version();
    // match v {
    //     Some(x) => {
    //         println!("v {:?}", x.hex_dump());
    //     }
    //     None => {
    //         println!("None");
    //     }
    // }
    // let (_, rest) = buf.split_at(taken + 5);
    // println!("reset {:?}", rest.hex_dump());

    // let ctx = packets::ParseContext::new();
    // let p = wireformat::packet_from_bytes(rest, &ctx)?;
    // println!("{p:#?}");

    Ok(())
}
