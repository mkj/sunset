#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, Error};
use pretty_hex::PrettyHex;

use pin_utils::*;

use smol::{net, prelude::*};
use smol::{future, io, Async, Unblock};

use std::net::TcpStream;

use door_sshproto::*;

use simplelog::*;

fn main() -> Result<()> {
    smol::block_on(async {
        run().await
    })
}

async fn run() -> Result<()> {

    let conf = simplelog::ConfigBuilder::new()
    .add_filter_allow_str("door")
    .build();

    CombinedLogger::init(
    vec![
        TermLogger::new(LevelFilter::Trace, conf, TerminalMode::Mixed, ColorChoice::Auto),
    ]
    ).unwrap();

    info!("running main");
    trace!("tracing main");

    // Connect to a peer
    let stream = Async::<TcpStream>::connect(([127, 0, 0, 1], 2244)).await?;
    // let mut stream = net::TcpStream::connect("::1:2244").await?;
    // let mut stream = TcpStream::connect("130.95.13.18:22").await?;

    let mut work = vec![0; 3000];
    let mut sess = door_smol::DoorSession {};
    let cli= Client::new(&mut sess)?;
    let conn = Conn::new_client(cli)?;
    let runner = Runner::new(conn, work.as_mut_slice())?;

    let door = async_dup::Mutex::new(door_smol::AsyncDoor { runner });

    future::try_zip(
        io::copy(&door, &stream),
        io::copy(&stream, &door),
    )
    .await?;


    Ok(())
}
