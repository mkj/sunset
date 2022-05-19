#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, Error};
use pretty_hex::PrettyHex;

use pin_utils::*;
use tokio::net::TcpStream;

use std::net::Ipv6Addr;

use door_sshproto::*;

use simplelog::*;

#[tokio::main]
async fn main() -> Result<()> {
    run().await
}

async fn handle_request(door: &door_smol::AsyncDoor<'_>, query: HookQuery) {
    match query {
        HookQuery::Username(_) => {
            let mut s = ResponseString::new();
            s.push_str("matt").unwrap();
            door.reply_request(Ok(HookQuery::Username(s))).unwrap();
        }
    }
}

async fn run() -> Result<()> {

    let conf = simplelog::ConfigBuilder::new()
    .add_filter_allow_str("door")
    .add_filter_allow_str("con1")
    .build();

    CombinedLogger::init(
    vec![
        TermLogger::new(LevelFilter::Trace, conf, TerminalMode::Mixed, ColorChoice::Auto),
    ]
    ).unwrap();

    info!("running main");
    trace!("tracing main");

    // Connect to a peer
    let addr: Ipv6Addr = "::1".parse()?;
    let mut stream = TcpStream::connect((addr, 2244)).await?;
    // let mut stream = net::TcpStream::connect("::1:2244").await?;
    // let mut stream = TcpStream::connect("130.95.13.18:22").await?;

    let mut work = vec![0; 3000];
    let mut sess = door_smol::DoorSession {};
    let cli = Client::new(&mut sess)?;
    let conn = Conn::new_client(cli)?;
    let runner = Runner::new(conn, work.as_mut_slice()).await?;

    let mut door = door_smol::AsyncDoor::new(runner);

    // let door = async_dup::Mutex::new(door_smol::AsyncDoor { runner });

    let mut d = door.clone();
    let netio = tokio::io::copy_bidirectional(&mut stream, &mut d);
    pin_mut!(netio);
    // let mut f = future::try_zip(netwrite, netread).fuse();
    // f.await;

    loop {
        tokio::select! {
            _ = &mut netio => break,
            q = door.next_request() => {
                handle_request(&door, q).await
            }
        }
    }

    // trace!("before loop");
    // loop {
    //     trace!("top loop");
    //     future::race(
    //         netwrite.race(netread).map(|_| ()),
    //         stream::repeat(())
    //             .then(|_| door.next_request())
    //             .then(|q| async {
    //                 handle_request(&door, q).await;
    //                 ()
    //             })
    //     ).await;

    //     // let r = futures::select! {
    //     //     q = door.next_request().fuse() => {
    //     //         handle_request(&door, q).await
    //     //     }
    //     //     _ = netwrite => break,
    //     //     _ = netread => break,
    //     // };
    //     // trace!("result {r:?}");
    // }


    Ok(())
}
