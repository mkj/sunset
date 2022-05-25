#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, Error};
use pretty_hex::PrettyHex;

use pin_utils::*;
use tokio::net::TcpStream;

use std::{net::Ipv6Addr, io::Read};

use door_sshproto::*;

use simplelog::*;

fn main() -> Result<()> {
    // time crate won't read TZ if we're threaded, in case someone
    // tries to mutate shared state with setenv.
    // https://github.com/rust-lang/rust/issues/90308 etc
    // So we can't use async main.
    setup_log();

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            run().await
        })
}

// async fn handle_request(door: &door_smol::AsyncDoor<'_>, query: HookQuery) {
//     match query {
//         HookQuery::Username(_) => {
//             let mut s = ResponseString::new();
//             s.push_str("matt").unwrap();
//             door.reply_request(Ok(HookQuery::Username(s))).unwrap();
//         }
//     }
// }

fn setup_log() {
    let mut conf = simplelog::ConfigBuilder::new();
    let conf = conf
    .add_filter_allow_str("door")
    .add_filter_allow_str("con1")
    .set_time_offset_to_local().expect("Couldn't get local timezone")
    .build();

    CombinedLogger::init(
    vec![
        TermLogger::new(LevelFilter::Trace, conf, TerminalMode::Mixed, ColorChoice::Auto),
    ]
    ).unwrap();
}

fn read_key(p: &str) -> Result<SignKey> {
    let mut f = std::fs::File::open("id_authkey")?;
    let mut v = vec![];
    f.read_to_end(&mut v)?;
    trace!("v {:?}", v.hex_dump());
    SignKey::from_openssh(v).context("reading openssh key")
}

async fn run() -> Result<()> {

    info!("running main");
    trace!("tracing main");

    // Connect to a peer
    let addr: Ipv6Addr = "::1".parse()?;
    let mut stream = TcpStream::connect((addr, 2244)).await?;
    // let mut stream = net::TcpStream::connect("::1:2244").await?;
    // let mut stream = TcpStream::connect("130.95.13.18:22").await?;

    let mut work = vec![0; 3000];
    let mut sess = door_smol::SimpleClient::new();
    sess.add_authkey(read_key("id_authkey")?);
    let conn = Conn::new_client()?;
    let runner = Runner::new(conn, work.as_mut_slice()).await?;

    let b = Behaviour::new_async_client(Box::new(sess));
    // let b = Behaviour::new_blocking_client(&mut sess);
    let mut door = door_smol::AsyncDoor::new(runner, b);

    // let door = async_dup::Mutex::new(door_smol::AsyncDoor { runner });

    let mut d = door.clone();
    let netio = tokio::io::copy_bidirectional(&mut stream, &mut d);
    pin_mut!(netio);
    // let mut f = future::try_zip(netwrite, netread).fuse();
    // f.await;

    loop {
        tokio::select! {
            _ = &mut netio => break,
            // q = door.next_request() => {
            //     handle_request(&door, q).await
            // }
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
