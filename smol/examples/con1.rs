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

#[derive(argh::FromArgs)]
/** con1
 */
struct Args {
    #[argh(switch, short='v')]
    /// verbose debug logging
    debug: bool,

    #[argh(switch)]
    /// more verbose
    trace: bool,

    #[argh(option, short='i')]
    /// a path to id_ed25519 or similar
    identityfile: Vec<String>,

    #[argh(option, short='l')]
    /// username
    username: Option<String>,

    #[argh(positional)]
    /// host
    host: String,

    #[argh(option, short='p', default="22")]
    /// port
    port: u16,

    #[argh(positional)]
    /// command
    cmd: Vec<String>,
}

fn parse_args() -> Result<Args> {
    let mut args: Args = argh::from_env();

    if args.username.is_none() {
        // user@host syntax. rsplit for usernames with @ in them
        if let Some((user, host)) = args.host.rsplit_once('@') {
            args.username = Some(user.into());
            args.host = host.into();
        }
    }
    if args.username.is_none() {
        // TODO current user
        args.username = Some("matt".into());
    }
    Ok(args)
}

fn main() -> Result<()> {
    let args = parse_args()?;

    // time crate won't read TZ if we're threaded, in case someone
    // tries to mutate shared state with setenv.
    // https://github.com/rust-lang/rust/issues/90308 etc
    // logging uses the timezone, so we can't use async main.
    setup_log(&args);

    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            run(&args).await
        })
        .map_err(|e| {
            error!("Exit with error: {e:?}");
            e
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

fn setup_log(args: &Args) {
    let mut conf = simplelog::ConfigBuilder::new();
    let conf = conf
    .add_filter_allow_str("door")
    .add_filter_allow_str("con1")
    // not debugging these bits of the stack at present
    // .add_filter_ignore_str("door_sshproto::traffic")
    // .add_filter_ignore_str("door_sshproto::runner")
    .add_filter_ignore_str("door_smol::async_door")
    .set_time_offset_to_local().expect("Couldn't get local timezone")
    .build();

    let level = if args.trace {
        LevelFilter::Trace
    } else if args.debug {
        LevelFilter::Debug
    } else {
        LevelFilter::Warn
    };

    CombinedLogger::init(
    vec![
        TermLogger::new(level, conf, TerminalMode::Mixed, ColorChoice::Auto),
    ]
    ).unwrap();
}

fn read_key(p: &str) -> Result<SignKey> {
    let mut v = vec![];
    std::fs::File::open(p)?.read_to_end(&mut v)?;
    SignKey::from_openssh(v).context("parsing openssh key")
}

async fn run(args: &Args) -> Result<()> {

    info!("running main");
    trace!("tracing main");

    // Connect to a peer
    let mut stream = TcpStream::connect((args.host.as_str(), args.port)).await?;
    // let mut stream = net::TcpStream::connect("::1:2244").await?;
    // let mut stream = TcpStream::connect("130.95.13.18:22").await?;

    let mut work = vec![0; 3000];
    let mut sess = door_smol::SimpleClient::new(args.username.as_ref().unwrap());
    for i in &args.identityfile {
        sess.add_authkey(read_key(&i)
            .with_context(|| format!("loading key {i}"))?);
    }
    let conn = Conn::new_client()?;
    let runner = Runner::new(conn, work.as_mut_slice())?;

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
            e = &mut netio => break e.map(|_| ()).context("net loop"),
            ev = door.progress(|ev| {
                trace!("progress event {ev:?}");
                Ok(())
            }) => {}
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
}
