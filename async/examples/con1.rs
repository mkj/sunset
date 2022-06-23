#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, Error, bail};
use pretty_hex::PrettyHex;

use tokio::net::TcpStream;

use std::{net::Ipv6Addr, io::Read};

use door_sshproto::*;
use door_async::SSHClient;

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

    tokio::runtime::Builder::new_current_thread()
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

fn setup_log(args: &Args) {
    let mut conf = simplelog::ConfigBuilder::new();
    let conf = conf
    .add_filter_allow_str("door")
    .add_filter_allow_str("con1")
    // not debugging these bits of the stack at present
    // .add_filter_ignore_str("door_sshproto::traffic")
    // .add_filter_ignore_str("door_sshproto::runner")
    // .add_filter_ignore_str("door_async::async_door")
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

    let work = vec![0; 3000];
    // TODO: better lifetime rather than leaking
    let work = Box::leak(Box::new(work));

    let mut sess = door_async::CmdlineClient::new(args.username.as_ref().unwrap());
    for i in &args.identityfile {
        sess.add_authkey(read_key(&i).with_context(|| format!("loading key {i}"))?);
    }

    let mut door = SSHClient::new(work.as_mut_slice(), Box::new(sess))?;

    let mut s = door.socket();
    let netloop = tokio::io::copy_bidirectional(&mut stream, &mut s);

    moro::async_scope!(|scope| {
        scope.spawn(netloop);

        scope.spawn(async {
            loop {
                let ev = door.progress(|ev| {
                    trace!("progress event {ev:?}");
                    let e = match ev {
                        Event::Authenticated => Some(Event::Authenticated),
                        _ => None,
                    };
                    Ok(e)
                }).await.context("progress loop")?;

                match ev {
                    Some(Event::Authenticated) => {
                        info!("Opening a new session channel");
                        let r = door.open_client_session_nopty(Some("cowsay it works")).await
                            .context("Opening session")?;
                        let (mut io, mut err) = r;
                        scope.spawn(async move {
                            let mut i = door_async::stdin()?;
                            let mut o = door_async::stdout()?;
                            let mut e = door_async::stderr()?;
                            let mut io2 = io.clone();
                            let co = tokio::io::copy(&mut io, &mut o);
                            let ci = tokio::io::copy(&mut i, &mut io2);
                            let ce = tokio::io::copy(&mut err, &mut e);
                            let (r1, r2, r3) = futures::join!(co, ci, ce);
                            r1?;
                            r2?;
                            r3?;
                            Ok::<_, anyhow::Error>(())
                        });
                        // TODO: handle channel completion
                    }
                    Some(_) => unreachable!(),
                    None => {},
                }
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())

        });
    }).await;

    Ok(())
}
