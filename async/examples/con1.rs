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
use door_async::{SSHClient, raw_pty};

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

    #[argh(option)]
    /// log to a file
    tracefile: Option<String>,

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

fn setup_log(args: &Args) -> Result<()> {
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

    let mut logs: Vec<Box<dyn SharedLogger>> = vec![
        TermLogger::new(level, conf.clone(), TerminalMode::Mixed, ColorChoice::Auto),
    ];

    if let Some(tf) = args.tracefile.as_ref() {
        let w = std::fs::File::create(tf).with_context(|| format!("Error opening {tf}"))?;
        logs.push(WriteLogger::new(LevelFilter::Trace, conf, w));
    }

    CombinedLogger::init(logs).unwrap();
    Ok(())
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

    let mut cli = door_async::CmdlineClient::new(args.username.as_ref().unwrap());
    for i in &args.identityfile {
        cli.add_authkey(read_key(&i).with_context(|| format!("loading key {i}"))?);
    }

    let mut door = SSHClient::new(work.as_mut_slice(), Box::new(cli))?;
    let mut s = door.socket();

    moro::async_scope!(|scope| {
        scope.spawn(tokio::io::copy_bidirectional(&mut stream, &mut s));

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
                        let mut raw_pty_guard = None;
                        info!("Opening a new session channel");
                        let (cmd, pty) = if args.cmd.is_empty() {
                            (None, true)
                        } else {
                            (Some(args.cmd.join(" ")), false)
                        };
                        let (mut io, mut err) = if pty {
                            raw_pty_guard = Some(raw_pty()?);
                            let io = door.open_client_session_pty(cmd.as_deref()).await
                                .context("Opening session")?;
                            (io, None)
                        } else {
                            let (io, err) = door.open_client_session_nopty(cmd.as_deref()).await
                                .context("Opening session")?;
                            (io, Some(err))
                        };
                        let mut i = door_async::stdin()?;
                        let mut o = door_async::stdout()?;
                        let mut e = if err.is_some() {
                            Some(door_async::stderr()?)
                        } else {
                            None
                        };
                        let mut io2 = io.clone();
                        scope.spawn(async move {
                            moro::async_scope!(|scope| {
                                scope.spawn(tokio::io::copy(&mut io, &mut o));
                                scope.spawn(tokio::io::copy(&mut i, &mut io2));
                                if let Some(ref mut err) = err {
                                    scope.spawn(tokio::io::copy(err, e.as_mut().unwrap()));
                                }
                            }).await;
                            drop(raw_pty_guard);
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
