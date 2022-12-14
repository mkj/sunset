#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, Error, bail};
use pretty_hex::PrettyHex;

use tokio::net::TcpStream;

use std::{net::Ipv6Addr, io::Read};

use sunset::*;
use sunset_async::{SSHClient, raw_pty};

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
    setup_log(&args)?;

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
    .add_filter_allow_str("sunset")
    .add_filter_allow_str("con1")
    // not debugging these bits of the stack at present
    // .add_filter_ignore_str("sunset::traffic")
    // .add_filter_ignore_str("sunset::runner")
    // .add_filter_ignore_str("sunset_async::async_sunset")
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

    let (cmd, wantpty) = if args.cmd.is_empty() {
        (None, true)
    } else {
        (Some(args.cmd.join(" ")), false)
    };

    // Connect to a peer
    let mut stream = TcpStream::connect((args.host.as_str(), args.port)).await?;

    let mut rxbuf = vec![0; 3000];
    let mut txbuf = vec![0; 3000];
    let mut cli = SSHClient::new(&mut rxbuf, &mut txbuf)?;

    // app is a Behaviour
    let mut app = sunset_async::CmdlineClient::new(
        args.username.as_ref().unwrap(),
        cmd,
        wantpty,
        );
    for i in &args.identityfile {
        app.add_authkey(read_key(&i).with_context(|| format!("loading key {i}"))?);
    }

    let mut s = cli.socket();


    moro::async_scope!(|scope| {
        scope.spawn(tokio::io::copy_bidirectional(&mut stream, &mut s));

        scope.spawn(async {
            loop {
                cli.progress(&mut app).await.context("progress loop")?;

                app.progress(&mut cli).await?;

                // match ev {
                //     Some(Event::CliAuthed) => {
                //         let mut raw_pty_guard = None;
                //         info!("Opening a new session channel");
                //         let (mut io, mut errpair) = if wantpty {
                //             raw_pty_guard = Some(raw_pty()?);
                //             let io = cli.open_session_pty(cmd.as_deref()).await
                //                 .context("Opening session")?;
                //             (io, None)
                //         } else {
                //             let (io, err) = cli.open_session_nopty(cmd.as_deref()).await
                //                 .context("Opening session")?;
                //             let errpair = (err, sunset_async::stderr()?);
                //             (io, Some(errpair))
                //         };

                //         let mut i = sunset_async::stdin()?;
                //         let mut o = sunset_async::stdout()?;
                //         let mut io2 = io.clone();
                //         scope.spawn(async move {
                //             moro::async_scope!(|scope| {
                //                 scope.spawn(tokio::io::copy(&mut io, &mut o));
                //                 scope.spawn(tokio::io::copy(&mut i, &mut io2));
                //                 if let Some(ref mut ep) = errpair {
                //                     let (err, e) = ep;
                //                     scope.spawn(tokio::io::copy(err, e));
                //                 }
                //             }).await;
                //             drop(raw_pty_guard);
                //             Ok::<_, anyhow::Error>(())
                //         });
                //         // TODO: handle channel completion or open failure
                //     }
                //     Some(_) => unreachable!(),
                //     None => {},
                // }
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())

        });
    }).await;

    Ok(())
}
