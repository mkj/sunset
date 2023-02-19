#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, Error, bail, anyhow};
use embassy_sync::{mutex::Mutex, blocking_mutex::raw::NoopRawMutex};
use pretty_hex::PrettyHex;

use tokio::net::TcpStream;
use tokio::task::spawn_local;

use std::{net::Ipv6Addr, io::Read};

use sunset::*;
use sunset_async::{raw_pty};
use sunset_embassy::SSHClient;

use embedded_io::adapters::FromTokio;

use zeroize::Zeroizing;

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
            // TODO: currently we just run it all on a single thread.
            // once SunsetRawWaker is configurable we could run threaded,
            // but would also need to have `Send` methods in `Behaviour`
            // which currently isn't supported by async functions in traits.
            let local = tokio::task::LocalSet::new();
            local.run_until(run(args)).await
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

async fn run(args: Args) -> Result<()> {

    trace!("tracing main");

    let (cmd, wantpty) = if args.cmd.is_empty() {
        (None, true)
    } else {
        (Some(args.cmd.join(" ")), false)
    };

    warn!("TODO: pty support");
    let wantpty = false;

    // Connect to a peer
    let mut stream = TcpStream::connect((args.host.as_str(), args.port)).await?;


    let ssh_task = spawn_local(async move {
        let mut rxbuf = Zeroizing::new(vec![0; 3000]);
        let mut txbuf = Zeroizing::new(vec![0; 3000]);

        let mut app = sunset_async::CmdlineClient::new(
            args.username.as_ref().unwrap(),
            cmd,
            wantpty,
            );
        let cli = SSHClient::new(&mut rxbuf, &mut txbuf)?;
        for i in &args.identityfile {
            app.add_authkey(read_key(&i).with_context(|| format!("loading key {i}"))?);
        }
        let (hooks, mut cmd) = app.split();

        let hooks = Mutex::<NoopRawMutex, _>::new(hooks);
        let hooks = &hooks as &Mutex::<NoopRawMutex, dyn CliBehaviour>;

        let (rsock, wsock) = stream.split();
        let mut rsock = FromTokio::new(rsock);
        let mut wsock = FromTokio::new(wsock);

        let ssh = cli.run(&mut rsock, &mut wsock, hooks);
        // Circular reference here, cli -> cmd and cmd->cli
        let sess = cmd.run(&cli);
        futures::future::join(ssh, sess).await;
        Ok::<_, anyhow::Error>(())
    });

    match ssh_task.await {
        Err(_) => Err(anyhow!("Sunset task panicked")),
        Ok(r) => r.context("Exited"),
    }
}
