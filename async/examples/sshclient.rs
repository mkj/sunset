#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, anyhow};
use embassy_sync::{mutex::Mutex, blocking_mutex::raw::NoopRawMutex};

use tokio::net::TcpStream;
use tokio::task::spawn_local;

use std::io::Read;

use sunset::*;
use sunset_embassy::SSHClient;

use sunset_async::{CmdlineClient, AgentClient};

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

    #[argh(switch, short='T')]
    /// force no pty
    force_no_pty: bool,

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
        args.username = Some(whoami::username());
    }

    Ok(args)
}

fn try_main() -> Result<()> {
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
}

fn main() {
    if let Err(e) = try_main() {
        error!("Exit with error: {e}");
    }
}

fn setup_log(args: &Args) -> Result<()> {
    let mut conf = simplelog::ConfigBuilder::new();
    let conf = conf
    .add_filter_allow_str("sunset")
    .add_filter_allow_str("sshclient")
    // not debugging these bits of the stack at present
    // .add_filter_ignore_str("sunset::traffic")
    .add_filter_ignore_str("sunset::runner")
    .add_filter_ignore_str("sunset_embassy")
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
        TermLogger::new(level, conf.clone(), TerminalMode::Stderr, ColorChoice::Auto),
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

async fn load_agent_keys(app: &mut CmdlineClient) -> Option<AgentClient> {
    let e = match std::env::var("SSH_AUTH_SOCK") {
        Ok(e) => e,
        _ => return None
    };
    let mut agent = match AgentClient::new(e).await {
        Ok(a) => a,
        Err(e) => {
            warn!("Error opening agent: {e}");
            return None
        }
    };

    let keys = match agent.keys().await {
        Ok(k) => k,
        Err(e) => {
            warn!("Error fetching agent keys: {e}");
            return None
        }
    };
    trace!("Loaded {} agent keys", keys.len());
    for k in keys {
        app.add_authkey(k)
    }
    Some(agent)
}

async fn run(args: Args) -> Result<()> {

    trace!("tracing main");
    debug!("verbose main");

    let (cmd, wantpty) = if args.cmd.is_empty() {
        (None, true)
    } else {
        (Some(args.cmd.join(" ")), false)
    };

    let wantpty = wantpty && !args.force_no_pty;

    let ssh_task = spawn_local(async move {
        let mut rxbuf = Zeroizing::new(vec![0; 3000]);
        let mut txbuf = Zeroizing::new(vec![0; 3000]);
        let cli = SSHClient::new(&mut rxbuf, &mut txbuf)?;

        let mut app = CmdlineClient::new(
            args.username.as_ref().unwrap(),
            &args.host,
            args.port,
            cmd,
            wantpty,
            );
        for i in &args.identityfile {
            app.add_authkey(read_key(&i).with_context(|| format!("loading key {i}"))?);
        }

        let agent = load_agent_keys(&mut app).await;
        if let Some(agent) = agent {
            app.set_agent(agent)
        }

        // Connect to a peer
        let mut stream = TcpStream::connect((args.host.as_str(), args.port)).await?;
        let (rsock, wsock) = stream.split();
        let mut rsock = FromTokio::new(rsock);
        let mut wsock = FromTokio::new(wsock);

        let (hooks, mut cmd) = app.split();

        let hooks = Mutex::<NoopRawMutex, _>::new(hooks);
        // let bhooks = &hooks as &Mutex::<NoopRawMutex, CliBehaviour>;

        let ssh = async {
            let r = cli.run(&mut rsock, &mut wsock, &hooks).await;
            trace!("ssh run finished");
            hooks.lock().await.exited().await;
            r
        };

        // Circular reference here, cli -> cmd and cmd->cli
        let session = cmd.run(&cli);
        let session = async {
            let r = session.await;
            trace!("client session run finished");
            cli.exit().await;
            r
        };

        let (res_ssh, res_session) = futures::future::join(ssh, session).await;
        debug!("res_ssh {res_ssh:?}");
        debug!("res_session {res_session:?}");
        res_ssh?;
        res_session?;
        Ok::<_, anyhow::Error>(())
    });

    match ssh_task.await {
        Err(_) => Err(anyhow!("Sunset task panicked")),
        Ok(r) => r,
    }
}
