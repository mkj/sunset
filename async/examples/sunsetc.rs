#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, anyhow, bail};
use argh::FromArgs;

use tokio::net::TcpStream;
use tokio::task::spawn_local;

use std::io::Read;

use sunset::*;
use sunset_embassy::{SSHClient, SunsetMutex};

use sunset_async::{CmdlineClient, AgentClient};

use embedded_io_adapters::tokio_1::FromTokio;

use zeroize::Zeroizing;

use simplelog::*;
use time::UtcOffset;

#[tokio::main]
async fn real_main(tz: UtcOffset) -> Result<()> {
    let args = parse_args(tz)?;

    // TODO: currently we just run it all on a single thread.
    // Running with tokio's normal multiple threads works fine
    // if we change SunsetRawMutex to a CriticalSectionMutex
    // (or something wrapping std::sync::Mutex).
    // Need to figure how to make it configurable.
    let local = tokio::task::LocalSet::new();
    local.run_until(run(args)).await
}

fn main() {
    // Crates won't let us read from environment variables once
    // threading starts, so do it before tokio main.
    let tz = UtcOffset::current_local_offset()
    .unwrap_or(UtcOffset::UTC);

    if let Err(e) = real_main(tz) {
        error!("Exit with error: {e}");
    }
}

async fn run(args: Args) -> Result<()> {

    trace!("tracing sunsetc. args {:?}", args);
    debug!("verbose sunsetc");

    if !args.cmd.is_empty() && args.subsystem.is_some() {
        bail!("can't have '-s subsystem' with a command")
    }

    let mut want_pty = true;
    let cmd = if args.cmd.is_empty() {
        None
    } else {
        want_pty = false;
        Some(args.cmd.join(" "))
    };

    if args.subsystem.is_some() {
        want_pty = false;
    }

    if args.force_no_pty {
        want_pty = false
    }

    let ssh_task = spawn_local(async move {
        let mut rxbuf = Zeroizing::new(vec![0; 3000]);
        let mut txbuf = Zeroizing::new(vec![0; 3000]);
        let ssh = SSHClient::new(&mut rxbuf, &mut txbuf)?;

        let mut app = CmdlineClient::new(
            args.username.as_ref().unwrap(),
            &args.host,
        );

        app.port(args.port);

        if want_pty {
            app.pty();
        }
        if let Some(c) = cmd {
            app.exec(&c);
        }
        if let Some(c) = args.subsystem {
            app.subsystem(&c);
        }
        for i in &args.identityfile {
            app.add_authkey(read_key(&i).with_context(|| format!("loading key {i}"))?);
        }

        let agent = load_agent_keys(&mut app).await;
        if let Some(agent) = agent {
            app.agent(agent);
        }

        // Connect to a peer
        let mut stream = TcpStream::connect((args.host.as_str(), args.port)).await?;
        let (rsock, wsock) = stream.split();
        let mut rsock = FromTokio::new(rsock);
        let mut wsock = FromTokio::new(wsock);

        // SSH connection future
        let ssh_fut = async {
            let r = ssh.run(&mut rsock, &mut wsock).await;
            trace!("ssh run finished {r:?}");
            // TODO split
            // hooks.lock().await.exited().await;
            r
        };

        // Client session future
        let session = async {
            let r = app.run(&ssh).await;
            trace!("client session run finished {r:?}");
            r
        };

        let (res_ssh, res_session) = futures::future::join(ssh_fut, session).await;
        debug!("res_ssh {res_ssh:?}");
        debug!("res_session {res_session:?}");
        res_ssh?;
        res_session?;
        Ok::<_, anyhow::Error>(())
    });

    ssh_task.await.context("Sunset task panicked")?
}

#[derive(argh::FromArgs, Debug)]
/** Sunset SSH Client
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

    #[argh(option, short='s')]
    /// ssh subsystem (eg "sftp")
    subsystem: Option<String>,

    #[argh(positional, greedy)]
    /// command
    cmd: Vec<String>,

    // options for compatibility with sshfs, are ignored

    #[allow(unused)]
    #[argh(switch, short='x', hidden_help)]
    /// no X11
    no_x11: bool,

    #[allow(unused)]
    #[argh(switch, short='a', hidden_help)]
    /// no agent forwarding
    no_agent: bool,

    #[allow(unused)]
    #[argh(switch, short='2', hidden_help)]
    /// ssh version 2
    version_2: bool,

    // openssh support -oThereWasNoSpace, so we preprocess that.
    #[argh(option, short='o')]
    /// extra options
    option: Vec<String>,
}

fn parse_args(tz: UtcOffset) -> Result<Args> {
    let mut in_args = std::env::args();

    // OpenSSH has some quirks such as -oCommand, so we pre-process the commandline.
    let cmd = in_args.next().expect("command name");
    let mut mangled_args = vec![];

    for a in in_args {
        if a.starts_with("-o") {
            let (o, v) = a.split_at(2);
            mangled_args.push(o.to_string());
            mangled_args.push(v.to_string());
        } else {
            mangled_args.push(a.to_string())
        }
    }

    let mangled_args: Vec<&str> = mangled_args.iter().map(|i| i.as_str()).collect();

    let mut args = Args::from_args(&[cmd.as_str()], mangled_args.as_slice())
    .unwrap_or_else(|e| {
        println!("{}", e.output);
        std::process::exit(1)
    });

    setup_log(&args, tz)?;

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

    for o in args.option.iter() {
        warn!("Ignoring -o {o}")
    }

    Ok(args)
}

fn setup_log(args: &Args, tz: UtcOffset) -> Result<()> {
    let mut conf = simplelog::ConfigBuilder::new();
    let conf = conf
    .add_filter_allow_str("sunset")
    .add_filter_allow_str("sshclient")
    // not debugging these bits of the stack at present
    // .add_filter_ignore_str("sunset::traffic")
    .add_filter_ignore_str("sunset::runner")
    // .add_filter_ignore_str("sunset_embassy")
    .set_time_offset(tz)
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

