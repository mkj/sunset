#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};

use std::{net::Ipv6Addr, io::Read};
use std::path::Path;

use anyhow::{Context, Result, Error, bail};
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, RawMutex};
use embassy_sync::mutex::Mutex;
use pretty_hex::PrettyHex;

use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt,AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::runtime::Runtime;
use tokio::task::spawn_local;

use embedded_io::adapters::FromTokio;

use sunset::*;
use sunset_embassy::SSHServer;

// struct StdRawMutex {
//     l: std::sync::Mutex<()>,
// }

// unsafe impl RawMutex for StdRawMutex {
//     const INIT: Self = Self::new();

//     fn lock<R>(&self, f: impl FnOnce() -> R) -> R {
//         let x = self.l.lock();
//         f()
//     }
// }

// impl StdRawMutex {
//     const fn new() -> Self {
//         Self {
//             l: std::sync::Mutex::new(()),
//         }
//     }
// }


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

    #[argh(option, short='p', default="2244")]
    /// port
    port: u16,

    #[argh(option)]
    /// a path to hostkeys. At most one of each key type.
    hostkey: Vec<String>,

}

fn parse_args() -> Result<Args> {
    let args: Args = argh::from_env();

    Ok(args)
}

fn main() -> Result<()> {
    let args = parse_args()?;

    setup_log(&args)?;

    if args.hostkey.is_empty() {
        error!("At least one --hostkey is required");
        return Ok(())
    }

    let rt  = Runtime::new().unwrap();
    let local = task::LocalSet::new();
    local.block_on(&rt, async {
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
    .add_filter_allow_str("serv1")
    // not debugging these bits of the stack at present
    .add_filter_ignore_str("sunset::traffic")
    .add_filter_ignore_str("sunset::runner")
    .add_filter_ignore_str("sunset_async::async_sunset")
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

    CombinedLogger::init(logs).unwrap();
    Ok(())
}

fn read_key(p: &str) -> Result<SignKey> {
    let mut v = vec![];
    std::fs::File::open(p)?.read_to_end(&mut v)?;
    SignKey::from_openssh(v).context("parsing openssh key")
}

struct DemoServer<'a> {
    keys: Vec<SignKey>,

    sess: Option<u32>,
    shell_started: bool,
    shell: &'a DemoShell,
}

impl<'a> DemoServer<'a> {
    fn new(shell: &'a DemoShell, keyfiles: &[String]) -> Result<Self> {
        let keys = keyfiles.iter().map(|f| {
            read_key(f).with_context(|| format!("loading key {f}"))
        }).collect::<Result<Vec<SignKey>>>()?;

        Ok(Self {
            sess: None,
            keys,
            shell_started: false,
            shell,
        })
    }
}

impl<'a> ServBehaviour for DemoServer<'a> {
    fn hostkeys(&mut self) -> BhResult<&[SignKey]> {
        Ok(&self.keys)
    }

    fn have_auth_password(&self, user: TextString) -> bool {
        true
    }

    fn have_auth_pubkey(&self, user: TextString) -> bool {
        true
    }

    fn auth_password(&mut self, user: TextString, password: TextString) -> bool {
        user.as_str().unwrap_or("") == "matt" && password.as_str().unwrap_or("") == "pw"
    }

    fn auth_pubkey(&mut self, user: TextString, pubkey: &PubKey) -> bool {
        if user.as_str().unwrap_or("") != "matt" {
            return false
        }

        // key is tested1
        pubkey.matches_openssh("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMkNdReJERy1rPGqdfTN73TnayPR+lTNhdZvOgkAOs5x")
        .unwrap_or_else(|e| {
            warn!("Failed loading openssh key: {e}");
            false
        })
    }

    fn open_session(&mut self, chan: ChanNum) -> ChanOpened {
        if self.sess.is_some() {
            ChanOpened::Failure(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
        } else {
            self.sess = Some(chan);
            ChanOpened::Success
        }
    }

    fn sess_shell(&mut self, chan: ChanNum) -> bool {
        let r = !self.shell_started && self.sess == Some(chan);
        self.shell_started = true;
        self.shell_notify.take().send(chan);
        trace!("req want shell");
        r
    }

    fn sess_pty(&mut self, chan: ChanNum, _pty: &Pty) -> bool {
        self.sess == Some(chan)
    }
}

struct DemoShell {
    notify: mpsc::Receiver<u32>,
}

impl DemoShell {
    async fn run<'f, S: ServBehaviour>(self, serv: &SSHServer<'_, S>) -> Result<()>
    {
        let session = async {
            // wait for a shell to start
            let chan = if let Ok(c) = self.notify.await {
                c
            } else {
                // no shell was started. that's OK.
                return Ok(())
            };

            loop {
                todo!("stuff");
                // let mut b = [0u8; 20];
                // let lr = serv.read_channel_stdin(chan, &mut b).await?;
                // let b = &mut b[..lr];
                // for c in b.iter() {
                //     menu.input_byte(*c);
                //     menu.context.flush(serv, chan).await?;
                // }
            }
            // Ok(())
        };

        session.await
    }
}

fn run_session(args: &Args, mut stream: TcpStream) -> Result<()> {
    // app is a Behaviour
    let mut shell = DemoShell::default();

    spawn_local(async move {
        // TODO: simplify
        let app = DemoServer::new(&shell, &args.hostkey)?;
        let app = Mutex::<NoopRawMutex, _>::new(app);

        let mut rxbuf = vec![0; 3000];
        let mut txbuf = vec![0; 3000];
        let serv = SSHServer::new(&mut rxbuf, &mut txbuf)?;
        let serv = &serv;

        spawn_local(async {
            let (rsock, wsock) = stream.split();
            let mut rsock = FromTokio::new(rsock);
            let mut wsock = FromTokio::new(wsock);
            serv.run(&mut rsock, &mut wsock, &app).await
        });

        spawn_local(shell.run(serv));
        Ok::<_, anyhow::Error>(())
    });
    Ok(())
}

async fn run(args: &Args) -> Result<()> {
    // TODO not localhost. also ipv6?
    let listener = TcpListener::bind(("127.6.6.6", args.port)).await.context("Listening")?;
    loop {
        let (stream, _) = listener.accept().await?;

        run_session(args, stream)?
    }
    #[allow(unreachable_code)]
    Ok::<_, anyhow::Error>(())
}
