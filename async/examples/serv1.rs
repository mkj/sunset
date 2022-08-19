#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, Error, bail};
use pretty_hex::PrettyHex;

use tokio::net::{TcpStream, TcpListener};

use std::{net::Ipv6Addr, io::Read};
use std::path::Path;

use door_sshproto::*;
use door_async::{SSHServer, raw_pty};

use async_trait::async_trait;

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

    #[argh(option, short='p', default="22")]
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
    .add_filter_allow_str("serv1")
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

    CombinedLogger::init(logs).unwrap();
    Ok(())
}

fn read_key(p: &str) -> Result<SignKey> {
    let mut v = vec![];
    std::fs::File::open(p)?.read_to_end(&mut v)?;
    SignKey::from_openssh(v).context("parsing openssh key")
}

struct DemoServer {
    sess: Option<u32>,
    keys: Vec<SignKey>
}

impl DemoServer {
    fn new(keyfiles: &[String]) -> Result<Self> {
        let keys = keyfiles.iter().map(|f| {
            read_key(f).with_context(|| format!("loading key {f}"))
        }).collect::<Result<Vec<SignKey>>>()?;

        Ok(Self {
            sess: None,
            keys,
        })
    }
}

#[async_trait]
impl AsyncServBehaviour for DemoServer {
    async fn hostkeys(&mut self) -> BhResult<&[SignKey]> {
        Ok(&self.keys)
    }


    fn have_auth_password(&self, user: &str) -> bool {
        true
    }

    fn have_auth_pubkey(&self, user: &str) -> bool {
        false
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> bool {
        user == "matt" && password == "pw"
    }

    fn open_session(&mut self, chan: u32) -> ChanOpened {
        if self.sess.is_some() {
            ChanOpened::Failure(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
        } else {
            self.sess = Some(chan);
            ChanOpened::Success
        }
    }

    fn sess_req_shell(&mut self, _chan: u32) -> bool {
        true
    }

    fn sess_pty(&mut self, _chan: u32, _pty: &Pty) -> bool {
        true
    }
}

fn run_session<'a, R: Send>(args: &'a Args, scope: &'a moro::Scope<'a, '_, R>, mut stream: TcpStream) -> Result<()> {
    // app is a Behaviour

    scope.spawn(async move {
        let mut app = DemoServer::new(&args.hostkey)?;
        let mut rxbuf = vec![0; 3000];
        let mut txbuf = vec![0; 3000];
        let mut serv = SSHServer::new(&mut rxbuf, &mut txbuf)?;
        let mut s = serv.socket();

        moro::async_scope!(|scope| {

            scope.spawn(tokio::io::copy_bidirectional(&mut stream, &mut s));

            scope.spawn(async {
                loop {
                    let ev = serv.progress(&mut app, |ev| {
                        trace!("progress event {ev:?}");
                        let e = match ev {
                            Event::CliAuthed => Some(Event::CliAuthed),
                            _ => None,
                        };
                        Ok(e)
                    }).await.context("progress loop")?;
                }
                #[allow(unreachable_code)]
                Ok::<_, anyhow::Error>(())
            });
            Ok::<_, anyhow::Error>(())
        }).await
    });
    Ok(())

}

async fn run(args: &Args) -> Result<()> {
    let listener = TcpListener::bind(("", args.port)).await?;
    moro::async_scope!(|scope| {
        scope.spawn(async {
            loop {
                let (stream, _) = listener.accept().await?;

                run_session(args, scope, stream)?
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        });

    }).await;
    Ok(())
}
