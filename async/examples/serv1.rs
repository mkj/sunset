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
use door_async::*;

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
    keys: Vec<SignKey>,

    sess: Option<u32>,
    want_shell: bool,
    shell_started: bool,
}

impl DemoServer {
    fn new(keyfiles: &[String]) -> Result<Self> {
        let keys = keyfiles.iter().map(|f| {
            read_key(f).with_context(|| format!("loading key {f}"))
        }).collect::<Result<Vec<SignKey>>>()?;

        Ok(Self {
            sess: None,
            keys,
            want_shell: false,
            shell_started: false,
        })
    }
}

impl ServBehaviour for DemoServer {
    fn hostkeys(&mut self) -> BhResult<&[SignKey]> {
        Ok(&self.keys)
    }


    fn have_auth_password(&self, user: TextString) -> bool {
        true
    }

    fn have_auth_pubkey(&self, user: TextString) -> bool {
        false
    }

    fn auth_password(&mut self, user: TextString, password: TextString) -> bool {
        user.as_str().unwrap_or("") == "matt" && password.as_str().unwrap_or("") == "pw"
    }

    fn open_session(&mut self, chan: u32) -> ChanOpened {
        if self.sess.is_some() {
            ChanOpened::Failure(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
        } else {
            self.sess = Some(chan);
            ChanOpened::Success
        }
    }

    fn sess_shell(&mut self, chan: u32) -> bool {
        let r = !self.want_shell && self.sess == Some(chan);
        self.want_shell = true;
        trace!("req want shell");
        r
    }

    fn sess_pty(&mut self, chan: u32, _pty: &Pty) -> bool {
        self.sess == Some(chan)
    }
}

fn run_session<'a, R: Send>(args: &'a Args, scope: &'a moro::Scope<'a, '_, R>, mut stream: TcpStream) -> Result<()> {
    // app is a Behaviour

    scope.spawn(async move {
        let mut app = DemoServer::new(&args.hostkey)?;
        let mut rxbuf = vec![0; 3000];
        let mut txbuf = vec![0; 3000];
        let mut serv = SSHServer::new(&mut rxbuf, &mut txbuf, &mut app)?;
        let mut s = serv.socket();

        let w = moro::async_scope!(|scope| {

            scope.spawn(tokio::io::copy_bidirectional(&mut stream, &mut s));

            let v = scope.spawn(async {
                loop {
                    serv.progress(&mut app).await.context("progress loop")?;
                    if app.want_shell && !app.shell_started {
                        trace!("make shell");
                        app.shell_started = true;

                        if let Some(ch) = app.sess {
                            let ch = ch.clone();
                            let (mut inout, mut _ext) = serv.channel(ch).await?;
                            let mut o = inout.clone();
                            scope.spawn(async move {
                                tokio::io::copy(&mut o, &mut inout).await?;
                                error!("fell out of stdio loop");
                                Ok::<_, anyhow::Error>(())
                            });
                        }

                    }
                }
                #[allow(unreachable_code)]
                Ok::<_, anyhow::Error>(())
            }).await;

            let r: () = scope.terminate(v).await;
            Ok(())
        }).await;
        trace!("Finished session {:?}", w);
        w
    });
    Ok(())

}

async fn run(args: &Args) -> Result<()> {
    // TODO not localhost. also ipv6?
    let listener = TcpListener::bind(("127.6.6.6", args.port)).await.context("Listening")?;
    moro::async_scope!(|scope| {
        scope.spawn(async {
            loop {
                let (stream, _) = listener.accept().await?;

                run_session(args, scope, stream)?
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        }).await

    }).await
}
