#[allow(unused_imports)]
use {
    // crate::error::Error,
    log::{debug, error, info, log, trace, warn},
};
use anyhow::{Context, Result, Error, bail};
use pretty_hex::PrettyHex;

use tokio::net::{TcpStream, TcpListener};

use std::{net::Ipv6Addr, io::Read};

use door_sshproto::*;
use door_async::{SSHServer, raw_pty};

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
}

fn parse_args() -> Result<Args> {
    let mut args: Args = argh::from_env();

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
        });
    Ok(())
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

fn run_session<'a, R: Send>(scope: &'a moro::Scope<'a, '_, R>, stream: TcpStream) -> Result<()> {
    let rxbuf = vec![0; 3000];
    // TODO: better lifetime rather than leaking
    let rxbuf = Box::leak(Box::new(rxbuf)).as_mut_slice();
    let txbuf = vec![0; 3000];
    let txbuf = Box::leak(Box::new(txbuf)).as_mut_slice();

    let mut serv = SSHServer::new(rxbuf, txbuf)?;

    scope.spawn(async {

    });
    Ok(())

}

async fn run(args: &Args) -> Result<()> {
    let listener = TcpListener::bind(("", args.port)).await?;
    moro::async_scope!(|scope| {
        scope.spawn(async {
            loop {
                let (stream, _) = listener.accept().await?;

                run_session(scope, stream)?
            }
            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        });

    }).await;
    Ok(())
}
