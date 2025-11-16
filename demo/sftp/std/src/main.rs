use sunset::*;
use sunset_async::{ProgressHolder, SSHServer, SunsetMutex, SunsetRawMutex};
use sunset_sftp::SftpHandler;

pub(crate) use sunset_demo_common as demo_common;

use demo_common::{DemoCommon, DemoServer, SSHConfig};

use crate::{
    demoopaquefilehandle::DemoOpaqueFileHandle, demosftpserver::DemoSftpServer,
};

use embassy_executor::Spawner;
use embassy_net::{Stack, StackResources, StaticConfigV4};

use rand::rngs::OsRng;
use rand::RngCore;

use embassy_futures::select::select;
use embassy_net_tuntap::TunTapDevice;
use embassy_sync::channel::Channel;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

mod demofilehandlemanager;
mod demoopaquefilehandle;
mod demosftpserver;

const NUM_LISTENERS: usize = 4;
// +1 for dhcp
const NUM_SOCKETS: usize = NUM_LISTENERS + 1;

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, TunTapDevice>) -> ! {
    runner.run().await
}

#[embassy_executor::task]
async fn main_task(spawner: Spawner) {
    let opt_tap0 = "tap0";
    let ip4 = "192.168.69.2";
    let cir = 24;

    let config = Box::leak(Box::new({
        let mut config = SSHConfig::new().unwrap();
        config.set_admin_pw(Some("pw")).unwrap();
        config.console_noauth = true;
        config.ip4_static = if let Ok(ip) = ip4.parse() {
            Some(StaticConfigV4 {
                address: embassy_net::Ipv4Cidr::new(ip, cir),
                gateway: None,
                dns_servers: { heapless::Vec::new() },
            })
        } else {
            None
        };
        SunsetMutex::new(config)
    }));

    let net_cf = if let Some(ref s) = config.lock().await.ip4_static {
        embassy_net::Config::ipv4_static(s.clone())
    } else {
        embassy_net::Config::dhcpv4(Default::default())
    };
    info!("Net config: {net_cf:?}");

    // Init network device
    let net_device = TunTapDevice::new(opt_tap0).unwrap();

    let seed = OsRng.next_u64();

    // Init network stack
    let res = Box::leak(Box::new(StackResources::<NUM_SOCKETS>::new()));
    let (stack, runner) = embassy_net::new(net_device, net_cf, res, seed);

    // Launch network task
    spawner.spawn(net_task(runner)).unwrap();

    for _ in 0..NUM_LISTENERS {
        spawner.spawn(listen(stack, config)).unwrap();
    }
}

#[derive(Default)]
struct StdDemo;

impl DemoServer for StdDemo {
    async fn run(&self, serv: &SSHServer<'_>, mut common: DemoCommon) -> Result<()> {
        let chan_pipe = Channel::<SunsetRawMutex, ChanHandle, 1>::new();

        let ssh_loop_inner = async {
            loop {
                let mut ph = ProgressHolder::new();
                let ev = serv.progress(&mut ph).await?;
                trace!("ev {ev:?}");
                match ev {
                    ServEvent::SessionShell(a) => {
                        a.fail()?; // Not allowed in this example, kept here for compatibility
                    }
                    ServEvent::SessionExec(a) => {
                        a.fail()?; // Not allowed in this example, kept here for compatibility
                    }
                    ServEvent::SessionSubsystem(a) => {
                        match a.command()?.to_lowercase().as_str() {
                            "sftp" => {
                                info!("Starting '{}' subsystem", a.command()?);

                                if let Some(ch) = common.sess.take() {
                                    debug_assert!(ch.num() == a.channel());
                                    a.succeed()?;
                                    let _ = chan_pipe.try_send(ch);
                                } else {
                                    a.fail()?;
                                }
                            }
                            _ => {
                                warn!(
                                "request for subsystem '{}' not implemented: fail",
                                a.command()?
                                );
                                a.fail()?;
                            }
                        }
                    }
                    other => common.handle_event(other)?,
                };
            }
            #[allow(unreachable_code)]
            Ok::<_, Error>(())
        };

        let ssh_loop = async {
            info!("prog_loop started");
            if let Err(e) = ssh_loop_inner.await {
                warn!("Prog Loop Exited: {e:?}");
                return Err(e);
            }
            Ok(())
        };

        #[allow(unreachable_code)]
        let sftp_loop = async {
            loop {
                let ch = chan_pipe.receive().await;

                info!("SFTP loop has received a channel handle {:?}", ch.num());

                // TODO Do some research to find reasonable default buffer lengths
                let mut buffer_in = [0u8; 512];
                let mut incomplete_request_buffer = [0u8; 256];

                match {
                    let stdio = serv.stdio(ch).await?;
                    let mut file_server = DemoSftpServer::new(
                        "./demo/sftp/std/testing/out/".to_string(),
                    );

                    SftpHandler::<DemoOpaqueFileHandle, DemoSftpServer, 512>::new(
                        &mut file_server,
                        &mut incomplete_request_buffer,
                    )
                    .process_loop(stdio, &mut buffer_in)
                    .await?;

                    Ok::<_, Error>(())
                } {
                    Ok(_) => {
                        warn!("sftp server loop finished gracefully");
                        return Ok(());
                    }
                    Err(e) => {
                        error!("sftp server loop finished with an error: {}", e);
                        return Err(e);
                    }
                };
            }
            Ok::<_, Error>(())
        };

        let selected = select(ssh_loop, sftp_loop).await;
        match selected {
            embassy_futures::select::Either::First(res) => {
                warn!("prog_loop finished: {:?}", res);
                res
            }
            embassy_futures::select::Either::Second(res) => {
                warn!("sftp_loop finished: {:?}", res);
                res
            }
        }
    }
}

// TODO pool_size should be NUM_LISTENERS but needs a literal
#[embassy_executor::task(pool_size = 4)]
async fn listen(
    stack: Stack<'static>,
    config: &'static SunsetMutex<SSHConfig>,
) -> ! {
    let demo = StdDemo::default();
    demo_common::listen(stack, config, &demo).await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .filter_module(
            "sunset_demo_sftp_std::demosftpserver",
            log::LevelFilter::Debug,
        )
        .filter_module("sunset_sftp::sftphandler", log::LevelFilter::Debug)
        .filter_module(
            "sunset_sftp::sftphandler::sftpoutputchannelhandler",
            log::LevelFilter::Trace,
        )
        // .filter_module("sunset_sftp::sftpsink", log::LevelFilter::Info)
        // .filter_module("sunset_sftp::sftpsource", log::LevelFilter::Info)
        // .filter_module("sunset_sftp::sftpserver", log::LevelFilter::Info)
        // .filter_module("sunset::runner", log::LevelFilter::Info)
        // .filter_module("sunset::encrypt", log::LevelFilter::Info)
        // .filter_module("sunset::conn", log::LevelFilter::Info)
        // .filter_module("sunset::kex", log::LevelFilter::Info)
        // .filter_module("sunset_async::async_sunset", log::LevelFilter::Info)
        // .filter_module("async_io", log::LevelFilter::Info)
        // .filter_module("polling", log::LevelFilter::Info)
        // .filter_module("embassy_net", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    spawner.spawn(main_task(spawner)).unwrap();
}
