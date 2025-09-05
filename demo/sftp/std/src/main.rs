use sunset::*;
use sunset_async::{ProgressHolder, SSHServer, SunsetMutex, SunsetRawMutex};
use sunset_sftp::SftpHandler;

pub(crate) use sunset_demo_common as demo_common;

use demo_common::{DemoCommon, DemoServer, SSHConfig};

use crate::demosftpserver::DemoSftpServer;

use embedded_io_async::{Read, Write};

use embassy_executor::Spawner;
use embassy_net::{Stack, StackResources, StaticConfigV4};

use rand::rngs::OsRng;
use rand::RngCore;

use embassy_futures::select::select;
use embassy_net_tuntap::TunTapDevice;
use embassy_sync::channel::Channel;

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

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
    // TODO config
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

        let prog_loop_inner = async {
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

        let prog_loop = async {
            info!("prog_loop started");
            if let Err(e) = prog_loop_inner.await {
                warn!("Prog Loop Exited: {e:?}");
                return Err(e);
            }
            Ok(())
        };

        let sftp_loop = async {
            let ch = chan_pipe.receive().await;
            info!("SFTP loop has received a channel handle");

            let mut stdio = serv.stdio(ch).await?;
            let mut buffer_in = [0u8; 1000];
            let mut buffer_out = [0u8; 1000];

            let mut sftp_handler =
                SftpHandler::<DemoSftpServer>::new(&buffer_in, &mut buffer_out);

            loop {
                let lr = stdio.read(&mut buffer_in).await?;
                debug!("SFTP <---- received: {:?}", &buffer_in[0..lr]);

                let lw =
                    sftp_handler.process(&buffer_in[0..lr], &mut buffer_out).await?;

                stdio.write(&mut buffer_out[0..lw]).await?;
                debug!("SFTP ----> Sent: {:?}", &buffer_out[0..lw]);
            }
            Ok::<_, Error>(())
        };

        let selected = select(prog_loop, sftp_loop).await;
        error!("Selected finished: {:?}", selected);
        todo!("Loop terminated: {:?}", selected)
    }
}

// TODO: pool_size should be NUM_LISTENERS but needs a literal
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
        .filter_module("sunset::runner", log::LevelFilter::Info)
        .filter_module("sunset::traffic", log::LevelFilter::Info)
        .filter_module("sunset::encrypt", log::LevelFilter::Info)
        .filter_module("sunset::conn", log::LevelFilter::Info)
        .filter_module("sunset::kex", log::LevelFilter::Info)
        .filter_module("sunset_async::async_sunset", log::LevelFilter::Info)
        .filter_module("async_io", log::LevelFilter::Info)
        .filter_module("polling", log::LevelFilter::Info)
        .filter_module("embassy_net", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    spawner.spawn(main_task(spawner)).unwrap();
}
