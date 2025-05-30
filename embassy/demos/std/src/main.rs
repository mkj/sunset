#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use embassy_executor::Spawner;
use embassy_net::{Stack, StackResources, StaticConfigV4};

use rand::rngs::OsRng;
use rand::RngCore;

use demo_common::menu::Runner as MenuRunner;
use embassy_futures::select::select;
use embassy_net_tuntap::TunTapDevice;
use embassy_sync::channel::Channel;
use embedded_io_async::Read;

use sunset::*;
use sunset_embassy::{ProgressHolder, SSHServer, SunsetMutex, SunsetRawMutex};

mod setupmenu;
pub(crate) use sunset_demo_embassy_common as demo_common;

use demo_common::{DemoCommon, DemoServer, SSHConfig};

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

        let prog_loop = async {
            loop {
                let mut ph = ProgressHolder::new();
                let ev = serv.progress(&mut ph).await?;
                trace!("ev {ev:?}");
                match ev {
                    ServEvent::SessionShell(a) => {
                        if let Some(ch) = common.sess.take() {
                            debug_assert!(ch.num() == a.channel()?);
                            a.succeed()?;
                            let _ = chan_pipe.try_send(ch);
                        } else {
                            a.fail()?;
                        }
                    }
                    other => common.handle_event(other)?,
                };
            }
            #[allow(unreachable_code)]
            Ok::<_, Error>(())
        };

        let shell_loop = async {
            let ch = chan_pipe.receive().await;

            debug!("got handle");

            let mut stdio = serv.stdio(ch).await?;

            // input buffer, large enough for a ssh-ed25519 key
            let mut menu_buf = [0u8; 150];
            let menu_out = demo_common::AsyncMenuBuf::default();

            let mut menu = MenuRunner::new(
                &setupmenu::SETUP_MENU,
                &mut menu_buf,
                true,
                menu_out,
            );

            // bodge
            for c in "help\r\n".bytes() {
                menu.input_byte(c);
            }
            menu.context.flush(&mut stdio).await?;

            loop {
                let mut b = [0u8; 20];
                let lr = stdio.read(&mut b).await?;
                if lr == 0 {
                    break;
                }
                let b = &mut b[..lr];
                for c in b.iter() {
                    menu.input_byte(*c);
                }
                menu.context.flush(&mut stdio).await?;
            }
            Ok::<_, Error>(())
        };

        select(prog_loop, shell_loop).await;
        todo!()
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
        .filter_level(log::LevelFilter::Trace)
        // .filter_module("sunset::runner", log::LevelFilter::Info)
        .filter_module("sunset::traffic", log::LevelFilter::Info)
        .filter_module("sunset::encrypt", log::LevelFilter::Info)
        // .filter_module("sunset::conn", log::LevelFilter::Info)
        // .filter_module("sunset_embassy::embassy_sunset", log::LevelFilter::Info)
        .filter_module("async_io", log::LevelFilter::Info)
        .filter_module("polling", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    spawner.spawn(main_task(spawner)).unwrap();
}
