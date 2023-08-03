#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

#[allow(unused_imports)]
use {
    log::{debug, error, info, log, trace, warn},
};

use embassy_executor::{Spawner, Executor};
use embassy_net::{Stack, StackResources};
use static_cell::StaticCell;

use rand::rngs::OsRng;
use rand::RngCore;

use demo_common::menu::Runner as MenuRunner;
use embedded_io::asynch::Read;
use embassy_sync::signal::Signal;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_net_tuntap::TunTapDevice;

use sunset::*;
use sunset_embassy::{SSHServer, SunsetMutex};

mod setupmenu;
pub(crate) use sunset_demo_embassy_common as demo_common;
use crate::demo_common::singleton;

use demo_common::{SSHConfig, demo_menu, DemoServer};

const NUM_LISTENERS: usize = 2;
// +1 for dhcp
const NUM_SOCKETS: usize = NUM_LISTENERS+1;

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<TunTapDevice>) -> ! {
    stack.run().await
}

#[embassy_executor::task]
async fn main_task(spawner: Spawner) {
    // TODO config
    let opt_tap0 = "tap0";

    let config = &*singleton!(  {
        let mut config = SSHConfig::new().unwrap();
        config.set_console_pw(Some("pw")).unwrap();
        SunsetMutex::new(config)
    } );

    let net_config = if let Some(ref s) = config.lock().await.ip4_static {
        embassy_net::Config::ipv4_static(s.clone())
    } else {
        embassy_net::Config::dhcpv4(Default::default())
    };

    // Init network device
    let device = TunTapDevice::new(opt_tap0).unwrap();

    let seed = OsRng.next_u64();

    // Init network stack
    let stack = &*singleton!(Stack::new(
        device,
        net_config,
        singleton!(StackResources::<NUM_SOCKETS>::new()),
        seed
    ));

    // Launch network task
    spawner.spawn(net_task(stack)).unwrap();

    for _ in 0..NUM_LISTENERS {
        spawner.spawn(listener(stack, config)).unwrap();
    }
}

#[derive(Default)]
struct StdDemo {
    notify: Signal<NoopRawMutex, ChanHandle>,
}

impl DemoServer for StdDemo {
    type Init = ();

    fn new(_init: &Self::Init) -> Self {
        Default::default()
    }

    fn open_shell(&self, handle: ChanHandle) {
        self.notify.signal(handle);
    }

    async fn run<'f, S: ServBehaviour>(&self, serv: &'f SSHServer<'f, S>) -> Result<()>
    {
        let session = async {
            // wait for a shell to start
            let chan_handle = self.notify.wait().await;
            trace!("got handle");

            let mut stdio = serv.stdio(chan_handle).await?;

            // input buffer, large enough for a ssh-ed25519 key
            let mut menu_buf = [0u8; 150];
            let menu_out = demo_menu::BufOutput::default();

            let mut menu = MenuRunner::new(&setupmenu::SETUP_MENU, &mut menu_buf, true, menu_out);

            // bodge
            for c in "help\r\n".bytes() {
                menu.input_byte(c);
            }
            menu.context.flush(&mut stdio).await?;

            loop {
                let mut b = [0u8; 20];
                let lr = stdio.read(&mut b).await?;
                if lr == 0 {
                    break
                }
                let b = &mut b[..lr];
                for c in b.iter() {
                    menu.input_byte(*c);
                }
                menu.context.flush(&mut stdio).await?;
            }
            Ok(())
        };

        session.await
    }
}

// TODO: pool_size should be NUM_LISTENERS but needs a literal
#[embassy_executor::task(pool_size = 4)]
async fn listener(stack: &'static Stack<TunTapDevice>,
    config: &'static SunsetMutex<SSHConfig>) -> ! {

    demo_common::listener::<_, StdDemo>(stack, config, ()).await
}


static EXECUTOR: StaticCell<Executor> = StaticCell::new();

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .filter_module("sunset::runner", log::LevelFilter::Info)
        .filter_module("sunset::traffic", log::LevelFilter::Info)
        .filter_module("sunset::encrypt", log::LevelFilter::Info)
        .filter_module("sunset::conn", log::LevelFilter::Info)
        .filter_module("sunset_embassy::embassy_sunset", log::LevelFilter::Info)
        .filter_module("async_io", log::LevelFilter::Info)
        .filter_module("polling", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(main_task(spawner)).unwrap();
    });
}
