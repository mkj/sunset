#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
#![allow(incomplete_features)]

#[allow(unused_imports)]
use {
    log::{debug, error, info, log, trace, warn},
};

use embassy_executor::{Spawner, Executor};
use embassy_net::{Stack, StackResources, Config};
use static_cell::StaticCell;

use rand::rngs::OsRng;
use rand::RngCore;

use demo_common::menu::Runner as MenuRunner;
use embedded_io::asynch::Read;
use embassy_sync::signal::Signal;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use crate::tuntap::TunTapDevice;

use sunset::*;
use sunset_embassy::SSHServer;

mod tuntap;
pub(crate) use sunset_demo_embassy_common as demo_common;
use crate::demo_common::singleton;

use demo_common::{SSHConfig, demo_menu, Shell};

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
    let config = Config::Dhcp(Default::default());

    // Init network device
    let device = TunTapDevice::new(opt_tap0).unwrap();

    let seed = OsRng.next_u64();

    // Init network stack
    let stack = &*singleton!(Stack::new(
        device,
        config,
        singleton!(StackResources::<NUM_SOCKETS>::new()),
        seed
    ));

    // Launch network task
    spawner.spawn(net_task(stack)).unwrap();

    let ssh_config = &*singleton!(
        SSHConfig::new().unwrap()
    );

    for _ in 0..NUM_LISTENERS {
        spawner.spawn(listener(stack, &ssh_config)).unwrap();
    }
}

#[derive(Default)]
struct DemoShell {
    notify: Signal<NoopRawMutex, ChanHandle>,
}

impl Shell for DemoShell {
    type Init = ();

    fn new(init: &Self::Init) -> Self {
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

            let mut menu_buf = [0u8; 64];
            let menu_out = demo_menu::BufOutput::default();

            let mut menu = MenuRunner::new(&demo_menu::ROOT_MENU, &mut menu_buf, menu_out);

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
async fn listener(stack: &'static Stack<TunTapDevice>, config: &'static SSHConfig) -> ! {

    demo_common::listener::<_, DemoShell>(stack, config, ()).await
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
