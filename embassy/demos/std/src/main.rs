#![feature(type_alias_impl_trait)]

#[allow(unused_imports)]
use {
    log::{debug, error, info, log, trace, warn},
};

use embassy_executor::{Spawner, Executor};
use embassy_net::{Stack, StackResources, Config};
use static_cell::StaticCell;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::tuntap::TunTapDevice;

mod tuntap;
#[path = "../../common/server.rs"]
mod demo_common;

use demo_common::SSHConfig;

const NUM_LISTENERS: usize = 2;
// +1 for dhcp
const NUM_SOCKETS: usize = NUM_LISTENERS+1;

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<TunTapDevice>) -> ! {
    stack.run().await
}

#[embassy_executor::task]
async fn main_task(spawner: Spawner) {
    info!("Hello World!");

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
        demo_common::SSHConfig::new().unwrap()
    );

    for _ in 0..NUM_LISTENERS {
        spawner.spawn(listener(stack, &ssh_config)).unwrap();
    }
}

// TODO: pool_size should be NUM_LISTENERS but needs a literal
#[embassy_executor::task(pool_size = 4)]
async fn listener(stack: &'static Stack<TunTapDevice>, config: &'static SSHConfig) -> ! {

    demo_common::listener(stack, config).await
}


static EXECUTOR: StaticCell<Executor> = StaticCell::new();

fn main() {
    env_logger::builder()
        .filter_level(log::LevelFilter::Trace)
        .filter_module("sunset::runner", log::LevelFilter::Info)
        .filter_module("sunset::traffic", log::LevelFilter::Info)
        .filter_module("async_io", log::LevelFilter::Info)
        .filter_module("polling", log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    let executor = EXECUTOR.init(Executor::new());
    executor.run(|spawner| {
        spawner.spawn(main_task(spawner)).unwrap();
    });
}
