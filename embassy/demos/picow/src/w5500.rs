// Modified from https://github.com/embassy-rs/embassy/
// Copyright (c) 2019-2022 Embassy project contributors
// MIT or Apache-2.0 license

#[allow(unused_imports)]
pub use log::{debug, error, info, log, trace, warn};

use embassy_executor::Spawner;
use embassy_net::{StackResources};
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_rp::peripherals::*;
use embassy_rp::spi::{Async, Config as SpiConfig, Spi};
use embassy_time::Delay;
use embedded_hal_bus::spi::ExclusiveDevice;

use embassy_net_wiznet::*;

use static_cell::StaticCell;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::{SSHConfig, SunsetMutex};

#[embassy_executor::task]
async fn ethernet_task(
    runner: Runner<
        'static,
        embassy_net_wiznet::chip::W5500,
        ExclusiveDevice<Spi<'static, SPI0, Async>, Output<'static, PIN_17>, Delay>,
        Input<'static, PIN_21>,
        Output<'static, PIN_20>,
    >,
) -> ! {
    runner.run().await
}

pub(crate) async fn w5500_stack(
    spawner: &Spawner,
    p16: PIN_16,
    p17: PIN_17,
    p18: PIN_18,
    p19: PIN_19,
    p20: PIN_20,
    p21: PIN_21,
    dma0: DMA_CH0,
    dma1: DMA_CH1,
    spi0: SPI0,
    config: &'static SunsetMutex<SSHConfig>,
) -> embassy_net::Stack<'static> {
    let mut spi_cfg = SpiConfig::default();
    spi_cfg.frequency = 50_000_000;
    let (miso, mosi, clk) = (p16, p19, p18);
    let spi = Spi::new(spi0, clk, mosi, miso, dma0, dma1, spi_cfg);
    let cs = Output::new(p17, Level::High);
    let w5500_int = Input::new(p21, Pull::Up);
    let w5500_reset = Output::new(p20, Level::High);

    let mac_addr = config.lock().await.mac;
    // 
    static STATE: StaticCell<State<8, 8>> = StaticCell::new();
    let state = STATE.init_with(|| State::new());
    let (net_device, runner) = embassy_net_wiznet::new(
        mac_addr,
        state,
        ExclusiveDevice::new(spi, cs, Delay),
        w5500_int,
        w5500_reset,
    )
    .await;
    spawner.spawn(ethernet_task(runner)).unwrap();

    let net_cf = if let Some(ref s) = config.lock().await.ip4_static {
        embassy_net::Config::ipv4_static(s.clone())
    } else {
        embassy_net::Config::dhcpv4(Default::default())
    };

    // Generate random seed
    let seed = OsRng.next_u64();

    // Init network stack
    static SR: StaticCell<StackResources::<{crate::NUM_SOCKETS}>> = StaticCell::new();
    let (stack, runner) = embassy_net::new(net_device, net_cf, SR.init(StackResources::new()), seed);

    // Launch network task
    spawner.spawn(net_task(runner)).unwrap();

    stack
}

#[embassy_executor::task]
async fn net_task(mut runner: embassy_net::Runner<'static, Device<'static>>) -> ! {
    runner.run().await
}
