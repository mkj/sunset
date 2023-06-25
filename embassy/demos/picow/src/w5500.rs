// Modified from https://github.com/embassy-rs/cyw43/
// Copyright (c) 2019-2022 Embassy project contributors
// MIT or Apache-2.0 license

#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use log::{debug, error, info, log, trace, warn};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, error, info, panic, trace, warn};

use embassy_executor::Spawner;
use embassy_net::{Stack, StackResources};
use embassy_rp::gpio::{Input, Level, Output, Pull};
use embassy_rp::peripherals::*;
use embassy_rp::spi::{Async, Config as SpiConfig, Spi};
use embedded_hal_async::spi::ExclusiveDevice;

use embassy_net_w5500::*;

use static_cell::make_static;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::{SSHConfig, SunsetMutex};

#[embassy_executor::task]
async fn ethernet_task(
    runner: Runner<
        'static,
        ExclusiveDevice<Spi<'static, SPI0, Async>, Output<'static, PIN_17>>,
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
) -> &'static embassy_net::Stack<embassy_net_w5500::Device<'static>> {
    let mut spi_cfg = SpiConfig::default();
    spi_cfg.frequency = 50_000_000;
    let (miso, mosi, clk) = (p16, p19, p18);
    let spi = Spi::new(spi0, clk, mosi, miso, dma0, dma1, spi_cfg);
    let cs = Output::new(p17, Level::High);
    let w5500_int = Input::new(p21, Pull::Up);
    let w5500_reset = Output::new(p20, Level::High);

    let mac_addr = config.lock().await.mac;
    // 
    let state = make_static!(State::<8, 8>::new());
    let (device, runner) = embassy_net_w5500::new(
        mac_addr,
        state,
        ExclusiveDevice::new(spi, cs),
        w5500_int,
        w5500_reset,
    )
    .await;
    spawner.spawn(ethernet_task(runner)).unwrap();

    let config = if let Some(ref s) = config.lock().await.ip4_static {
        embassy_net::Config::ipv4_static(s.clone())
    } else {
        embassy_net::Config::dhcpv4(Default::default())
    };

    // Generate random seed
    let seed = OsRng.next_u64();

    // Init network stack
    let stack = &*make_static!(Stack::new(
        device,
        config,
        make_static!(StackResources::<{ crate::NUM_SOCKETS }>::new()),
        seed
    ));

    // Launch network task
    spawner.spawn(net_task(&stack)).unwrap();

    stack
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<Device<'static>>) -> ! {
    stack.run().await
}
