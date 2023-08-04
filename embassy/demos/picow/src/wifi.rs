// Modified from embassy 
// examples/rp/src/bin/wifi_tcp_server.rs
// Copyright (c) 2019-2022 Embassy project contributors
// MIT or Apache-2.0 license

#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use {
    log::{debug, error, info, log, trace, warn},
};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, info, warn, panic, error, trace};

use embassy_rp::gpio::{Level, Output};
use embassy_rp::pio::Pio;
use embassy_rp::peripherals::*;
use embassy_rp::bind_interrupts;
use embassy_executor::Spawner;
use embassy_net::{Stack, StackResources};

use cyw43_pio::PioSpi;

use static_cell::StaticCell;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::demo_common::singleton;
use crate::{SunsetMutex, SSHConfig};

bind_interrupts!(struct Irqs {
    PIO0_IRQ_0 => embassy_rp::pio::InterruptHandler<PIO0>;
});

#[embassy_executor::task]
async fn wifi_task(
    runner: cyw43::Runner<
        'static,
        Output<'static, PIN_23>,
        PioSpi<'static, PIN_25, PIO0, 0, DMA_CH0>,
    >,
) -> ! {
    runner.run().await
}

// It would be nice to make Pio0, Sm0, DMA_CH0 generic, but wifi_task can't have generics.
pub(crate) async fn wifi_stack(spawner: &Spawner,
    p23: PIN_23, p24: PIN_24, p25: PIN_25, p29: PIN_29, dma: DMA_CH0,
    pio0: PIO0,
    config: &'static SunsetMutex<SSHConfig>,
    ) -> &'static embassy_net::Stack<cyw43::NetDriver<'static>>
    {
    // TODO: return `control` once it can do something useful

    let (fw, clm) = get_fw();

    let pwr = Output::new(p23, Level::Low);
    let cs = Output::new(p25, Level::High);
    let mut pio = Pio::new(pio0, Irqs);
    let spi = PioSpi::new(&mut pio.common, pio.sm0, pio.irq0, cs, p24, p29, dma);

    let state = singleton!(cyw43::State::new());
    let (net_device, mut control, runner) = cyw43::new(state, pwr, spi, fw).await;
    spawner.spawn(wifi_task(runner)).unwrap();

    control.init(clm).await;
    // the default is PowerSave. None is fastest.
    // control.set_power_management(cyw43::PowerManagementMode::None).await;
    // control.set_power_management(cyw43::PowerManagementMode::Performance).await;

    let (wifi_net, wifi_pw) = {
        let c = config.lock().await;
        (c.wifi_net.clone(), c.wifi_pw.clone())
    };

    // TODO: this should move out of the critical path, run in the bg.
    // just return control before joining.
    for _ in 0..2 {
        let status = if let Some(ref pw) = wifi_pw {
            info!("wifi net {} wpa2", wifi_net);
            control.join_wpa2(&wifi_net, &pw).await
        } else {
            info!("wifi net {} open", wifi_net);
            control.join_open(&wifi_net).await
        };
        if let Err(ref e) = status {
            info!("wifi join failed, code {}", e.status);
        } else {
            break;
        }
    }

    let config = if let Some(ref s) = config.lock().await.ip4_static {
        embassy_net::Config::ipv4_static(s.clone())
    } else {
        embassy_net::Config::dhcpv4(Default::default())
    };

    let seed = OsRng.next_u64();

    // Init network stack
    let stack = Stack::new(
        net_device,
        config,
        singleton!(StackResources::<{crate::NUM_SOCKETS}>::new()),
        seed
    );

    let stack = &*singleton!(stack);
    spawner.spawn(net_task(&stack)).unwrap();

    stack
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<cyw43::NetDriver<'static>>) -> ! {
    stack.run().await
}

// Get the WiFi firmware and Country Locale Matrix (CLM) blobs.
fn get_fw() -> (&'static [u8], &'static [u8]) {
    let (fw, clm) = (
        include_bytes!("../firmware/43439A0.bin"),
        include_bytes!("../firmware/43439A0_clm.bin"),
        );

    // To make flashing faster for development, you may want to flash the firmwares independently
    // at hardcoded addresses, instead of baking them into the program with `include_bytes!`:
    //     probe-rs-cli download 43439A0.bin --format bin --chip RP2040 --base-address 0x10100000
    //     probe-rs-cli download 43439A0_clm.bin --format bin --chip RP2040 --base-address 0x10140000
    #[cfg(feature = "romfw")]
    let (fw, clm) = (
        unsafe { core::slice::from_raw_parts(0x10100000 as *const u8, fw.len()) },
        unsafe { core::slice::from_raw_parts(0x10140000 as *const u8, clm.len()) },
        );

    (fw, clm)
}
