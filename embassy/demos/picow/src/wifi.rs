// Modified from https://github.com/embassy-rs/cyw43/
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
use embassy_rp::pio::{PioStateMachineInstance, Sm0, Pio0};
use embassy_rp::peripherals::*;
use embassy_executor::Spawner;
use embassy_net::{Stack, StackResources};

use cyw43_pio::PioSpi;

use static_cell::StaticCell;
use heapless::String;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::demo_common::singleton;

#[embassy_executor::task]
async fn wifi_task(
    runner: cyw43::Runner<
        'static,
        Output<'static, PIN_23>,
        PioSpi<PIN_25, PioStateMachineInstance<Pio0, Sm0>, DMA_CH0>,
    >,
) -> ! {
    runner.run().await
}

// It would be nice to make Pio0, Sm0, DMA_CH0 generic, but wifi_task can't have generics.
pub(crate) async fn wifi_stack(spawner: &Spawner,
    p23: PIN_23, p24: PIN_24, p25: PIN_25, p29: PIN_29, dma: DMA_CH0,
    sm: PioStateMachineInstance<Pio0, Sm0>,
    wifi_net: String<32>, wpa_password: Option<String<63>>,

    ) -> (embassy_net::Stack<cyw43::NetDriver<'static>>, cyw43::Control<'static>)
    {

    let (fw, clm) = get_fw();

    let pwr = Output::new(p23, Level::Low);
    let cs = Output::new(p25, Level::High);
    let spi = PioSpi::new(sm, cs, p24, p29, dma);

    let state = singleton!(cyw43::State::new());
    let (net_device, mut control, runner) = cyw43::new(state, pwr, spi, fw).await;
    spawner.spawn(wifi_task(runner)).unwrap();

    control.init(clm).await;
    // the default is PowerSave. None is fastest.
    // control.set_power_management(cyw43::PowerManagementMode::None).await;
    // control.set_power_management(cyw43::PowerManagementMode::Performance).await;

    let mut status = Ok(());
    for i in 0..5 {
        status = if let Some(ref pw) = wpa_password {
            info!("wifi net {} wpa2 {}", wifi_net, &pw);
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

    if let Err(e) = status {
        // wait forever
        let () = futures::future::pending().await;
    }

    let config = embassy_net::Config::Dhcp(Default::default());

    let seed = OsRng.next_u64();

    // Init network stack
    let stack = Stack::new(
        net_device,
        config,
        singleton!(StackResources::<{crate::NUM_SOCKETS}>::new()),
        seed
    );
    (stack, control)
}

fn get_fw() -> (&'static [u8], &'static [u8]) {
    // Include the WiFi firmware and Country Locale Matrix (CLM) blobs.
    #[cfg(not(feature = "romfw"))]
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
        unsafe { core::slice::from_raw_parts(0x10100000 as *const u8, 224190) },
        unsafe { core::slice::from_raw_parts(0x10140000 as *const u8, 4752) },
        );

    (fw, clm)
}
