// Modified from embassy
// examples/rp/src/bin/wifi_tcp_server.rs
// Copyright (c) 2019-2022 Embassy project contributors
// MIT or Apache-2.0 license

#[allow(unused_imports)]
pub use log::{debug, error, info, log, trace, warn};

use embassy_executor::Spawner;
use embassy_net::StackResources;
use embassy_rp::bind_interrupts;
use embassy_rp::gpio::{Level, Output};
use embassy_rp::peripherals::*;
use embassy_rp::pio::Pio;

use cyw43_pio::PioSpi;

use rand::rngs::OsRng;
use rand::RngCore;
use static_cell::StaticCell;

use crate::{SSHConfig, SunsetMutex};

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
pub(crate) async fn wifi_stack(
    spawner: &Spawner,
    p23: PIN_23,
    p24: PIN_24,
    p25: PIN_25,
    p29: PIN_29,
    dma: DMA_CH0,
    pio0: PIO0,
    config: &'static SunsetMutex<SSHConfig>,
) -> embassy_net::Stack<'static> {
    let (fw, _clm) = get_fw();

    let pwr = Output::new(p23, Level::Low);
    let cs = Output::new(p25, Level::High);
    let mut pio = Pio::new(pio0, Irqs);
    let spi = PioSpi::new(&mut pio.common, pio.sm0, pio.irq0, cs, p24, p29, dma);

    static STATE: StaticCell<cyw43::State> = StaticCell::new();
    let state = STATE.init_with(|| cyw43::State::new());
    let (net_device, control, runner) = cyw43::new(state, pwr, spi, fw).await;
    spawner.spawn(wifi_task(runner)).unwrap();

    let seed = OsRng.next_u64();
    let net_cf = if let Some(ref s) = config.lock().await.ip4_static {
        embassy_net::Config::ipv4_static(s.clone())
    } else {
        embassy_net::Config::dhcpv4(Default::default())
    };

    // Init network stack
    static SR: StaticCell<StackResources<{ crate::NUM_SOCKETS }>> =
        StaticCell::new();
    let (stack, runner) =
        embassy_net::new(net_device, net_cf, SR.init(StackResources::new()), seed);

    spawner.spawn(net_task(runner, control, config)).unwrap();

    stack
}

#[embassy_executor::task]
async fn net_task(
    mut runner: embassy_net::Runner<'static, cyw43::NetDriver<'static>>,
    mut control: cyw43::Control<'static>,
    config: &'static SunsetMutex<SSHConfig>,
) -> ! {
    let (_fw, clm) = get_fw();
    // control init() must occur before the net stack tries to access cyw43, otherwise
    // it seems to get stuck. await it here before spawning the net task.
    control.init(clm).await;

    // the default is PowerSave. None is fastest.
    control.set_power_management(cyw43::PowerManagementMode::None).await;

    let (wifi_net, wifi_pw) = {
        let c = config.lock().await;
        (c.wifi_net.clone(), c.wifi_pw.clone())
    };

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
            info!("wifi joined");
            break;
        }
    }

    runner.run().await
}

// Get the WiFi firmware and Country Locale Matrix (CLM) blobs.
fn get_fw() -> (&'static [u8], &'static [u8]) {
    let (fw, clm) = (
        include_bytes!("../firmware/43439A0.bin"),
        include_bytes!("../firmware/43439A0_clm.bin"),
    );

    // To make flashing faster for development, you may want to flash the firmwares independently
    // at hardcoded addresses, instead of baking them into the program with `include_bytes!`:
    /*
       probe-rs download firmware/43439A0.bin --binary-format bin  --chip RP2040 --base-address 0x10100000
       probe-rs download firmware/43439A0_clm.bin --binary-format bin  --chip RP2040 --base-address 0x10140000
    */
    #[cfg(feature = "romfw")]
    let (fw, clm) = (
        unsafe { core::slice::from_raw_parts(0x10100000 as *const u8, fw.len()) },
        unsafe { core::slice::from_raw_parts(0x10140000 as *const u8, clm.len()) },
    );

    (fw, clm)
}
