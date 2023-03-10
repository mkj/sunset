// Modified from https://github.com/embassy-rs/cyw43/
// Copyright (c) 2019-2022 Embassy project contributors
// MIT or Apache-2.0 license

use core::convert::Infallible;

use embassy_rp::gpio::{Flex, Output};
use embassy_rp::peripherals::{PIN_23, PIN_24, PIN_25, PIN_29};
use embassy_executor::Spawner;
use embassy_net::{Stack, StackResources};
use embedded_hal_1::spi::ErrorType;
use embedded_hal_async::spi::{ExclusiveDevice, SpiBusFlush, SpiBusRead, SpiBusWrite};

use static_cell::StaticCell;

use rand::rngs::OsRng;
use rand::RngCore;

use crate::singleton;

#[embassy_executor::task]
pub(crate) async fn wifi_task(
    runner: cyw43::Runner<'static, Output<'static, PIN_23>, ExclusiveDevice<MySpi, Output<'static, PIN_25>>>,
) -> ! {
    runner.run().await
}

pub(crate) struct MySpi {
    /// SPI clock
    pub clk: Output<'static, PIN_29>,

    /// 4 signals, all in one!!
    /// - SPI MISO
    /// - SPI MOSI
    /// - IRQ
    /// - strap to set to gSPI mode on boot.
    pub dio: Flex<'static, PIN_24>,
}

impl ErrorType for MySpi {
    type Error = Infallible;
}

impl SpiBusFlush for MySpi {
    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl SpiBusRead<u32> for MySpi {
    async fn read(&mut self, words: &mut [u32]) -> Result<(), Self::Error> {
        self.dio.set_as_input();
        for word in words {
            let mut w = 0;
            for _ in 0..32 {
                w = w << 1;

                // rising edge, sample data
                if self.dio.is_high() {
                    w |= 0x01;
                }
                self.clk.set_high();

                // falling edge
                self.clk.set_low();
            }
            *word = w
        }

        Ok(())
    }
}

impl SpiBusWrite<u32> for MySpi {
    async fn write(&mut self, words: &[u32]) -> Result<(), Self::Error> {
        self.dio.set_as_output();
        for word in words {
            let mut word = *word;
            for _ in 0..32 {
                // falling edge, setup data
                self.clk.set_low();
                if word & 0x8000_0000 == 0 {
                    self.dio.set_low();
                } else {
                    self.dio.set_high();
                }

                // rising edge
                self.clk.set_high();

                word = word << 1;
            }
        }
        self.clk.set_low();

        self.dio.set_as_input();
        Ok(())
    }
}

pub(crate) async fn wifi_stack(spawner: &Spawner, pwr: Output<'static, PIN_23>, cs: Output<'static, PIN_25>,
    clk: Output<'static, PIN_29>, mut dio: Flex<'static, PIN_24>)
    -> embassy_net::Stack<cyw43::NetDriver<'static>> {

    dio.set_low();
    dio.set_as_output();

    let bus = MySpi { clk, dio };
    let spi = ExclusiveDevice::new(bus, cs);

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

    let state = singleton!(cyw43::State::new());
    let (net_device, mut control, runner) = cyw43::new(state, pwr, spi, fw).await;

    spawner.spawn(wifi_task(runner)).unwrap();

    control.init(clm).await;
    // control.set_power_management(cyw43::PowerManagementMode::PowerSave).await;


    let net = option_env!("WIFI_NETWORK").unwrap_or("guest");
    let pw = option_env!("WIFI_PASSWORD");
    if let Some(pw) = pw {
        control.join_wpa2(net, pw).await;
    } else {
        control.join_open(net).await;
    }

    let config = embassy_net::Config::Dhcp(Default::default());
    //let config = embassy_net::ConfigStrategy::Static(embassy_net::Config {
    //    address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 69, 2), 24),
    //    dns_servers: Vec::new(),
    //    gateway: Some(Ipv4Address::new(192, 168, 69, 1)),
    //});

    let seed = OsRng.next_u64();

    // Init network stack
    let stack = Stack::new(
        net_device,
        config,
        singleton!(StackResources::<{crate::NUM_SOCKETS}>::new()),
        seed
    );

    stack
}
