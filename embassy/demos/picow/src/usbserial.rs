
#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use {
    log::{debug, error, info, log, trace, warn},
};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, info, warn, panic, error, trace};

use embassy_usb::{Builder};
use embassy_rp::usb::Instance;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_futures::join::join;

use embedded_io::asynch;

use sunset::*;

pub async fn usb_serial(usb: embassy_rp::peripherals::USB,
    irq: embassy_rp::interrupt::USBCTRL_IRQ,
    tx: &mut impl asynch::Write,
    rx: &mut impl asynch::Read,
    ) {

    info!("usb_serial top");

    let driver = embassy_rp::usb::Driver::new(usb, irq);

    let mut config = embassy_usb::Config::new(0xf055, 0x6053);
    config.manufacturer = Some("Sunset SSH");
    config.product = Some("picow demo");
    config.serial_number = Some("4");
    config.max_power = 100;
    config.max_packet_size_0 = 64;

    // Required for windows 7 compatiblity.
    // https://developer.nordicsemi.com/nRF_Connect_SDK/doc/1.9.1/kconfig/CONFIG_CDC_ACM_IAD.html#help
    config.device_class = 0xEF;
    config.device_sub_class = 0x02;
    config.device_protocol = 0x01;
    config.composite_with_iads = true;

    // Create embassy-usb DeviceBuilder using the driver and config.
    // It needs some buffers for building the descriptors.
    let mut device_descriptor = [0; 256];
    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut control_buf = [0; 64];

    let mut state = State::new();

    let mut builder = Builder::new(
        driver,
        config,
        &mut device_descriptor,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut control_buf,
    );

    let cdc = CdcAcmClass::new(&mut builder, &mut state, 64);
    let (mut cdc_tx, mut cdc_rx) = cdc.split();

    let mut usb = builder.build();

    // Run the USB device.
    let usb_fut = usb.run();

    struct IoDone;

    let io = async {
        loop {
            info!("usb waiting");
            cdc_rx.wait_connection().await;
            info!("Connected");

            let io_tx = async {
                let mut b = [0u8; 64];
                loop {
                    let n = cdc_rx.read_packet(&mut b).await .map_err(|_| IoDone)?;
                    let b = &b[..n];
                    tx.write_all(b).await.map_err(|_| IoDone)?;
                }
                #[allow(unreachable_code)]
                Ok::<_, IoDone>(())
            };

            let io_rx = async {
                // limit to 63 so we can ignore dealing with ZLPs for now
                let mut b = [0u8; 63];
                loop {
                    let n = rx.read(&mut b).await.map_err(|_| IoDone)?;
                    if n == 0 {
                        return Err(IoDone);
                    }
                    let b = &b[..n];
                    cdc_tx.write_packet(b).await.map_err(|_| IoDone)?;
                }
                #[allow(unreachable_code)]
                Ok::<_, IoDone>(())
            };

            join(io_rx, io_tx).await;
            info!("Disconnected");
        }
    };

    info!("usb join");
    join(usb_fut, io).await;

}
