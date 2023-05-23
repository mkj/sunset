#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use log::{debug, error, info, log, trace, warn};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, error, info, panic, trace, warn};

use embassy_futures::join::{join, join3};
use embassy_rp::usb::Instance;
use embassy_usb::class::cdc_acm::{self, CdcAcmClass, State};
use embassy_usb::Builder;
use embassy_usb_driver::Driver;

use embedded_io::{asynch, Io, asynch::BufRead};

use heapless::Vec;

use sunset::*;
use sunset_embassy::*;

use crate::*;

pub(crate) async fn usb_serial(
    usb: embassy_rp::peripherals::USB,
    irq: embassy_rp::interrupt::USBCTRL_IRQ,
    global: &'static GlobalState,
)
{
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

    // lives longer than builder
    let mut usb_state0 = State::new();
    let mut usb_state2 = State::new();

    let mut builder = Builder::new(
        driver,
        config,
        &mut device_descriptor,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut control_buf,
    );

    // if00
    let cdc0 = CdcAcmClass::new(&mut builder, &mut usb_state0, 64);
    let (mut cdc0_tx, mut cdc0_rx) = cdc0.split();
    // if02
    let cdc2 = CdcAcmClass::new(&mut builder, &mut usb_state2, 64);
    let (mut cdc2_tx, mut cdc2_rx) = cdc2.split();

    let mut usb = builder.build();


    // Run the USB device.
    let usb_fut = usb.run();

    let io0 = async {
        let (mut chan_rx, mut chan_tx) = global.usb_pipe.split();
        let chan_rx = &mut chan_rx;
        let chan_tx = &mut chan_tx;
        loop {
            info!("usb waiting");
            cdc0_rx.wait_connection().await;
            info!("Connected");
            let mut cdc0_tx = CDCWrite::new(&mut cdc0_tx);
            let mut cdc0_rx = CDCRead::new(&mut cdc0_rx);

            let io_tx = io_buf_copy(&mut cdc0_rx, chan_tx);
            let io_rx = io_copy::<64, _, _>(chan_rx, &mut cdc0_tx);

            let _ = join(io_rx, io_tx).await;
            info!("Disconnected");
        }
    };

    let setup = async {
        loop {
            info!("usb waiting");
            cdc2_rx.wait_connection().await;
            info!("Connected");
            let cdc2_tx = CDCWrite::new(&mut cdc2_tx);
            let cdc2_rx = CDCRead::new(&mut cdc2_rx);

            let _ = menu(cdc2_rx, cdc2_tx, true, global).await;

            info!("Disconnected");
        }
    };

    info!("usb join");
    join3(usb_fut, io0, setup).await;
}

pub struct CDCRead<'a, 'p, D: Driver<'a>> {
    cdc: &'p mut cdc_acm::Receiver<'a, D>,
    // sufficient for max packet
    buf: [u8; 64],
    // when start reaches end, we set both to 0.
    start: usize,
    end: usize,
}

impl<'a, 'p, D: Driver<'a>> CDCRead<'a, 'p, D> {
    pub fn new(cdc: &'p mut cdc_acm::Receiver<'a, D>) -> Self {
        Self { cdc, buf: [0u8; 64], start: 0, end: 0 }
    }
}

impl<'a, D: Driver<'a>> asynch::Read for CDCRead<'a, '_, D> {
    async fn read(&mut self, ret: &mut [u8]) -> sunset::Result<usize> {
        debug_assert!(self.start < self.end || self.end == 0);

        if self.end == 0 && ret.len() > self.buf.len() {
            // perform an unbuffered read if possible, saves a copy
            let n = self
                .cdc
                .read_packet(ret)
                .await
                .map_err(|_| sunset::Error::ChannelEOF)?;
            info!("direct read_packet {:?}", &ret[..n]);
            return Ok(n)
        }

        let b = self.fill_buf().await?;
        let n = ret.len().min(b.len());
        info!("buf read {:?}, rl {} bl {}", &b[..n], ret.len(), b.len());
        (&mut ret[..n]).copy_from_slice(&b[..n]);
        self.consume(n);
        return Ok(n)
    }
}

impl<'a, D: Driver<'a>> asynch::BufRead for CDCRead<'a, '_, D> {
    async fn fill_buf(&mut self) -> sunset::Result<&[u8]> {
        debug_assert!(self.start < self.end || self.end == 0);

        if self.end == 0 {
            debug_assert!(self.start == 0);
            let n = self
                .cdc
                .read_packet(self.buf.as_mut())
                .await
                .map_err(|_| sunset::Error::ChannelEOF)?;
            info!("buf read_packet {:?}", &self.buf[..n]);

            self.end = n;
        }
        debug_assert!(self.end > 0);
        info!("fill {}..{}", self.start, self.end);

        return Ok(&self.buf[self.start..self.end]);
    }

    fn consume(&mut self, amt: usize) {
        debug_assert!(self.start < self.end || self.end == 0);

        debug_assert!(amt <= (self.end - self.start));

        self.start += amt;
        if self.start >= self.end {
            self.start = 0;
            self.end = 0;
        }
        info!("consumed {},  {}..{}", amt, self.start, self.end);
    }
}

impl<'a, D: Driver<'a>> Io for CDCRead<'a, '_, D> {
    type Error = sunset::Error;
}

pub struct CDCWrite<'a, 'p, D: Driver<'a>>(&'p mut cdc_acm::Sender<'a, D>);

impl<'a, 'p, D: Driver<'a>> CDCWrite<'a, 'p, D> {
    pub fn new(cdc: &'p mut cdc_acm::Sender<'a, D>) -> Self {
        Self(cdc)
    }
}

impl<'a, D: Driver<'a>> asynch::Write for CDCWrite<'a, '_, D> {
    async fn write(&mut self, buf: &[u8]) -> sunset::Result<usize> {
        // limit to 63 so we can ignore dealing with ZLPs for now
        let b = &buf[..buf.len().min(63)];
        self.0.write_packet(b).await.map_err(|_| sunset::Error::ChannelEOF)?;
        Ok(b.len())
    }
}

impl<'a, D: Driver<'a>> Io for CDCWrite<'a, '_, D> {
    type Error = sunset::Error;
}
