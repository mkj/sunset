#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use log::{debug, error, info, log, trace, warn};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, error, info, panic, trace, warn};

use embassy_futures::join::join;
use embassy_rp::usb::Instance;
use embassy_usb::class::cdc_acm::{self, CdcAcmClass, State};
use embassy_usb::Builder;
use embassy_usb_driver::Driver;

use embedded_io::{asynch, Io, asynch::BufRead};

use heapless::Vec;

use sunset::*;
use sunset_embassy::io_copy;

pub async fn usb_serial<R, W>(
    usb: embassy_rp::peripherals::USB,
    irq: embassy_rp::interrupt::USBCTRL_IRQ,
    tx: &mut W,
    rx: &mut R,
)
    where R: asynch::Read+Io<Error=sunset::Error>,
        W: asynch::Write+Io<Error=sunset::Error>
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
    // let cdc_tx = &mut cdc_tx;
    // let cdc_rx = &mut cdc_rx;

    let mut usb = builder.build();

    // Run the USB device.
    let usb_fut = usb.run();

    let io = async {
        loop {
            info!("usb waiting");
            cdc_rx.wait_connection().await;
            info!("Connected");
            let mut cdc_tx = CDCWrite::new(&mut cdc_tx);
            let mut cdc_rx = CDCRead::new(&mut cdc_rx);

            let io_tx = io_copy::<64, _, _>(&mut cdc_rx, tx);
            let io_rx = io_copy::<64, _, _>(rx, &mut cdc_tx);

            join(io_rx, io_tx).await;
            info!("Disconnected");
        }
    };

    info!("usb join");
    join(usb_fut, io).await;
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
        self.0
            .write_packet(b)
            .await
            .map_err(|_| sunset::Error::ChannelEOF)?;
        Ok(b.len())
    }
}

impl<'a, D: Driver<'a>> Io for CDCWrite<'a, '_, D> {
    type Error = sunset::Error;
}
