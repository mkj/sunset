#[allow(unused_imports)]
pub use log::{debug, error, info, log, trace, warn};

use embassy_futures::join::{join, join3};
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::InterruptHandler;
use embassy_usb::class::cdc_acm::{self, CdcAcmClass};
// use embassy_usb::class::hid::{self, HidReaderWriter};
use embassy_usb::Builder;
use embassy_usb_driver::Driver;
// use usbd_hid::descriptor::{KeyboardReport, SerializedDescriptor};

use embedded_io_async::{BufRead, ErrorType, Read, Write};

use sunset_async::*;

use crate::*;
use picowmenu::request_pw;

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

#[embassy_executor::task]
pub(crate) async fn task(
    usb: embassy_rp::peripherals::USB,
    global: &'static PicoDemo,
) -> ! {
    let driver = embassy_rp::usb::Driver::new(usb, Irqs);

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
    let mut config_descriptor = [0; 256];
    let mut bos_descriptor = [0; 256];
    let mut msos_descriptor = [0; 16];
    let mut control_buf = [0; 64];

    // lives longer than builder
    let mut usb_state0 = cdc_acm::State::new();
    let mut usb_state2 = cdc_acm::State::new();
    // let mut usb_state4 = hid::State::new();

    let mut builder = Builder::new(
        driver,
        config,
        &mut config_descriptor,
        &mut bos_descriptor,
        &mut msos_descriptor,
        &mut control_buf,
    );

    // if00
    let cdc0 = CdcAcmClass::new(&mut builder, &mut usb_state0, 64);
    // if02
    let cdc2 = CdcAcmClass::new(&mut builder, &mut usb_state2, 64);

    // let hid_config = embassy_usb::class::hid::Config {
    //     report_descriptor: KeyboardReport::desc(),
    //     request_handler: None,
    //     poll_ms: 20,
    //     max_packet_size: 64,
    // };
    // let hid =
    //     HidReaderWriter::<_, 1, 8>::new(&mut builder, &mut usb_state4, hid_config);

    let mut usb = builder.build();

    // Run the USB device.
    let usb_fut = usb.run();

    // console via SSH on if00
    let io0_run = console_if00_run(&global, cdc0);

    // Admin menu on if02
    let io2_run = menu_if02_run(&global, cdc2);

    // keyboard
    // let hid_run = keyboard::run(&global, hid);

    // join4(usb_fut, io0_run, io2_run, hid_run).await;
    join3(usb_fut, io0_run, io2_run).await;
    unreachable!()
}

async fn console_if00_run<'a, D: Driver<'a>>(
    global: &'static PicoDemo,
    cdc: CdcAcmClass<'a, D>,
) -> ! {
    let (mut cdc_tx, mut cdc_rx) = cdc.split();
    let (mut chan_rx, mut chan_tx) = global.usb_pipe.split();
    let chan_rx = &mut chan_rx;
    let chan_tx = &mut chan_tx;
    loop {
        info!("USB waiting");
        cdc_rx.wait_connection().await;
        info!("USB connected");
        let mut cdc_tx = CDCWrite::new(&mut cdc_tx);
        let mut cdc_rx = CDCRead::new(&mut cdc_rx);

        let io_tx = io_buf_copy(&mut cdc_rx, chan_tx);
        let io_rx = io_copy::<64, _, _>(chan_rx, &mut cdc_tx);

        let _ = join(io_rx, io_tx).await;
        info!("USB disconnected");
    }
}

async fn menu_if02_run<'a, D: Driver<'a>>(
    global: &'static PicoDemo,
    cdc: CdcAcmClass<'a, D>,
) -> ! {
    let (mut cdc_tx, mut cdc_rx) = cdc.split();
    'usb: loop {
        debug!("wait menu if02 conn");
        cdc_rx.wait_connection().await;
        debug!("got menu if02 conn");
        let mut cdc_tx = CDCWrite::new(&mut cdc_tx);
        let mut cdc_rx = CDCRead::new(&mut cdc_rx);

        // wait for a keystroke before writing anything.
        let mut c = [0u8];
        let _ = cdc_rx.read_exact(&mut c).await;
        debug!("read {:02x}", c[0]);

        let p = {
            let c = global.config.lock().await;
            c.admin_pw.clone()
        };

        if let Some(p) = p {
            'pw: loop {
                match request_pw(&mut cdc_tx, &mut cdc_rx).await {
                    Ok(pw) => {
                        if p.check(&pw) {
                            let _ = cdc_tx.write_all(b"Good\r\n").await;
                            break 'pw;
                        }
                    }
                    Err(_) => continue 'usb,
                }
            }
        }

        let _ = menu(&mut cdc_rx, &mut cdc_tx, true, global).await;
    }
}

// TODO: this could be merged into embassy?
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

impl<'a, D: Driver<'a>> Read for CDCRead<'a, '_, D> {
    async fn read(&mut self, ret: &mut [u8]) -> sunset::Result<usize> {
        debug_assert!(self.start < self.end || self.end == 0);

        if self.end == 0 && ret.len() > self.buf.len() {
            // perform an unbuffered read if possible, saves a copy
            let n = self
                .cdc
                .read_packet(ret)
                .await
                .map_err(|_| sunset::Error::ChannelEOF)?;
            return Ok(n);
        }

        let b = self.fill_buf().await?;
        let n = ret.len().min(b.len());
        (&mut ret[..n]).copy_from_slice(&b[..n]);
        self.consume(n);
        return Ok(n);
    }
}

impl<'a, D: Driver<'a>> BufRead for CDCRead<'a, '_, D> {
    async fn fill_buf(&mut self) -> sunset::Result<&[u8]> {
        debug_assert!(self.start < self.end || self.end == 0);

        if self.end == 0 {
            debug_assert!(self.start == 0);
            let n = self
                .cdc
                .read_packet(self.buf.as_mut())
                .await
                .map_err(|_| sunset::Error::ChannelEOF)?;

            self.end = n;
        }
        debug_assert!(self.end > 0);

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
    }
}

impl<'a, D: Driver<'a>> ErrorType for CDCRead<'a, '_, D> {
    type Error = sunset::Error;
}

pub struct CDCWrite<'a, 'p, D: Driver<'a>>(&'p mut cdc_acm::Sender<'a, D>);

impl<'a, 'p, D: Driver<'a>> CDCWrite<'a, 'p, D> {
    pub fn new(cdc: &'p mut cdc_acm::Sender<'a, D>) -> Self {
        Self(cdc)
    }
}

impl<'a, D: Driver<'a>> Write for CDCWrite<'a, '_, D> {
    async fn write(&mut self, buf: &[u8]) -> sunset::Result<usize> {
        // limit to 63 so we can ignore dealing with ZLPs for now
        let b = &buf[..buf.len().min(63)];
        self.0.write_packet(b).await.map_err(|_| sunset::Error::ChannelEOF)?;
        Ok(b.len())
    }
}

impl<'a, D: Driver<'a>> ErrorType for CDCWrite<'a, '_, D> {
    type Error = sunset::Error;
}
