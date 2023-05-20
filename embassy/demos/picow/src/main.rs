#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
// #![allow(incomplete_features)]

#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use {
    log::{debug, error, info, log, trace, warn},
};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, info, warn, panic, error, trace};

use {defmt_rtt as _, panic_probe as _};

use embassy_executor::Spawner;
use embassy_net::Stack;
use embassy_futures::join::join;
use embassy_rp::{pio::PioPeripheral, interrupt};
use embedded_io::{asynch, Io};
use embedded_io::asynch::Write;

use heapless::{String, Vec};

use static_cell::StaticCell;

use menu::Runner as MenuRunner;
use embedded_io::asynch::Read;
use embassy_sync::signal::Signal;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;

use sunset::*;
use sunset_embassy::{SSHServer, SunsetMutex};

pub(crate) use sunset_demo_embassy_common as demo_common;
use crate::demo_common::singleton;

mod flashconfig;
mod wifi;
mod usbserial;
mod takepipe;

use demo_common::{SSHConfig, demo_menu, Shell};

use takepipe::TakeBase;

const NUM_LISTENERS: usize = 4;
// +1 for dhcp. referenced directly by wifi_stack() function
pub(crate) const NUM_SOCKETS: usize = NUM_LISTENERS+1;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Hello World!");

    let mut p = embassy_rp::init(Default::default());

    caprand::setup(&mut p.PIN_10).unwrap();
    getrandom::register_custom_getrandom!(caprand::getrandom);

    let mut flash = embassy_rp::flash::Flash::new(p.FLASH);

    let config = if option_env!("RESET_FLASH").is_some() {
        flashconfig::create(&mut flash).unwrap()
    } else {
        flashconfig::load_or_create(&mut flash).unwrap()
    };

    let ssh_config = &*singleton!(
        config
    );

    let usb_pipe = singleton!(takepipe::TakePipe::new());
    let usb_pipe = singleton!(usb_pipe.base());
    let usb_irq = interrupt::take!(USBCTRL_IRQ);
    spawner.spawn(usb_serial_task(p.USB, usb_irq, usb_pipe)).unwrap();

    let (_, sm, _, _, _) = p.PIO0.split();
    let wifi_net = ssh_config.wifi_net.as_str();
    let wifi_pw = ssh_config.wifi_pw.as_ref().map(|p| p.as_str());
    // spawn the wifi stack
    let (stack, wifi_control) = wifi::wifi_stack(&spawner, p.PIN_23, p.PIN_24, p.PIN_25, p.PIN_29, p.DMA_CH0, sm,
        wifi_net, wifi_pw).await;
    let stack = &*singleton!(stack);
    let wifi_control = singleton!(SunsetMutex::new(wifi_control));
    spawner.spawn(net_task(&stack)).unwrap();

    let init = DemoShellInit {
        usb_pipe,
        wifi_control,
    };
    let init = singleton!(init);

    for _ in 0..NUM_LISTENERS {
        spawner.spawn(listener(&stack, &ssh_config, init)).unwrap();
    }
}

// TODO: pool_size should be NUM_LISTENERS but needs a literal
#[embassy_executor::task(pool_size = 4)]
async fn listener(stack: &'static Stack<cyw43::NetDriver<'static>>,
    config: &'static SSHConfig,
    ctx: &'static DemoShellInit) -> ! {
    demo_common::listener::<_, DemoShell>(stack, config, ctx).await
}

struct DemoShellInit {
    usb_pipe: &'static TakeBase<'static>,
    wifi_control: &'static SunsetMutex<cyw43::Control<'static>>,
}

struct DemoShell {
    notify: Signal<NoopRawMutex, ChanHandle>,
    ctx: &'static DemoShellInit,

    // Mutex is a bit of a bodge
    username: SunsetMutex<String<20>>,
}

impl DemoShell {
    async fn menu<C>(&self, mut stdio: C) -> Result<()>
        where C: asynch::Read + asynch::Write + Io<Error=sunset::Error> {
        let mut menu_buf = [0u8; 64];
        let menu_out = demo_menu::BufOutput::default();

        let mut menu = MenuRunner::new(&demo_menu::ROOT_MENU, &mut menu_buf, menu_out);

        // bodge
        for c in "help\r\n".bytes() {
            menu.input_byte(c);
        }
        menu.context.flush(&mut stdio).await?;

        loop {
            let mut b = [0u8; 20];
            let lr = stdio.read(&mut b).await?;
            if lr == 0 {
                break
            }
            let b = &mut b[..lr];
            for c in b.iter() {
                menu.input_byte(*c);
                menu.context.flush(&mut stdio).await?;
            }
        }
        Ok(())
    }

    async fn serial<R, W>(&self, mut sshr: R, mut sshw: W) -> Result<()>
        where R: asynch::Read+Io<Error=sunset::Error>,
            W: asynch::Write+Io<Error=sunset::Error> {

        let (mut rx, mut tx) = self.ctx.usb_pipe.take().await;
        let r = async {
            // TODO: could have a single buffer to translate in-place.
            const DOUBLE: usize = 2*takepipe::READ_SIZE;
            let mut b = [0u8; takepipe::READ_SIZE];
            let mut btrans = Vec::<u8, DOUBLE>::new();
            loop {
                let n = rx.read(&mut b).await?;
                let b = &mut b[..n];
                btrans.clear();
                for c in b {
                    if *c == b'\n' {
                        // OK unwrap: btrans.len() = 2*b.len()
                        btrans.push(b'\r').unwrap();
                    }
                    btrans.push(*c).unwrap();
                }
                sshw.write_all(&btrans).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), sunset::Error>(())
        };
        let w = async {
            let mut b = [0u8; 64];
            loop {
                let n = sshr.read(&mut b).await?;
                if n == 0 {
                    return Err(sunset::Error::ChannelEOF);
                }
                let b = &mut b[..n];
                for c in b.iter_mut() {
                    // input translate CR to LF
                    if *c == b'\r' {
                        *c = b'\n';
                    }
                }
                tx.write_all(b).await?;
            }
            #[allow(unreachable_code)]
            Ok::<(), sunset::Error>(())
        };

        join(r, w).await;
        info!("serial task completed");
        Ok(())
    }
}

impl Shell for DemoShell {
    type Init = &'static DemoShellInit;

    fn new(ctx: &Self::Init) -> Self {
        Self {
            notify: Default::default(),
            ctx,
            username: SunsetMutex::new(String::new()),
        }
    }

    fn open_shell(&self, handle: ChanHandle) {
        self.notify.signal(handle);
    }

    async fn authed(&self, username: &str) {
        let mut u = self.username.lock().await;
        *u = username.try_into().unwrap_or(String::new());
    }

    async fn run<'f, S: ServBehaviour>(&self, serv: &'f SSHServer<'f, S>) -> Result<()>
    {
        let session = async {
            // wait for a shell to start
            let chan_handle = self.notify.wait().await;
            let stdio = serv.stdio(chan_handle).await?;

            if *self.username.lock().await == "serial" {
                self.serial(stdio.clone(), stdio).await
            } else {
                self.menu(stdio).await
            }
        };

        session.await
    }
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<cyw43::NetDriver<'static>>) -> ! {
    stack.run().await
}

#[embassy_executor::task]
async fn usb_serial_task(usb: embassy_rp::peripherals::USB,
    irq: embassy_rp::interrupt::USBCTRL_IRQ,
    pipe: &'static TakeBase<'static>,
    ) -> ! {

    info!("usb serial");
    let (mut rx, mut tx) = pipe.split();

    usbserial::usb_serial(usb, irq, &mut tx, &mut rx).await;
    todo!("shoudln't exit");
}

