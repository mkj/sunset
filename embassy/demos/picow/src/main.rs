#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(async_fn_in_trait)]
// #![allow(incomplete_features)]

#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use log::{debug, error, info, log, trace, warn};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, error, info, panic, trace, warn};

use {defmt_rtt as _, panic_probe as _};

use core::fmt::Write as _;
use pretty_hex::PrettyHex;

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_futures::select::select;
use embassy_net::Stack;
use embassy_rp::peripherals::FLASH;
use embassy_rp::{interrupt, pio::PioPeripheral};
use embassy_time::Duration;
use embedded_io::asynch::Write as _;
use embedded_io::{asynch, Io};

use heapless::{String, Vec};

use static_cell::StaticCell;

use demo_common::menu::Runner as MenuRunner;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embedded_io::asynch::Read;

use sunset::*;
use sunset_embassy::{SSHServer, SunsetMutex};

use crate::demo_common::singleton;
pub(crate) use sunset_demo_embassy_common as demo_common;

mod flashconfig;
mod picowmenu;
mod takepipe;
mod usbserial;
mod wifi;

use demo_common::{demo_menu, SSHConfig, Shell};

use takepipe::TakeBase;

const NUM_LISTENERS: usize = 4;
// +1 for dhcp. referenced directly by wifi_stack() function
pub(crate) const NUM_SOCKETS: usize = NUM_LISTENERS + 1;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Hello World!");

    let mut p = embassy_rp::init(Default::default());

    caprand::setup(&mut p.PIN_10).unwrap();
    getrandom::register_custom_getrandom!(caprand::getrandom);

    let mut flash = embassy_rp::flash::Flash::new(p.FLASH);

    let config = if option_env!("RESET_CONFIG").is_some() {
        flashconfig::create(&mut flash).unwrap()
    } else {
        flashconfig::load_or_create(&mut flash).unwrap()
    };

    let flash = &*singleton!(SunsetMutex::new(flash));

    let config = &*singleton!(SunsetMutex::new(config));

    let (wifi_net, wifi_pw) = {
        let c = config.lock().await;
        (c.wifi_net.clone(), c.wifi_pw.clone())
    };
    // spawn the wifi stack
    let (_, sm, _, _, _) = p.PIO0.split();
    let (stack, wifi_control) = wifi::wifi_stack(
        &spawner, p.PIN_23, p.PIN_24, p.PIN_25, p.PIN_29, p.DMA_CH0, sm, wifi_net,
        wifi_pw,
    )
    .await;
    let stack = &*singleton!(stack);
    let wifi_control = singleton!(SunsetMutex::new(wifi_control));
    spawner.spawn(net_task(&stack)).unwrap();

    let usb_pipe = singleton!(takepipe::TakePipe::new());
    let usb_pipe = singleton!(usb_pipe.base());

    let watchdog = singleton!(SunsetMutex::new(
        embassy_rp::watchdog::Watchdog::new(p.WATCHDOG)
    ));

    let state = GlobalState { usb_pipe, wifi_control, config, flash, watchdog };
    let state = singleton!(state);

    let usb_irq = interrupt::take!(USBCTRL_IRQ);
    spawner.spawn(usb_serial_task(p.USB, usb_irq, state)).unwrap();

    for _ in 0..NUM_LISTENERS {
        spawner.spawn(listener(&stack, config, state)).unwrap();
    }
}

// TODO: pool_size should be NUM_LISTENERS but needs a literal
#[embassy_executor::task(pool_size = 4)]
async fn listener(
    stack: &'static Stack<cyw43::NetDriver<'static>>,
    config: &'static SunsetMutex<SSHConfig>,
    ctx: &'static GlobalState,
) -> ! {
    demo_common::listener::<_, DemoShell>(stack, config, ctx).await
}

pub(crate) struct GlobalState {
    // If taking multiple mutexes, lock in the order below avoid inversion.
    pub usb_pipe: &'static TakeBase<'static>,
    pub wifi_control: &'static SunsetMutex<cyw43::Control<'static>>,
    pub config: &'static SunsetMutex<SSHConfig>,
    pub flash: &'static SunsetMutex<
        embassy_rp::flash::Flash<'static, FLASH, { flashconfig::FLASH_SIZE }>,
    >,
    pub watchdog: &'static SunsetMutex<embassy_rp::watchdog::Watchdog>,
}

struct DemoShell {
    notify: Signal<NoopRawMutex, ChanHandle>,
    ctx: &'static GlobalState,

    // Mutex is a bit of a bodge
    username: SunsetMutex<String<20>>,
}

// `local` is set for usb serial menus which require different auth
async fn menu<R, W>(
    mut chanr: R,
    mut chanw: W,
    local: bool,
    state: &'static GlobalState,
) -> Result<()>
where
    R: asynch::Read + Io<Error = sunset::Error>,
    W: asynch::Write + Io<Error = sunset::Error>,
{
    let mut menu_buf = [0u8; 64];
    let menu_ctx = picowmenu::MenuCtx::new(state);

    // let echo = !local;
    let echo = true;
    let mut menu =
        MenuRunner::new(&picowmenu::SETUP_MENU, &mut menu_buf, echo, menu_ctx);

    // Bodge. Isn't safe for local serial either since Linux would reply to those
    // bytes with echo (a terminal emulator isn't attached yet), and then we get
    // confused by it.
    if !local {
        for c in "help\r\n".bytes() {
            menu.input_byte(c);
        }
        menu.context.out.flush(&mut chanw).await?;
    }

    'io: loop {
        let mut b = [0u8; 20];
        let lr = chanr.read(&mut b).await?;
        if lr == 0 {
            break;
        }
        let b = &mut b[..lr];

        for c in b.iter() {
            menu.input_byte(*c);
            menu.context.out.flush(&mut chanw).await?;

            // TODO: move this to a function or something
            if menu.context.switch_usb1 {
                menu.context.switch_usb1 = false;
                if local {
                    writeln!(menu.context.out, "serial can't loop");
                } else {
                    if state.usb_pipe.is_in_use() {
                        writeln!(
                            menu.context.out,
                            "Opening usb1, stealing existing session"
                        );
                    } else {
                        writeln!(menu.context.out, "Opening usb1");
                    }
                    serial(chanr, chanw, state).await?;
                    // TODO we could return to the menu on serial error?
                    break 'io;
                }
            }

            if menu.context.need_save {
                info!("needs save");
                // clear regardless of success, don't want a tight loop.
                menu.context.need_save = false;

                let conf = state.config.lock().await;
                let mut fl = state.flash.lock().await;
                if let Err(_e) = flashconfig::save(&mut fl, &conf) {
                    warn!("Error writing flash");
                }
            }

            if menu.context.logout {
                break 'io;
            }

            if menu.context.reset {
                let _ = chanw.write_all(b"Resetting\r\n").await;
                let mut wd = state.watchdog.lock().await;
                wd.start(Duration::from_millis(200));
                loop {
                    embassy_time::Timer::after(Duration::from_secs(1)).await;
                }
            }

            // messages from handling
            menu.context.out.flush(&mut chanw).await?;
        }
    }
    Ok(())
}

async fn serial<R, W>(
    mut chanr: R,
    mut chanw: W,
    state: &'static GlobalState,
) -> Result<()>
where
    R: asynch::Read + Io<Error = sunset::Error>,
    W: asynch::Write + Io<Error = sunset::Error>,
{
    let (mut rx, mut tx) = state.usb_pipe.take().await;
    let r = async {
        // TODO: could have a single buffer to translate in-place.
        const DOUBLE: usize = 2 * takepipe::READ_SIZE;
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
            chanw.write_all(&btrans).await?;
        }
        #[allow(unreachable_code)]
        Ok::<(), sunset::Error>(())
    };
    let w = async {
        let mut b = [0u8; 64];
        loop {
            let n = chanr.read(&mut b).await?;
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

    select(r, w).await;
    info!("serial task completed");
    Ok(())
}

impl Shell for DemoShell {
    type Init = &'static GlobalState;

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
        info!("authed for {}", username);
        let mut u = self.username.lock().await;
        *u = username.try_into().unwrap_or(String::new());
    }

    async fn run<'f, S: ServBehaviour>(
        &self,
        serv: &'f SSHServer<'f, S>,
    ) -> Result<()> {
        let session = async {
            // wait for a shell to start
            let chan_handle = self.notify.wait().await;
            let stdio = serv.stdio(chan_handle).await?;

            if *self.username.lock().await == "config" {
                menu(stdio.clone(), stdio, false, self.ctx).await
            } else {
                serial(stdio.clone(), stdio, self.ctx).await
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
async fn usb_serial_task(
    usb: embassy_rp::peripherals::USB,
    irq: embassy_rp::interrupt::USBCTRL_IRQ,
    global: &'static GlobalState,
) -> ! {
    usbserial::usb_serial(usb, irq, global).await;
    todo!("shoudln't exit");
}
