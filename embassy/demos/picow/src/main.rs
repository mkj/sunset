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

use embassy_executor::Spawner;
use embassy_futures::select::select;
use embassy_net::Stack;
use embassy_rp::peripherals::FLASH;
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
mod serial;
mod takepipe;
mod usbserial;
mod wifi;

use demo_common::{SSHConfig, Shell};

use takepipe::TakePipe;

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
    let (stack, wifi_control) = wifi::wifi_stack(
        &spawner, p.PIN_23, p.PIN_24, p.PIN_25, p.PIN_29, p.DMA_CH0, p.PIO0,
        wifi_net, wifi_pw,
    )
    .await;
    let stack = &*singleton!(stack);
    let wifi_control = singleton!(SunsetMutex::new(wifi_control));
    spawner.spawn(net_task(&stack)).unwrap();

    let usb_pipe = {
        let p = singleton!(takepipe::TakePipeStorage::new());
        singleton!(p.pipe())
    };

    let serial1_pipe = {
        let s = singleton!(takepipe::TakePipeStorage::new());
        singleton!(s.pipe())
    };
    spawner
        .spawn(serial::task(
            p.UART0,
            p.PIN_0,
            p.PIN_1,
            p.PIN_2,
            p.PIN_3,
            serial1_pipe,
        ))
        .unwrap();

    let watchdog = singleton!(SunsetMutex::new(
        embassy_rp::watchdog::Watchdog::new(p.WATCHDOG)
    ));

    let state = GlobalState {
        usb_pipe,
        serial1_pipe,

        _wifi_control: wifi_control,
        config,
        flash,
        watchdog,
    };
    let state = singleton!(state);

    spawner.spawn(usbserial::task(p.USB, state)).unwrap();

    for _ in 0..NUM_LISTENERS {
        spawner.spawn(listener(&stack, config, state)).unwrap();
    }
}

// TODO: pool_size should be NUM_LISTENERS but needs a literal
#[embassy_executor::task(pool_size = 4)]
async fn listener(
    stack: &'static Stack<cyw43::NetDriver<'static>>,
    config: &'static SunsetMutex<SSHConfig>,
    global: &'static GlobalState,
) -> ! {
    demo_common::listener::<_, DemoShell>(stack, config, global).await
}

pub(crate) struct GlobalState {
    // If taking multiple mutexes, lock in the order below avoid inversion.
    pub usb_pipe: &'static TakePipe<'static>,
    pub serial1_pipe: &'static TakePipe<'static>,

    pub _wifi_control: &'static SunsetMutex<cyw43::Control<'static>>,
    pub config: &'static SunsetMutex<SSHConfig>,
    pub flash: &'static SunsetMutex<
        embassy_rp::flash::Flash<'static, FLASH, { flashconfig::FLASH_SIZE }>,
    >,
    pub watchdog: &'static SunsetMutex<embassy_rp::watchdog::Watchdog>,
}

struct DemoShell {
    notify: Signal<NoopRawMutex, ChanHandle>,
    global: &'static GlobalState,

    // Mutex is a bit of a bodge
    username: SunsetMutex<String<20>>,
}

// `local` is set for usb serial menus which require different auth
async fn menu<R, W>(
    chanr: &mut R,
    chanw: &mut W,
    local: bool,
    state: &'static GlobalState,
) -> Result<()>
where
    R: asynch::Read + Io<Error = sunset::Error>,
    W: asynch::Write + Io<Error = sunset::Error>,
{
    let mut menu_buf = [0u8; 64];
    let menu_ctx = picowmenu::MenuCtx::new(state, local);

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
        menu.context.out.flush(chanw).await?;
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
            menu.context.out.flush(chanw).await?;

            if menu.context.progress(chanr, chanw).await? {
                break 'io;
            }
        }
    }
    Ok(())
}

pub(crate) async fn serial<R, W>(
    chanr: &mut R,
    chanw: &mut W,
    serial_pipe: &'static TakePipe<'static>,
) -> Result<()>
where
    R: asynch::Read + Io<Error = sunset::Error>,
    W: asynch::Write + Io<Error = sunset::Error>,
{
    info!("start serial");
    let (mut rx, mut tx) = serial_pipe.take().await;
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

    fn new(global: &Self::Init) -> Self {
        Self {
            notify: Default::default(),
            global,
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
            let mut stdio = serv.stdio(chan_handle).await?;

            #[cfg(feature = "serial1")]
            let default_pipe = self.global.serial1_pipe;
            #[cfg(not(feature = "serial1"))]
            let default_pipe = self.global.usb_pipe;

            let username = self.username.lock().await;
            let mut stdio2 = stdio.clone();
            match username.as_str() {
                "config" => menu(&mut stdio, &mut stdio2, false, self.global).await,
                "usb" => serial(&mut stdio, &mut stdio2, self.global.usb_pipe).await,
                _ => serial(&mut stdio, &mut stdio2, default_pipe).await,
            }
        };

        session.await
    }
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<cyw43::NetDriver<'static>>) -> ! {
    stack.run().await
}
