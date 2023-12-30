#![no_std]
#![no_main]

#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use log::{debug, error, info, log, trace, warn};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, error, info, panic, trace, warn};

use {defmt_rtt as _, panic_probe as _};

use embassy_executor::Spawner;
use embassy_futures::select::select;
use embassy_net::{Stack, HardwareAddress, EthernetAddress};
use embedded_io_async::{Write, Read};

use heapless::{String, Vec};

use static_cell::StaticCell;

use demo_common::menu::Runner as MenuRunner;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;

use sunset::*;
use sunset_embassy::{SSHServer, SunsetMutex};

pub(crate) use sunset_demo_embassy_common as demo_common;

mod flashconfig;
mod picowmenu;
mod serial;
mod usb;
mod keyboard;
#[cfg(feature = "w5500")]
mod w5500;
#[cfg(feature = "cyw43")]
mod wifi;

#[cfg(not(any(feature = "cyw43", feature = "w5500")))]
compile_error!("No network device selected. Use cyw43 or w5500 feature");

#[cfg(all(feature = "cyw43", feature = "w5500"))]
compile_error!("Select only one of cyw43 or w5500");

use demo_common::{SSHConfig, DemoServer, takepipe};

use takepipe::TakePipe;

const NUM_LISTENERS: usize = 4;
// +1 for dhcp. referenced directly by wifi_stack() function
pub(crate) const NUM_SOCKETS: usize = NUM_LISTENERS + 1;

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Welcome to Sunset SSH");

    let mut p = embassy_rp::init(Default::default());

    // RNG initialised early, all crypto relies on it
    caprand::setup(&mut p.PIN_10).unwrap();
    getrandom::register_custom_getrandom!(caprand::getrandom);

    // Configuration loaded from flash
    let mut flash = flashconfig::Fl::new(p.FLASH, p.DMA_CH2);

    let config = if option_env!("RESET_CONFIG").is_some() {
        flashconfig::create(&mut flash).await.unwrap()
    } else {
        flashconfig::load_or_create(&mut flash).await.unwrap()
    };
    static FLASH: StaticCell<SunsetMutex<flashconfig::Fl>> = StaticCell::new();
    let flash = FLASH.init(SunsetMutex::new(flash));
    static CONFIG: StaticCell<SunsetMutex<SSHConfig>> = StaticCell::new();
    let config = CONFIG.init(SunsetMutex::new(config));

    // A shared pipe to a local USB-serial (CDC)
    static USBS: StaticCell<takepipe::TakePipeStorage> = StaticCell::new();
    static USBP: StaticCell<takepipe::TakePipe> = StaticCell::new();
    let usb_pipe = {
        let p = USBS.init(Default::default());
        USBP.init_with(|| p.build())
    };

    // A shared pipe to a local uart
    static SERS: StaticCell<takepipe::TakePipeStorage> = StaticCell::new();
    static SERP: StaticCell<takepipe::TakePipe> = StaticCell::new();
    let serial1_pipe = {
        let p = SERS.init(Default::default());
        SERP.init_with(|| p.build())
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

    // Watchdog currently only used for triggering reset manually
    static WD: StaticCell<SunsetMutex<embassy_rp::watchdog::Watchdog>> = StaticCell::new();
    let watchdog = WD.init(SunsetMutex::new(
        embassy_rp::watchdog::Watchdog::new(p.WATCHDOG)
    ));

    static STATE: StaticCell<GlobalState> = StaticCell::new();
    let state;

    // Spawn network tasks to handle incoming connections with demo_common::session()

    #[cfg(feature = "cyw43")]
    {
        let stack = wifi::wifi_stack(
            &spawner, p.PIN_23, p.PIN_24, p.PIN_25, p.PIN_29, p.DMA_CH0, p.PIO0,
            config,
        )
        .await;

        let net_mac = match stack.hardware_address() {
            HardwareAddress::Ethernet(EthernetAddress(eth)) => eth,
        };
        state = STATE.init_with(|| GlobalState { usb_pipe, serial1_pipe, config, flash, watchdog, net_mac });
        for _ in 0..NUM_LISTENERS {
            spawner.spawn(cyw43_listener(&stack, config, state)).unwrap();
        }
    }


    #[cfg(feature = "w5500")]
    {
        let stack = w5500::w5500_stack(
            &spawner, p.PIN_16, p.PIN_17, p.PIN_18, p.PIN_19, p.PIN_20, p.PIN_21,
            p.DMA_CH0, p.DMA_CH1, p.SPI0, config,
        )
        .await;

        let net_mac = match stack.hardware_address() {
            HardwareAddress::Ethernet(EthernetAddress(eth)) => eth,
        };
        state = STATE.init_with(|| GlobalState { usb_pipe, serial1_pipe, config, flash, watchdog, net_mac });
        for _ in 0..NUM_LISTENERS {
            spawner.spawn(w5500_listener(&stack, config, state)).unwrap();
        }
    }

    // USB task requires `state`
    spawner.spawn(usb::task(p.USB, state)).unwrap();
}

// TODO: pool_size should be NUM_LISTENERS but needs a literal
#[cfg(feature = "cyw43")]
#[embassy_executor::task(pool_size = 4)]
async fn cyw43_listener(
    stack: &'static Stack<cyw43::NetDriver<'static>>,
    config: &'static SunsetMutex<SSHConfig>,
    global: &'static GlobalState,
) -> ! {
    demo_common::listener::<_, PicoServer>(stack, config, global).await
}

#[cfg(feature = "w5500")]
#[embassy_executor::task(pool_size = 4)]
async fn w5500_listener(
    stack: &'static Stack<embassy_net_wiznet::Device<'static>>,
    config: &'static SunsetMutex<SSHConfig>,
    global: &'static GlobalState,
) -> ! {
    demo_common::listener::<_, PicoServer>(stack, config, global).await
}

pub(crate) struct GlobalState {
    // If locking multiple mutexes, always lock in the order below avoid inversion.
    pub usb_pipe: &'static TakePipe<'static>,
    pub serial1_pipe: &'static TakePipe<'static>,

    pub config: &'static SunsetMutex<SSHConfig>,
    pub flash: &'static SunsetMutex<flashconfig::Fl<'static>>,
    pub watchdog: &'static SunsetMutex<embassy_rp::watchdog::Watchdog>,

    pub net_mac: [u8; 6],
}

struct PicoServer {
    notify: Signal<NoopRawMutex, ChanHandle>,
    global: &'static GlobalState,

    // Mutex is a bit of a bodge
    username: SunsetMutex<String<20>>,
}

// Presents a menu, either on serial or incoming SSH
//
// `local` is set for usb serial menus which require different auth
async fn menu<R, W>(
    chanr: &mut R,
    chanw: &mut W,
    local: bool,
    state: &'static GlobalState,
) -> Result<()>
where
    R: Read<Error = sunset::Error>,
    W: Write<Error = sunset::Error>,
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

/// Forwards an incoming SSH connection to a local serial port, either uart or USB
pub(crate) async fn serial<R, W>(
    chanr: &mut R,
    chanw: &mut W,
    serial_pipe: &'static TakePipe<'static>,
) -> Result<()>
where
    R: Read<Error = sunset::Error>,
    W: Write<Error = sunset::Error>,
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

impl DemoServer for PicoServer {
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

    async fn run<'f>(
        &self,
        serv: &'f SSHServer<'f>,
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
