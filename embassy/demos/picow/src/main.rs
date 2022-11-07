#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]

use core::future::Future;

use core::todo;
use defmt::*;
use embassy_executor::Spawner;
use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, CriticalSectionRawMutex};
use embassy_sync::signal::Signal;
use embassy_net::tcp::TcpSocket;
use embassy_net::{Stack, StackResources};
use embassy_rp::gpio::{Flex, Level, Output};
use embassy_futures::join::join;
use embassy_rp::peripherals::{PIN_23, PIN_24, PIN_25, PIN_29};
use embedded_hal_async::spi::{ExclusiveDevice, SpiBusFlush, SpiBusRead, SpiBusWrite};
use embedded_io::asynch::{Read, Write};
use static_cell::StaticCell;
use {defmt_rtt as _, panic_probe as _};

use core::str::FromStr;
use core::cell::RefCell;
use core::num::NonZeroU32;
use futures::{task::noop_waker_ref,pending};
use core::task::{Context,Poll,Waker,RawWaker,RawWakerVTable};
use pin_utils::{pin_mut,unsafe_pinned};
use core::pin::Pin;

use rand::rngs::OsRng;
use rand::RngCore;

use sunset::*;
use sunset_embassy::SSHServer;

mod wifi;

const NUM_LISTENERS: usize = 4;

macro_rules! singleton {
    ($val:expr) => {{
        type T = impl Sized;
        static STATIC_CELL: StaticCell<T> = StaticCell::new();
        STATIC_CELL.init_with(move || $val)
    }};
}

#[embassy_executor::task]
async fn net_task(stack: &'static Stack<cyw43::NetDevice<'static>>) -> ! {
    stack.run().await
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    info!("Hello World!");

    let mut p = embassy_rp::init(Default::default());

    caprand::setup(&mut p.PIN_25).unwrap();
    getrandom::register_custom_getrandom!(caprand::random);

    // TODO: move this to wifi mod

    // Include the WiFi firmware and Country Locale Matrix (CLM) blobs.
    let fw = include_bytes!("../firmware/43439A0.bin");
    let clm = include_bytes!("../firmware/43439A0_clm.bin");

    // To make flashing faster for development, you may want to flash the firmwares independently
    // at hardcoded addresses, instead of baking them into the program with `include_bytes!`:
    //     probe-rs-cli download 43439A0.bin --format bin --chip RP2040 --base-address 0x10100000
    //     probe-rs-cli download 43439A0.clm_blob --format bin --chip RP2040 --base-address 0x10140000
    //let fw = unsafe { core::slice::from_raw_parts(0x10100000 as *const u8, 224190) };
    //let clm = unsafe { core::slice::from_raw_parts(0x10140000 as *const u8, 4752) };

    let pwr = Output::new(p.PIN_23, Level::Low);
    let cs = Output::new(p.PIN_25, Level::High);
    let clk = Output::new(p.PIN_29, Level::Low);
    let mut dio = Flex::new(p.PIN_24);
    dio.set_low();
    dio.set_as_output();

    let bus = wifi::MySpi { clk, dio };
    let spi = ExclusiveDevice::new(bus, cs);

    let state = singleton!(cyw43::State::new());
    let (mut control, runner) = cyw43::new(state, pwr, spi, fw).await;

    spawner.spawn(wifi::wifi_task(runner)).unwrap();

    let net_device = control.init(clm).await;

    //control.join_open(env!("WIFI_NETWORK")).await;
    control.join_wpa2(env!("WIFI_NETWORK"), env!("WIFI_PASSWORD")).await;
    //control.join_wpa2("WIFI_NETWORK", "WIFI_PASSWORD").await;

    let config = embassy_net::ConfigStrategy::Dhcp;
    //let config = embassy_net::ConfigStrategy::Static(embassy_net::Config {
    //    address: Ipv4Cidr::new(Ipv4Address::new(192, 168, 69, 2), 24),
    //    dns_servers: Vec::new(),
    //    gateway: Some(Ipv4Address::new(192, 168, 69, 1)),
    //});

    let seed = OsRng.next_u64();

    // Init network stack
    let stack = &*singleton!(Stack::new(
        net_device,
        config,
        singleton!(StackResources::<1, 10, 8>::new()),
        seed
    ));

    unwrap!(spawner.spawn(net_task(stack)));

    for _ in 0..NUM_LISTENERS {
        spawner.spawn(listener(stack)).unwrap();
    }
}

// TODO: pool_size should be NUM_LISTENERS but needs a literal
#[embassy_executor::task(pool_size = 4)]
async fn listener(stack: &'static Stack<cyw43::NetDevice<'static>>) -> ! {
    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        socket.set_timeout(Some(embassy_net::SmolDuration::from_secs(10)));

        info!("Listening on TCP:22...");
        if let Err(e) = socket.accept(22).await {
            warn!("accept error: {:?}", e);
            continue;
        }

        let r = session(&mut socket).await;
        if let Err(_e) = r {
            // warn!("Ended with error: {:?}", e);
            warn!("Ended with error");
        }
    }
}

struct DemoServer {
    keys: [SignKey; 1],

    sess: Option<u32>,
    want_shell: bool,
    shell_started: bool,

    notify: Signal<CriticalSectionRawMutex, ()>,
}

impl DemoServer {
    fn new() -> Result<Self> {
        let keys = [SignKey::generate(KeyType::Ed25519)?];

        Ok(Self {
            sess: None,
            keys,
            want_shell: false,
            shell_started: false,
            notify: Signal::new(),
        })
    }
}

impl ServBehaviour for DemoServer {
    fn hostkeys(&mut self) -> BhResult<&[SignKey]> {
        Ok(&self.keys)
    }


    fn have_auth_password(&self, user: TextString) -> bool {
        true
    }

    fn have_auth_pubkey(&self, user: TextString) -> bool {
        true
    }

    fn auth_unchallenged(&mut self, username: TextString) -> bool {
        let u = username.as_str().unwrap_or("mystery user");
        info!("Allowing auth for user {}", u);
        true
    }

    fn auth_password(&mut self, user: TextString, password: TextString) -> bool {
        user.as_str().unwrap_or("") == "matt" && password.as_str().unwrap_or("") == "pw"
    }

    // fn auth_pubkey(&mut self, user: TextString, pubkey: &PubKey) -> bool {
    //     if user.as_str().unwrap_or("") != "matt" {
    //         return false
    //     }

    //     // key is tested1
    //     pubkey.matches_openssh("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMkNdReJERy1rPGqdfTN73TnayPR+lTNhdZvOgkAOs5x")
    //     .unwrap_or_else(|e| {
    //         warn!("Failed loading openssh key: {e}");
    //         false
    //     })
    // }

    fn open_session(&mut self, chan: u32) -> ChanOpened {
        if self.sess.is_some() {
            ChanOpened::Failure(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
        } else {
            self.sess = Some(chan);
            ChanOpened::Success
        }
    }

    fn sess_shell(&mut self, chan: u32) -> bool {
        let r = !self.want_shell && self.sess == Some(chan);
        self.want_shell = true;
        trace!("req want shell");
        r
    }

    fn sess_pty(&mut self, chan: u32, _pty: &Pty) -> bool {
        self.sess == Some(chan)
    }
}

async fn session(socket: &mut TcpSocket<'_>) -> sunset::Result<()> {
    let mut app = DemoServer::new()?;

    let mut ssh_rxbuf = [0; 2000];
    let mut ssh_txbuf = [0; 2000];
    let serv = SSHServer::new(&mut ssh_rxbuf, &mut ssh_txbuf, &mut app)?;
    let serv = &serv;

    let app = Mutex::<NoopRawMutex, _>::new(app);
    let app = &app as &Mutex::<NoopRawMutex, dyn ServBehaviour>;

    let run = serv.run(socket, app);

    let session = async {
        loop {
        }
    };

    // TODO: handle results
    join(run, session).await;

    Ok(())
}
