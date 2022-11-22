#![feature(type_alias_impl_trait)]

#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
use {
    log::{debug, error, info, log, trace, warn},
};

#[cfg(feature = "defmt")]
use defmt::{debug, info, warn, panic, error, trace};

use core::future::Future;

use embassy_executor::{Spawner, Executor};
use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::{NoopRawMutex, CriticalSectionRawMutex};
use embassy_sync::signal::Signal;
use embassy_net::tcp::TcpSocket;
use embassy_net::{Stack, Device, StackResources, ConfigStrategy};
use embassy_futures::join::join;
use static_cell::StaticCell;

use menu::Runner as MenuRunner;
use menu::Menu;

use sunset::*;
use sunset::error::TrapBug;
use sunset_embassy::SSHServer;

mod demo_menu;

#[macro_export]
macro_rules! singleton {
    ($val:expr) => {{
        type T = impl Sized;
        static STATIC_CELL: StaticCell<T> = StaticCell::new();
        STATIC_CELL.init_with(move || $val)
    }};
}

pub struct SSHConfig {
    keys: [SignKey; 1],
}

impl SSHConfig {
    pub fn new() -> Result<Self> {
        let keys = [SignKey::generate(KeyType::Ed25519)?];
        Ok(Self {
            keys
        })
    }
}

// main entry point
pub async fn listener<D: Device>(stack: &'static Stack<D>, config: &SSHConfig) -> ! {
    let mut rx_buffer = [0; 4096];
    let mut tx_buffer = [0; 4096];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

        info!("Listening on TCP:22...");
        if let Err(e) = socket.accept(22).await {
            warn!("accept error: {:?}", e);
            continue;
        }

        let r = session(&mut socket, &config).await;
        if let Err(_e) = r {
            // warn!("Ended with error: {:?}", e);
            warn!("Ended with error");
        }
    }
}

struct DemoServer<'a> {
    config: &'a SSHConfig,

    sess: Option<u32>,
    shell_started: bool,

    shell: &'a DemoShell,
}

impl<'a> DemoServer<'a> {
    fn new(shell: &'a DemoShell, config: &'a SSHConfig) -> Result<Self> {

        Ok(Self {
            sess: None,
            config,
            shell_started: false,
            shell,
        })
    }
}

impl<'a> ServBehaviour for DemoServer<'a> {
    fn hostkeys(&mut self) -> BhResult<&[SignKey]> {
        Ok(&self.config.keys)
    }

    fn auth_unchallenged(&mut self, username: TextString) -> bool {
        info!("Allowing auth for user {}", username.as_str().unwrap_or("bad"));
        true
    }

    fn open_session(&mut self, chan: u32) -> ChanOpened {
        if self.sess.is_some() {
            ChanOpened::Failure(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
        } else {
            self.sess = Some(chan);
            ChanOpened::Success
        }
    }

    fn sess_shell(&mut self, chan: u32) -> bool {
        let r = !self.shell_started && self.sess == Some(chan);
        self.shell_started = true;
        self.shell.notify.signal(chan);
        trace!("req want shell");
        r
    }

    fn sess_pty(&mut self, chan: u32, _pty: &Pty) -> bool {
        self.sess == Some(chan)
    }
}


#[derive(Default)]
struct DemoShell {
    notify: Signal<CriticalSectionRawMutex, u32>,
}

impl DemoShell {
    async fn run<'f>(&self, serv: &SSHServer<'f>) -> Result<()>
    {
        let session = async {
            // wait for a shell to start
            let chan = self.notify.wait().await;

            let mut menu_buf = [0u8; 64];
            let menu_out = demo_menu::Output::default();

            let mut menu = MenuRunner::new(&demo_menu::ROOT_MENU, &mut menu_buf, menu_out);

            loop {
                let mut b = [0u8; 20];
                let lr = serv.read_channel_stdin(chan, &mut b).await?;
                let b = &mut b[..lr];
                for c in b.iter() {
                    menu.input_byte(*c);
                    menu.context.flush(serv, chan).await?;
                }
            }
            Ok(())
        };

        session.await
    }
}


async fn session(socket: &mut TcpSocket<'_>, config: &SSHConfig) -> sunset::Result<()> {
    let shell = DemoShell::default();
    let app = DemoServer::new(&shell, config)?;

    let mut ssh_rxbuf = [0; 2000];
    let mut ssh_txbuf = [0; 2000];
    let serv = SSHServer::new(&mut ssh_rxbuf, &mut ssh_txbuf)?;
    let serv = &serv;

    let app = Mutex::<NoopRawMutex, _>::new(app);

    let session = shell.run(serv);

    let app = &app as &Mutex::<NoopRawMutex, dyn ServBehaviour>;
    let run = serv.run(socket, app);

    join(run, session).await;

    Ok(())
}
