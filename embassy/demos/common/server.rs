#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
use {
    log::{debug, error, info, log, trace, warn},
};

#[allow(unused)]
#[cfg(feature = "defmt")]
use defmt::{debug, info, warn, panic, error, trace};

use embassy_sync::mutex::Mutex;
use embassy_sync::blocking_mutex::raw::NoopRawMutex;
use embassy_sync::signal::Signal;
use embassy_net::tcp::TcpSocket;
use embassy_net::Stack;
use embassy_net_driver::Driver;
use embassy_futures::join::join;

use menu::Runner as MenuRunner;
use embedded_io::asynch::Read;

use sunset::*;
use sunset_embassy::SSHServer;

mod demo_menu;

#[macro_export]
macro_rules! singleton {
    ($val:expr) => {{
        type T = impl Sized;
        static STATIC_CELL: StaticCell<T> = StaticCell::new();
        STATIC_CELL.init($val)
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
pub async fn listener<D: Driver>(stack: &'static Stack<D>, config: &SSHConfig) -> ! {
    // TODO: buffer size?
    // Does it help to be larger than ethernet MTU?
    // Should TX and RX be symmetrical? Or larger TX might fill ethernet
    // frames more efficiently, RX doesn't matter so much?
    // How does this interact with the channel copy buffer sizes?
    let mut rx_buffer = [0; 1550];
    let mut tx_buffer = [0; 1550];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        // TODO: disable nagle. smoltcp supports it, requires embassy-net addition

        info!("Listening on TCP:22...");
        if let Err(_) = socket.accept(22).await {
            warn!("accept error");
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

    handle: Option<ChanHandle>,
    sess: Option<ChanNum>,

    shell: &'a DemoShell,
}

impl<'a> DemoServer<'a> {
    fn new(shell: &'a DemoShell, config: &'a SSHConfig) -> Result<Self> {

        Ok(Self {
            handle: None,
            sess: None,
            config,
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

    fn open_session(&mut self, chan: ChanHandle) -> ChanOpened {
        if self.sess.is_some() {
            ChanOpened::Failure((ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, chan))
        } else {
            self.sess = Some(chan.num());
            self.handle = Some(chan);
            ChanOpened::Success
        }
    }

    fn sess_shell(&mut self, chan: ChanNum) -> bool {
        if self.sess != Some(chan) {
            return false
        }

        if let Some(handle) = self.handle.take() {
            debug_assert_eq!(self.sess, Some(handle.num()));
            self.shell.notify.signal(handle);
            trace!("req want shell");
            true
        } else {
            false
        }
    }

    fn sess_pty(&mut self, chan: ChanNum, _pty: &Pty) -> bool {
        self.sess == Some(chan)
    }

    fn disconnected(&mut self, desc: TextString) {
        info!("Disconnect by client: {}", desc.as_str().unwrap_or("bad"));
    }
}

#[derive(Default)]
struct DemoShell {
    notify: Signal<NoopRawMutex, ChanHandle>,
}

impl DemoShell {
    async fn run<'f>(&self, serv: &'f SSHServer<'f>) -> Result<()>
    {
        let session = async {
            // wait for a shell to start
            let chan_handle = self.notify.wait().await;

            let mut stdio = serv.stdio(chan_handle).await?;

            let mut menu_buf = [0u8; 64];
            let menu_out = demo_menu::Output::default();

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
                }
                menu.context.flush(&mut stdio).await?;
            }
            Ok(())
        };

        session.await
    }
}


async fn session(socket: &mut TcpSocket<'_>, config: &SSHConfig) -> sunset::Result<()> {
    // OK unwrap: has been accepted
    let src = socket.remote_endpoint().unwrap();
    info!("Connection from {}:{}", src.addr, src.port);

    let shell = DemoShell::default();

    let app = DemoServer::new(&shell, config)?;
    let app = Mutex::<NoopRawMutex, _>::new(app);
    let app = &app as &Mutex::<NoopRawMutex, dyn ServBehaviour>;

    let mut ssh_rxbuf = [0; 2000];
    let mut ssh_txbuf = [0; 2000];
    let serv = SSHServer::new(&mut ssh_rxbuf, &mut ssh_txbuf)?;
    let serv = &serv;

    let session = shell.run(serv);

    let (mut rsock, mut wsock) = socket.split();

    let run = serv.run(&mut rsock, &mut wsock, app);

    let (r1, r2) = join(run, session).await;
    r1?;
    r2?;

    Ok(())
}
