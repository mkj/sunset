//! Shared between `picow` and `std` Embassy demos
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use embassy_net::tcp::TcpSocket;
use embassy_net::Stack;
use embassy_net_driver::Driver;
use embassy_futures::select::{select, Either};

use embedded_io_async::Write;

use heapless::String;

use sunset::{event::{ServFirstAuth, ServOpenSession, ServPasswordAuth, ServPubkeyAuth}, *};
use sunset_embassy::{SSHServer, SunsetMutex};

use crate::SSHConfig;

// common entry point
pub async fn listener<D: Driver, S: DemoServer>(stack: &'static Stack<D>,
    config: &SunsetMutex<SSHConfig>,
    init: S::Init) -> ! {
    // TODO: buffer size?
    // Does it help to be larger than ethernet MTU?
    // Should TX and RX be symmetrical? Or larger TX might fill ethernet
    // frames more efficiently, RX doesn't matter so much?
    // How does this interact with the channel copy buffer sizes?
    let mut rx_buffer = [0; 1550];
    let mut tx_buffer = [0; 1550];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        // socket.set_nagle_enabled(false);

        info!("Listening on TCP:22...");
        if let Err(_) = socket.accept(22).await {
            warn!("accept error");
            continue;
        }

        let r = session::<S>(&mut socket, &config, &init).await;
        if let Err(e) = r {
            warn!("Ended with error {e:#?}");
        }

        // Make sure a TCP socket reset is sent on exit to the remote host
        socket.abort();
        if let Err(e) = socket.flush().await {
            warn!("Ended with error {e:?}");
        }
    }
}

/// Run a SSH session when a socket accepts a connection
async fn session<S: DemoServer>(socket: &mut TcpSocket<'_>, config: &SunsetMutex<SSHConfig>,
    init: &S::Init) -> sunset::Result<()> {
    // OK unwrap: has been accepted
    let src = socket.remote_endpoint().unwrap();
    info!("Connection from {}:{}", src.addr, src.port);

    // Create the SSH instance. These buffers are for decoding/encoding
    // SSH packets.
    let mut ssh_rxbuf = [0; 2000];
    let mut ssh_txbuf = [0; 1000];
    let serv = SSHServer::new(&mut ssh_rxbuf, &mut ssh_txbuf)?;

    // Create the handler. ServerApp is common handling (this file),
    // demo is the specific demo (std or picow).
    let demo = S::new(init);
    let conf = config.lock().await.clone();
    let app = ServerApp::new(conf)?;
    // .run returns a future that runs for the life of the session
    let session = demo.run(&serv, app);

    // Connect the SSH instance to the sockets, .run is a future
    // that reads and writes sockets.
    let (mut rsock, mut wsock) = socket.split();
    let run = serv.run(&mut rsock, &mut wsock);

    // Run until completion
    match select(run, session).await {
        Either::First(r) => r,
        Either::Second(r) => r,
    }
}

/// Provides `ServBehaviour` for the server
///
/// Further customisations are provided by `DemoServer` generic
pub struct ServerApp {
    config: SSHConfig,

    opened: bool,
    // Can be taken by the demoserver to run an interactive session.
    pub sess: Option<ChanHandle>,
}

impl ServerApp {
    const ADMIN_USER: &'static str = "config";

    fn new(config: SSHConfig) -> Result<Self> {

        Ok(Self {
            sess: None,
            opened: false,
            config,
        })
    }

    // Handles most events except for shell and Defunct
    pub fn handle_event(&mut self, event: ServEvent) -> Result<()> {
        trace!("ev {event:?}");
        match event {
            ServEvent::Hostkeys(h) => h.hostkeys(&[&self.config.hostkey]),
            ServEvent::FirstAuth(a) => {
                self.handle_firstauth(a)
            }
            ServEvent::PasswordAuth(a) => {
                self.handle_password(a)
            }
            | ServEvent::PubkeyAuth(a) => {
                self.handle_pubkey(a)
            }
            ServEvent::OpenSession(a) => {
                self.open_session(a)
            }
            ServEvent::SessionPty(a) => {
                a.succeed()
            }
            ServEvent::SessionExec(a) => {
                a.fail()
            }
            | ServEvent::Defunct
            | ServEvent::SessionShell(_) => {
                error!("Expected caller to handle {event:?}");
                error::BadUsage.fail()
            }
        }
    }

    fn handle_password(&mut self, a: ServPasswordAuth) -> Result<()> {
        let username = match a.username() {
            Ok(u) => u,
            Err(_) => return Ok(()),
        };
        let password = match a.password() {
            Ok(u) => u,
            Err(_) => return Ok(()),
        };

        let p = if self.is_admin(username) {
            &self.config.admin_pw
        } else {
            &self.config.console_pw
        };
        let p = match p {
            Some(u) => u,
            None => return Ok(()),
        };

        if p.check(password) {
            a.allow()?
        }
        Ok(())
    }

    fn handle_pubkey(&mut self, a: ServPubkeyAuth) -> Result<()> {
        a.deny()
    }

    fn handle_firstauth(&self, a: ServFirstAuth) -> Result<()> {
        let username = a.username()?;
        if !self.is_admin(username) && self.config.console_noauth {
            info!("Allowing auth for user {username}");
            return a.allow()
        };

        // a.pubkey().password()
        Ok(())
    }

    fn open_session(&mut self, a: ServOpenSession) -> Result<()> {
        if self.opened {
            // only allow one session
            a.reject(ChanFail::SSH_OPEN_ADMINISTRATIVELY_PROHIBITED)
        } else {
            self.opened = true;
            // store the ChanHandle for the DemoServer to use
            self.sess = Some(a.accept()?);
            Ok(())
        }
    }

    fn is_admin(&self, username: &str) -> bool {
        username == Self::ADMIN_USER
    }
}

pub trait DemoServer {
    /// State to be passed to each new connection by the server
    type Init;

    fn new(init: &Self::Init) -> Self;

    /// A task to run for each incoming connection.
    async fn run(&self, serv: &SSHServer<'_>, common: ServerApp) -> Result<()>;
}


/// A wrapper writing `Menu` output into a buffer that can be later written
/// asynchronously to a channel.
#[derive(Default)]
pub struct BufOutput {
    /// Sufficient to hold output produced from a single keystroke input. Further output will be discarded
    // pub s: String<300>,
    // todo size
    pub s: String<500>,
}

impl BufOutput {
    pub async fn flush<W>(&mut self, w: &mut W) -> Result<()>
    where W: Write<Error = sunset::Error>
    {
        let mut b = self.s.as_str().as_bytes();
        while b.len() > 0 {
            let l = w.write(b).await?;
            b = &b[l..];
        }
        self.s.clear();
        Ok(())
    }
}

impl core::fmt::Write for BufOutput {
    fn write_str(&mut self, s: &str) -> Result<(), core::fmt::Error> {
        let mut inner = || {
            for c in s.chars() {
                if c == '\n' {
                    self.s.push('\r').map_err(|_| core::fmt::Error)?;
                }
                self.s.push(c).map_err(|_| core::fmt::Error)?;
            }
            Ok::<_, core::fmt::Error>(())
        };

        if inner().is_err() {
            trace!("Buffer full in BufOutput");
        }

        Ok(())
    }
}

