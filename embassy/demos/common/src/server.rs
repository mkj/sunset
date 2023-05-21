//! Shared between `picow` and `std` Embassy demos
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
use embassy_net::tcp::TcpSocket;
use embassy_net::Stack;
use embassy_net_driver::Driver;
use embassy_futures::join::join;
use embassy_futures::select::{select, Either};
use embassy_time::{Duration, Timer};

use embedded_io::asynch;

use heapless::String;

use sunset::*;
use sunset_embassy::{SSHServer, SunsetMutex};

use crate::SSHConfig;

// #[macro_export]
// macro_rules! singleton {
//     ($val:expr) => {{
//         type T = impl Sized;
//         static STATIC_CELL: StaticCell<T> = StaticCell::new();
//         STATIC_CELL.init($val)
//     }};
// }
#[macro_export]
macro_rules! singleton {
    ($val:expr) => {{
        type T = impl Sized;
        static STATIC_CELL: StaticCell<T> = StaticCell::new();
        let (x,) = STATIC_CELL.init(($val,));
        x
    }};
}


// common entry point
pub async fn listener<D: Driver, S: Shell>(stack: &'static Stack<D>,
    config: &SunsetMutex<SSHConfig>,
    init: S::Init) -> ! {
    // TODO: buffer size?
    // Does it help to be larger than ethernet MTU?
    // Should TX and RX be symmetrical? Or larger TX might fill ethernet
    // frames more efficiently, RX doesn't matter so much?
    // How does this interact with the channel copy buffer sizes?
    let mut rx_buffer = [0; 1550];
    let mut tx_buffer = [0; 4500];

    loop {
        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);
        // socket.set_nagle_enabled(false);

        info!("Listening on TCP:22...");
        if let Err(_) = socket.accept(22).await {
            warn!("accept error");
            continue;
        }

        let r = session::<S>(&mut socket, &config, &init).await;
        if let Err(_e) = r {
            // warn!("Ended with error: {:?}", e);
            warn!("Ended with error");
        }

        // Make sure a TCP socket reset is sent to the remote host
        socket.abort();

        // TODO: Replace this with something proper like
        // https://github.com/embassy-rs/embassy/pull/1471
        Timer::after(Duration::from_millis(200)).await;
    }
}

/// Run a SSH session when a socket accepts a connection
async fn session<S: Shell>(socket: &mut TcpSocket<'_>, config: &SunsetMutex<SSHConfig>,
    init: &S::Init) -> sunset::Result<()> {
    // OK unwrap: has been accepted
    let src = socket.remote_endpoint().unwrap();
    info!("Connection from {}:{}", src.addr, src.port);

    let shell = S::new(init);

    let conf = config.lock().await.clone();
    let app = DemoServer::new(&shell, conf)?;
    let app = Mutex::<NoopRawMutex, _>::new(app);

    let mut ssh_rxbuf = [0; 2000];
    let mut ssh_txbuf = [0; 2000];
    let serv = SSHServer::new(&mut ssh_rxbuf, &mut ssh_txbuf)?;
    let serv = &serv;

    let session = shell.run(serv);

    let (mut rsock, mut wsock) = socket.split();

    let run = serv.run(&mut rsock, &mut wsock, &app);

    let f = select(run, session).await;
    match f {
        Either::First(r) => r?,
        Either::Second(r) => r?,
    }

    Ok(())
}

struct DemoServer<'a, S: Shell> {
    config: SSHConfig,

    handle: Option<ChanHandle>,
    sess: Option<ChanNum>,

    shell: &'a S,
}

impl<'a, S: Shell> DemoServer<'a, S> {
    fn new(shell: &'a S, config: SSHConfig) -> Result<Self> {

        Ok(Self {
            handle: None,
            sess: None,
            config,
            shell,
        })
    }
}

impl<'a, S: Shell> ServBehaviour for DemoServer<'a, S> {
    fn hostkeys(&mut self) -> BhResult<heapless::Vec<&SignKey, 2>> {
        // OK unwrap: only one element
        Ok(heapless::Vec::from_slice(&[&self.config.hostkey]).unwrap())
    }

    async fn auth_unchallenged(&mut self, username: TextString<'_>) -> bool {
        info!("Allowing auth for user {}", username.as_str().unwrap_or("bad"));
        self.shell.authed(username.as_str().unwrap_or("")).await;
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
            self.shell.open_shell(handle);
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

pub trait Shell {
    type Init: Copy;

    fn new(init: &Self::Init) -> Self;

    #[allow(unused_variables)]
    // TODO: eventually the compiler should add must_use automatically?
    async fn authed(&self, username: &str) {
        info!("Authenticated")
    }

    fn open_shell(&self, handle: ChanHandle);

    #[must_use]
    async fn run<'f, S: ServBehaviour>(&self, serv: &'f SSHServer<'f, S>) -> Result<()>;
}


/// A wrapper writing `Menu` output into a buffer that can be later written
/// asynchronously to a channel.
#[derive(Default)]
pub struct BufOutput {
    /// Sufficient to hold output produced from a single keystroke input. Further output will be discarded
    s: heapless::String<300>,
}

impl BufOutput {
    pub async fn flush<W>(&mut self, w: &mut W) -> Result<()>
    where W: asynch::Write + embedded_io::Io<Error = sunset::Error>
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

