use futures::pin_mut;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};
use sunset::event::CliEvent;

use core::str::FromStr;
use core::fmt::Debug;

use sunset::{AuthSigMsg, SignKey, OwnedSig, Pty, sshnames};
use sunset::{Error, Result, Runner, SessionCommand};
use sunset_embassy::*;

use std::collections::VecDeque;
use embassy_sync::channel::{Channel, Sender, Receiver};
use embassy_sync::signal::Signal;
use embedded_io_async::{Read as _, Write as _};

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::signal::unix::{signal, SignalKind};

use futures::{select_biased, future::Fuse};
use futures::FutureExt;

use crate::*;
use crate::AgentClient;
use crate::{raw_pty, RawPtyGuard};
use crate::pty::win_size;

/// A commandline client session
///
/// This opens a single channel and presents it to the stdin/stdout terminal.
pub struct CmdlineClient {
    cmd: SessionCommand<String>,
    want_pty: bool,

    // parameters
    authkeys: VecDeque<SignKey>,
    username: String,
    host: String,
    port: u16,
    agent: Option<AgentClient>,

    pty_guard: Option<RawPtyGuard>,

    pty: Option<Pty>,
}

impl CmdlineClient {
    pub fn new(username: impl AsRef<str>, host: impl AsRef<str>) -> Self {
        Self {
            cmd: SessionCommand::Shell,
            want_pty: false,
            agent: None,

            username: username.as_ref().into(),
            host: host.as_ref().into(),
            port: sshnames::SSH_PORT,
            authkeys: Default::default(),
            pty: None,
            pty_guard: None,
        }
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    pub fn pty(&mut self) -> &mut Self {
        match pty::current_pty() {
            Ok(p) => {
                self.pty = Some(p);
                self.want_pty = true;
            },
            Err(e) => warn!("Failed getting current pty: {e:?}"),
        };
        self
    }

    pub fn exec(&mut self, cmd: &str) -> &mut Self {
        self.cmd = SessionCommand::Exec(cmd.into());
        self
    }

    pub fn subsystem(&mut self, subsystem: &str) -> &mut Self {
        self.cmd = SessionCommand::Subsystem(subsystem.into());
        self
    }

    pub fn add_authkey(&mut self, k: SignKey) {
        self.authkeys.push_back(k)
    }

    pub fn agent(&mut self, agent: AgentClient) {
        self.agent = Some(agent)
    }

    async fn chan_run(io: ChanInOut<'_, '_>,
        io_err: Option<ChanIn<'_, '_>>,
        pty_guard: Option<RawPtyGuard>) -> Result<()> {
        // out
        let fo = async {
            let mut io = io.clone();
            let mut so = crate::stdout().map_err(|_| {
                Error::msg("opening stdout failed")
            })?;
            loop {
                // TODO buffers
                let mut buf = [0u8; 1000];
                let l = io.read(&mut buf).await?;
                if l == 0 {
                    break;
                }
                so.write_all(&buf[..l]).await.map_err(|_| Error::ChannelEOF)?;
            }
            #[allow(unreachable_code)]
            Ok::<_, sunset::Error>(())
        };

        // err
        let fe = async {
            // if io_err is None we complete immediately
            if let Some(mut errin) = io_err {
                let mut eo = crate::stderr_out().map_err(|_e| {
                    Error::msg("opening stderr failed")
                })?;
                loop {
                    // TODO buffers
                    let mut buf = [0u8; 1000];
                    let l = errin.read(&mut buf).await?;
                    if l == 0 {
                        break;
                    }
                    eo.write_all(&buf[..l]).await.map_err(|_| Error::ChannelEOF)?;
                }
                #[allow(unreachable_code)]
                Ok::<_, sunset::Error>(())
            } else {
                Ok(())
            }
        };

        let terminate = Signal::<SunsetRawMutex, ()>::new();

        // in
        let fi = async {
            let mut io = io.clone();
            let mut si = crate::stdin().map_err(|_| Error::msg("opening stdin failed"))?;
            let mut esc = if pty_guard.is_some() {
                Some(Escaper::new())
            } else {
                None
            };

            loop {
                // TODO buffers
                let mut buf = [0u8; 1000];
                let l = si.read(&mut buf).await.map_err(|_| Error::ChannelEOF)?;
                if l == 0 {
                    return Err(Error::ChannelEOF)
                }

                let buf = &buf[..l];

                if let Some(ref mut esc) = esc {
                    let a = esc.escape(buf);
                    match a {
                        EscapeAction::None => (),
                        EscapeAction::Output { extra } => {
                            if let Some(e) = extra {
                                io.write_all(&[e]).await?;
                            }
                            io.write_all(buf).await?;
                        }
                        EscapeAction::Terminate => {
                            info!("Terminated");
                            terminate.signal(());
                            return Ok(())
                        }
                        EscapeAction::Suspend => {
                            // disabled for the time being, doesn't resume OK.
                            // perhaps a bad interaction with dup_async(),
                            // maybe the new guard needs to be on the dup-ed
                            // FDs?

                            // pty_guard = None;
                            // nix::sys::signal::raise(nix::sys::signal::Signal::SIGTSTP)
                            // .unwrap_or_else(|e| {
                            //     warn!("Failed to stop: {e:?}");
                            // });
                            // // suspended here until resumed externally
                            // set_pty_guard(&mut pty_guard);
                            // continue;
                        }
                    }
                } else {
                    io.write_all(buf).await?;
                }

            }
            #[allow(unreachable_code)]
            Ok::<_, sunset::Error>(())
        };

        // output needs to complete when the channel is closed
        let fi = embassy_futures::select::select(fi, io.until_closed());

        // let fo = fo.map(|x| {
        //     error!("fo done {x:?}");
        //     x
        // });
        // let fi = fi.map(|x| {
        //     error!("fi done {x:?}");
        //     x
        // });
        // let fe = fe.map(|x| {
        //     error!("fe done {x:?}");
        //     x
        // });

        let io_done = embassy_futures::join::join3(fe, fi, fo);
        let _ = embassy_futures::select::select(io_done, terminate.wait()).await;
        // TODO handle errors from the join?
        Ok(())
    }

    /// Runs the `CmdlineClient` session to completion.
    ///
    /// Performs authentication, requests a shell or command, performs channel IO.
    /// Will return `Ok` after the session ends normally, or an error.
    pub async fn run<'g: 'a, 'a>(&mut self, cli: &'g SSHClient<'a>) -> Result<i32> {

        let mut winch_signal = self.want_pty
            .then(|| signal(SignalKind::window_change()))
            .transpose()
            .unwrap_or_else(|_| {
                warn!("Couldn't watch for window change signals");
                None
            });

        let mut io = None;
        let mut extin = None;

        let launch_chan: Channel::<SunsetRawMutex, (ChanInOut, Option<ChanIn>, Option<RawPtyGuard>), 1>
            = Channel::new();

        let mut exit_code = 1i32;

        let prog_loop = async {
            loop {
                let winch_fut = Fuse::terminated();
                pin_mut!(winch_fut);
                if let Some(w) = winch_signal.as_mut() {
                    winch_fut.set(w.recv().fuse());
                }

                let mut ph = ProgressHolder::new();
                let ev = cli.progress(&mut ph).await?;
                // Note that while ph is held, calls to cli will block.
                match ev {
                    CliEvent::Hostkey(h) => {
                        let key = h.hostkey()?;
                        match knownhosts::check_known_hosts(&self.host, self.port, &key) {
                            Ok(()) => h.accept(),
                            Err(_e) => h.reject(),
                        }?;
                    }
                    CliEvent::Username(u) => {
                        u.username(&self.username)?;
                    }
                    CliEvent::Password(p) => {
                        let pw = rpassword::prompt_password(format!(
                            "password for {}: ", self.username))?;
                        p.password(pw)?;
                    }
                    CliEvent::Pubkey(p) => {
                        if let Some(k) = self.authkeys.pop_front() {
                            p.pubkey(k)
                        } else {
                            p.skip()
                        }?;
                    }
                    CliEvent::AgentSign(k) => {
                        let agent = self.agent.as_mut().expect("agent keys without agent?");
                        let key = k.key()?;
                        let msg = k.message()?;
                        let sig = agent.sign_auth(key, &msg).await?;
                        k.signed(&sig)?;
                    }
                    CliEvent::Authenticated => {
                        debug!("Authentication succeeded");
                        // drop it so we can use cli
                        drop(ph);
                        let (i, e) = self.open_session(cli).await?;
                        io = Some(i);
                        extin = e;
                    }
                    CliEvent::SessionOpened(mut opener) => {
                        if let Some(p) = self.pty.take() {
                            opener.pty(p)?;
                        }
                        opener.cmd(&self.cmd)?;
                        // Start the IO loop
                        // TODO is there a better way
                        launch_chan.send((io.clone().unwrap(), extin.clone(), self.pty_guard.take())).await;
                    }
                    CliEvent::SessionExit(ex) => {
                        trace!("session exit {ex:?}");
                        if let sunset::CliSessionExit::Status(u) = ex {
                            if u <= 255 {
                                exit_code = i8::from_be_bytes([(u & 0xff) as u8]) as i32;
                            } else {
                                exit_code = 1;
                            }
                        }
                    }
                    CliEvent::Banner(b) => {
                        println!("Banner from server:\n{}", b.banner()?)
                    }
                    CliEvent::Defunct => {
                        trace!("break defunct");
                        break Ok::<_, Error>(())
                    }
                }
            }
        };

        let chanio = async {
            let (io, extin, pty) = launch_chan.receive().await;
            Self::chan_run(io, extin, pty).await
        };

        embassy_futures::select::select(prog_loop, chanio).await;

        Ok(exit_code)
    }

    /// Requests a PTY or non-PTY session
    ///
    /// Sets up the PTY if required.
    async fn open_session<'g: 'a, 'a>(&mut self, cli: &'g SSHClient<'a>) ->
        Result<(ChanInOut<'g, 'a>, Option<ChanIn<'g, 'a>>)> {
            trace!("opens s");
        let (io, extin) = if self.want_pty {
            set_pty_guard(&mut self.pty_guard);
            let io = cli.open_session_pty().await?;
            (io, None)
        } else {
            let (io, extin) = cli.open_session_nopty().await?;
            (io, Some(extin))
        };
        Ok((io, extin))
    }
}

fn set_pty_guard(pty_guard: &mut Option<RawPtyGuard>) {
    match raw_pty() {
        Ok(p) => *pty_guard = Some(p),
        Err(e) => {
            warn!("Failed getting raw pty: {e:?}");
        }
    }
}

#[derive(Debug, PartialEq)]
enum EscapeAction {
    None,
    // an extra character of output to prepend
    Output { extra: Option<u8> },
    Terminate,
    Suspend,
}

#[derive(Debug)]
enum Escaper {
    Idle,
    Newline,
    Escape,
}

impl Escaper {
    fn new() -> Self {
        // start as if we had received a '\r'
        Self::Newline
    }

    /// Handle ~. escape sequences.
    fn escape(&mut self, buf: &[u8]) -> EscapeAction {
        // Only handle single input keystrokes. Provides some protection against
        // pasting escape sequences too.

        let mut newline = false;
        if buf.len() == 1 {
            let c = buf[0];
            newline = c == b'\r';

            match self {
                Self::Newline if c == b'~' => {
                    *self = Self::Escape;
                    return EscapeAction::None
                }
                Self::Escape => {
                    // handle the actual escape character
                    match c {
                        b'~' => {
                            // output the single '~' in buf.
                            *self = Self::Idle;
                            return EscapeAction::Output { extra: None }
                        }
                        b'.' => {
                            *self = Self::Idle;
                            return EscapeAction::Terminate
                        }
                        // ctrl-z, suspend
                        0x1a => {
                            *self = Self::Idle;
                            return EscapeAction::Suspend
                        }
                        // fall through to reset below
                        _ => (),
                    }
                }
                _ => (),
            }
        }

        // Reset escaping state
        let extra = match self {
            // output the '~' that was previously consumed
            Self::Escape => Some(b'~'),
            _ => None,
        };
        if newline {
            *self = Self::Newline
        } else {
            *self = Self::Idle
        }

        EscapeAction::Output { extra }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::cmdline_client::*;

    #[test]
    fn escaping() {
        // None expect_action is shorthand for ::Output
        let seqs = vec![
            ("~.", Some(EscapeAction::Terminate), ""),
            ("\r~.", Some(EscapeAction::Terminate), "\r"),
            ("~~.", None, "~."),
            ("~~~.", None, "~~."),
            ("\r\r~.", Some(EscapeAction::Terminate), "\r\r"),
            ("a~/~.", None, "a~/~."),
            ("a~/\r~.", Some(EscapeAction::Terminate), "a~/\r"),
            ("~\r~.", Some(EscapeAction::Terminate), "~\r"),
            ("~\r~ ", None, "~\r~ "),
        ];
        for (inp, expect_action, expect) in seqs.iter() {
            let mut out = vec![];
            let mut esc = Escaper::new();
            let mut last_action = None;
            println!("input \"{}\"", inp.escape_default());
            for i in inp.chars() {
                let i: u8 = i.try_into().unwrap();
                let e = esc.escape(&[i]);

                if let EscapeAction::Output { ref extra } = e {
                    if let Some(extra) = extra {
                        out.push(*extra);
                    }
                    out.push(i)
                }

                last_action = Some(e);
            }
            assert_eq!(out.as_slice(), expect.as_bytes());

            let last_action = last_action.unwrap();
            if let Some(expect_action) = expect_action {
                assert_eq!(&last_action, expect_action);
            } else {
                match last_action {
                    EscapeAction::Output { .. } => (),
                    _ => panic!("Unexpected action {last_action:?}"),
                }
            }
        }
    }

}

