use futures::pin_mut;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::str::FromStr;
use core::fmt::Debug;

use sunset::{AuthSigMsg, SignKey, OwnedSig, Pty, sshnames};
use sunset::{BhError, BhResult};
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

#[derive(Debug)]
enum CmdlineState<'a> {
    PreAuth,
    Authed,
    Opening {
        io: ChanInOut<'a>,
        extin: Option<ChanIn<'a>>,
    },
    Ready {
        io: ChanInOut<'a>,
    },
}

enum Msg {
    Authed,
    Opened,
    /// The SSH session exited
    Exited,
}

/// A commandline client session
///
/// This opens a single channel and presents it to the stdin/stdout terminal.
pub struct CmdlineClient {
    cmd: SessionCommand<String>,
    want_pty: bool,

    // to be passed to hooks
    authkeys: VecDeque<SignKey>,
    username: String,
    host: String,
    port: u16,
    agent: Option<AgentClient>,

    notify: Channel<SunsetRawMutex, Msg, 1>,
}

pub struct CmdlineRunner<'a> {
    state: CmdlineState<'a>,

    want_pty: bool,
    pty_guard: Option<RawPtyGuard>,

    notify: Receiver<'a, SunsetRawMutex, Msg, 1>,
}

pub struct CmdlineHooks<'a> {
    authkeys: VecDeque<SignKey>,
    username: &'a str,
    host: &'a str,
    port: u16,
    agent: Option<AgentClient>,
    cmd: &'a SessionCommand<String>,
    pty: Option<Pty>,

    notify: Sender<'a, SunsetRawMutex, Msg, 1>,
}

impl CmdlineClient {
    pub fn new(username: impl AsRef<str>, host: impl AsRef<str>) -> Self {
        Self {
            cmd: SessionCommand::Shell,
            want_pty: false,
            agent: None,

            notify: Channel::new(),

            username: username.as_ref().into(),
            host: host.as_ref().into(),
            port: sshnames::SSH_PORT,
            authkeys: Default::default(),
        }
    }

    /// Splits a `CmdlineClient` into hooks and the runner.
    ///
    /// `CmdlineRunner` should be awaited until the session completes.
    /// `CmdlineHooks` can be used to exit early (and may in future provide
    /// other functionality).
    pub fn split(&mut self) -> (CmdlineHooks, CmdlineRunner) {

        let pty = self.make_pty();

        let authkeys = core::mem::replace(&mut self.authkeys, Default::default());

        let runner = CmdlineRunner::new(pty.is_some(), self.notify.receiver());

        let hooks = CmdlineHooks {
            username: &self.username,
            host: &self.host,
            port: self.port,
            authkeys,
            agent: self.agent.take(),
            cmd: &self.cmd,
            pty,
            notify: self.notify.sender(),
        };

        (hooks, runner)
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    pub fn pty(&mut self) -> &mut Self {
        self.want_pty = true;
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

    fn make_pty(&mut self) -> Option<Pty> {
        let mut pty = None;
        if self.want_pty {
            match pty::current_pty() {
                Ok(p) => pty = Some(p),
                Err(e) => warn!("Failed getting current pty: {e:?}"),
            }

        }
        pty
    }

}


impl<'a> CmdlineRunner<'a> {
    fn new(want_pty: bool, notify: Receiver<'a, SunsetRawMutex, Msg, 1>) -> Self {
        Self {
            state: CmdlineState::PreAuth,
            want_pty,
            notify,
            pty_guard: None,
        }
    }

    async fn chan_run(io: ChanInOut<'a>,
        io_err: Option<ChanIn<'a>>,
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
                            ()

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
    pub async fn run(&mut self, cli: &'a SSHClient<'a>) -> Result<()> {
        // chanio is only set once a channel is opened below
        let chanio = Fuse::terminated();
        pin_mut!(chanio);

        let mut winch_signal = self.want_pty
            .then(|| signal(SignalKind::window_change()))
            .transpose()
            .unwrap_or_else(|_| {
                warn!("Couldn't watch for window change signals");
                None
            });

        loop {
            let winch_fut = Fuse::terminated();
            pin_mut!(winch_fut);
            if let Some(w) = winch_signal.as_mut() {
                winch_fut.set(w.recv().fuse());
            }

            select_biased! {
                msg = self.notify.receive().fuse() => {
                    match msg {
                        Msg::Authed => {
                            if !matches!(self.state, CmdlineState::PreAuth) {
                                warn!("Unexpected auth success, state {:?}", self.state);
                                return Ok(())
                            }
                            self.state = CmdlineState::Authed;
                            debug!("Opening a new session channel");
                            self.open_session(cli).await?;
                        }
                        Msg::Opened => {
                            let st = core::mem::replace(&mut self.state, CmdlineState::Authed);
                            if let CmdlineState::Opening { io, extin } = st {
                                let r = Self::chan_run(io.clone(), extin.clone(), self.pty_guard.take())
                                    .fuse();
                                chanio.set(r);
                                self.state = CmdlineState::Ready { io };
                            } else {
                                warn!("Unexpected Msg::Opened")
                            }
                        }
                        Msg::Exited => {
                            trace!("SSH exited, finishing cli loop");
                            break;
                        }
                    }
                    Ok::<_, sunset::Error>(())
                },

                e = chanio => {
                    trace!("chanio finished: {e:?}");
                    cli.exit().await;
                    break;
                }

                _ = winch_fut => {
                    self.window_change_signal().await;
                    Ok::<_, sunset::Error>(())
                }
            }?
        }

        Ok(())
    }

    async fn open_session(&mut self, cli: &'a SSHClient<'a>) -> Result<()> {
        debug_assert!(matches!(self.state, CmdlineState::Authed));

        let (io, extin) = if self.want_pty {
            set_pty_guard(&mut self.pty_guard);
            let io = cli.open_session_pty().await?;
            (io, None)
        } else {
            let (io, extin) = cli.open_session_nopty().await?;
            (io, Some(extin))
        };
        self.state = CmdlineState::Opening { io, extin };
        Ok(())
    }

    async fn window_change_signal(&mut self) {
        let io = match &self.state {
            CmdlineState::Opening { io, ..} => io,
            CmdlineState::Ready { io, ..} => io,
            _ => return,
        };

        let winch = match win_size() {
            Ok(w) => w,
            Err(e) => {
                debug!("Error getting window size: {e:?}");
                return;
            }
        };

        if let Err(e) = io.term_window_change(winch).await {
            debug!("window change failed: {e:?}");
        }
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

impl<'a> CmdlineHooks<'a> {
    /// Notify the `CmdlineClient` that the main SSH session has exited.
    ///
    /// This will cause the `CmdlineRunner` to finish flushing output and terminate.
    pub async fn exited(&mut self) {
        self.notify.send(Msg::Exited).await
    }
}

impl sunset::CliBehaviour for CmdlineHooks<'_> {
    fn username(&mut self) -> BhResult<sunset::ResponseString> {
        sunset::ResponseString::from_str(&self.username).map_err(|_| BhError::Fail)
    }

    fn valid_hostkey(&mut self, key: &sunset::PubKey) -> BhResult<bool> {
        trace!("checking hostkey for {key:?}");

        match knownhosts::check_known_hosts(self.host, self.port, key) {
            Ok(()) => Ok(true),
            Err(e) => {
                debug!("Error for hostkey: {e:?}");
                Ok(false)
            }
        }
    }

    fn next_authkey(&mut self) -> BhResult<Option<sunset::SignKey>> {
        Ok(self.authkeys.pop_front())
    }

    fn auth_password(
        &mut self,
        pwbuf: &mut sunset::ResponseString,
    ) -> BhResult<bool> {
        let pw =
            rpassword::prompt_password(format!("password for {}: ", self.username))
                .map_err(|e| {
                    warn!("read_password failed {e:}");
                    BhError::Fail
                })?;
        if pwbuf.push_str(&pw).is_err() {
            Err(BhError::Fail)
        } else {
            Ok(true)
        }
    }

    async fn agent_sign(&mut self, key: &SignKey, msg: &AuthSigMsg<'_>) -> BhResult<OwnedSig> {
        if let Some(ref mut agent) = self.agent {
            agent.sign_auth(key, msg).await.map_err(|_e| {
                error!("agent signing failed");
                BhError::Fail
            })
        } else {
            error!("agent signing wrong");
            Err(BhError::Fail)
        }
    }

    fn authenticated(&mut self) {
        debug!("Authentication succeeded");
        // TODO: need better handling, what else could we do?
        while self.notify.try_send(Msg::Authed).is_err() {
            warn!("Full notification queue");
        }
    }

    async fn session_opened(&mut self, _chan: sunset::ChanNum, opener: &mut sunset::SessionOpener<'_, '_, '_>) -> BhResult<()> {
        if let Some(p) = self.pty.take() {
            opener.pty(p)
        }
        opener.cmd(self.cmd);
        self.notify.send(Msg::Opened).await;
        Ok(())
    }
}

impl<'a> Debug for CmdlineHooks<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CmdlineHooks")
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

