use futures::pin_mut;
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::str::FromStr;

use sunset::SignKey;
use sunset::{BhError, BhResult};
use sunset::{ChanMsg, ChanMsgDetails, Error, Result, Runner};
use sunset_embassy::*;

use std::collections::VecDeque;
use embassy_sync::channel::{Channel, Sender, Receiver};
use embedded_io::asynch::{Read as _, Write as _};

use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::signal::unix::{signal, SignalKind};

use futures::{select_biased, future::Fuse};
use futures::FutureExt;

use crate::*;
use crate::{raw_pty, RawPtyGuard};
use crate::pty::win_size;

#[derive(Debug)]
enum CmdlineState<'a> {
    PreAuth,
    Authed,
    Ready { io: ChanInOut<'a>, extin: Option<ChanIn<'a>> },
}

enum Msg {
    Authed,
    /// The SSH session exited
    Exited,
}

pub struct CmdlineClient {
    cmd: Option<String>,
    want_pty: bool,

    // to be passed to hooks
    authkeys: VecDeque<SignKey>,
    username: String,
    host: String,
    port: u16,

    notify: Channel<SunsetRawMutex, Msg, 1>,
}

pub struct CmdlineRunner<'a> {
    state: CmdlineState<'a>,
    pty_guard: Option<RawPtyGuard>,

    cmd: &'a Option<String>,
    want_pty: bool,

    notify: Receiver<'a, SunsetRawMutex, Msg, 1>,
}

pub struct CmdlineHooks<'a> {
    authkeys: VecDeque<SignKey>,
    username: &'a str,
    host: &'a str,
    port: u16,

    notify: Sender<'a, SunsetRawMutex, Msg, 1>,
}

impl<'a> CmdlineRunner<'a> {
    fn new(cmd: &'a Option<String>, want_pty: bool, notify: Receiver<'a, SunsetRawMutex, Msg, 1>) -> Self {
        Self {
            state: CmdlineState::PreAuth,
            pty_guard: None,
            cmd,
            want_pty,
            notify,
        }
    }

    async fn chan_run(io: ChanInOut<'a>, io_err: Option<ChanIn<'a>>) -> Result<()> {
        trace!("chan_run top");
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
                let mut eo = crate::stderr_out().map_err(|e| {
                    error!("open stderr: {e:?}");
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

        // in
        let fi = async {
            let mut io = io.clone();
            let mut si = crate::stdin().map_err(|_| Error::msg("opening stdin failed"))?;
            loop {
                // TODO buffers
                let mut buf = [0u8; 1000];
                let l = si.read(&mut buf).await.map_err(|_| Error::ChannelEOF)?;
                io.write_all(&buf[..l]).await?;
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

        let _ = embassy_futures::join::join3(fe, fi, fo).await;
        // TODO handle errors from the join?
        Ok(())
    }

    /// Runs the `CmdlineClient` session. Requests a shell or command, performs
    /// channel IO.
    pub async fn run(&mut self, cli: &'a SSHClient<'a>) -> Result<()> {
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
                msg = self.notify.recv().fuse() => {
                    match msg {
                        Msg::Authed => {
                            if !matches!(self.state, CmdlineState::PreAuth) {
                                warn!("Unexpected auth success, state {:?}", self.state);
                                return Ok(())
                            }
                            self.state = CmdlineState::Authed;
                            debug!("Opening a new session channel");
                            self.open_session(cli).await?;
                            if let CmdlineState::Ready { io, extin } = &self.state {
                                chanio.set(Self::chan_run(io.clone(), extin.clone()).fuse())
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
                    trace!("break");
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

        let cmd = self.cmd.as_ref().map(|s| s.as_str());
        let (io, extin) = if self.want_pty {
            // TODO expect
            let pty = pty::current_pty().expect("pty fetch");
            self.pty_guard = Some(raw_pty().expect("raw pty"));
            let io = cli.open_session_pty(cmd, pty).await?;
            (io, None)
        } else {
            let (io, extin) = cli.open_session_nopty(cmd).await?;
            (io, Some(extin))
        };
        self.state = CmdlineState::Ready { io, extin };
        Ok(())
    }

    async fn window_change_signal(&mut self) {
        let io = match &self.state {
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

impl CmdlineClient {
    pub fn new(username: impl AsRef<str>, host: impl AsRef<str>, port: u16,
        cmd: Option<impl AsRef<str>>, want_pty: bool) -> Self {
        Self {

            // TODO: shorthand for this?
            cmd: cmd.map(|c| c.as_ref().into()),
            want_pty,

            notify: Channel::new(),

            username: username.as_ref().into(),
            host: host.as_ref().into(),
            port,
            authkeys: Default::default(),
        }
    }

    pub fn split(&mut self) -> (CmdlineHooks, CmdlineRunner) {
        let ak = core::mem::replace(&mut self.authkeys, Default::default());
        let hooks = CmdlineHooks::new(&self.username, &self.host, self.port, ak, self.notify.sender());
        let runner = CmdlineRunner::new(&self.cmd, self.want_pty, self.notify.receiver());
        (hooks, runner)
    }

    pub fn add_authkey(&mut self, k: SignKey) {
        self.authkeys.push_back(k)
    }
}

impl<'a> CmdlineHooks<'a> {
    fn new(username: &'a str, host: &'a str, port: u16, authkeys: VecDeque<SignKey>, notify: Sender<'a, SunsetRawMutex, Msg, 1>) -> Self {
        Self {
            authkeys,
            username,
            host,
            port,
            notify,
        }
    }

    /// Notify the `CmdlineClient` that the main SSH session has exited.
    ///
    /// This will cause the `CmdlineRunner` to finish flushing output and terminate.
    pub async fn exited(&mut self) {
        self.notify.send(Msg::Exited).await
    }
}

impl<'a> sunset::CliBehaviour for CmdlineHooks<'a> {
    fn username(&mut self) -> BhResult<sunset::ResponseString> {
        sunset::ResponseString::from_str(&self.username).map_err(|_| BhError::Fail)
    }

    fn valid_hostkey(&mut self, key: &sunset::PubKey) -> BhResult<bool> {
        trace!("checking hostkey for {key:?}");

        match known_hosts::check_known_hosts(self.host, self.port, key) {
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

    fn authenticated(&mut self) {
        debug!("Authentication succeeded");
        // TODO: need better handling, what else could we do?
        while self.notify.try_send(Msg::Authed).is_err() {
            warn!("Full notification queue");
        }
    }
}
