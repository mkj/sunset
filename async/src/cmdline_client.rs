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

use futures::{select_biased, future::Fuse};
use futures::FutureExt;

use crate::*;
use crate::{raw_pty, RawPtyGuard};

#[derive(Debug)]
enum CmdlineState<'a> {
    PreAuth,
    Authed,
    // TODO split sending the channel open and the request strings
    _ChanOpen,
    _ChanReq,
    Ready { io: ChanInOut<'a>, extin: Option<ChanIn<'a>> },
}

enum Msg {
    Authed,
}

pub struct CmdlineClient {
    cmd: Option<String>,
    want_pty: bool,

    // to be passed to hooks
    authkeys: VecDeque<SignKey>,
    username: String,

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
            let mut so = crate::stdout().map_err(|e| {
                error!("open stdout: {e:?}");
                Error::msg("opening stdout failed")
            })?;
            loop {
                // TODO buffers
                let mut buf = [0u8; 1000];
                let l = io.read(&mut buf).await?;
                if l == 0 {
                    break;
                }
                so.write(&buf[..l]).await.map_err(|_| Error::ChannelEOF)?;
            }
            #[allow(unreachable_code)]
            Ok::<_, sunset::Error>(())
        };

        // err
        let fe = async {
            // if io_err is None we complete immediately
            if let Some(mut errin) = io_err {
                let mut eo = crate::stderr_out().map_err(|e| {
                    Error::msg("opening stderr failed")
                })?;
                loop {
                    // TODO buffers
                    let mut buf = [0u8; 1000];
                    let l = errin.read(&mut buf).await?;
                    if l == 0 {
                        break;
                    }
                    eo.write(&buf[..l]).await.map_err(|_| Error::ChannelEOF)?;
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
                io.write(&buf[..l]).await?;
            }
            Ok::<_, sunset::Error>(())
        };


        // output needs to complete when the channel is closed
        let fi = embassy_futures::select::select(fi, io.until_closed());

        let fo = fo.map(|x| {
            error!("fo done {x:?}");
            x
        });
        let fi = fi.map(|x| {
            error!("fi done {x:?}");
            x
        });
        let fe = fe.map(|x| {
            error!("fe done {x:?}");
            x
        });

        embassy_futures::join::join3(fe, fi, fo).await;
        // TODO handle errors from the join?
        Ok(())
    }

    /// Runs the `CmdlineClient` session. Requests a shell or command, performs
    /// channel IO.
    pub async fn run(&mut self, cli: &'a SSHClient<'a>) -> Result<()> {
        let mut chanio = Fuse::terminated();
        pin_mut!(chanio);

        loop {
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
                    }
                    Ok::<_, sunset::Error>(())
                },
                e = chanio => {
                    trace!("chanio finished: {e:?}");
                    if e.is_ok() {
                        cli.exit().await;
                        break;
                    }
                    e
                }
            }?
        }

        Ok(())
    }

    async fn open_session(&mut self, cli: &'a SSHClient<'a>) -> Result<()> {
        debug_assert!(matches!(self.state, CmdlineState::Authed));

        // TODO expect
        if self.want_pty {
            // self.pty_guard = Some(raw_pty().expect("raw pty"));
        }

        let cmd = self.cmd.as_ref().map(|s| s.as_str());
        let (io, extin) = if self.want_pty {
            let io = cli.open_session_pty(cmd).await?;
            (io, None)
        } else {
            let (io, extin) = cli.open_session_nopty(cmd).await?;
            (io, Some(extin))
        };
        self.state = CmdlineState::Ready { io, extin };
        Ok(())
    }
}

impl CmdlineClient {
    pub fn new(username: impl AsRef<str>, cmd: Option<impl AsRef<str>>, want_pty: bool) -> Self {
        Self {

            // TODO: shorthand for this?
            cmd: cmd.map(|c| c.as_ref().into()),
            want_pty,

            notify: Channel::new(),

            username: username.as_ref().into(),
            authkeys: Default::default(),
        }
    }

    pub fn split(&mut self) -> (CmdlineHooks, CmdlineRunner) {
        let ak = core::mem::replace(&mut self.authkeys, Default::default());
        let hooks = CmdlineHooks::new(&self.username, ak, self.notify.sender());
        let runner = CmdlineRunner::new(&self.cmd, self.want_pty, self.notify.receiver());
        (hooks, runner)
    }

    pub fn add_authkey(&mut self, k: SignKey) {
        self.authkeys.push_back(k)
    }
}

impl<'a> CmdlineHooks<'a> {
    fn new(username: &'a str, authkeys: VecDeque<SignKey>, notify: Sender<'a, SunsetRawMutex, Msg, 1>) -> Self {
        Self {
            authkeys,
            username,
            notify,
        }
    }
}

impl<'a> sunset::CliBehaviour for CmdlineHooks<'a> {
    fn username(&mut self) -> BhResult<sunset::ResponseString> {
        sunset::ResponseString::from_str(&self.username).map_err(|_| BhError::Fail)
    }

    fn valid_hostkey(&mut self, key: &sunset::PubKey) -> BhResult<bool> {
        trace!("valid_hostkey for {key:?}");
        Ok(true)
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
            // tokio::task::yield_now();
        }
    }
}
