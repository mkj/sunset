#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::str::FromStr;

use door::SignKey;
use door_sshproto as door;
use door_sshproto::{BhError, BhResult};
use door_sshproto::{ChanMsg, ChanMsgDetails, Error, Result, Runner};

use std::collections::VecDeque;

use async_trait::async_trait;

use crate::*;
use crate::{raw_pty, RawPtyGuard, SSHClient, ChanInOut, ChanExtIn};

enum CmdlineState<'a> {
    PreAuth,
    Authed,
    // TODO split sending the channel open and the request strings
    _ChanOpen,
    _ChanReq,
    Ready { io: ChanInOut<'a>, extin: Option<ChanExtIn<'a>> },
}

/// Command line interface SSH client behaviour
pub struct CmdlineClient<'a> {
    state: CmdlineState<'a>,
    main_ch: Option<u32>,
    pty_guard: Option<RawPtyGuard>,

    authkeys: VecDeque<SignKey>,
    username: String,
    cmd: Option<String>,
    want_pty: bool,
}

impl<'a> CmdlineClient<'a> {
    pub fn new(username: impl AsRef<str>, cmd: Option<impl AsRef<str>>, want_pty: bool) -> Self {
        CmdlineClient {
            state: CmdlineState::PreAuth,
            main_ch: None,
            pty_guard: None,

            authkeys: VecDeque::new(),
            username: username.as_ref().into(),
            // TODO: shorthand for this?
            cmd: cmd.map(|c| c.as_ref().into()),
            want_pty,
        }
    }

    pub async fn progress(&mut self, cli: &mut SSHClient<'a>) -> Result<()> {
        match self.state {
            CmdlineState::Authed => {
                info!("Opening a new session channel");
                self.open_session(cli).await?;
            }
            | CmdlineState::PreAuth => (),
            | CmdlineState::Ready {..} => (),
            _ => todo!(),
        }
        Ok(())

    }

    pub fn add_authkey(&mut self, k: SignKey) {
        self.authkeys.push_back(k)
    }

    async fn open_session(&mut self, cli: &mut SSHClient<'a>) -> Result<()> {
        debug_assert!(matches!(self.state, CmdlineState::Authed));

        // TODO expect
        // self.pty_guard = Some(raw_pty().expect("raw pty"));

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

// #[async_trait(?Send)]
#[async_trait]
impl door::CliBehaviour for CmdlineClient<'_> {
    fn username(&mut self) -> BhResult<door::ResponseString> {
        door::ResponseString::from_str(&self.username).map_err(|_| BhError::Fail)
    }

    fn valid_hostkey(&mut self, key: &door::PubKey) -> BhResult<bool> {
        trace!("valid_hostkey for {key:?}");
        Ok(true)
    }

    fn next_authkey(&mut self) -> BhResult<Option<door::SignKey>> {
        Ok(self.authkeys.pop_front())
    }

    fn auth_password(
        &mut self,
        pwbuf: &mut door::ResponseString,
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
        match self.state {
            CmdlineState::PreAuth => {
                info!("Authentication succeeded");
                self.state = CmdlineState::Authed;
            }
            _ => warn!("Unexpected auth response")
        }
    }
}
