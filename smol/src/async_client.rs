#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use core::str::FromStr;

use door::SignKey;
use door_sshproto as door;
use door_sshproto::{BhError, BhResult};
use door_sshproto::{ChanMsg, ChanMsgDetails, Error, RespPackets, Result, Runner};

use std::collections::VecDeque;

use async_trait::async_trait;

pub struct SimpleClient {
    auth_done: bool,
    main_ch: Option<u32>,
    authkeys: VecDeque<SignKey>,
    username: String,
}

impl SimpleClient {
    pub fn new(username: &impl AsRef<str>) -> Self {
        SimpleClient {
            auth_done: false,
            main_ch: None,
            authkeys: VecDeque::new(),
            username: username.as_ref().into(),
        }
    }

    pub fn add_authkey(&mut self, k: SignKey) {
        self.authkeys.push_back(k)
    }
}

// #[async_trait(?Send)]
#[async_trait]
impl door::AsyncCliBehaviour for SimpleClient {
    async fn chan_handler(
        &mut self,
        resp: &mut RespPackets,
        chan_msg: ChanMsg,
    ) -> Result<()> {
        if Some(chan_msg.num) != self.main_ch {
            return Err(Error::SSHProtoError);
        }

        match chan_msg.msg {
            ChanMsgDetails::ExtData { .. } => {}
            ChanMsgDetails::Req { .. } => {}
            _ => {}
        }
        Ok(())
    }

    fn progress(&mut self, runner: &mut Runner) -> Result<()> {
        if self.auth_done {
            if self.main_ch.is_none() {
                let ch =
                    runner.open_client_session(Some("cowsay it works"), false)?;
                self.main_ch = Some(ch);
            }
        }
        Ok(())
    }

    async fn username(&mut self) -> BhResult<door::ResponseString> {
        door::ResponseString::from_str(&self.username).map_err(|_| BhError::Fail)
    }

    async fn valid_hostkey(&mut self, key: &door::PubKey) -> BhResult<bool> {
        trace!("valid_hostkey for {key:?}");
        Ok(true)
    }

    async fn next_authkey(&mut self) -> BhResult<Option<door::SignKey>> {
        Ok(self.authkeys.pop_front())
    }

    async fn auth_password(
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

    async fn authenticated(&mut self) {
        info!("Authentication succeeded");
        self.auth_done = true;
    }
    // }

    // impl door::BlockCliBehaviour for SimpleClient {
    //     fn chan_handler<'f>(&mut self, resp: &mut RespPackets, chan_msg: ChanMsg<'f>) -> Result<()> {
    //         if Some(chan_msg.num) != self.main_ch {
    //             return Err(Error::SSHProtoError)
    //         }

    //         match chan_msg.msg {
    //             ChanMsgDetails::Data(buf) => {
    //                 let _ = std::io::stdout().write_all(buf);
    //             },
    //             ChanMsgDetails::ExtData{..} => {
    //             }
    //             ChanMsgDetails::Req{..} => {
    //             }
    //             _ => {}
    //         }
    //         Ok(())
    //     }

    //     fn progress(&mut self, runner: &mut Runner) -> Result<()> {
    //         if self.auth_done {
    //             if self.main_ch.is_none() {
    //                 let ch = runner.open_client_session(Some("cowsay it works"), false)?;
    //                 self.main_ch = Some(ch);
    //             }
    //         }
    //         Ok(())
    //     }

    //     fn username(&mut self) -> BhResult<door::ResponseString> {
    //         // TODO unwrap
    //         let mut p = door::ResponseString::new();
    //         p.push_str("matt").unwrap();
    //         Ok(p)
    //     }

    //     fn valid_hostkey(&mut self, key: &door::PubKey) -> BhResult<bool> {
    //         trace!("valid_hostkey for {key:?}");
    //         Ok(true)
    //     }

    //     fn auth_password(&mut self, pwbuf: &mut door::ResponseString) -> BhResult<bool> {
    //         let pw = rpassword::prompt_password("password: ").map_err(|e| {
    //             warn!("read_password failed {e:}");
    //             BhError::Fail
    //         })?;
    //         if pwbuf.push_str(&pw).is_err() {
    //             Err(BhError::Fail)
    //         } else {
    //             Ok(true)
    //         }
    //     }

    //     fn authenticated(&mut self) {
    //         info!("Authentication succeeded");
    //         self.auth_done = true;
    //     }
}
