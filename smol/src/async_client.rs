#[allow(unused_imports)]
use {
    log::{debug, error, info, log, trace, warn},
};

use door_sshproto as door;
use door_sshproto::{BhResult,BhError};
use door_sshproto::{Result,Error,Runner};


use async_trait::async_trait;

pub struct SimpleClient {
    session_pending: bool,
}

impl SimpleClient {
    pub fn new() -> Self {
        SimpleClient {
            session_pending: false,
        }
    }
}

#[async_trait(?Send)]
impl door::AsyncCliBehaviour for SimpleClient {
    async fn username(&mut self) -> BhResult<door::ResponseString> {
        // TODO unwrap
        let mut p = door::ResponseString::new();
        p.push_str("matt").unwrap();
        Ok(p)
    }

    async fn valid_hostkey(&mut self, key: &door::PubKey) -> BhResult<bool> {
        trace!("valid_hostkey for {key:?}");
        Ok(true)
    }

    async fn auth_password(&mut self, pwbuf: &mut door::ResponseString) -> BhResult<bool> {
        let pw = rpassword::prompt_password("password: ").map_err(|e| {
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
        self.session_pending = true;
    }

    fn progress(&mut self, runner: &mut Runner) -> Result<()> {
        if self.session_pending {
            self.session_pending = false;
            runner.open_client_session(None, false)?;
        }
        Ok(())
    }

}

