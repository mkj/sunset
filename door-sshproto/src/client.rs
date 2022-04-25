use crate::*;
use crate::cliauth::CliAuth;

pub(crate) struct Client<'a> {
    pub auth: CliAuth<'a>,
}

impl<'a> Client<'a> {
    pub fn new() -> Self {
        Client {
            auth: CliAuth::new(),
        }
    }
}
