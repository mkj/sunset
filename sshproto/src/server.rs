use crate::*;
use crate::servauth::ServAuth;

pub(crate) struct Server {
    auth: ServAuth,
}

impl Server {
    pub fn new() -> Self {
        Server {
            auth: ServAuth::new(),
        }
    }
}
