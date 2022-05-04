#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};


use crate::*;
use crate::packets::{Packet, PubKey};
use crate::sshnames::*;
use crate::cliauth::CliAuth;
use crate::conn::RespPackets;
use crate::sign::SignKey;

pub(crate) struct Client<'a> {
    pub auth: CliAuth<'a>,
}

impl<'a> Client<'a> {
    pub fn new() -> Self {
        Client {
            auth: CliAuth::new(),
        }
    }

    // pub fn check_hostkey(hostkey: )

    pub fn auth_success(&mut self, resp: &mut RespPackets) -> Result<()> {
        resp.push(Packet::ServiceRequest(
            packets::ServiceRequest { name: SSH_SERVICE_CONNECTION } )).trap()?;
        Ok(())
    }


    pub fn banner(&mut self, banner: &packets::UserauthBanner) {
    }
}


// TODO: probably want a special Result here. Which ones can return an error?
trait ClientSetup<'a> {
    // TODO is `&'a str` return lifetime odious here?
    /// The username to use for authentication
    fn username(&mut self) -> Result<&str>;
    /// Whether to accept a hostkey
    fn valid_hostkey(&mut self, hostname: &str, key: & PubKey<'a>) -> Result<bool>;

    /// Get the set of public keys to authenticate with
    fn auth_keys(&mut self) -> &[&PubKey] {
        &[]
    }

    /// Retrieves a privkey to use for signing an authentication request.
    /// The SSH client will make the signature itself.
    /// `use_pubkey` is one of the entries provided to [`auth_keys()`].
    /// An alternative to this is for users to sign the request themselves
    /// with [`auth_sign()`]
    fn auth_privkey(&mut self, use_pubkey: &PubKey) -> Option<&SignKey> {
        None
    }

    /// Create a signature blob suitable for the SSH authentication.
    /// `use_pubkey` is one of the entries provided to [`auth_keys()`].
    /// The returned signature shouldn't include a total length prefix.
    /// Alternatively [`auth_privkey()`] can be used.
    fn auth_sign(&mut self, use_pubkey: &PubKey, sign_data: &[u8]) -> Option<&[u8]> {
        None
    }

    /// Get a password to use for authentication
    fn auth_password(&mut self) -> Option<&str> {
        None
    }

    /// A banner sent from a server. Has already been escaped with [`core::ascii:escape_default`]
    /// Language may be empty, is provided by the server.
    fn show_banner(&mut self, banner: &str, language: &str) {
        let _ = language;
        info!("Got banner:\n{}", banner);
    }

    /// Called once authentication is successful
    fn authenticated(&mut self);

    // TODO: postauth channel callbacks
}
