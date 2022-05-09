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
use heapless::String;

pub struct Client<'a> {
    pub(crate) auth: CliAuth<'a>,
    pub(crate) hooks: RefHooks<'a>,
}

impl<'a> Client<'a> {
    pub fn new(hooks: RefHooks<'a>) -> Result<Self> {
        Ok(Client {
            auth: CliAuth::new(),
            hooks,
        })
    }

    // pub fn check_hostkey(hostkey: )

    pub fn auth_success(&mut self, resp: &mut RespPackets) -> Result<()> {
        resp.push(Packet::ServiceRequest(
            packets::ServiceRequest { name: SSH_SERVICE_CONNECTION } )).trap()?;
        self.auth.success(self.hooks);
        Ok(())
    }

    pub fn banner(&mut self, banner: &packets::UserauthBanner) {
        self.hooks.show_banner(banner.message, banner.lang);
    }
}

// A bit of a mouthful.
pub(crate) type RefHooks<'a> = &'a mut dyn ClientHooks<'a>;

/// A stack-allocated string to store responses for usernames or passwords.
// 100 bytes is an arbitrary size.
pub type ResponseString = heapless::String<100>;

#[derive(Debug)]
pub enum HookError {
    Fail,
    /// To skip a particular authentication method
    Skip,
}

pub type HookResult<T> = core::result::Result<T, HookError>;

// TODO: probably want a special Result here. They probably all want
// Result, it can return an error or other options like Disconnect?
pub trait ClientHooks<'a> {
    /// Provide the username to use for authentication. Will only be called once
    /// per session.
    /// If the username needs to change a new connection should be made
    /// – servers often have limits on authentication attempts.
    ///
    fn username(&self, username: &mut ResponseString) -> HookResult<()>;

    /// Whether to accept a hostkey for the server
    fn valid_hostkey(&mut self, hostname: &str, key: &PubKey<'a>) -> HookResult<bool>;

    /// Get a password to use for authentication, or `None` to skip password
    /// authentication
    ///
    /// # Examples
    ///
    /// ```
    /// fn auth_password(&mut self) -> Option<ResponseString> {
    /// // TODO
    /// }
    /// ```
    #[allow(unused)]
    fn auth_password(&mut self, pwbuf: &mut ResponseString) -> HookResult<()> {
        Err(HookError::Skip)
    }

    /// Get the list of public keys to authenticate with.
    /// The default implementation returns an empty list.
    fn auth_keys(&mut self) -> HookResult<&[&PubKey]> {
        Ok(&[])
    }

    /// Retrieves a privkey to use for signing an authentication request.
    /// The caller will make the signature itself.
    /// `use_pubkey` is one of the entries provided to [`auth_keys()`](Self::auth_keys).
    /// An alternative to this is for users to sign the request themselves
    /// with [`auth_sign()`](Self::auth_sign)
    #[allow(unused)]
    fn auth_privkey(&mut self, use_pubkey: &PubKey) -> HookResult<&SignKey> {
        Err(HookError::Skip)
    }

    /// Create a signature blob suitable for the SSH authentication,
    /// for use by SSH agent implementations etc.
    /// `use_pubkey` is one of the entries provided to [`auth_keys()`](Self::auth_keys).
    /// The returned signature shouldn't include a total length prefix.
    /// Alternatively [`auth_privkey()`](Self::auth_privkey) can be used.
    #[allow(unused)]
    fn auth_sign(&mut self, use_pubkey: &PubKey, sign_data: &[u8]) -> HookResult<&[u8]> {
        Err(HookError::Skip)
    }

    /// Called after authentication has succeeded
    fn authenticated(&mut self) -> HookResult<()>;

    /// Show a banner sent from a server. Arguments are provided
    /// by the server so could be hazardous, they should be escaped with
    /// [`banner.escape_default()`](core::str::escape_default) or similar.
    /// Language may be empty, is provided by the server.
    #[allow(unused)]
    fn show_banner(&mut self, banner: &str, language: &str) -> HookResult<()> {
        info!("Got banner:\n{}", banner.escape_default());
        Ok(())
    }
    // TODO: postauth channel callbacks
}
