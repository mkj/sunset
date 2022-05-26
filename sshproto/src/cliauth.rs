#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};
use heapless::{String, Vec};
use no_panic::no_panic;
use pretty_hex::PrettyHex;
use ring::digest::Digest;

use ring::signature::Signature as RingSig;

use crate::{packets::UserauthPkOk, *};
use behaviour::CliBehaviour;
use client::*;
use conn::RespPackets;
use packets::{AuthMethod, MethodPubKey, ParseContext, UserauthRequest};
use packets::{Packet, Signature, Userauth60};
use sign::SignKey;
use sshnames::*;
use wireformat::{BinString, Blob};

// pub for packets::ParseContext
pub enum Req {
    Password(ResponseString),
    PubKey { key: SignKey },
}

#[derive(Clone, Debug)]
pub enum AuthType {
    Password,
    PubKey,
}

pub enum AuthState {
    Unstarted,
    MethodQuery,
    Request { last_req: Req, sig: Option<RingSig> },
    Idle,
}

impl Req {
    // Creates a packet from the current request
    fn req_packet<'b>(
        &'b self,
        username: &'b str,
        parse_ctx: &mut ParseContext,
    ) -> Result<Packet<'b>> {
        let p = match self {
            Req::PubKey { key, .. } => {
                // already checked by make_pubkey_req()
                parse_ctx.cli_auth_type = Some(AuthType::PubKey);
                Packet::UserauthRequest(packets::UserauthRequest {
                    username,
                    service: SSH_SERVICE_CONNECTION,
                    method: key.pubkey().try_into()?,
                })
            }
            Req::Password(pw) => {
                parse_ctx.cli_auth_type = Some(AuthType::Password);
                Packet::UserauthRequest(packets::UserauthRequest {
                    username,
                    service: SSH_SERVICE_CONNECTION,
                    method: packets::AuthMethod::Password(packets::MethodPassword {
                        change: false,
                        password: pw,
                    }),
                })
            }
        };
        Ok(p)
    }
}

pub(crate) struct CliAuth {
    state: AuthState,

    username: ResponseString,

    // Starts as true, set to false if hook.auth_password() returns None.
    // Not set false if the server rejects auth.
    try_password: bool,

    // Set to false if hook.next_pubkey() returns None.
    try_pubkey: bool,
}

impl CliAuth {
    // TODO: take preferred/ordered authmethods
    pub fn new() -> Self {
        CliAuth {
            state: AuthState::Unstarted,
            username: ResponseString::new(),
            try_password: true,
            try_pubkey: true,
        }
    }

    // May be called multiple times
    pub async fn start<'b>(
        &'b mut self,
        resp: &mut RespPackets<'b>,
        mut b: CliBehaviour<'_>,
    ) -> Result<()> {
        if let AuthState::Unstarted = self.state {
            self.state = AuthState::MethodQuery;
            self.username = b.username().await?;

            let p = Packet::ServiceRequest(packets::ServiceRequest {
                name: SSH_SERVICE_USERAUTH,
            });
            resp.push(p.into()).trap()?;

            let p = Packet::UserauthRequest(packets::UserauthRequest {
                username: &self.username,
                service: SSH_SERVICE_CONNECTION,
                method: packets::AuthMethod::None,
            });
            resp.push(p.into()).trap()?;
        }
        Ok(())
    }

    async fn make_password_req(
        &mut self,
        b: &mut CliBehaviour<'_>,
    ) -> Result<Option<Req>> {
        let mut pw = ResponseString::new();
        match b.auth_password(&mut pw).await {
            Err(_) => Err(Error::BehaviourError { msg: "No password returned" }),
            Ok(r) if r => Ok(Some(Req::Password(pw))),
            Ok(_) => Ok(None),
        }
    }

    async fn make_pubkey_req(
        &mut self,
        b: &mut CliBehaviour<'_>,
    ) -> Result<Option<Req>> {
        let pk = b.next_authkey().await.map_err(|_| {
            self.try_pubkey = false;
            Error::BehaviourError { msg: "next_pubkey failed TODO" }
        })?;
        let pk = pk.map(|pk| Req::PubKey { key: pk });
        if pk.is_none() {
            self.try_pubkey = false;
        }
        Ok(pk)
    }

    pub fn auth_sig_msg(
        key: &SignKey,
        sess_id: &Digest,
        p: &Packet,
    ) -> Result<RingSig> {
        if let Packet::UserauthRequest(UserauthRequest {
            username,
            service,
            method: AuthMethod::PubKey(MethodPubKey { sig_algo, pubkey, .. }),
        }) = p
        {
            let sig_packet = Packet::UserauthRequest(UserauthRequest {
                username,
                service,
                method: AuthMethod::PubKey(MethodPubKey {
                    sig_algo,
                    pubkey: pubkey.clone(),
                    sig: None,
                    signing_now: true,
                }),
            });

            let msg = auth::AuthSigMsg {
                sess_id: BinString(sess_id.as_ref()),
                p: sig_packet,
            };
            let mut b = [0u8; 1000];
            let l = wireformat::write_ssh(&mut b, &msg)?;
            let b = &b[..l];
            trace!("msg {:?}", b.hex_dump());
            let s = key.sign_serialize(&msg)?;
            trace!("sig {:?}", s.hex_dump());
            Ok(s)
        } else {
            Err(Error::bug())
        }
    }

    pub async fn auth60<'b>(
        &'b mut self,
        auth60: &packets::Userauth60<'_>,
        resp: &mut RespPackets<'b>,
        sess_id: &Digest,
        parse_ctx: &mut ParseContext,
    ) -> Result<()> {
        parse_ctx.cli_auth_type = None;

        match auth60 {
            Userauth60::PkOk(pkok) => self.auth_pkok(pkok, resp, sess_id, parse_ctx),
            _ => todo!(),
        }
    }

    fn auth_pkok<'b>(
        &'b mut self,
        pkok: &UserauthPkOk<'_>,
        resp: &mut RespPackets<'b>,
        sess_id: &Digest,
        parse_ctx: &mut ParseContext,
    ) -> Result<()> {
        // We are only sending keys one at a time so they shouldn't
        // get out of sync. In future we could change it to send
        // multiple requests pipelined, though unsure of server
        // acceptance of that.
        match &mut self.state {
            // Some tricky logistics to create the signature in self.state
            // using a packet borrowed from other parts of self.state
            AuthState::Request { last_req, ref mut sig } => {
                if sig.is_some() {
                    return Err(Error::SSHProtoError);
                }
                if let Req::PubKey { key, .. } = last_req {
                    if key.pubkey() != pkok.key.0 {
                        return Err(Error::SSHProtoError);
                    }
                }

                let mut p = last_req.req_packet(&self.username, parse_ctx)?;
                let last_req = &last_req;
                if let Req::PubKey { key, .. } = last_req {
                    // Create the signature
                    let new_sig = Self::auth_sig_msg(&key, sess_id, &p)?;
                    let rsig = sig.insert(new_sig);

                    // Put it in the packet
                    if let Packet::UserauthRequest(UserauthRequest {
                        method:
                            AuthMethod::PubKey(MethodPubKey {
                                sig: ref mut psig, ..
                            }),
                        ..
                    }) = p
                    {
                        *psig = Some(Blob(Signature::from_ring(key, rsig)?))
                    }
                    resp.push(p.into()).trap()?;
                    return Ok(());
                }
            }
            _ => (),
        }
        trace!("Unexpected userauth60");
        Err(Error::SSHProtoError)
    }

    // mystery: not quite sure why the 'b lifetime is required
    pub async fn failure<'b>(
        &'b mut self,
        failure: &packets::UserauthFailure<'_>,
        b: &mut CliBehaviour<'_>,
        resp: &mut RespPackets<'b>,
        parse_ctx: &mut ParseContext,
    ) -> Result<()> {
        parse_ctx.cli_auth_type = None;
        // TODO: look at existing self.state, handle the failure.
        self.state = AuthState::Idle;

        if failure.methods.has_algo(SSH_AUTHMETHOD_PUBLICKEY)? {
            while self.try_pubkey {
                let req = self.make_pubkey_req(b).await?;
                if let Some(req) = req {
                    self.state = AuthState::Request { last_req: req, sig: None };
                    break;
                }
            }
        }

        if matches!(self.state, AuthState::Idle)
            && self.try_password
            && failure.methods.has_algo(SSH_AUTHMETHOD_PASSWORD)?
        {
            let req = self.make_password_req(b).await?;
            if let Some(req) = req {
                self.state = AuthState::Request { last_req: req, sig: None };
            }
        }

        if !(self.try_pubkey || self.try_password) {
            return Err(Error::BehaviourError {
                msg: "No authentication methods left",
            });
        }

        if let AuthState::Request { last_req, .. } = &self.state {
            let p = last_req.req_packet(&self.username, parse_ctx)?;
            resp.push(p.into()).trap()?;
        }
        Ok(())
    }

    pub async fn success(&mut self, b: &mut CliBehaviour<'_>) -> Result<()> {
        // TODO: check current state? Probably just informational
        self.state = AuthState::Idle;
        let _ = b.authenticated().await;
        // TODO errors
        Ok(())
    }
}
