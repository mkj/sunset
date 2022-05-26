#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use core::task::{Poll, Waker};
use heapless::{String, Vec};
use no_panic::no_panic;
use ring::digest::Digest;

use ring::signature::Signature as RingSig;

use crate::*;
use behaviour::CliBehaviour;
use client::*;
use conn::RespPackets;
use packets::{ParseContext, UserauthRequest, AuthMethod, MethodPubKey};
use wireformat::{BinString, Blob};
use packets::{Packet, Signature, Userauth60};
use sign::SignKey;
use sshnames::*;

// pub for packets::ParseContext
pub enum Req {
    Password(ResponseString),
    PubKey { key: SignKey, sig: Option<RingSig> },
}

#[derive(Clone, Debug)]
pub enum AuthType {
    Password,
    PubKey,
}

pub enum AuthState {
    Unstarted,
    MethodQuery,
    Request { last_req: Req, sig2: Option<RingSig> },
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
            Req::PubKey { key, sig } => {
                // already checked by make_pubkey_req()
                let sig_algo = Signature::sig_name_for_pubkey(
                    &key.pubkey()).trap()?;
                let pubmethod = packets::MethodPubKey {
                    sig_algo,
                    pubkey: Blob(key.pubkey()),
                    sig: None
                };
                parse_ctx.cli_auth_type = Some(AuthType::PubKey);
                Packet::UserauthRequest(packets::UserauthRequest {
                    username,
                    service: SSH_SERVICE_CONNECTION,
                    method: packets::AuthMethod::PubKey(pubmethod),
                })
            }
            Req::Password(pw) => {
                parse_ctx.cli_auth_type = Some(AuthType::Password);
                Packet::UserauthRequest(packets::UserauthRequest {
                    username    ,
                    service: SSH_SERVICE_CONNECTION,
                    method: packets::AuthMethod::Password(
                        packets::MethodPassword { change: false, password: pw },
                    ),
                })
            }
        };
        trace!("parse_ctx => {:?}", parse_ctx);
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
        let pk = pk.map(|pk| Req::PubKey { key: pk, sig: None });
        if pk.is_none() {
            self.try_pubkey = false;
        }
        Ok(pk)
    }

    pub fn auth_sig_msg(key: &SignKey, sess_id: &Digest, p: &Packet) -> Result<RingSig> {
        if let Packet::UserauthRequest(
            UserauthRequest{username, service,
                method: AuthMethod::PubKey(MethodPubKey{sig_algo, pubkey, ..})}) = p {

            let sig_packet = Packet::UserauthRequest(
                    UserauthRequest{username, service,
                method: AuthMethod::PubKey(MethodPubKey{
                    sig_algo, pubkey: pubkey.clone(), sig: None})});

            let msg = auth::AuthSigMsg {
                sess_id: BinString(sess_id.as_ref()),
                p: sig_packet,
            };
            key.sign_serialize(&msg)
        } else {
            Err(Error::bug())
        }
    }

    // Creates a packet from the current request
    fn req_packet<'b>(
        &'b self,
        username: &'b str,
        parse_ctx: &mut ParseContext,
    ) -> Result<Packet<'b>> {
        if let AuthState::Request { last_req: req, .. } = &self.state {
            let p = match req {
                Req::PubKey { key, .. } => {
                    // already checked by make_pubkey_req()
                    let sig_algo = Signature::sig_name_for_pubkey(
                        &key.pubkey()).trap()?;
                    let pubmethod = packets::MethodPubKey {
                        sig_algo,
                        pubkey: Blob(key.pubkey()),
                        sig: None
                    };
                    parse_ctx.cli_auth_type = Some(AuthType::PubKey);
                    Packet::UserauthRequest(packets::UserauthRequest {
                        username,
                        service: SSH_SERVICE_CONNECTION,
                        method: packets::AuthMethod::PubKey(pubmethod),
                    })
                }
                Req::Password(pw) => {
                    parse_ctx.cli_auth_type = Some(AuthType::Password);
                    Packet::UserauthRequest(packets::UserauthRequest {
                        username    ,
                        service: SSH_SERVICE_CONNECTION,
                        method: packets::AuthMethod::Password(
                            packets::MethodPassword { change: false, password: pw },
                        ),
                    })
                }
            };
            trace!("parse_ctx => {:?}", parse_ctx);
            Ok(p)
        } else {
            Err(Error::bug())
        }
    }

    // mystery: not quite sure why the 'b lifetime is required
    pub async fn auth60<'b>(
        &'b mut self,
        auth60: &packets::Userauth60<'_>,
        resp: &mut RespPackets<'b>,
        sess_id: &Digest,
        parse_ctx: &mut ParseContext,
    ) -> Result<()> {
        parse_ctx.cli_auth_type = None;
        trace!("parse_ctx => {:?}", parse_ctx);
        // We are only sending keys one at a time so they shouldn't
        // get out of sync. In future we could change it to send
        // multiple requests pipelined, though unsure of server
        // acceptance of that.
        match (auth60, &mut self.state) {
            (
                Userauth60::PkOk(pkok),
                AuthState::Request {
                    last_req,
                    ref mut sig2,
                },
            ) => {
                let mut p;
                if let Req::PubKey { key, .. } = last_req {
                    if key.pubkey() != pkok.key.0 {
                        trace!("Mismatch userauth60");
                        return Err(Error::SSHProtoError);
                    }
                }
                // TODO check sig2
                p = last_req.req_packet(&self.username, parse_ctx)?;
                let last_req = &last_req;
                let new_sig = if let Req::PubKey { key, .. } = last_req {
                    Self::auth_sig_msg(&key, sess_id, &p)?
                } else {
                    unreachable!();
                };
                let rsig = sig2.insert(new_sig);
            // self.state = AuthState::Request { last_req: Req::PubKey { key, sig: Some(sig) }};
            // let rsig = if let AuthState::Request { last_req: Req::PubKey { sig: ref mut sig, .. }} = self.state {
            //     sig.insert(new_sig)
            // } else {
            //     unreachable!();
            // };

                if let Packet::UserauthRequest(UserauthRequest{
                        method: AuthMethod::PubKey(MethodPubKey{sig: ref mut psig, ..}), ..}) = p {
                    *psig = Some(Blob(Signature::from_ring(key, rsig)?))
                }
                resp.push(p.into()).trap()?;
                return Ok(())
            }
            _ => ()
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
        trace!("parse_ctx => {:?}", parse_ctx);
        // TODO: look at existing self.state, handle the failure.
        self.state = AuthState::Idle;

        if failure.methods.has_algo(SSH_AUTHMETHOD_PUBLICKEY)? {
            while self.try_pubkey {
                let req = self.make_pubkey_req(b).await?;
                if let Some(req) = req {
                    self.state = AuthState::Request { last_req: req, sig2: None };
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
                self.state = AuthState::Request { last_req: req, sig2: None };
                trace!("parse_ctx => {:?}", parse_ctx);
            }
        }

        if !(self.try_pubkey || self.try_password) {
            return Err(Error::BehaviourError {
                msg: "No authentication methods left",
            });
        }

        if let AuthState::Request { last_req: req, .. } = &self.state {
            let p = self.req_packet(&self.username, parse_ctx)?;
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
