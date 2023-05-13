#[allow(unused_imports)]
use {
    sunset::{Error, Result},
    log::{debug, error, info, log, trace, warn},
};

use std::path::Path;

use pretty_hex::PrettyHex;
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use sunset_sshwire_derive::*;

use crate::*;
use sunset::sshwire;
use sunset::{PubKey, AuthSigMsg, Signature};
use sshwire::{WireError, WireResult, BinString, TextString, Blob, SSHSink, SSHSource, SSHDecode, SSHEncode};
use sshwire::{SSHEncodeEnum, SSHDecodeEnum};
use sunset::sign::{OwnedSig, SignKey};
use sunset::sshnames::*;

/* Must be sufficient for the list of all public keys */
const BUF_SIZE: usize = 10240;

#[derive(Debug, SSHEncode)]
struct AgentSignRequest<'a> {
    pub key_blob: Blob<PubKey<'a>>,
    pub msg: Blob<&'a AuthSigMsg<'a>>,
    pub flags: u32,
}

#[derive(Debug, SSHDecode)]
struct AgentSignResponse<'a> {
    pub sig: Blob<Signature<'a>>,
}

#[derive(Debug)]
struct AgentIdentitiesAnswer<'a> {
    // [(key blob, comment)]
    pub keys: Vec<(PubKey<'a>, TextString<'a>)>,
}

#[derive(Debug)]
enum AgentRequest<'a> {
    SignRequest(AgentSignRequest<'a>),
    RequestIdentities,
}

impl SSHEncode for AgentRequest<'_> {
    fn enc(&self, s: &mut dyn SSHSink) -> WireResult<()> {
        match self {
            Self::SignRequest(a) => {
                let n = AgentMessageNum::SSH_AGENTC_SIGN_REQUEST as u8;
                n.enc(s)?;
                a.enc(s)?;
            }
            Self::RequestIdentities => {
                let n = AgentMessageNum::SSH_AGENTC_REQUEST_IDENTITIES as u8;
                n.enc(s)?;
            }
        }
        Ok(())
    }
}

/// The subset of responses we recognise
#[derive(Debug)]
enum AgentResponse<'a> {
    IdentitiesAnswer(AgentIdentitiesAnswer<'a>),
    SignResponse(AgentSignResponse<'a>),
}

impl<'de: 'a, 'a> SSHDecode<'de> for AgentResponse<'a> {
    fn dec<S>(s: &mut S) -> WireResult<Self>
    where S: SSHSource<'de> {
        let number = u8::dec(s)?;
        if number == AgentMessageNum::SSH_AGENT_IDENTITIES_ANSWER as u8 {
            Ok(Self::IdentitiesAnswer(AgentIdentitiesAnswer::dec(s)?))
        } else if number == AgentMessageNum::SSH_AGENT_SIGN_RESPONSE as u8 {
            Ok(Self::SignResponse(AgentSignResponse::dec(s)?))
        } else {
            Err(WireError::UnknownPacket { number })
        }
    }
}

impl<'de: 'a, 'a> SSHDecode<'de> for AgentIdentitiesAnswer<'a> {
    fn dec<S>(s: &mut S) -> WireResult<Self> where S: SSHSource<'de> {
        //     uint32                  nkeys
        // Where "nkeys" indicates the number of keys to follow.  Following the
        // preamble are zero or more keys, each encoded as:
        //     string                  key blob
        //     string                  comment
        let l = u32::dec(s)?;
        let mut keys = vec![];
        for _ in 0..l {
            let kb = Blob::<PubKey>::dec(s)?;
            let comment = TextString::dec(s)?;
            keys.push((kb.0, comment))
        }
        Ok(AgentIdentitiesAnswer {
            keys,
        })
    }
}

pub struct AgentClient {
    conn: UnixStream,
    buf: Vec<u8>,
}

impl AgentClient {
    pub async fn new(path: impl AsRef<Path>) -> Result<Self, std::io::Error> {
        let conn = UnixStream::connect(path).await?;
        Ok(Self {
            conn,
            buf: vec![0u8; BUF_SIZE],
        })
    }

    async fn request(&mut self, r: AgentRequest<'_>) -> Result<AgentResponse> {
        let mut ctx = sunset::packets::ParseContext::new();
        ctx.method_pubkey_force_sig_bool = true;

        let l = sshwire::write_ssh_ctx(&mut self.buf, &Blob(r), ctx)?;
        let b = &self.buf[..l];

        trace!("agent request {:?}", b.hex_dump());

        self.conn.write_all(b).await?;
        self.response().await
    }

    async fn response(&mut self) -> Result<AgentResponse> {
        let mut l = [0u8; 4];
        self.conn.read_exact(&mut l).await?;
        let l = u32::from_be_bytes(l) as usize;
        if l > BUF_SIZE {
            return Err(Error::msg("Bad buffer size"));
        }
        let b = &mut self.buf[..l];
        self.conn.read_exact(b).await?;
        let r: AgentResponse = sshwire::read_ssh(b, None)?;
        Ok(r)
    }

    pub async fn keys(&mut self) -> Result<Vec<SignKey>> {
        match self.request(AgentRequest::RequestIdentities).await? {
            AgentResponse::IdentitiesAnswer(i) => {
                let mut keys = vec![];
                for (pk, comment) in i.keys.iter() {
                    match SignKey::from_agent_pubkey(pk) {
                        Ok(k) => keys.push(k),
                        Err(e) => debug!("skipping agent key {comment:?}: {e}")
                    }
                }
                Ok(keys)
            }
            resp => {
                debug!("response: {resp:?}");
                Err(Error::msg("Unexpected agent response"))
            }
        }
    }

    pub async fn sign_auth(&mut self, key: &SignKey, msg: &AuthSigMsg<'_>) -> Result<OwnedSig> {
        let flags = match key {
            #[cfg(feature = "rsa")]
            SignKey::AgentRSA(_) => SSH_AGENT_FLAG_RSA_SHA2_256,
            _ => 0,
        };
        trace!("flags {key:?}");
        let r = AgentRequest::SignRequest(AgentSignRequest {
            key_blob: Blob(key.pubkey()),
            msg: Blob(msg),
            flags,
        });

        match self.request(r).await? {
            AgentResponse::SignResponse(s) => {
                s.sig.0.try_into()
            }
            resp => {
                debug!("response: {resp:?}");
                Err(Error::msg("Unexpected agent response"))
            }
        }
    }

}
