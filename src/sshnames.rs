//! Named SSH algorithms, methods, and extensions.
//!
//! Some identifiers are also listed directly in `packet.rs` derive attributes.
//! Packet numbers are listed in `packets.rs`.
//!
//! This module also serves as an index of SSH specifications.

pub const SSH_PORT: u16 = 22;

/// [RFC8731](https://tools.ietf.org/html/rfc8731)
pub const SSH_NAME_CURVE25519: &str = "curve25519-sha256";
/// An older alias prior to standardisation. Eventually could be removed
pub const SSH_NAME_CURVE25519_LIBSSH: &str = "curve25519-sha256@libssh.org";
/// [RFC8308](https://tools.ietf.org/html/rfc8308) Extension Negotiation
pub const SSH_NAME_EXT_INFO_S: &str = "ext-info-s";
/// [RFC8308](https://tools.ietf.org/html/rfc8308) Extension Negotiation
pub const SSH_NAME_EXT_INFO_C: &str = "ext-info-c";
/// Implemented by Dropbear to improve first_kex_packet_follows, described
/// [https://mailarchive.ietf.org/arch/msg/secsh/3n6lNzDHmsGsIQSqhmHHwigIbuo/](https://mailarchive.ietf.org/arch/msg/secsh/3n6lNzDHmsGsIQSqhmHHwigIbuo/)
pub const SSH_NAME_KEXGUESS2: &str = "kexguess2@matt.ucc.asn.au";
/// Strict Kex
/// TODO
pub const SSH_NAME_STRICT_KEX_S: &str = "kex-strict-s-v00@openssh.com";
/// Strict Kex
/// TODO
pub const SSH_NAME_STRICT_KEX_C: &str = "kex-strict-c-v00@openssh.com";

/// [RFC8709](https://tools.ietf.org/html/rfc8709)
pub const SSH_NAME_ED25519: &str = "ssh-ed25519";
/// [RFC8332](https://tools.ietf.org/html/rfc8332)
pub const SSH_NAME_RSA_SHA256: &str = "rsa-sha2-256";
/// [RFC4253](https://tools.ietf.org/html/rfc4253). Deprecated for signatures but is a valid key type.
pub const SSH_NAME_RSA: &str = "ssh-rsa";

/// [RFC4344](https://tools.ietf.org/html/rfc4344)
pub const SSH_NAME_AES256_CTR: &str = "aes256-ctr";
/// OpenSSH [PROTOCOL.chacha20poly1305.txt](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL.chacha20poly1305?annotate=HEAD)
pub const SSH_NAME_CHAPOLY: &str = "chacha20-poly1305@openssh.com";
/// OpenSSH [PROTOCOL](https://cvsweb.openbsd.org/src/usr.bin/ssh/PROTOCOL?annotate=HEAD).
/// (No-one directly uses `AEAD_AES_256_GCM` [RFC5647](https://tools.ietf.org/html/rfc5647) from the NSA, it fails to define mac negotiation
/// sensibly and has incongruous naming style)
pub const SSH_NAME_AES256_GCM: &str = "aes256-gcm@openssh.com";

/// [RFC6668](https://tools.ietf.org/html/rfc6668)
pub const SSH_NAME_HMAC_SHA256: &str = "hmac-sha2-256";

/// [RFC4253](https://tools.ietf.org/html/rfc4253)
pub const SSH_NAME_NONE: &str = "none";

/// [RFC4252](https://tools.ietf.org/html/rfc4252)
pub const SSH_SERVICE_USERAUTH: &str = "ssh-userauth";
/// [RFC4254](https://tools.ietf.org/html/rfc4254)
///
/// `IUTF8` is specified in
/// [RFC8160](https://tools.ietf.org/html/rfc8160)
pub const SSH_SERVICE_CONNECTION: &str = "ssh-connection";

/// [RFC4252](https://tools.ietf.org/html/rfc4252)
pub const SSH_AUTHMETHOD_PASSWORD: &str = "password";
/// [RFC4252](https://tools.ietf.org/html/rfc4252)
pub const SSH_AUTHMETHOD_PUBLICKEY: &str = "publickey";
/// [RFC4256](https://tools.ietf.org/html/rfc4256)
pub const SSH_AUTHMETHOD_INTERACTIVE: &str = "keyboard-interactive";

/// [RFC4254](https://tools.ietf.org/html/rfc4254)
pub const SSH_EXTENDED_DATA_STDERR: u32 = 1;

/// [RFC8308](https://tools.ietf.org/html/rfc8308) Extension Negotiation
pub const SSH_EXT_SERVER_SIG_ALGS: &str = "server-sig-algs";

/// [RFC4254](https://tools.ietf.org/html/rfc4254)
#[allow(non_camel_case_types)]
#[derive(Debug)]
pub enum ChanFail {
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
    SSH_OPEN_CONNECT_FAILED = 2,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
    SSH_OPEN_RESOURCE_SHORTAGE = 4,
}

/// SSH agent message numbers
///
/// [draft-miller-ssh-agent-04](https://tools.ietf.org/html/draft-miller-ssh-agent-04)
#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
pub enum AgentMessageNum {
    SSH_AGENT_FAILURE = 5,
    SSH_AGENT_SUCCESS = 6,
    SSH_AGENTC_REQUEST_IDENTITIES = 11,
    SSH_AGENT_IDENTITIES_ANSWER = 12,
    SSH_AGENTC_SIGN_REQUEST = 13,
    SSH_AGENT_SIGN_RESPONSE = 14,

}

/// [draft-miller-ssh-agent-04](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04)
pub const SSH_AGENT_FLAG_RSA_SHA2_256: u32 = 0x02;
