//! Named SSH algorithms, methods and extensions. This module also serves as
//! an index of SSH specifications.

//! Some identifiers are also listed directly in `packet.rs` derive attributes.
//! Packet numbers are listed in `packet.rs`.

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
/// (No-one uses aes-gcm [RFC5647](https://tools.ietf.org/html/rfc5647) from the NSA, it fails to define mac negotiation
/// sensibly and has horrible naming style)
pub const SSH_NAME_AES256_GCM: &str = "aes256-gcm@openssh.com";

/// [RFC6668](https://tools.ietf.org/html/rfc6668)
pub const SSH_NAME_HMAC_SHA256: &str = "hmac-sha2-256";

/// [RFC4253](https://tools.ietf.org/html/rfc4253)
pub const SSH_NAME_NONE: &str = "none";

/// [RFC4252](https://tools.ietf.org/html/rfc4252)
pub const SSH_SERVICE_USERAUTH: &str = "ssh-userauth";
/// [RFC4254](https://tools.ietf.org/html/rfc4254)
pub const SSH_SERVICE_CONNECTION: &str = "ssh-connection";

/// [RFC4252](https://tools.ietf.org/html/rfc4252)
pub const SSH_AUTHMETHOD_PASSWORD: &str = "password";
/// [RFC4252](https://tools.ietf.org/html/rfc4252)
pub const SSH_AUTHMETHOD_PUBLICKEY: &str = "publickey";
/// [RFC4256](https://tools.ietf.org/html/rfc4256)
pub const SSH_AUTHMETHOD_INTERACTIVE: &str = "keyboard-interactive";

/// [RFC4254](https://tools.ietf.org/html/rfc4254)
pub const SSH_EXTENDED_DATA_STDERR: u32 = 1;
