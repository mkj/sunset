// Note these string literals are also copy+pasted to #[serde(rename)]
// directives in packets.rs

// RFC8731
pub const SSH_NAME_CURVE25519: &str = "curve25519-sha256";
// An older alias prior to standardisation. Eventually could be removed
pub const SSH_NAME_CURVE25519_LIBSSH: &str = "curve25519-sha256@libssh.org";
// RFC8308 Extension Negotiation
pub const SSH_NAME_EXT_INFO_S: &str = "ext-info-s";
pub const SSH_NAME_EXT_INFO_C: &str = "ext-info-c";
// Implemented by Dropbear to improve first_kex_packet_follows, described
// https://mailarchive.ietf.org/arch/msg/secsh/3n6lNzDHmsGsIQSqhmHHwigIbuo/
pub const SSH_NAME_KEXGUESS2: &str = "kexguess2@matt.ucc.asn.au";

// RFC8709
pub const SSH_NAME_ED25519: &str = "ssh-ed25519";
// RFC8332
pub const SSH_NAME_RSA_SHA256: &str = "rsa-sha2-256";
// RFC4253. Deprecated for signatures but is a valid key type.
pub const SSH_NAME_RSA: &str = "ssh-rsa";

// RFC4344
pub const SSH_NAME_AES256_CTR: &str = "aes256-ctr";
// OpenSSH PROTOCOL.chacha20poly1305.txt
pub const SSH_NAME_CHAPOLY: &str = "chacha20-poly1305@openssh.com";
// OpenSSH PROTOCOL.
pub const SSH_NAME_AES256_GCM: &str = "aes256-gcm@openssh.com";
// (No-one uses aes-gcm RFC5647 from the NSA, it fails to define mac negotiation
// sensibly and has horrible naming style)

// RFC6668
pub const SSH_NAME_HMAC_SHA256: &str = "hmac-sha2-256";

// RFC4253
pub const SSH_NAME_NONE: &str = "none";

// RFC4252
pub const SSH_SERVICE_USERAUTH: &str = "ssh-userauth";
// RFC4254
pub const SSH_SERVICE_CONNECTION: &str = "ssh-connection";

