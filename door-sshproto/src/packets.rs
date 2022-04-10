use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct Packet<'a> {
    pub ty: u8,
    #[serde(borrow)]
    pub p: SpecificPacket<'a>,
}

#[derive(Serialize, Deserialize)]
pub enum SpecificPacket<'a> {
    #[serde(borrow)]
    KexInit(KexInit<'a>),
    KexDHInit(KexDHInit),
    KexDHReply(KexDHReply),
}

// TODO: impl matching
 // XXX - how does a str reference work? prob needs to be [u8]?
#[derive(Serialize, Deserialize, Debug)]
pub struct NameList<'a>(&'a str);

impl<'a> From<&'a str> for NameList<'a> {
    fn from(s: &'a str) -> Self {
        Self(s)
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KexInit<'a> {
    pub cookie: &'a [u8], // 16 bytes
    pub kex: NameList<'a>,
    pub hostkey: NameList<'a>,
    pub enc_c2s: NameList<'a>,
    pub enc_s2c: NameList<'a>,
    pub mac_c2s: NameList<'a>,
    pub mac_s2c: NameList<'a>,
    pub comp_c2s: NameList<'a>,
    pub comp_s2c: NameList<'a>,
    pub lang_c2s: NameList<'a>,
    pub lang_s2c: NameList<'a>,
    pub first_follows: bool,
    pub reserved: u32
}

#[derive(Serialize, Deserialize)]
pub enum KexDHInit {
    Curve25519Init(Curve25519Init),
}

#[derive(Serialize, Deserialize)]
pub enum KexDHReply {
    Curve25519Reply(Curve25519Reply),
}

#[derive(Serialize, Deserialize)]
pub struct Curve25519Init {

}
#[derive(Serialize, Deserialize)]
pub struct Curve25519Reply {

}
