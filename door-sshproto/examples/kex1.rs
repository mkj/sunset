#![allow(unused_imports)]

use anyhow::{Context, Error, Result};
use pretty_hex::PrettyHex;

use door_sshproto::packets::*;
use door_sshproto::wireformat::BinString;

fn main() -> Result<(), Error> {
    let k = KexInit {
        // cookie: &[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],
        cookie: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        kex: "hello,more".into(),
        hostkey: "hello,more".into(),
        cipher_c2s: "hello,more".into(),
        cipher_s2c: "hello,more".into(),
        mac_c2s: "hi".into(),
        mac_s2c: "hello,more".into(),
        comp_c2s: "hello,more".into(),
        comp_s2c: "hello,more".into(),
        lang_c2s: "hello,more".into(),
        lang_s2c: "hello,more".into(),
        first_follows: false,
        reserved: 0,
    };
    let p = Packet::KexInit(k);
    println!("p {p:?}");

    let bs = BinString(&[0x11, 0x22, 0x33]);
    let dhc =
        Packet::KexDHInit(KexDHInit::Curve25519Init(Curve25519Init { q_c: bs }));
    println!("dhc1 {dhc:?}");

    // if let SpecificPacket::KexInit(ref k2) = p.p {
    //     let t = toml::to_string(&k2)?;
    //     println!("as toml:\n{}", t);

    // }
    // let k2: KexInit = toml::from_str(&t).context("deser")?;
    // println!("kex2 {k:?}");

    let mut buf = vec![0; 2000];
    let written = door_sshproto::wireformat::write_ssh(&mut buf, &p)?;
    buf.truncate(written);
    println!("{:?}", buf.hex_dump());
    let ctx = door_sshproto::packets::ParseContext::new();
    let x: Packet = door_sshproto::wireformat::packet_from_bytes(&buf, &ctx)?;
    println!("fetched {x:?}");

    // let mut buf = vec![0; 2000];
    // let written = door_sshproto::wireformat::write_ssh(&mut buf, &dhc)?;
    // buf.truncate(written);
    // println!("wrote {written} {:?}", buf.hex_dump());
    // let mut ctx = door_sshproto::packets::ParseContext::new();
    // ctx.kextype = KexType::Curve25519;
    // let x: Packet = door_sshproto::wireformat::packet_from_bytes(&buf, ctx)?;
    // println!("fetched {:?}", buf.hex_dump());
    // println!("fetched {x:?} {:p}", &x);
    Ok(())
}
