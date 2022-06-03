#![allow(unused_imports)]

use anyhow::{Context, Error, Result};
use pretty_hex::PrettyHex;

use door_sshproto::*;
use door_sshproto::packets::*;
use door_sshproto::sshwire::BinString;

use simplelog::{TestLogger,self,LevelFilter};

fn main() -> Result<()> {
    let _ = TestLogger::init(LevelFilter::Trace, simplelog::Config::default());
    // do_kexinit()?;
    do_userauth()?;
    Ok(())
}

fn do_userauth() -> Result<()> {
    let p: Packet = packets::UserauthRequest {
        username: "matt".into(),
        service: "con",
        method: AuthMethod::Password(packets::MethodPassword { change: false, password: "123".into() }),
    }.into();

    let mut buf = vec![0; 2000];
    let written = door_sshproto::sshwire::write_ssh(&mut buf, &p)?;
    buf.truncate(written);
    println!("buf {:?}", buf.hex_dump());

    let ctx = ParseContext::new();
    let x: Packet = door_sshproto::sshwire::packet_from_bytes(&buf, &ctx)?;
    println!("{x:?}");

    Ok(())


}

fn do_kexinit() -> Result<()> {

    let k = KexInit {
        // cookie: &[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16],
        cookie: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        kex: "hello,more".try_into().unwrap(),
        hostkey: "hello,more".try_into().unwrap(),
        cipher_c2s: "hello,more".try_into().unwrap(),
        cipher_s2c: "hello,more".try_into().unwrap(),
        mac_c2s: "hi".try_into().unwrap(),
        mac_s2c: "hello,more".try_into().unwrap(),
        comp_c2s: "hello,more".try_into().unwrap(),
        comp_s2c: "hello,more".try_into().unwrap(),
        lang_c2s: "hello,more".try_into().unwrap(),
        lang_s2c: "hello,more".try_into().unwrap(),
        first_follows: false,
        reserved: 0,
    };
    let p = Packet::KexInit(k);
    println!("p {p:?}");

    let bs = BinString(&[0x11, 0x22, 0x33]);
    let dhc: Packet = KexDHInit { q_c: bs }.into();
    println!("dhc1 {dhc:?}");

    // if let SpecificPacket::KexInit(ref k2) = p.p {
    //     let t = toml::to_string(&k2)?;
    //     println!("as toml:\n{}", t);

    // }
    // let k2: KexInit = toml::from_str(&t).context("deser")?;
    // println!("kex2 {k:?}");


    let mut buf = vec![0; 2000];
    let written = door_sshproto::sshwire::write_ssh(&mut buf, &p)?;
    buf.truncate(written);
    println!("{:?}", buf.hex_dump());
    let ctx = ParseContext::new();
    let x: Packet = door_sshproto::sshwire::packet_from_bytes(&buf, &ctx)?;
    println!("fetched {x:?}");

    // let cli= Client::new();
    // let c = Conn::new_client(cli)?;
    // let mut work = vec![0; 2000];
    // let mut r = conn::Runner::new(c, work.as_mut_slice())?;
    // r.input(&buf)?;
    Ok(())

}
