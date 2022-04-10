use anyhow::{Result, Error, Context};

use door_sshproto::packets::KexInit;

fn main() -> Result<(), Error> {
    let k = KexInit {
        cookie: &[1,2,3],
        kex: "hello,more".into(),
        hostkey: "hello,more".into(),
        enc_c2s: "hello,more".into(),
        enc_s2c: "hello,more".into(),
        mac_c2s: "hello,more".into(),
        mac_s2c: "hello,more".into(),
        comp_c2s: "hello,more".into(),
        comp_s2c: "hello,more".into(),
        lang_c2s: "hello,more".into(),
        lang_s2c: "hello,more".into(),
        first_follows: false,
        reserved: 0,
    };
    println!("kex1 {k:?}");
    let t = toml::to_string(&k)?;
    println!("as toml:\n{}", t);
    // let k2: KexInit = toml::from_str(&t).context("deser")?;
    // println!("kex2 {k:?}");

    let mut buf = vec![0; 2000];
    let written = door_sshproto::wireformat::write_ssh(&mut buf, &k)?;
    buf.truncate(written);
    println!("buf is {buf:#?}");
    Ok(())
}
