#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::packets::*;
    use crate::packets::{Packet, ParseContext};
    use crate::sshwire;
    use crate::sshwire::BinString;
    use simplelog::{self, LevelFilter, TestLogger};

    pub fn init_log() {
        let _ = TestLogger::init(LevelFilter::Trace, simplelog::Config::default());
    }

    fn test_roundtrip_packet(p: &Packet) -> Result<(), Error> {
        init_log();
        let mut buf1 = vec![99; 500];
        let w1 = sshwire::write_ssh(&mut buf1, p)?;

        let ctx = ParseContext::new();

        let p2 = sshwire::packet_from_bytes(&buf1[..w1], &ctx)?;

        let mut buf2 = vec![99; 500];
        let _w2 = sshwire::write_ssh(&mut buf2, &p2)?;
        // println!("{p:?}");
        // println!("{p2:?}");
        // println!("{:?}", buf1.hex_dump());
        // println!("{:?}", buf2.hex_dump());

        assert_eq!(buf1, buf2);
        Ok(())
    }

    #[test]
    fn roundtrip_kexinit() {
        let k = KexInit {
            cookie: KexCookie([
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            ]),
            kex: "kex".try_into().unwrap(),
            hostsig: "hostkey,another".try_into().unwrap(),
            cipher_c2s: "chacha20-poly1305@openssh.com,aes128-ctr"
                .try_into()
                .unwrap(),
            cipher_s2c: "blowfish".try_into().unwrap(),
            mac_c2s: "hmac-sha1".try_into().unwrap(),
            mac_s2c: "hmac-md5".try_into().unwrap(),
            comp_c2s: "none".try_into().unwrap(),
            comp_s2c: "".try_into().unwrap(),
            lang_c2s: "".try_into().unwrap(),
            lang_s2c: "".try_into().unwrap(),
            first_follows: true,
            reserved: 0x6148291e,
        };
        let p = Packet::KexInit(k);
        test_roundtrip_packet(&p).unwrap();
    }

    #[test]
    fn roundtrip_packet_kexdh() {
        // XXX: this should break later if the q_c length is
        let bs = BinString(&[0x11, 0x22, 0x33]);
        let p = KexDHInit { q_c: bs }.into();

        test_roundtrip_packet(&p).unwrap();
        // packet format needs to be consistent
        // test_roundtrip_packet(&p, KexType::DiffieHellman).unwrap_err();
        // test_roundtrip_packet(&p, KexType::Unset).unwrap_err();
    }
}
