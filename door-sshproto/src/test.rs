#[cfg(test)]
mod tests {
    use crate::error::Error;
    use crate::packets::*;
    use crate::wireformat::BinString;
    use crate::packets::{Packet};
    use crate::kex::{KexType};
    use crate::{packets, wireformat};
    use pretty_hex::PrettyHex;
    use serde::de::Unexpected;
    use serde::{Deserialize, Serialize};

    fn test_roundtrip_packet(p: &Packet) -> Result<(), Error> {
        let mut buf1 = vec![99; 500];
        let _w1 = wireformat::write_ssh(&mut buf1, &p)?;

        let p2 = wireformat::packet_from_bytes(&buf1)?;

        let mut buf2 = vec![99; 500];
        let _w2 = wireformat::write_ssh(&mut buf2, &p2)?;
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
            cookie: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
            kex: "kex".into(),
            hostkey: "hostkey,another".into(),
            cipher_c2s: "chacha20-poly1305@openssh.com,aes128-ctr".into(),
            cipher_s2c: "blowfish".into(),
            mac_c2s: "hmac-sha1".into(),
            mac_s2c: "hmac-md5".into(),
            comp_c2s: "none".into(),
            comp_s2c: "".into(),
            lang_c2s: "".into(),
            lang_s2c: "".into(),
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
        let p =
            Packet::KexDHInit(KexDHInit{ q_c: bs });

        test_roundtrip_packet(&p).unwrap();
        // packet format needs to be consistent
        // test_roundtrip_packet(&p, KexType::DiffieHellman).unwrap_err();
        // test_roundtrip_packet(&p, KexType::Unset).unwrap_err();
    }
}
