use sunset::packets::Unknown;
use sunset::sshwire::{read_ssh, ssh_push_vec};
use sunset_sshwire_derive::*;

#[test]
fn enum_tuple() {
    #[derive(SSHEncode, SSHDecode, PartialEq, Debug)]
    enum En<'a> {
        #[sshwire(variant = "a")]
        A,
        #[sshwire(variant = "b")]
        B(u32, u8),
        #[sshwire(variant = "c")]
        C(bool),
        #[sshwire(unknown)]
        U(Unknown<'a>),
    }

    let mut v = vec![];
    ssh_push_vec(&mut v, &En::A).unwrap();
    assert!(v.is_empty());

    let mut v = vec![];
    ssh_push_vec(&mut v, &En::B(0xa1, 0x20)).unwrap();
    assert_eq!(v, [0x00u8, 0x00, 0x00, 0xa1, 0x20]);

    let mut v = vec![];
    ssh_push_vec(&mut v, &En::C(true)).unwrap();
    assert_eq!(v, [0x01u8]);
}
