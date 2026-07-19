use sunset::sshwire::Unknown;
use sunset::sshwire::{self, WireError, read_ssh, ssh_push_vec};
use sunset_sshwire_derive::*;

#[test]
fn enum_tuple() {
    #[derive(SSHEncode, SSHDecode, PartialEq, Debug)]
    #[sshwire(variant_prefix)]
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
    assert_eq!(v, [0x00u8, 0, 0, 1, b'a']);

    let mut v = vec![];
    ssh_push_vec(&mut v, &En::B(0xa1, 0x20)).unwrap();
    assert_eq!(v, [0x00u8, 0, 0, 1, b'b', 0x00u8, 0x00, 0x00, 0xa1, 0x20]);

    let mut v = vec![];
    ssh_push_vec(&mut v, &En::C(true)).unwrap();
    assert_eq!(v, [0x00u8, 0, 0, 1, b'c', 0x01]);
}

#[test]
fn unknown_variant() {
    #[derive(SSHEncode, SSHDecode, PartialEq, Debug)]
    #[sshwire(variant_prefix)]
    enum En<'a> {
        #[sshwire(variant = "a")]
        A,
        #[sshwire(variant = "b")]
        B(u32, u8),
        #[sshwire(unknown)]
        U(Unknown<'a>),
    }

    let s = [0x00u8, 0x00, 0x00, 0x02, b'X', b'X'];
    let (r, l) = read_ssh::<En>(&s, None).unwrap();
    assert_eq!(l, s.len());
    assert_eq!(r, En::U(Unknown(b"XX")));

    // encoding fails
    let e = sshwire::length_enc(&r);
    assert_eq!(e, Err(WireError::EncodeUnknown));
}

#[test]
fn no_unknown_variant() {
    #[derive(SSHEncode, SSHDecode, PartialEq, Debug)]
    #[sshwire(variant_prefix)]
    #[sshwire(decode_unknown_fail)]
    enum En {
        #[sshwire(variant = "a")]
        A,
        #[sshwire(variant = "b")]
        B(u32, u8),
        #[sshwire(variant = "c")]
        C,
    }

    let s = [0x00u8, 0x00, 0x00, 0x02, b'X', b'X'];
    let r = read_ssh::<En>(&s, None);
    assert!(
        matches!(r, Err(sunset::Error::UnknownMethod { .. })),
        "Unexpected {r:?}"
    );

    let s = [0x00u8, 0x00, 0x00, 0x01, b'a'];
    let r = read_ssh::<En>(&s, None);
    assert!(matches!(r, Ok((En::A, 5))), "Unexpected {r:?}");

    let s = [0x00u8, 0x00, 0x00, 0x01, b'c'];
    let r = read_ssh::<En>(&s, None);
    assert!(matches!(r, Ok((En::C, 5))), "Unexpected {r:?}");
}

#[test]
fn unknown_unit_variant() {
    #[derive(SSHEncode, SSHDecode, PartialEq, Debug)]
    #[sshwire(variant_prefix)]
    enum En {
        #[sshwire(variant = "a")]
        A,
        #[sshwire(variant = "b")]
        B(u32, u8),
        #[sshwire(unknown)]
        U,
    }

    let s = [0x00u8, 0x00, 0x00, 0x02, b'X', b'X'];
    let (r, l) = read_ssh::<En>(&s, None).unwrap();
    assert_eq!(l, s.len());
    assert_eq!(r, En::U);

    // encoding fails
    let e = sshwire::length_enc(&En::U);
    assert_eq!(e, Err(WireError::EncodeUnknown));
}

#[test]
fn enum_struct() {
    #[derive(SSHEncode, SSHDecode, PartialEq, Debug)]
    #[sshwire(variant_prefix)]
    enum En<'a> {
        #[sshwire(variant = "a")]
        A,
        #[sshwire(variant = "b")]
        B { first: u32, second: u8 },
        #[sshwire(variant = "c")]
        C { one: bool },
        #[sshwire(unknown)]
        U(Unknown<'a>),
    }

    let mut v = vec![];
    ssh_push_vec(&mut v, &En::B { first: 0xa1, second: 0x20 }).unwrap();
    assert_eq!(v, [0x00u8, 0x00, 0x00, 0x01, b'b', 0x00, 0x00, 0x00, 0xa1, 0x20]);

    let mut v = vec![];
    ssh_push_vec(&mut v, &En::C { one: true }).unwrap();
    assert_eq!(v, [0x00u8, 0x00, 0x00, 0x01, b'c', 0x01]);
}
