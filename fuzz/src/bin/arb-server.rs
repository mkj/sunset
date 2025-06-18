#![allow(unreachable_code)]
#![allow(dead_code)]

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use std::path::Path;

use sunset::namelist::NameList;
use sunset::packets::Packet;
use sunset::*;

use sunset_fuzz::*;

fn push_packet(p: &Packet, out: &mut Vec<u8>, pad_chapoly: bool) {
    let payload_len = sshwire::length_enc(p).expect("Packet size fits u32") as usize;

    // both are min size
    let size_block = 8;
    let ssh_length_size = 4;
    let ssh_min_padlen = 4;
    // calculate length of "encrypted" part, for padding
    let lenenc = if pad_chapoly {
        // is_aead(), length isn't encrypted
        1 + payload_len
    } else {
        1 + payload_len + ssh_length_size
    };
    // tag
    let integ = if pad_chapoly { 16 } else { 0 };

    let mut padlen = size_block - lenenc % size_block;
    if padlen < ssh_min_padlen {
        padlen += size_block
    }

    // The length of the packet in bytes, not including 'mac' or the
    // 'packet_length' field itself.
    let packet_len = 1 + payload_len + padlen;
    let total = ssh_length_size + packet_len + integ;
    let l1 = out.len();

    sshwire::ssh_push_vec(out, &(packet_len as u32)).expect("no overflow");
    out.push(padlen as u8);
    sshwire::ssh_push_vec(out, p).expect("encode packet succeeds");
    out.resize(out.len() + padlen + integ, 0);
    assert_eq!(l1 + total, out.len());
}

fn refine_packet(p: &mut Packet) -> Result<()> {
    use sshnames::*;
    use sunset::packets::*;
    match p {
        Packet::KexInit(k) => {
            *k = packets::KexInit {
                cookie: k.cookie.clone(),
                hostsig: NameList::single(SSH_NAME_ED25519)?,
                kex: NameList::single(SSH_NAME_CURVE25519)?,
                cipher_c2s: NameList::single(SSH_NAME_CHAPOLY)?,
                cipher_s2c: NameList::single(SSH_NAME_CHAPOLY)?,
                mac_c2s: NameList::empty(),
                mac_s2c: NameList::empty(),
                comp_c2s: NameList::single(SSH_NAME_NONE)?,
                comp_s2c: NameList::single(SSH_NAME_NONE)?,
                lang_c2s: NameList::empty(),
                lang_s2c: NameList::empty(),
                first_follows: k.first_follows,
                reserved: 0,
            }
        }
        Packet::UserauthRequest(r) => {
            r.service = SSH_SERVICE_CONNECTION;
        }
        Packet::ServiceRequest(r) => {
            // doesn't matter what it is, as long as it's known.
            r.name = SSH_SERVICE_CONNECTION;
        }

        Packet::ChannelOpen(ChannelOpen { sender_num: num, .. })
        | Packet::ChannelOpenConfirmation(ChannelOpenConfirmation {
            sender_num: num,
            ..
        })
        | Packet::ChannelOpenFailure(ChannelOpenFailure { num, .. })
        | Packet::ChannelWindowAdjust(ChannelWindowAdjust { num, .. })
        | Packet::ChannelData(ChannelData { num, .. })
        | Packet::ChannelDataExt(ChannelDataExt { num, .. })
        | Packet::ChannelEof(ChannelEof { num, .. })
        | Packet::ChannelClose(ChannelClose { num, .. })
        | Packet::ChannelSuccess(ChannelSuccess { num, .. })
        | Packet::ChannelFailure(ChannelFailure { num, .. })
        | Packet::ChannelRequest(ChannelRequest { num, .. }) => {
            // Limit channel ranges
            *num %= config::MAX_CHANNELS as u32 + 2;
        }
        _ => (),
    }
    Ok(())
}

fn packets(seed: &[u8]) -> Vec<u8> {
    let mut out = vec![];
    out.extend(b"SSH-2.0-fuzz\r\n");

    let mut u = arbitrary::Unstructured::new(seed);
    let mut pad_chapoly = false;
    let Ok(packets) = u.arbitrary_iter::<Packet>() else {
        return out;
    };
    for p in packets {
        let Ok(mut p) = p else {
            break;
        };

        refine_packet(&mut p).unwrap();

        push_packet(&p, &mut out, pad_chapoly);

        if matches!(p, Packet::NewKeys(_)) {
            // packets after newkeys are encrypted
            pad_chapoly = true;
        }
    }
    out
}

#[derive(argh::FromArgs, Debug)]
/** Server fuzz target with arbitrary packet generation.
 */
struct Args {
    #[cfg(feature = "nofuzz")]
    #[argh(option)]
    /// path to save raw network stream
    raw: Option<String>,

    #[cfg(feature = "nofuzz")]
    #[argh(option)]
    /// path to save inputs for fuzz-server
    fuzzin: Option<String>,

    #[argh(positional)]
    /// input corpus files or directories
    paths: Vec<String>,
}

fn save_raw(dest: &str, path: &Path, out: &[u8]) {
    // Save raw network input to a file
    let filename =
        Path::new(dest).join(path.file_name().unwrap()).with_extension("arbraw");
    info!("Writing to {filename:?}");
    std::fs::write(&filename, out).expect(&format!("Writing {filename:?}"))
}

fn save_fuzzin(dest: &str, path: &Path, fuzzin: &[u8]) {
    // Save raw network input to a file
    let filename =
        Path::new(dest).join(path.file_name().unwrap()).with_extension("arbfuzz");
    info!("Writing to {filename:?}");
    std::fs::write(&filename, fuzzin).expect(&format!("Writing {filename:?}"))
}

fn main() {
    #[cfg(feature = "nofuzz")]
    {
        let args: Args = argh::from_env();
        if let Some(fuzzdir) = &args.fuzzin {
            std::fs::create_dir_all(fuzzdir)
                .expect(&format!("Failed creating {fuzzdir:?}"));
        }
        if let Some(rawdir) = &args.raw {
            std::fs::create_dir_all(rawdir)
                .expect(&format!("Failed creating {rawdir:?}"));
        }
    }

    let conf =
        server::Config { key: SignKey::generate(KeyType::Ed25519, None).unwrap() };
    run_main(&conf, |path, ctx, data| {
        let _ = path;
        let input = FuzzInput::new(data)?;
        let data = packets(input.data.0);

        let newinput = FuzzInput::from_parts(&data, input.control.0);
        let mut fuzzin = vec![];
        sshwire::ssh_push_vec(&mut fuzzin, &newinput).unwrap();

        #[cfg(feature = "nofuzz")]
        {
            if let Some(fuzzdir) = &args.fuzzin {
                let path = path.expect("nofuzz has paths");
                save_fuzzin(&fuzzdir, path, &fuzzin);
            }
            if let Some(rawdir) = &args.raw {
                let path = path.expect("nofuzz has paths");
                save_raw(&rawdir, path, &newinput.data.0);
            }
        }
        server::run(&fuzzin, ctx)
    })
}
