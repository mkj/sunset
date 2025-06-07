#![allow(unreachable_code)]
#![allow(dead_code)]

#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use std::path::Path;
use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
    io::ErrorKind,
};

use sshwire::BinString;
use sunset::namelist::NameList;
use sunset::packets::Packet;
use sunset::*;

use sunset_sshwire_derive::*;

const BUFSIZE: usize = 50_000;
const READBUF: [u8; BUFSIZE] = [0; BUFSIZE];

#[derive(SSHDecode)]
struct FuzzInput<'p> {
    data: BinString<'p>,
    control: BinString<'p>,
}

impl<'p> FuzzInput<'p> {
    const MIN_DATA: usize = 2000;
    const MIN_CONTROL: usize = 2000;

    fn new(data: &'p [u8]) -> Result<Self> {
        let input = sshwire::read_ssh::<FuzzInput>(data, None)?;
        if input.data.0.len() < Self::MIN_DATA {
            return error::RanOut.fail();
        }
        if input.control.0.len() < Self::MIN_CONTROL {
            return error::RanOut.fail();
        }
        Ok(input)
    }

    fn done_data(&mut self, len: usize) {
        let (_, d) = self.data.0.split_at(len);
        self.data.0 = d;
    }

    fn control_u32(&mut self) -> Result<u32> {
        self.control
            .0
            .split_at_checked(core::mem::size_of::<u32>())
            .map(|(v, rest)| {
                let val = u32::from_be_bytes(v.try_into().unwrap());
                self.control.0 = rest;
                val
            })
            .ok_or(error::RanOut.build())
    }

    /// Returns `Err` when input runs out.
    fn chance(&mut self, chance: f32) -> Result<bool> {
        self.control_u32().map(|v| (v as f32 / u32::MAX as f32) < chance)
    }
}

struct State<'a> {
    conf: &'a Config,
    firstauth: bool,
    authed: bool,

    // BTreeMap for deterministic ordering
    chans: BTreeMap<ChanNum, ChanHandle>,
}

impl<'a> State<'a> {
    fn new(conf: &'a Config) -> Self {
        Self { conf, authed: false, firstauth: false, chans: Default::default() }
    }
}

#[derive(Clone)]
struct Config {
    key: SignKey,
}

fn serv_event(input: &mut FuzzInput, ev: Event, state: &mut State) -> Result<()> {
    let ev = match ev {
        Event::Cli(_) => panic!(),
        Event::Serv(ev) => ev,
        Event::Progressed | Event::None => return Ok(()),
    };

    match ev {
        ServEvent::Hostkeys(h) => {
            h.hostkeys(core::slice::from_ref(&&state.conf.key))?;
        }
        ServEvent::FirstAuth(h) => {
            assert!(!state.authed);
            assert!(!state.firstauth);
            state.firstauth = true;
            black_box(h.username()?);
            if input.chance(0.9)? {
                state.authed = true;
                h.allow()?;
            } else if input.chance(0.1)? {
                h.reject()?;
            }
        }
        ServEvent::PasswordAuth(h) => {
            assert!(!state.authed);
            black_box(h.username()?);
            black_box(h.password()?);
            if input.chance(0.9)? {
                h.allow()?;
                state.authed = true;
            } else if input.chance(0.4)? {
                h.reject()?;
            }
        }
        ServEvent::PubkeyAuth(h) => {
            assert!(!state.authed);
            black_box(h.username()?);
            black_box(h.pubkey()?);
            if input.chance(0.9)? {
                let real = h.real();
                h.allow()?;
                if real {
                    state.authed = true;
                }
            } else if input.chance(0.4)? {
                h.reject()?;
            }
        }
        ServEvent::OpenSession(h) => {
            assert!(state.authed);

            if input.chance(0.9)? {
                // TODO: this shouldn't fail with NoRoom
                let ch = h.accept()?;
                let inserted = state.chans.insert(ch.num(), ch);
                assert!(inserted.is_none());
            }
        }
        ServEvent::SessionShell(h) => {
            assert!(state.authed);
            assert!(state.chans.contains_key(&h.channel()));
            if input.chance(0.9)? {
                // TODO: this shouldn't fail with NoRoom
                h.succeed()?;
            }
        }
        _ => (),
    }
    Ok(())
}

#[cfg(feature = "arbfuzz")]
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
            r.service = SSH_SERVICE_CONNECTION.into();
        }
        Packet::ServiceRequest(r) => {
            // doesn't matter what it is, as long as it's known.
            r.name = SSH_SERVICE_CONNECTION.into();
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
            *num = *num % (config::MAX_CHANNELS as u32 + 2);
        }
        _ => (),
    }
    Ok(())
}

#[cfg(feature = "arbfuzz")]
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

fn run(data: &[u8], conf: &Config) -> Result<()> {
    let mut input = FuzzInput::new(data)?;

    let mut inbuf = [0u8; BUFSIZE];
    let mut outbuf = [0u8; BUFSIZE];
    let mut runner = Runner::new_server(&mut inbuf, &mut outbuf);

    #[cfg(feature = "arbfuzz")]
    let arb = packets(input.data.0);
    #[cfg(feature = "arbfuzz")]
    {
        input.data = BinString(&arb);
    }

    trace!("Total input {:02x?}", input.data.0);

    let mut state = State::new(conf);

    let mut prev_stuck = false;
    loop {
        trace!("fuz top. prev stuck {prev_stuck}");
        let mut stuck = true;
        // Input
        let len = runner.input(input.data.as_ref())?;
        trace!("fuz in len {len}");
        input.done_data(len);
        stuck &= len == 0;

        // Output
        let l = runner.output_buf();
        trace!("fuz out len {}", l.len());
        stuck &= l.len() == 0;
        let lim = input.control_u32()?;
        let len = l.len().min(lim as usize);
        runner.consume_output(len);

        // Progress
        let ev = runner.progress()?;
        trace!("fuz ev {ev:?}");
        stuck &= matches!(&ev, Event::None | Event::Serv(ServEvent::PollAgain));
        serv_event(&mut input, ev, &mut state)?;
        // TODO: assert that serv_event doesn't return NoRoom, at least for
        // normal things.

        // Channels

        // Find which channel is ready to read
        let mut ready_len = None;
        let mut ready_ch = None;
        if let Some((ch, dt, len)) = runner.read_channel_ready() {
            assert!(state.chans.contains_key(&ch));
            assert_eq!(dt, ChanData::Normal);
            assert!(len > 0);
            assert!(len < BUFSIZE);
            ready_len = Some(len);
            ready_ch = Some(ch);
        }

        let mut remove_chans = BTreeSet::new();

        // Operate on channels
        for ch in state.chans.values() {
            if chan_read(
                &mut input,
                &mut runner,
                &ch,
                ready_ch,
                ready_len,
                &mut remove_chans,
            )? {
                stuck = false;
            }
            if chan_write(&mut input, &mut runner, &ch, &mut remove_chans)? {
                stuck = false;
            }
            // Randomly close channels
            if input.chance(0.1)? {
                trace!("fuz random close channel {ch:?}");
                remove_chans.insert(ch.num());
            }
        }

        // Remove the chosen ones
        for ch in remove_chans {
            trace!("fuz removing channel {ch}");
            runner.channel_done(state.chans.remove(&ch).unwrap())?;
        }

        // Ensure forward progress
        if stuck {
            if input.data.0.is_empty() {
                // No more input
                trace!("fuz ran out of input");
                break Err(error::RanOut.build());
            }

            if prev_stuck {
                trace!("stuck, {runner:?}");
                panic!("stuck");
            }
        }

        prev_stuck = stuck;
    }
}

// Returns Ok(true) if progressed
fn chan_read(
    input: &mut FuzzInput,
    runner: &mut Runner<Server>,
    ch: &ChanHandle,
    ready_ch: Option<ChanNum>,
    ready_len: Option<usize>,
    remove_chans: &mut BTreeSet<ChanNum>,
) -> Result<bool> {
    let mut progressed = false;
    if input.chance(0.9)? {
        let mut buf = [0u8; BUFSIZE];
        let lim = input.control_u32()? as usize;
        let lim = lim.min(buf.len());
        let buf = &mut buf[..lim];

        // no stderr read for servers.
        let dt = ChanData::Normal;
        match runner.read_channel(&ch, dt, buf) {
            Ok(len) => {
                // Successful read
                progressed = true;
                assert!(len <= buf.len());
                if ready_ch == Some(ch.num()) {
                    let ready_len = ready_len.unwrap();
                    if buf.len() > 0 {
                        assert!(len > 0, "ready means read_channel should succeed");
                    }
                    if buf.len() >= ready_len {
                        assert!(len == ready_len, "ready returned correct length");
                    }
                }
            }
            Err(Error::ChannelEOF) => {
                if input.chance(0.8)? {
                    remove_chans.insert(ch.num());
                }
            }
            Err(e) => return Err(e),
        }
    } else {
        // Don't warn as about "stuck" if we randomly skipped reading.
        if ready_ch == Some(ch.num()) {
            progressed = true;
        }
    }
    Ok(progressed)
}

// Returns Ok(true) if progressed
fn chan_write(
    input: &mut FuzzInput,
    runner: &mut Runner<Server>,
    ch: &ChanHandle,
    remove_chans: &mut BTreeSet<ChanNum>,
) -> Result<bool> {
    let mut progressed = false;
    if input.chance(0.9)? {
        // Arbitrary length to write
        let lim = input.control_u32()? as usize;
        let lim = lim.min(READBUF.len());
        let buf = &READBUF[..lim];

        // Random stdout or stderr
        let dt =
            if input.chance(0.5)? { ChanData::Normal } else { ChanData::Stderr };
        let ready = runner.write_channel_ready(&ch, dt);
        // if let Ok(Some(l)) = ready {
        //     assert!(l != 0, "Can't be ready for 0 bytes");
        // }

        match runner.write_channel(&ch, dt, buf) {
            Ok(len) => {
                // Successful read
                progressed = true;
                assert!(len <= buf.len());
                // Check it matches the write_channel_ready()
                match ready {
                    Err(_) => panic!("Ready error, read succeeded"),
                    Ok(Some(ready_len)) => {
                        if buf.len() > 0 && ready_len > 0 {
                            assert!(len > 0)
                        }
                        if buf.len() >= ready_len {
                            assert!(len == ready_len);
                        }
                    }
                    Ok(None) => panic!("read succeeded, but ready EOF"),
                }
            }
            Err(Error::ChannelEOF) => {
                assert!(matches!(ready, Ok(None)));
                if input.chance(0.8)? {
                    remove_chans.insert(ch.num());
                }
            }
            Err(e) => return Err(e),
        }
    } else {
        // Don't warn as about "stuck" if we randomly skipped reading.
        progressed = true;
    }
    Ok(progressed)
}

fn each_arg<F>(f: F)
where
    F: Fn(&Path, &[u8]),
{
    for arg in std::env::args().skip(1) {
        let mut paths = vec![];
        match std::fs::read_dir(&arg) {
            Ok(dir) => {
                for ent in dir {
                    match &ent {
                        Ok(e) => {
                            paths.push(e.path());
                        }
                        Err(e) => warn!("Problem with {ent:?}: {e:?}"),
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::NotADirectory => {
                paths.push(arg.into());
            }
            Err(e) => warn!("Bad path {arg:?}: {e:?}"),
        }
        for s in paths {
            let data = match std::fs::read(&s) {
                Ok(data) => data,
                Err(e) if e.kind() == ErrorKind::IsADirectory => continue,
                Err(e) => {
                    warn!("Failed {s:?}: {e:?}");
                    continue;
                }
            };
            f(&s, &data);
        }
    }
}

fn check_error(r: Result<()>) {
    if let Err(e) = r {
        match e {
            // Errors that should not occur.
            // May indicate a bug in this fuzz harness.
            Error::BadChannel { .. }
            | Error::BadChannelData
            | Error::BadUsage { .. }
            | Error::Custom { .. }
            | Error::Bug { .. } => panic!("Unexpected error {e:#?}"),
            _ => (),
        }
    }
}

fn main() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("debug"),
    )
    .init();

    let conf = Config { key: SignKey::generate(KeyType::Ed25519, None).unwrap() };

    #[cfg(feature = "honggfuzz")]
    {
        loop {
            honggfuzz::fuzz!(|data: &[u8]| {
                let e = run(data, &conf);
                check_error(e);
            })
        }
    }

    #[cfg(feature = "afl")]
    {
        afl::fuzz!(|data: &[u8]| {
            let e = run(data, &conf);
            check_error(e);
        });
        return;
    }

    #[cfg(feature = "nofuzz")]
    {
        each_arg(|filename, data| {
            info!("running {filename:?}");
            match run(data, &conf) {
                Err(Error::AlgoNoMatch { algo }) => {
                    error!("{filename:?} No Algo match {algo:?}")
                }
                Err(e) => {
                    warn!("Exited with error: {e:?}");
                    check_error(Err(e));
                }
                Ok(_) => panic!("Finished somehow"),
            }
        });
        return;
    }

    panic!("missing feature");
}
