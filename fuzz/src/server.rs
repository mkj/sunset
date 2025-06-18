#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use std::{
    collections::{BTreeMap, BTreeSet},
    hint::black_box,
};

use sunset::*;

use crate::*;

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
pub struct Config {
    pub key: SignKey,
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

pub fn run(data: &[u8], conf: &Config) -> Result<()> {
    let mut input = FuzzInput::new(data)?;

    let mut inbuf = [0u8; BUFSIZE];
    let mut outbuf = [0u8; BUFSIZE];
    let mut runner = Runner::new_server(&mut inbuf, &mut outbuf);

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
        stuck &= l.is_empty();
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
                ch,
                ready_ch,
                ready_len,
                &mut remove_chans,
            )? {
                stuck = false;
            }
            if chan_write(&mut input, &mut runner, ch, &mut remove_chans)? {
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
        match runner.read_channel(ch, dt, buf) {
            Ok(len) => {
                // Successful read
                progressed = true;
                assert!(len <= buf.len());
                if ready_ch == Some(ch.num()) {
                    let ready_len = ready_len.unwrap();
                    if !buf.is_empty() {
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

pub const BUFSIZE: usize = 50_000;
static READBUF: [u8; BUFSIZE] = [0; BUFSIZE];

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
        let ready = runner.write_channel_ready(ch, dt);
        // if let Ok(Some(l)) = ready {
        //     assert!(l != 0, "Can't be ready for 0 bytes");
        // }

        match runner.write_channel(ch, dt, buf) {
            Ok(len) => {
                // Successful read
                progressed = true;
                assert!(len <= buf.len());
                // Check it matches the write_channel_ready()
                match ready {
                    Err(_) => panic!("Ready error, read succeeded"),
                    Ok(Some(ready_len)) => {
                        if !buf.is_empty() && ready_len > 0 {
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
