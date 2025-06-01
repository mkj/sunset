//! Code to manipulate PTYs
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use std::io::Error as IoError;
use std::os::fd::AsRawFd;

use libc::{ioctl, winsize};
use nix::sys::termios::Termios;

use sunset::config::*;
use sunset::packets::WinChange;
use sunset::{Pty, Result, Runner};

/// Returns the size of the current terminal
pub fn win_size() -> Result<WinChange, IoError> {
    let mut ws = winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    // OK unsafe: TIOCGWINSZ returns a winsize
    let r = unsafe { ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if r != 0 {
        return Err(IoError::last_os_error());
    }

    Ok(WinChange {
        rows: ws.ws_row as u32,
        cols: ws.ws_col as u32,
        width: ws.ws_xpixel as u32,
        height: ws.ws_ypixel as u32,
    })
}

/// Returns a `Pty` describing the current terminal.
pub fn current_pty() -> Result<Pty, IoError> {
    let mut term = heapless::String::<MAX_TERM>::new();
    let t = std::env::var("TERM").unwrap_or(DEFAULT_TERM.into());
    // XXX error
    term.push_str(&t).expect("$TERM is too long");

    let wc = win_size()?;

    // TODO modes
    let modes = heapless::Vec::new();

    Ok(Pty {
        term,
        rows: wc.rows,
        cols: wc.cols,
        width: wc.width,
        height: wc.height,
        modes,
    })
}

/// Puts stdin/stdout into raw mode.
///
/// This assumes that stdin/stdout
/// share a common file descriptor, as is the case with a pty.
/// The returned `RawPtyGuard` reverts to previous terminal settings
/// when it is dropped.
pub fn raw_pty() -> Result<RawPtyGuard, IoError> {
    RawPtyGuard::new()
}

pub struct RawPtyGuard {
    // nix Termios isn't Sync, pending https://github.com/nix-rust/nix/pull/1324
    saved: libc::termios,
}

impl RawPtyGuard {
    fn new() -> Result<Self, IoError> {
        let saved = Self::set_raw()?.into();

        Ok(Self { saved })
    }

    fn set_raw() -> nix::Result<Termios> {
        use nix::sys::termios::*;

        let fd = std::io::stdin().as_raw_fd();

        let current = tcgetattr(fd)?;
        let mut raw = current.clone();

        raw.input_flags.insert(InputFlags::IGNPAR);
        // We could also set IUCLC but it isn't in posix
        raw.input_flags.remove(
            InputFlags::ISTRIP
                | InputFlags::INLCR
                | InputFlags::IGNCR
                | InputFlags::ICRNL
                | InputFlags::IXON
                | InputFlags::IXANY
                | InputFlags::IXOFF,
        );
        raw.local_flags.remove(
            LocalFlags::ISIG
                | LocalFlags::ICANON
                | LocalFlags::ECHO
                | LocalFlags::ECHOE
                | LocalFlags::ECHOK
                | LocalFlags::ECHONL,
        );
        raw.output_flags.remove(OutputFlags::OPOST);

        tcsetattr(fd, SetArg::TCSADRAIN, &raw)?;
        Ok(current)
    }
}

impl Drop for RawPtyGuard {
    fn drop(&mut self) {
        use nix::sys::termios::*;
        let fd = std::io::stdin().as_raw_fd();
        let r = tcsetattr(fd, SetArg::TCSADRAIN, &self.saved.into());
        if let Err(e) = r {
            warn!("Failed restoring TTY: {e}");
        }
    }
}
