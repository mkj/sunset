//! Code to manipulate PTYs
#[allow(unused_imports)]
use log::{debug, error, info, log, trace, warn};

use std::io::Error as IoError;

use libc::{ioctl, winsize, termios, tcgetattr, tcsetattr };

use door_sshproto as door;
use door::{Behaviour, Runner, Result, Pty};
use door::config::*;
use door::packets::WinChange;

/// Returns the size of the current terminal
pub fn win_size() -> Result<WinChange, IoError> {
    let mut ws = winsize { ws_row: 0, ws_col: 0, ws_xpixel: 0, ws_ypixel: 0 };
    let r = unsafe { ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) };
    if r != 0 {
        return Err(IoError::last_os_error())
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
    term.push_str(&t).expect("TERM fits buffer");

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

/// Puts stdin/stdout into raw mode. This assumes that stdin/stdout
/// share a common file descriptor, as is the case with a pty.
/// The returned `RawPtyGuard` reverts to previous terminal settings
/// when it is dropped.
pub fn raw_pty() -> Result<RawPtyGuard, IoError> {
    RawPtyGuard::new()
}

pub struct RawPtyGuard {
    saved: termios,
}

impl RawPtyGuard {
    fn new() -> Result<Self, IoError> {
        let mut saved: termios = unsafe { core::mem::zeroed() };
        let r = unsafe { tcgetattr(libc::STDIN_FILENO, &mut saved) };
        if r != 0 {
            return Err(IoError::last_os_error())
        }

        Self::set_raw(&saved)?;

        Ok(Self {
            saved,
        })
    }

    fn set_raw(current: &termios) -> Result<(), IoError> {
        use libc::*;
        let mut raw = current.clone();

        raw.c_iflag |= IGNPAR;
        // We could also set IUCLC but it isn't in posix
        raw.c_iflag &= !(ISTRIP | INLCR | IGNCR | ICRNL | IXON | IXANY | IXOFF);
        raw.c_lflag &= !(ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHONL);
        raw.c_oflag &= !OPOST;

        let r = unsafe { tcsetattr(libc::STDIN_FILENO, TCSADRAIN, &raw) };
        if r != 0 {
            return Err(IoError::last_os_error())
        }

        info!("set_raw");

        Ok(())

    }
}

impl Drop for RawPtyGuard {
    fn drop(&mut self) {

        let r = unsafe { tcsetattr(libc::STDIN_FILENO, libc::TCSADRAIN, &self.saved) };
        if r != 0 {
            let e = IoError::last_os_error();
            warn!("Failed restoring TTY: {e}");
        } else {
            info!("Restored TTY");
        }
    }
}
