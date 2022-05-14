#[allow(unused_imports)]
use {
    crate::error::{Error, Result, TrapBug},
    log::{debug, error, info, log, trace, warn},
};

use snafu::prelude::*;

// TODO: probably want a special Result here. They probably all want
// Result, it can return an error or other options like Disconnect?
pub type HookResult<T> = core::result::Result<T, HookError>;

#[derive(Debug,Snafu)]
pub enum HookError {
    Fail,
    #[doc(hidden)]
    Unimplemented,
}

