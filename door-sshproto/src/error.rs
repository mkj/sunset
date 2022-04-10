use snafu::{prelude::*};

#[derive(Snafu,Debug)]
pub enum Error {
    /// Bad serialize
    BadSerialize,
    /// Buffer ran out of room
    NoSpace,
    /// Not implemented (unused in SSH protocol)
    NoSerializer,
    /// Custom error
    Custom,
}

impl serde::ser::Error for Error {
    fn custom<T>(msg: T) -> Self
        where T:std::fmt::Display {
            // TODO: something noalloc
            println!("custom error: {}", msg.to_string());
            Error::Custom
    }
}
