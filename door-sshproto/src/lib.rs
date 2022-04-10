#![forbid(unsafe_code)]

pub mod packets;
// XXX public?
pub mod wireformat;
pub mod error;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
