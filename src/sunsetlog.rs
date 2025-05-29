#[cfg(test)]
use simplelog::{self, LevelFilter, TestLogger};

pub use ::log::{debug, error, info, log, trace, warn};

#[cfg(test)]
pub fn init_test_log() {
    let conf =
        simplelog::ConfigBuilder::new().add_filter_ignore_str("serde").build();
    let _ = TestLogger::init(LevelFilter::Trace, conf);
}
