#[cfg(test)]
use simplelog::{TestLogger,self,LevelFilter};

pub use ::log::{debug, error, info, log, trace, warn};

#[cfg(test)]
pub fn init_test_log() {
    let _ = TestLogger::init(LevelFilter::Trace, simplelog::Config::default());
}
