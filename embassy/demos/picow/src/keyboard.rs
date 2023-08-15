#[allow(unused_imports)]
#[cfg(not(feature = "defmt"))]
pub use log::{debug, error, info, log, trace, warn};

#[allow(unused_imports)]
#[cfg(feature = "defmt")]
pub use defmt::{debug, error, info, panic, trace, warn};

use embassy_futures::join::join;
use embassy_usb::class::hid::{HidReaderWriter, ReportId, RequestHandler};
use embassy_usb::control::OutResponse;
use embassy_usb_driver::Driver;

use crate::*;

pub(crate) async fn run<'a, D: Driver<'a>>(
    _global: &'static GlobalState,
    hid: HidReaderWriter<'a, D, 1, 8>,
) -> ! {
    let (reader, _writer) = hid.split();
    let keyb_fut = async {
        loop {
            todo!();
        }
    };

    let handler = Handler;
    let control_fut = reader.run(false, &handler);

    join(keyb_fut, control_fut).await;
    unreachable!()
}


struct Handler;

impl RequestHandler for Handler {
    fn get_report(&self, _id: ReportId, _buf: &mut [u8]) -> Option<usize> {
        None
    }

    fn set_report(&self, _id: ReportId, _data: &[u8]) -> OutResponse {
        OutResponse::Accepted
    }

    fn set_idle_ms(&self, _id: Option<ReportId>, _dur: u32) {
    }

    fn get_idle_ms(&self, _id: Option<ReportId>) -> Option<u32> {
        None
    }
}
