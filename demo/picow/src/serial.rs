//! Serial on rp2040 pins with a `BufferedUart`.

#[allow(unused_imports)]
pub use log::{debug, error, info, log, trace, warn};

use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::*;
use embassy_rp::uart::{self as rp_uart, BufferedInterruptHandler, BufferedUart};

use sunset_async::*;

use crate::*;

bind_interrupts!(struct Irqs {
    UART0_IRQ => BufferedInterruptHandler<UART0>;
});

#[embassy_executor::task]
pub(crate) async fn task(
    uart: UART0,
    pin_tx: PIN_0,
    pin_rx: PIN_1,
    pin_cts: PIN_2,
    pin_rts: PIN_3,
    pipe: &'static TakePipe<'static>,
) -> ! {
    static TX_BUF: StaticCell<[u8; 16]> = StaticCell::new();
    let tx_buf = TX_BUF.init(Default::default()).as_mut_slice();
    static RX_BUF: StaticCell<[u8; 300]> = StaticCell::new();
    let rx_buf = RX_BUF.init_with(|| [0u8; 300]).as_mut_slice();
    let uart = BufferedUart::new_with_rtscts(
        uart,
        Irqs,
        pin_tx,
        pin_rx,
        pin_rts,
        pin_cts,
        tx_buf,
        rx_buf,
        rp_uart::Config::default(),
    );

    // let uart = BufferedUart::new(
    //     uart,
    //     Irqs,
    //     pin_tx,
    //     pin_rx,
    //     tx_buf,
    //     rx_buf,
    //     rp_uart::Config::default(),
    // );

    let (mut tx, mut rx) = uart.split();

    // console via SSH
    let (mut chan_rx, mut chan_tx) = pipe.split();
    let chan_rx = &mut chan_rx;
    let chan_tx = &mut chan_tx;
    info!("serial task copying");
    let io_tx = io_buf_copy_noreaderror(&mut rx, chan_tx);
    let io_rx = io_copy_nowriteerror::<64, _, _>(chan_rx, &mut tx);

    let _ = select(io_rx, io_tx).await;
    panic!("serial finished");
}
